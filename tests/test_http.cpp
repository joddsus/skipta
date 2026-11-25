// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The HTTP transport is the one place where bytes cross a machine boundary.
// These tests pin what may cross it: only exact sealed object names, never a
// symlink, never a key, and the reader still authenticates every byte.
#if !defined(_WIN32)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/http.hpp"
#include "skipta/share.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

constexpr int kLocalSendFlags =
#ifdef MSG_NOSIGNAL
    MSG_NOSIGNAL;
#else
    0;
#endif

int connect_loopback(std::uint16_t port) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) throw std::runtime_error("cannot create a test socket");
#if defined(SO_NOSIGPIPE)
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if (::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
      ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ::close(fd);
    throw std::runtime_error("cannot connect to the test server");
  }
  return fd;
}

bool send_bytes(int fd, const std::string& data) {
  std::size_t sent = 0;
  while (sent < data.size()) {
    const ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, kLocalSendFlags);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return false;
    sent += static_cast<std::size_t>(n);
  }
  return true;
}

std::string raw_http(std::uint16_t port, const std::string& request) {
  const int fd = connect_loopback(port);
  if (!send_bytes(fd, request)) {
    ::close(fd);
    throw std::runtime_error("cannot send the test request");
  }
  ::shutdown(fd, SHUT_WR);
  std::string response;
  char buffer[4096];
  for (;;) {
    const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;
    response.append(buffer, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return response;
}

int status_code(const std::string& response) {
  if (response.rfind("HTTP/1.", 0) != 0) return -1;
  const std::size_t space = response.find(' ');
  if (space == std::string::npos || space + 4 > response.size()) return -1;
  try {
    return std::stoi(response.substr(space + 1, 3));
  } catch (const std::exception&) {
    return -1;
  }
}

std::string response_body(const std::string& response) {
  const std::size_t split = response.find("\r\n\r\n");
  return split == std::string::npos ? std::string() : response.substr(split + 4);
}

unsigned mode_of(const fs::path& path) {
  struct stat info {};
  if (::stat(path.c_str(), &info) != 0) return 0;
  return static_cast<unsigned>(info.st_mode) & 0777u;
}

class RunningServer {
 public:
  explicit RunningServer(const fs::path& root)
      : server_({root, "127.0.0.1", 0}), thread_([this] { server_.run(); }) {}
  ~RunningServer() {
    server_.stop();
    if (thread_.joinable()) thread_.join();
  }
  RunningServer(const RunningServer&) = delete;
  RunningServer& operator=(const RunningServer&) = delete;

  std::uint16_t port() const { return server_.port(); }
  std::string origin() const { return server_.origin(); }

 private:
  HttpServer server_;
  std::thread thread_;
};

/// One connection, one scripted response; the client's view of a hostile or
/// broken origin.
class ScriptedServer {
 public:
  explicit ScriptedServer(std::string response) : response_(std::move(response)) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) throw std::runtime_error("cannot create a scripted server");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = 0;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        ::listen(listen_fd_, 1) != 0) {
      ::close(listen_fd_);
      throw std::runtime_error("cannot bind a scripted server");
    }
    socklen_t length = sizeof(address);
    ::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&address), &length);
    port_ = ntohs(address.sin_port);
    thread_ = std::thread([this] {
      while (!stopping_.load()) {
        pollfd waiting{listen_fd_, POLLIN, 0};
        const int ready = ::poll(&waiting, 1, 100);
        if (ready <= 0) continue;
        const int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) continue;
        char request[2048];
        (void)::recv(fd, request, sizeof(request), 0);
        (void)send_bytes(fd, response_);
        ::close(fd);
        return;
      }
    });
  }
  ~ScriptedServer() {
    stopping_.store(true);
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
  }
  ScriptedServer(const ScriptedServer&) = delete;
  ScriptedServer& operator=(const ScriptedServer&) = delete;

  std::string url(const std::string& path) const {
    return "http://127.0.0.1:" + std::to_string(port_) + path;
  }

 private:
  std::string response_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0;
  std::atomic<bool> stopping_{false};
  std::thread thread_;
};

}  // namespace

TEST_CASE("serve a store read-only and read it through a remote cache") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::TempDir cache_dir("cache");
  skiptest::write_text(source.path() / "a.txt", "hello skipta");
  skiptest::write_text(source.path() / "docs" / "nested.txt", "nested");
  skiptest::write_pattern(source.path() / "big.bin", 200000, 5);

  FileStore local(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), local);
  const fs::path cache = cache_dir.path() / "cache";

  {
    RunningServer server(local.root());
    CHECK(server.port() != 0);
    CHECK(server.origin().rfind("http://127.0.0.1:", 0) == 0);

    FileStore remote(cache, server.origin());
    CHECK(remote.is_remote());
    const ShareSession session = open_share(remote, published.link);
    CHECK(session.pointer.drive == published.drive);

    const std::vector<Entry> root = list_path(remote, session, "");
    REQUIRE(root.size() == 3);
    CHECK(root[0].name == "a.txt");

    const std::optional<Entry> big = resolve_path(remote, session, "big.bin");
    REQUIRE(big.has_value());
    std::ostringstream fetched;
    CHECK(fetch_file(remote, session, *big, fetched) == 200000);
    CHECK(fetched.str() == to_string(ByteView(skiptest::pattern(200000, 5))));

    // verify walks every manifest and block, all through the origin.
    const VerifyResult verified = verify_path(remote, session);
    CHECK(verified.files == 3);
    CHECK(verified.blocks == 6);

    // The cache holds objects and reader state, but never an identity.
    CHECK(fs::exists(cache / "pointers"));
    CHECK(fs::exists(cache / "manifests"));
    CHECK(fs::exists(cache / "blocks"));
    CHECK(!fs::exists(cache / "identities"));
    CHECK(mode_of(cache / "pointers") == 0700u);
    CHECK(mode_of(cache / "blocks") == 0700u);
    const fs::path cached_block = cache / "blocks" / hex_encode(ByteView(big->file_id)) /
                                  skiptest::block_name(0);
    CHECK(fs::exists(cached_block));
    CHECK(mode_of(cached_block) == 0600u);

    const ShareLink link = decode_link(published.link);
    CHECK(accepted_pointer_seq(remote, link.drive) == 0);
    remember_pointer_seq(remote, session.pointer.drive, session.pointer.seq);
    CHECK(accepted_pointer_seq(remote, link.drive) == 1);
    CHECK(mode_of(cache / "accepted" / (hex_encode(ByteView(link.drive)) + ".seq")) == 0600u);
  }

  // With the server gone, the cache alone still opens and reads the share.
  FileStore cached(cache);
  const ShareSession offline = open_share(cached, published.link);
  const std::optional<Entry> nested = resolve_path(cached, offline, "docs/nested.txt");
  REQUIRE(nested.has_value());
  std::ostringstream nested_out;
  CHECK(fetch_file(cached, offline, *nested, nested_out) == 6);
  CHECK(nested_out.str() == "nested");
}

TEST_CASE("the server answers only exact object names and never follows links") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "hello skipta");
  skiptest::write_pattern(source.path() / "big.bin", 70000, 9);

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::vector<Entry> root = list_path(store, session, "");
  REQUIRE(root.size() == 2);
  const Entry& big = root[1];
  CHECK(big.name == "big.bin");

  RunningServer server(store.root());

  // A real pointer, manifest and block are served byte-for-byte.
  const std::string pointer_path =
      "/pointers/" + hex_encode(ByteView(published.drive)) + ".ptr";
  const std::string pointer_response =
      raw_http(server.port(), "GET " + pointer_path + " HTTP/1.1\r\nHost: test\r\n\r\n");
  CHECK(status_code(pointer_response) == 200);
  CHECK(response_body(pointer_response) ==
        to_string(ByteView(*store.get_pointer(published.drive))));

  const std::string manifest_path = "/manifests/" + hex_encode(ByteView(session.root.id)) + ".mf";
  const std::string manifest_response =
      raw_http(server.port(), "GET " + manifest_path + " HTTP/1.1\r\nHost: test\r\n\r\n");
  CHECK(status_code(manifest_response) == 200);
  CHECK(!response_body(manifest_response).empty());

  const std::string block_path = "/blocks/" + hex_encode(ByteView(big.file_id)) + "/" +
                                 skiptest::block_name(0);
  const std::string block_response =
      raw_http(server.port(), "GET " + block_path + " HTTP/1.1\r\nHost: test\r\n\r\n");
  CHECK(status_code(block_response) == 200);
  CHECK(response_body(block_response) ==
        to_string(ByteView(*store.get_block(big.file_id, 0))));

  // Anything that is not exactly one of those names is refused.
  const std::string drive_hex = hex_encode(ByteView(published.drive));
  const std::string id_hex = hex_encode(ByteView(big.file_id));
  const std::string too_long(300, 'a');
  const std::string bad_requests[] = {
      "GET / HTTP/1.1\r\n\r\n",
      "GET /identities/x HTTP/1.1\r\n\r\n",
      "GET /pointers/../identities/x HTTP/1.1\r\n\r\n",
      "GET /pointers/../../etc/passwd HTTP/1.1\r\n\r\n",
      "GET /pointers/" + drive_hex + ".ptr/ HTTP/1.1\r\n\r\n",
      "GET /pointers/" + drive_hex + ".tr HTTP/1.1\r\n\r\n",
      "GET /pointers/" + drive_hex + " HTTP/1.1\r\n\r\n",
      "GET //pointers/" + drive_hex + ".ptr HTTP/1.1\r\n\r\n",
      "GET /blocks/" + id_hex + "/" + skiptest::block_name(0) + "x HTTP/1.1\r\n\r\n",
      "GET /blocks/" + id_hex + "/../" + skiptest::block_name(0) + " HTTP/1.1\r\n\r\n",
      "GET /blocks/" + id_hex + "//" + skiptest::block_name(0) + " HTTP/1.1\r\n\r\n",
      "GET /manifests/" + id_hex + ".mf%00 HTTP/1.1\r\n\r\n",
      "GET /manifests/" + too_long + ".mf HTTP/1.1\r\n\r\n",
  };
  for (const std::string& request : bad_requests) {
    const std::string response = raw_http(server.port(), request);
    CHECK(status_code(response) == 404);
  }

  // An unknown but well-formed object is a plain 404.
  const std::string unknown =
      "/manifests/" + hex_encode(ByteView(crypto::random_id())) + ".mf";
  CHECK(status_code(raw_http(server.port(), "GET " + unknown + " HTTP/1.1\r\n\r\n")) == 404);

  // Methods other than GET are refused, so the endpoint is read-only.
  CHECK(status_code(raw_http(server.port(), "POST " + block_path + " HTTP/1.1\r\n\r\n")) == 405);
  CHECK(status_code(raw_http(server.port(), "PUT " + pointer_path + " HTTP/1.1\r\n\r\n")) ==
        405);
  CHECK(status_code(raw_http(server.port(), "GET " + block_path + " HTTP/2.0\r\n\r\n")) == 400);

  // A symlinked object is refused even though a regular file is behind it.
  skiptest::TempDir outside("outside");
  skiptest::write_text(outside.path() / "secret", "SECRET-OUTSIDE");
  const std::string linked_id = hex_encode(ByteView(crypto::random_id()));
  std::error_code ec;
  fs::create_symlink(outside.path() / "secret",
                     store.root() / "manifests" / (linked_id + ".mf"), ec);
  if (!ec) {
    const std::string response =
        raw_http(server.port(), "GET /manifests/" + linked_id + ".mf HTTP/1.1\r\n\r\n");
    CHECK(status_code(response) == 500);
    CHECK(response_body(response).find("SECRET-OUTSIDE") == std::string::npos);
  }

  // A symlinked *directory* in the store cannot redirect the server outside it.
  skiptest::TempDir redirected("redirected");
  fs::create_directories(redirected.path() / linked_id);
  skiptest::write_text(redirected.path() / linked_id / skiptest::block_name(0),
                       "SECRET-DIRECTORY");
  const fs::path trap_store = work.path() / "trap";
  fs::create_directories(trap_store);
  fs::create_symlink(redirected.path(), trap_store / "blocks", ec);
  if (!ec) {
    RunningServer trapped(trap_store);
    const std::string response = raw_http(
        trapped.port(), "GET /blocks/" + linked_id + "/" + skiptest::block_name(0) +
                            " HTTP/1.1\r\n\r\n");
    CHECK(status_code(response) == 500);
    CHECK(response_body(response).find("SECRET-DIRECTORY") == std::string::npos);
  }

  // A local object larger than the format allows is not served as if valid.
  const std::string huge_id = hex_encode(ByteView(crypto::random_id())) +
                              hex_encode(ByteView(crypto::random_id()));
  skiptest::write_pattern(store.root() / "pointers" / (huge_id + ".ptr"), 5000, 1);
  const std::string huge =
      raw_http(server.port(), "GET /pointers/" + huge_id + ".ptr HTTP/1.1\r\n\r\n");
  CHECK(status_code(huge) == 500);
}

TEST_CASE("remote objects are still authenticated and corruption is not cached as truth") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::TempDir cache_dir("cache");
  skiptest::write_pattern(source.path() / "video.bin", 150000, 3);

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> video = resolve_path(store, session, "video.bin");
  REQUIRE(video.has_value());

  // Damage the first block in the served store.
  const fs::path block_path =
      store.root() / "blocks" / hex_encode(ByteView(video->file_id)) / skiptest::block_name(0);
  {
    std::fstream file(block_path, std::ios::binary | std::ios::in | std::ios::out);
    REQUIRE(file.good());
    char byte = 0;
    file.read(&byte, 1);
    REQUIRE(file.gcount() == 1);
    byte = static_cast<char>(byte ^ 0x01);
    file.seekp(0);
    file.write(&byte, 1);
  }

  RunningServer server(store.root());
  FileStore remote(cache_dir.path() / "cache", server.origin());
  const ShareSession remote_session = open_share(remote, published.link);
  const std::optional<Entry> remote_video = resolve_path(remote, remote_session, "video.bin");
  REQUIRE(remote_video.has_value());

  std::ostringstream out;
  CHECK_THROWS_AS(fetch_file(remote, remote_session, *remote_video, out), Error);
  try {
    std::ostringstream again;
    fetch_file(remote, remote_session, *remote_video, again);
    FAIL("a damaged remote block was accepted");
  } catch (const Error& e) {
    CHECK(e.code() == ErrorCode::AuthFailed);
  }
}

TEST_CASE("store URLs are validated and remote stores refuse writes") {
  skiptest::TempDir work("cache");
  CHECK(looks_like_store_url("http://127.0.0.1:1"));
  CHECK(looks_like_store_url("https://example.test/store"));
  CHECK(!looks_like_store_url("./skipta-store"));
  CHECK(!looks_like_store_url("skipta-store"));

  CHECK(normalize_http_store_url("http://127.0.0.1:8787/") == "http://127.0.0.1:8787");
  CHECK(normalize_http_store_url("http://example.test:80/skipta/") ==
        "http://example.test:80/skipta");
  CHECK_THROWS_AS(normalize_http_store_url("https://example.test"), Error);
  CHECK_THROWS_AS(normalize_http_store_url("http://"), Error);
  CHECK_THROWS_AS(normalize_http_store_url("http://host:0"), Error);
  CHECK_THROWS_AS(normalize_http_store_url("http://host:99999"), Error);
  CHECK_THROWS_AS(normalize_http_store_url("http://host/store?x=1"), Error);
  CHECK_THROWS_AS(normalize_http_store_url("http://user:pass@host"), Error);

  FileStore remote(work.path() / "cache", "http://127.0.0.1:9/prefix/");
  CHECK(remote.remote_origin() == "http://127.0.0.1:9/prefix");
  CHECK_THROWS_AS(remote.put_manifest(crypto::random_id(), ByteView(std::string("x"))), Error);
  CHECK_THROWS_AS(remote.put_block(crypto::random_id(), 0, ByteView(std::string("x"))), Error);

  // An origin that is not listening is a store error, not "object missing".
  CHECK_THROWS_AS(remote.get_block(crypto::random_id(), 0), Error);
  try {
    remote.get_block(crypto::random_id(), 0);
  } catch (const Error& e) {
    CHECK(e.code() == ErrorCode::StoreIo);
  }
}

TEST_CASE("the HTTP client refuses malformed, oversized, chunked and redirected responses") {
  {
    ScriptedServer server("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody");
    const std::optional<Bytes> body = http_get_object(server.url("/pointers/x.ptr"), 100);
    REQUIRE(body.has_value());
    CHECK(to_string(ByteView(*body)) == "body");
  }
  {
    ScriptedServer server("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    CHECK(!http_get_object(server.url("/manifests/x.mf"), 100).has_value());
  }
  {
    ScriptedServer server("HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n");
    CHECK_THROWS_AS(http_get_object(server.url("/blocks/x/0.blk"), 100), Error);
  }
  {
    ScriptedServer server(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n");
    CHECK_THROWS_AS(http_get_object(server.url("/blocks/x/0.blk"), 100), Error);
  }
  {
    ScriptedServer server(
        "HTTP/1.1 302 Found\r\nLocation: http://elsewhere.test/\r\nContent-Length: 0\r\n\r\n");
    CHECK_THROWS_AS(http_get_object(server.url("/pointers/x.ptr"), 100), Error);
  }
  {
    ScriptedServer server("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc");
    CHECK_THROWS_AS(http_get_object(server.url("/pointers/x.ptr"), 100), Error);
  }
  {
    ScriptedServer server("not http at all\r\n\r\n");
    CHECK_THROWS_AS(http_get_object(server.url("/pointers/x.ptr"), 100), Error);
  }
  {
    ScriptedServer server("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    CHECK(http_get_object(server.url("/pointers/x.ptr"), 0).has_value());
  }
  // A server that never answers must not hang the reader forever; the client
  // sets a receive timeout, which is covered by the I/O timeout constant and
  // exercised here by closing without a response.
  {
    ScriptedServer server("");
    CHECK_THROWS_AS(http_get_object(server.url("/pointers/x.ptr"), 100), Error);
  }
}

#endif  // !_WIN32
