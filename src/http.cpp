// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/http.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstring>
#include <string>
#include <utility>

#if !defined(_WIN32)
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "skipta/error.hpp"
#include "skipta/store.hpp"

namespace skipta {
namespace {

constexpr std::size_t kMaxRequestBytes = 8 * 1024;
constexpr std::size_t kMaxResponseHeaderBytes = 16 * 1024;

// The pure request/response parsers compile on every platform; only the
// socket transport below is POSIX-only.
#if !defined(_WIN32)
constexpr int kConnectTimeoutMs = 10000;
constexpr int kIoTimeoutSeconds = 20;
// An absolute bound on one object fetch, so a peer that trickles bytes cannot
// hold a reader forever just by resetting the per-read timeout.
constexpr int kObjectDeadlineSeconds = 60;
// A request header is small; it must arrive quickly even on a slow link.
constexpr int kRequestDeadlineSeconds = 10;

using Clock = std::chrono::steady_clock;

bool expired(Clock::time_point deadline) { return Clock::now() > deadline; }

/// A peer that disappears mid-response must not raise SIGPIPE on platforms
/// that have neither MSG_NOSIGNAL (Linux) nor a socket-level opt-out.
void suppress_sigpipe(int fd) {
#if defined(SO_NOSIGPIPE)
  int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
  (void)fd;
#endif
}
#endif  // !_WIN32

std::string ascii_lower(std::string_view text) {
  std::string out(text);
  for (char& c : out) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return out;
}

bool starts_with_ci(std::string_view text, std::string_view prefix) {
  if (text.size() < prefix.size()) return false;
  return ascii_lower(text.substr(0, prefix.size())) == prefix;
}

bool is_digits(std::string_view text) {
  if (text.empty()) return false;
  for (char c : text) {
    if (c < '0' || c > '9') return false;
  }
  return true;
}

#if !defined(_WIN32)
bool valid_host_char(char c) {
  const unsigned char u = static_cast<unsigned char>(c);
  if (u <= 0x20 || u == 0x7f) return false;
  return std::isalnum(u) != 0 || c == '-' || c == '.' || c == '_' || c == ':';
}

struct ParsedUrl {
  std::string authority;  ///< as written, including [] around an IPv6 literal
  std::string host;       ///< without brackets, for getaddrinfo
  std::string port;       ///< always explicit or "80"
  std::string path;       ///< starts with '/' or is empty
};

ParsedUrl parse_http_url(std::string_view url) {
  if (!starts_with_ci(url, "http://")) {
    fail(ErrorCode::BadOptions,
         "only http:// store URLs are supported (this build has no TLS client): " +
             std::string(url));
  }
  std::string_view rest = url.substr(7);
  const std::size_t slash = rest.find('/');
  const std::string_view authority = slash == std::string_view::npos ? rest : rest.substr(0, slash);
  std::string_view path = slash == std::string_view::npos ? std::string_view() : rest.substr(slash);

  if (authority.empty()) fail(ErrorCode::BadOptions, "store URL has no host: " + std::string(url));
  if (authority.find('@') != std::string_view::npos) {
    fail(ErrorCode::BadOptions, "store URLs must not carry credentials");
  }

  ParsedUrl out;
  out.authority = std::string(authority);
  std::string_view port;
  if (authority.front() == '[') {
    const std::size_t close = authority.find(']');
    if (close == std::string_view::npos) fail(ErrorCode::BadOptions, "unterminated IPv6 address in store URL");
    out.host = std::string(authority.substr(1, close - 1));
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') fail(ErrorCode::BadOptions, "malformed store URL authority");
      port = authority.substr(close + 2);
    }
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string_view::npos) {
      if (authority.find(':') != colon) {
        fail(ErrorCode::BadOptions, "IPv6 addresses in a store URL must be bracketed");
      }
      out.host = std::string(authority.substr(0, colon));
      port = authority.substr(colon + 1);
    } else {
      out.host = std::string(authority);
    }
  }
  if (out.host.empty()) fail(ErrorCode::BadOptions, "store URL has no host");
  for (char c : out.host) {
    if (!valid_host_char(c)) fail(ErrorCode::BadOptions, "store URL has an invalid host");
  }
  if (port.empty()) {
    out.port = authority.back() == ':' ? std::string() : std::string("80");
    if (out.port.empty()) fail(ErrorCode::BadOptions, "store URL has an empty port");
  } else {
    if (!is_digits(port) || port.size() > 5) {
      fail(ErrorCode::BadOptions, "store URL has a non-numeric or out-of-range port");
    }
    const unsigned long value = std::stoul(std::string(port));
    if (value == 0 || value > 65535) fail(ErrorCode::BadOptions, "store URL port is out of range");
    out.port = std::string(port);
  }

  if (!path.empty()) {
    if (path.front() != '/') fail(ErrorCode::BadOptions, "store URL path must be absolute");
    for (char c : path) {
      const unsigned char u = static_cast<unsigned char>(c);
      if (u <= 0x20 || u == 0x7f || c == '?' || c == '#' || c == '%' || c == '\\') {
        fail(ErrorCode::BadOptions, "store URL path contains an unsupported character");
      }
    }
  }
  out.path = std::string(path);
  while (out.path.size() > 1 && out.path.back() == '/') out.path.pop_back();
  if (out.path == "/") out.path.clear();
  return out;
}

int connect_to(const std::string& host, const std::string& port) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  addrinfo* addresses = nullptr;
  const int rc = ::getaddrinfo(host.c_str(), port.c_str(), &hints, &addresses);
  if (rc != 0) {
    fail(ErrorCode::StoreIo, "cannot resolve store host " + host + ": " + ::gai_strerror(rc));
  }

  int fd = -1;
  for (addrinfo* ai = addresses; ai != nullptr; ai = ai->ai_next) {
    fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    suppress_sigpipe(fd);
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
      ::close(fd);
      fd = -1;
      continue;
    }
    int result = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (result != 0 && errno == EINPROGRESS) {
      pollfd waiting{fd, POLLOUT, 0};
      int ready = 0;
      do {
        ready = ::poll(&waiting, 1, kConnectTimeoutMs);
      } while (ready < 0 && errno == EINTR);
      if (ready > 0) {
        int socket_error = 0;
        socklen_t length = sizeof(socket_error);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) != 0 ||
            socket_error != 0) {
          result = -1;
        } else {
          result = 0;
        }
      } else {
        result = -1;
      }
    }
    if (result == 0) {
      ::fcntl(fd, F_SETFL, flags);
      break;
    }
    ::close(fd);
    fd = -1;
  }
  ::freeaddrinfo(addresses);
  if (fd < 0) fail(ErrorCode::StoreIo, "cannot connect to store at " + host + ":" + port);

  timeval timeout{};
  timeout.tv_sec = kIoTimeoutSeconds;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  return fd;
}

void send_all(int fd, std::string_view data) {
#ifdef MSG_NOSIGNAL
  constexpr int kSendFlags = MSG_NOSIGNAL;
#else
  constexpr int kSendFlags = 0;
#endif
  std::size_t sent = 0;
  while (sent < data.size()) {
    const ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, kSendFlags);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail(ErrorCode::StoreIo, "store connection failed while sending a request");
    }
    if (n == 0) fail(ErrorCode::StoreIo, "store connection closed while sending a request");
    sent += static_cast<std::size_t>(n);
  }
}
#endif  // !_WIN32

std::string_view trim(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
  return text;
}

void append_uniquely(std::optional<std::uint64_t>* slot, std::uint64_t value, const char* what) {
  if (slot->has_value() && **slot != value) {
    fail(ErrorCode::StoreIo, std::string("store response has conflicting ") + what);
  }
  *slot = value;
}

std::uint64_t parse_decimal(std::string_view text, const char* what) {
  if (!is_digits(text) || text.size() > 20) {
    fail(ErrorCode::StoreIo, std::string("store response has an invalid ") + what);
  }
  std::uint64_t value = 0;
  for (char c : text) {
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10) {
      fail(ErrorCode::StoreIo, std::string("store response has an overflowing ") + what);
    }
    value = value * 10 + digit;
  }
  return value;
}

template <std::size_t N>
bool parse_hex_id(std::string_view text, std::array<unsigned char, N>* out) {
  if (text.size() != N * 2) return false;
  for (char c : text) {
    if (std::isxdigit(static_cast<unsigned char>(c)) == 0) return false;
  }
  try {
    const Bytes raw = hex_decode(text, "object name");
    if (raw.size() != N) return false;
    std::copy(raw.begin(), raw.end(), out->begin());
    return true;
  } catch (const Error&) {
    return false;
  }
}

bool parse_block_index(std::string_view digits, std::uint64_t* out) {
  if (digits.empty() || digits.size() > 20) return false;
  std::uint64_t value = 0;
  for (char c : digits) {
    if (c < '0' || c > '9') return false;
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    if (value > (UINT64_MAX - digit) / 10) return false;
    value = value * 10 + digit;
  }
  *out = value;
  return true;
}

bool header_name_char(char c) {
  const unsigned char u = static_cast<unsigned char>(c);
  if (std::isalnum(u) != 0) return true;
  constexpr std::string_view kExtra = "!#$%&'*+-.^_`|~";
  return kExtra.find(c) != std::string_view::npos;
}

bool has_control(std::string_view text, bool allow_tab) {
  for (char c : text) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u == 0x7f) return true;
    if (u < 0x20 && !(allow_tab && c == '\t')) return true;
  }
  return false;
}

std::optional<http_detail::RequestHead> parse_request_head_impl(std::string_view head) {
  if (head.size() > kMaxRequestBytes) return std::nullopt;
  const std::size_t line_end = head.find("\r\n");
  const std::string_view line = head.substr(0, line_end);
  if (line.empty() || has_control(line, false)) return std::nullopt;
  const std::size_t first_space = line.find(' ');
  const std::size_t second_space =
      first_space == std::string_view::npos ? std::string_view::npos
                                            : line.find(' ', first_space + 1);
  if (first_space == std::string_view::npos || second_space == std::string_view::npos) {
    return std::nullopt;
  }
  if (line.find(' ', second_space + 1) != std::string_view::npos) return std::nullopt;

  http_detail::RequestHead out;
  out.method = std::string(line.substr(0, first_space));
  out.target = std::string(line.substr(first_space + 1, second_space - first_space - 1));
  out.version = std::string(line.substr(second_space + 1));
  if (out.method.empty() || out.target.empty()) return std::nullopt;
  for (char c : out.method) {
    if (c < 'A' || c > 'Z') return std::nullopt;
  }
  if (out.version != "HTTP/1.0" && out.version != "HTTP/1.1") return std::nullopt;
  if (out.target.front() != '/') return std::nullopt;
  for (char c : out.target) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u == 0x7f) return std::nullopt;
  }
  return out;
}

std::optional<http_detail::ObjectRoute> parse_object_target_impl(std::string_view target) {
  http_detail::ObjectRoute route;
  constexpr std::string_view kPointer = "/pointers/";
  if (target.size() == kPointer.size() + 68 && target.substr(0, kPointer.size()) == kPointer) {
    const std::string_view rest = target.substr(kPointer.size());
    if (rest.substr(64) != ".ptr") return std::nullopt;
    if (!parse_hex_id<32>(rest.substr(0, 64), &route.drive)) return std::nullopt;
    route.kind = http_detail::RouteKind::Pointer;
    return route;
  }
  constexpr std::string_view kManifest = "/manifests/";
  if (target.size() == kManifest.size() + 35 &&
      target.substr(0, kManifest.size()) == kManifest) {
    const std::string_view rest = target.substr(kManifest.size());
    if (rest.substr(32) != ".mf") return std::nullopt;
    if (!parse_hex_id<16>(rest.substr(0, 32), &route.id)) return std::nullopt;
    route.kind = http_detail::RouteKind::Manifest;
    return route;
  }
  constexpr std::string_view kBlocks = "/blocks/";
  if (target.size() > kBlocks.size() + 32 + 1 + 4 &&
      target.substr(0, kBlocks.size()) == kBlocks) {
    const std::string_view rest = target.substr(kBlocks.size());
    if (rest.size() <= 33 || rest[32] != '/') return std::nullopt;
    if (!parse_hex_id<16>(rest.substr(0, 32), &route.id)) return std::nullopt;
    const std::string_view name = rest.substr(33);
    if (name.size() < 5 || name.substr(name.size() - 4) != ".blk") return std::nullopt;
    if (!parse_block_index(name.substr(0, name.size() - 4), &route.index)) return std::nullopt;
    route.kind = http_detail::RouteKind::Block;
    return route;
  }
  return std::nullopt;
}

http_detail::ResponseHead parse_response_head_impl(std::string_view head) {
  if (head.size() > kMaxResponseHeaderBytes) {
    fail(ErrorCode::StoreIo, "store response headers are too large");
  }
  const std::size_t line_end = head.find("\r\n");
  const std::string_view status_line = head.substr(0, line_end);
  if (status_line.empty() || has_control(status_line, false)) {
    fail(ErrorCode::StoreIo, "malformed store status line");
  }
  const std::size_t status_space = status_line.find(' ');
  if (status_space == std::string_view::npos) {
    fail(ErrorCode::StoreIo, "malformed store status line");
  }
  const std::string_view protocol = status_line.substr(0, status_space);
  if (protocol != "HTTP/1.0" && protocol != "HTTP/1.1") {
    fail(ErrorCode::StoreIo, "store did not answer with HTTP/1.x");
  }
  const std::size_t reason_space = status_line.find(' ', status_space + 1);
  const std::string_view code_text =
      status_line.substr(status_space + 1,
                         (reason_space == std::string_view::npos ? status_line.size() : reason_space) -
                             (status_space + 1));
  if (code_text.size() != 3 || !is_digits(code_text)) {
    fail(ErrorCode::StoreIo, "malformed store status code");
  }

  http_detail::ResponseHead out;
  out.status = std::stoi(std::string(code_text));
  std::size_t cursor = line_end == std::string_view::npos ? head.size() : line_end + 2;
  while (cursor < head.size()) {
    const std::size_t next = head.find("\r\n", cursor);
    const std::string_view line =
        head.substr(cursor, (next == std::string_view::npos ? head.size() : next) - cursor);
    cursor = next == std::string_view::npos ? head.size() : next + 2;
    if (line.empty()) continue;
    if (line.front() == ' ' || line.front() == '\t') {
      fail(ErrorCode::StoreIo, "store response has an obsolete header continuation");
    }
    if (has_control(line, true)) fail(ErrorCode::StoreIo, "malformed store response header");
    const std::size_t colon = line.find(':');
    if (colon == std::string_view::npos) {
      fail(ErrorCode::StoreIo, "malformed store response header");
    }
    const std::string_view name_text = trim(line.substr(0, colon));
    if (name_text.empty()) fail(ErrorCode::StoreIo, "malformed store response header");
    for (char c : name_text) {
      if (!header_name_char(c)) fail(ErrorCode::StoreIo, "malformed store response header");
    }
    const std::string name = ascii_lower(name_text);
    const std::string_view value = trim(line.substr(colon + 1));
    if (name == "content-length") {
      append_uniquely(&out.content_length, parse_decimal(value, "Content-Length"),
                      "Content-Length");
    } else if (name == "transfer-encoding") {
      if (ascii_lower(value) != "identity") {
        fail(ErrorCode::StoreIo, "store used an unsupported transfer encoding");
      }
    }
  }
  return out;
}

#if !defined(_WIN32)
void send_response(int fd, int status, std::string_view reason, std::string_view body,
                   std::string_view content_type) {
  std::string head = "HTTP/1.1 " + std::to_string(status) + " " + std::string(reason) + "\r\n";
  head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  head += "Content-Type: " + std::string(content_type) + "\r\n";
  head += "Cache-Control: no-store\r\n";
  head += "X-Content-Type-Options: nosniff\r\n";
  head += "Connection: close\r\n\r\n";
  try {
    send_all(fd, head);
    if (!body.empty()) send_all(fd, body);
  } catch (const Error&) {
    // The peer went away; closing the connection is the whole response.
  }
}

void handle_connection(int fd, const std::filesystem::path& root) {
  timeval timeout{};
  timeout.tv_sec = 5;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  const Clock::time_point deadline = Clock::now() + std::chrono::seconds(kRequestDeadlineSeconds);

  std::string raw;
  char buffer[2048];
  std::size_t end = std::string::npos;
  while (end == std::string::npos) {
    if (raw.size() > kMaxRequestBytes) {
      send_response(fd, 400, "Bad Request", "request too large\n", "text/plain");
      return;
    }
    if (expired(deadline)) {
      send_response(fd, 408, "Request Timeout", "request header took too long\n", "text/plain");
      return;
    }
    const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;  // timeout or reset: nothing useful to answer
    }
    if (n == 0) return;
    raw.append(buffer, static_cast<std::size_t>(n));
    end = raw.find("\r\n\r\n");
  }
  if (end > kMaxRequestBytes) {
    send_response(fd, 400, "Bad Request", "request too large\n", "text/plain");
    return;
  }

  const std::optional<http_detail::RequestHead> request =
      parse_request_head_impl(std::string_view(raw.data(), end + 4));
  if (!request) {
    send_response(fd, 400, "Bad Request", "malformed request\n", "text/plain");
    return;
  }
  if (request->method != "GET") {
    send_response(fd, 405, "Method Not Allowed", "read-only store\n", "text/plain");
    return;
  }
  const std::optional<http_detail::ObjectRoute> route =
      parse_object_target_impl(request->target);
  if (!route) {
    send_response(fd, 404, "Not Found", "not found\n", "text/plain");
    return;
  }

  const FileStore store(root);
  try {
    std::optional<Bytes> body;
    switch (route->kind) {
      case http_detail::RouteKind::Pointer:
        body = store.get_pointer(route->drive);
        break;
      case http_detail::RouteKind::Manifest:
        body = store.get_manifest(route->id);
        break;
      case http_detail::RouteKind::Block:
        body = store.get_block(route->id, route->index);
        break;
    }
    if (!body) {
      send_response(fd, 404, "Not Found", "not found\n", "text/plain");
      return;
    }
    send_response(fd, 200, "OK", to_string(ByteView(*body)), "application/octet-stream");
  } catch (const Error&) {
    // The local object is unreadable (a link, a directory, too large). Do not
    // serve it and do not leak why.
    send_response(fd, 500, "Internal Server Error", "store object unreadable\n", "text/plain");
  }
}
#endif  // !_WIN32

}  // namespace

namespace http_detail {

std::optional<RequestHead> parse_request_head(std::string_view head) {
  return parse_request_head_impl(head);
}

std::optional<ObjectRoute> parse_object_target(std::string_view target) {
  return parse_object_target_impl(target);
}

ResponseHead parse_response_head(std::string_view head) {
  return parse_response_head_impl(head);
}

}  // namespace http_detail

bool looks_like_store_url(std::string_view text) {
  return starts_with_ci(text, "http://") || starts_with_ci(text, "https://");
}

std::string normalize_http_store_url(std::string_view text) {
#if defined(_WIN32)
  (void)text;
  fail(ErrorCode::BadOptions, "this build has no HTTP store support");
#else
  const ParsedUrl url = parse_http_url(text);
  return "http://" + url.authority + url.path;
#endif
}

std::optional<Bytes> http_get_object(const std::string& url, std::size_t cap) {
#if defined(_WIN32)
  (void)url;
  (void)cap;
  fail(ErrorCode::StoreIo, "this build has no HTTP store support");
#else
  const ParsedUrl parsed = parse_http_url(url);
  const std::string target = parsed.path.empty() ? std::string("/") : parsed.path;
  const int fd = connect_to(parsed.host, parsed.port);
  struct CloseFd {
    int fd;
    ~CloseFd() { ::close(fd); }
  } closer{fd};
  const Clock::time_point deadline = Clock::now() + std::chrono::seconds(kObjectDeadlineSeconds);

  std::string request = "GET " + target + " HTTP/1.1\r\n";
  request += "Host: " + parsed.authority + "\r\n";
  request += "Accept: application/octet-stream\r\n";
  request += "User-Agent: skipta/1\r\n";
  request += "Connection: close\r\n\r\n";
  send_all(fd, request);

  std::string raw;
  char buffer[4096];
  std::size_t header_end = std::string::npos;
  while (header_end == std::string::npos) {
    if (raw.size() > kMaxResponseHeaderBytes) {
      fail(ErrorCode::StoreIo, "store response headers are too large");
    }
    if (expired(deadline)) fail(ErrorCode::StoreIo, "store did not answer in time");
    const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail(ErrorCode::StoreIo, "store connection failed while reading a response");
    }
    if (n == 0) fail(ErrorCode::StoreIo, "store closed the connection before a response");
    raw.append(buffer, static_cast<std::size_t>(n));
    header_end = raw.find("\r\n\r\n");
  }
  if (header_end > kMaxResponseHeaderBytes) fail(ErrorCode::StoreIo, "store response headers are too large");

  const http_detail::ResponseHead parsed_head =
      parse_response_head_impl(std::string_view(raw.data(), header_end));
  const int status = parsed_head.status;
  const std::optional<std::uint64_t>& content_length = parsed_head.content_length;

  if (status == 404) return std::nullopt;
  if (status != 200) {
    fail(ErrorCode::StoreIo, "store returned HTTP " + std::to_string(status) + " for " + target);
  }

  const std::string_view prefix(raw.data() + header_end + 4, raw.size() - header_end - 4);
  Bytes body;
  if (content_length.has_value()) {
    const std::uint64_t length = *content_length;
    if (length > cap) fail(ErrorCode::TooLarge, "store object is larger than the format allows");
    body.reserve(static_cast<std::size_t>(length));
    const std::size_t take = std::min<std::size_t>(prefix.size(), static_cast<std::size_t>(length));
    body.insert(body.end(), prefix.begin(), prefix.begin() + static_cast<std::ptrdiff_t>(take));
    while (body.size() < length) {
      if (expired(deadline)) fail(ErrorCode::StoreIo, "store did not finish the object in time");
      const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
      if (n < 0) {
        if (errno == EINTR) continue;
        fail(ErrorCode::StoreIo, "store connection failed while reading an object");
      }
      if (n == 0) fail(ErrorCode::StoreIo, "store closed the connection before the whole object arrived");
      if (body.size() + static_cast<std::size_t>(n) > length) {
        body.insert(body.end(), buffer, buffer + (length - body.size()));
      } else {
        body.insert(body.end(), buffer, buffer + n);
      }
    }
    return body;
  }

  if (prefix.size() > cap) fail(ErrorCode::TooLarge, "store object is larger than the format allows");
  body.assign(prefix.begin(), prefix.end());
  for (;;) {
    if (expired(deadline)) fail(ErrorCode::StoreIo, "store did not finish the object in time");
    const ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail(ErrorCode::StoreIo, "store connection failed while reading an object");
    }
    if (n == 0) break;
    if (body.size() + static_cast<std::size_t>(n) > cap) {
      fail(ErrorCode::TooLarge, "store object is larger than the format allows");
    }
    body.insert(body.end(), buffer, buffer + n);
  }
  return body;
#endif
}

HttpServer::HttpServer(HttpServeOptions options)
    : root_(std::move(options.root)), bind_address_(std::move(options.bind_address)) {
#if defined(_WIN32)
  (void)options.port;
  fail(ErrorCode::StoreIo, "skipta serve needs a POSIX socket build");
#else
  if (root_.empty()) fail(ErrorCode::BadOptions, "serve needs a store directory");
  for (char c : bind_address_) {
    if (!valid_host_char(c)) fail(ErrorCode::BadOptions, "invalid listen address");
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* addresses = nullptr;
  const std::string port_text = std::to_string(options.port);
  const int rc = ::getaddrinfo(bind_address_.empty() ? nullptr : bind_address_.c_str(),
                               port_text.c_str(), &hints, &addresses);
  if (rc != 0) {
    fail(ErrorCode::StoreIo, "cannot resolve listen address " + bind_address_ + ": " +
                                 ::gai_strerror(rc));
  }
  for (addrinfo* ai = addresses; ai != nullptr; ai = ai->ai_next) {
    const int fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (::bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && ::listen(fd, 64) == 0) {
      listen_fd_ = fd;
      break;
    }
    ::close(fd);
  }
  ::freeaddrinfo(addresses);
  if (listen_fd_ < 0) {
    fail(ErrorCode::StoreIo, "cannot listen on " + bind_address_ + ":" + port_text);
  }
  sockaddr_storage bound{};
  socklen_t bound_length = sizeof(bound);
  if (::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0) {
    if (bound.ss_family == AF_INET) {
      port_ = ntohs(reinterpret_cast<const sockaddr_in*>(&bound)->sin_port);
    } else if (bound.ss_family == AF_INET6) {
      port_ = ntohs(reinterpret_cast<const sockaddr_in6*>(&bound)->sin6_port);
    }
  }
#endif
}

HttpServer::~HttpServer() {
  stop();
#if !defined(_WIN32)
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
#endif
}

std::string HttpServer::origin() const {
#if defined(_WIN32)
  return std::string();
#else
  std::string host = bind_address_;
  if (host.empty() || host == "0.0.0.0") host = "127.0.0.1";
  else if (host == "::" || host == "[::]") host = "::1";
  if (host.find(':') != std::string::npos && host.front() != '[') host = "[" + host + "]";
  return "http://" + host + ":" + std::to_string(port_);
#endif
}

void HttpServer::run() {
#if defined(_WIN32)
  fail(ErrorCode::StoreIo, "skipta serve needs a POSIX socket build");
#else
  while (!stopping_.load() && listen_fd_ >= 0) {
    pollfd waiting{listen_fd_, POLLIN, 0};
    const int ready = ::poll(&waiting, 1, 500);
    if (ready < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (ready == 0) continue;
    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    const int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (fd < 0) {
      if (errno == EINTR) continue;
      if (stopping_.load() || listen_fd_ < 0) break;
      continue;
    }
    suppress_sigpipe(fd);
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    handle_connection(fd, root_);
    ::close(fd);
  }
#endif
}

void HttpServer::stop() noexcept {
#if !defined(_WIN32)
  // run() checks this on every 500 ms tick; shutdown() wakes poll() where the
  // platform supports it. The destructor closes the descriptor once.
  stopping_.store(true);
  if (listen_fd_ >= 0) {
    ::shutdown(listen_fd_, SHUT_RDWR);
  }
#endif
}

}  // namespace skipta
