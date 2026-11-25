// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Sanitizer mutation fuzzer for every parser that consumes untrusted bytes.
//
// The seed corpus is produced by publishing a real folder into a temporary
// store with the normal code path, then reading back its signed pointer,
// sealed manifests, sealed blocks and link. Inputs are mutated from those
// objects (plus optionally files from --corpus) and from random bytes, and fed
// to each parser in turn. Nothing here is linked into the library or the CLI.
//
// Build and run with sanitizers:   make fuzz-build
//                                  ./scripts/fuzz.sh --iterations 3000000 --seed 1
//
// A parser that runs longer than --timeout seconds ends the run with exit 124
// and writes the input to <artifacts>/hang.bin. ASan/UBSan findings write
// <artifacts>/sanitizer.bin. Any other escaping exception is a failure too.
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/drive.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/http.hpp"
#include "skipta/identity.hpp"
#include "skipta/keywrap.hpp"
#include "skipta/link.hpp"
#include "skipta/manifest.hpp"
#include "skipta/pointer.hpp"
#include "skipta/share.hpp"
#include "skipta/store.hpp"

namespace {

namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using namespace skipta;

constexpr std::size_t kDefaultMaxInput = 64 * 1024;
constexpr int kDefaultTimeoutSeconds = 5;
constexpr std::size_t kMemoryLimit = 1024u * 1024u * 1024u;  // 1 GiB RSS

char g_artifact_dir[512] = "/tmp/skipta-fuzz-artifacts";
const unsigned char* g_input = nullptr;
volatile std::size_t g_input_size = 0;
char g_meta[256] = {};
volatile sig_atomic_t g_meta_size = 0;

// ---- async-signal-safe crash/hang artifact writer -------------------------

void write_artifact(const char* stem, const char* extension, const char* data,
                    std::size_t size) {
  char path[sizeof(g_artifact_dir) + 64];
  std::size_t pos = 0;
  for (const char* p = g_artifact_dir; *p != '\0' && pos + 1 < sizeof(path); ++p) {
    path[pos++] = *p;
  }
  if (pos + 1 < sizeof(path)) path[pos++] = '/';
  for (const char* p = stem; *p != '\0' && pos + 1 < sizeof(path); ++p) path[pos++] = *p;
  for (const char* p = extension; *p != '\0' && pos + 1 < sizeof(path); ++p) path[pos++] = *p;
  path[pos] = '\0';

  const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) return;
  std::size_t sent = 0;
  while (sent < size) {
    const ssize_t n = ::write(fd, data + sent, size - sent);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    sent += static_cast<std::size_t>(n);
  }
  ::close(fd);
}

void save_current(const char* stem) {
  if (g_input != nullptr) {
    write_artifact(stem, ".bin", reinterpret_cast<const char*>(g_input), g_input_size);
  }
  write_artifact(stem, ".txt", g_meta, static_cast<std::size_t>(g_meta_size));
}

void on_alarm(int) {
  save_current("hang");
  const char message[] = "skipta-fuzz: TIMEOUT (input saved under artifacts/hang.bin)\n";
  const ssize_t ignored = ::write(STDERR_FILENO, message, sizeof(message) - 1);
  (void)ignored;
  ::_exit(124);
}

extern "C" void skipta_fuzz_death_callback(void) { save_current("sanitizer"); }
extern "C" void __ubsan_on_report(void) { save_current("ubsan"); }
extern "C" void __sanitizer_set_death_callback(void (*callback)(void)) __attribute__((weak));

void install_sanitizer_hooks() {
  if (__sanitizer_set_death_callback != nullptr) {
    __sanitizer_set_death_callback(skipta_fuzz_death_callback);
  }
  struct sigaction action {};
  action.sa_handler = on_alarm;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;
  ::sigaction(SIGALRM, &action, nullptr);
}

// ---- small utilities ------------------------------------------------------

struct Rng {
  std::uint64_t state;

  explicit Rng(std::uint64_t seed) : state(seed == 0 ? 0x9e3779b97f4a7c15ULL : seed) {}

  std::uint64_t next() {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 0x2545F4914F6CDD1DULL;
  }

  std::size_t below(std::size_t n) {
    return n == 0 ? 0 : static_cast<std::size_t>(next() % static_cast<std::uint64_t>(n));
  }
};

std::size_t read_rss_bytes() {
  std::ifstream statm("/proc/self/statm");
  std::size_t total = 0;
  std::size_t resident = 0;
  if (!(statm >> total >> resident)) return 0;
  const long page = ::sysconf(_SC_PAGESIZE);
  return resident * static_cast<std::size_t>(page > 0 ? page : 4096);
}

std::optional<std::string> read_file_capped(const fs::path& path, std::size_t max) {
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) return std::nullopt;
  const std::uintmax_t size = fs::file_size(path, ec);
  if (ec || size > max) return std::nullopt;
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  std::string out(static_cast<std::size_t>(size), '\0');
  if (!out.empty()) {
    in.read(out.data(), static_cast<std::streamsize>(out.size()));
    if (!in || static_cast<std::size_t>(in.gcount()) != out.size()) return std::nullopt;
  }
  return out;
}

void write_text(const fs::path& path, std::string_view text) {
  std::error_code ec;
  fs::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

// ---- parsers --------------------------------------------------------------

enum class Parser {
  Pointer,
  SignedPointer,
  Manifest,
  Name,
  RelativePath,
  SealedManifest,
  Block,
  Link,
  Base64,
  Hex,
  StoreName,
  HttpRequest,
  HttpRoute,
  HttpResponse,
  Url,
  Identity,
  KeywrapEnvelope,
};

constexpr Parser kParsers[] = {
    Parser::Pointer,        Parser::SignedPointer, Parser::Manifest,
    Parser::Name,           Parser::RelativePath,  Parser::SealedManifest,
    Parser::Block,          Parser::Link,          Parser::Base64,
    Parser::Hex,            Parser::StoreName,     Parser::HttpRequest,
    Parser::HttpRoute,      Parser::HttpResponse,  Parser::Url,
    Parser::Identity,       Parser::KeywrapEnvelope,
};
constexpr std::size_t kParserCount = sizeof(kParsers) / sizeof(kParsers[0]);

const char* parser_name(Parser parser) {
  switch (parser) {
    case Parser::Pointer: return "pointer";
    case Parser::SignedPointer: return "signed-pointer";
    case Parser::Manifest: return "manifest";
    case Parser::Name: return "name";
    case Parser::RelativePath: return "relative-path";
    case Parser::SealedManifest: return "sealed-manifest";
    case Parser::Block: return "block";
    case Parser::Link: return "link";
    case Parser::Base64: return "base64";
    case Parser::Hex: return "hex";
    case Parser::StoreName: return "store-name";
    case Parser::HttpRequest: return "http-request";
    case Parser::HttpRoute: return "http-route";
    case Parser::HttpResponse: return "http-response";
    case Parser::Url: return "store-url";
    case Parser::Identity: return "legacy-identity";
    case Parser::KeywrapEnvelope: return "keywrap-envelope";
  }
  return "unknown";
}

struct Corpus {
  std::vector<std::string> pointer;
  std::vector<std::string> signed_pointer;
  std::vector<std::string> manifest;
  std::vector<std::string> name;
  std::vector<std::string> relative_path;
  std::vector<std::string> sealed_manifest;
  std::vector<std::string> block;
  std::vector<std::string> link;
  std::vector<std::string> base64;
  std::vector<std::string> hex;
  std::vector<std::string> store_name;
  std::vector<std::string> http_request;
  std::vector<std::string> http_route;
  std::vector<std::string> http_response;
  std::vector<std::string> url;
  std::vector<std::string> identity;
  std::vector<std::string> keywrap;
  std::vector<std::string> extra;
};

struct Fixture {
  fs::path base;
  Key32 drive_key{};
  PubKey32 drive{};
  Id128 manifest_id{};
  Id128 file_id{};
  std::uint64_t file_size = 0;
};

std::vector<std::string>& seeds_for(Corpus& corpus, Parser parser) {
  switch (parser) {
    case Parser::Pointer: return corpus.pointer;
    case Parser::SignedPointer: return corpus.signed_pointer;
    case Parser::Manifest: return corpus.manifest;
    case Parser::Name: return corpus.name;
    case Parser::RelativePath: return corpus.relative_path;
    case Parser::SealedManifest: return corpus.sealed_manifest;
    case Parser::Block: return corpus.block;
    case Parser::Link: return corpus.link;
    case Parser::Base64: return corpus.base64;
    case Parser::Hex: return corpus.hex;
    case Parser::StoreName: return corpus.store_name;
    case Parser::HttpRequest: return corpus.http_request;
    case Parser::HttpRoute: return corpus.http_route;
    case Parser::HttpResponse: return corpus.http_response;
    case Parser::Url: return corpus.url;
    case Parser::Identity: return corpus.identity;
    case Parser::KeywrapEnvelope: return corpus.keywrap;
  }
  return corpus.extra;
}

void run_parser(Parser parser, std::string_view input, const Fixture& fixture,
                std::uint64_t block_size, std::uint64_t block_index) {
  switch (parser) {
    case Parser::Pointer:
      (void)parse_pointer(ByteView(input));
      break;
    case Parser::SignedPointer: {
      const SignedPointer signed_pointer = decode_signed_pointer(ByteView(input));
      (void)parse_pointer(ByteView(signed_pointer.pointer));
      (void)verify_pointer(fixture.drive, signed_pointer, 0);
      break;
    }
    case Parser::Manifest:
      (void)Manifest::parse(ByteView(input));
      break;
    case Parser::Name:
      validate_name(input);
      break;
    case Parser::RelativePath:
      validate_relative_path(input);
      break;
    case Parser::SealedManifest:
      (void)open_manifest(fixture.drive_key, fixture.manifest_id, ByteView(input));
      break;
    case Parser::Block:
      (void)format::decrypt_block(fixture.drive_key, fixture.file_id, block_size, block_index,
                                 ByteView(input));
      break;
    case Parser::Link:
      (void)decode_link(input);
      break;
    case Parser::Base64:
      (void)base64url_decode(input, "fuzz");
      break;
    case Parser::Hex:
      (void)hex_decode(input, "fuzz");
      break;
    case Parser::StoreName:
      (void)classify_stored_object_name(input);
      break;
    case Parser::HttpRequest:
      (void)http_detail::parse_request_head(input);
      break;
    case Parser::HttpRoute:
      (void)http_detail::parse_object_target(input);
      break;
    case Parser::HttpResponse:
      (void)http_detail::parse_response_head(input);
      break;
    case Parser::Url:
      (void)normalize_http_store_url(input);
      break;
    case Parser::Identity:
      (void)decode_identity(ByteView(input));
      break;
    case Parser::KeywrapEnvelope:
      (void)parse_keywrap_envelope(ByteView(input));
      break;
  }
}

// ---- fixture and seed corpus ---------------------------------------------

Fixture make_fixture(const fs::path& base, Corpus* corpus, std::size_t max_input) {
  Fixture fixture;
  fixture.base = base;
  std::error_code ec;
  fs::remove_all(base, ec);
  fs::create_directories(base / "source" / "docs", ec);
  write_text(base / "source" / "a.txt", "hello fuzz corpus\n");
  write_text(base / "source" / "docs" / "nested.txt", "nested\n");
  std::string big(200000, '\0');
  for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<char>((i * 31u) & 0xff);
  write_text(base / "source" / "big.bin", big);
  for (int i = 0; i < 48; ++i) {
    char name[32];
    std::snprintf(name, sizeof(name), "f%03d.txt", i);
    write_text(base / "source" / name, "entry " + std::to_string(i) + "\n");
  }

  FileStore store(base / "store");
  const PublishResult published = publish_directory(base / "source", store);
  const ShareLink link = decode_link(published.link);
  fixture.drive_key = link.key;
  fixture.drive = published.drive;

  const Bytes pointer_bytes = *store.get_pointer(published.drive);
  const SignedPointer signed_pointer = decode_signed_pointer(ByteView(pointer_bytes));
  const RootPointer pointer = parse_pointer(ByteView(signed_pointer.pointer));
  fixture.manifest_id = pointer.root;
  const Bytes sealed_root = *store.get_manifest(pointer.root);
  const Manifest root =
      open_manifest(fixture.drive_key, pointer.root, ByteView(sealed_root));
  const Entry* big_entry = root.find("big.bin");
  if (big_entry != nullptr) {
    fixture.file_id = big_entry->file_id;
    fixture.file_size = big_entry->size;
  } else {
    fixture.file_id = crypto::random_id();
    fixture.file_size = 100;
  }

  corpus->pointer.push_back(to_string(ByteView(signed_pointer.pointer)));
  corpus->pointer.push_back(to_string(ByteView(pointer_bytes)));
  corpus->signed_pointer.push_back(to_string(ByteView(pointer_bytes)));
  corpus->manifest.push_back(to_string(ByteView(root.serialize())));
  corpus->link.push_back(published.link);

  for (const Entry& entry : root.entries) {
    corpus->name.push_back(entry.name);
    if (entry.kind == EntryKind::File) {
      corpus->store_name.push_back(hex_encode(ByteView(entry.file_id)));
    }
  }
  corpus->name.push_back(std::string(255, 'n'));
  corpus->name.push_back("..");
  corpus->name.push_back("a/b");
  corpus->name.push_back("\xE2\x80\xAE");
  corpus->relative_path.push_back("docs/nested.txt");
  corpus->relative_path.push_back("a/b/c/d");
  corpus->base64.push_back(base64url_encode(ByteView(link.key)));
  corpus->hex.push_back(hex_encode(ByteView(link.key)));
  corpus->hex.push_back(hex_encode(ByteView(pointer.root)));
  corpus->store_name.push_back(hex_encode(ByteView(pointer.root)) + ".mf");
  corpus->store_name.push_back(hex_encode(ByteView(link.key)) + ".ptr");
  corpus->store_name.push_back(std::string(16, '0') + ".blk");

  const std::string drive_hex = hex_encode(ByteView(fixture.drive));
  const std::string root_hex = hex_encode(ByteView(pointer.root));
  const std::string file_hex = hex_encode(ByteView(fixture.file_id));
  corpus->http_request.push_back("GET /pointers/" + drive_hex + ".ptr HTTP/1.1\r\nHost: x\r\n\r\n");
  corpus->http_request.push_back("GET /manifests/" + root_hex + ".mf HTTP/1.0\r\n\r\n");
  corpus->http_request.push_back("GET /blocks/" + file_hex + "/" +
                                 hex_encode(ByteView(Bytes(8, 0))).substr(0, 16) +
                                 ".blk HTTP/1.1\r\n\r\n");
  corpus->http_route.push_back("/pointers/" + drive_hex + ".ptr");
  corpus->http_route.push_back("/manifests/" + root_hex + ".mf");
  corpus->http_route.push_back("/blocks/" + file_hex + "/0000000000000000.blk");
  corpus->http_response.push_back("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
  corpus->http_response.push_back("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
  corpus->http_response.push_back("HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n");
  corpus->url.push_back("http://127.0.0.1:8787");
  corpus->url.push_back("http://[::1]:80/prefix/");
  corpus->url.push_back("https://example.test/store");

  const DriveIdentity identity = DriveIdentity::create();
  corpus->identity.push_back(to_string(ByteView(encode_identity(identity))));
  corpus->keywrap.push_back(to_string(ByteView(wrap_secret(
      ByteView(link.key), "fuzz", Argon2Params::interactive()))));

  // Every real sealed object the fixture store holds, subject to the input cap.
  for (const auto& entry : fs::directory_iterator(store.root() / "manifests", ec)) {
    if (const auto bytes = read_file_capped(entry.path(), max_input)) {
      corpus->sealed_manifest.push_back(*bytes);
    }
  }
  std::size_t blocks = 0;
  for (const auto& file_dir : fs::directory_iterator(store.root() / "blocks", ec)) {
    if (blocks >= 24) break;
    for (const auto& entry : fs::directory_iterator(file_dir.path(), ec)) {
      if (blocks >= 24) break;
      if (const auto bytes = read_file_capped(entry.path(), max_input)) {
        corpus->block.push_back(*bytes);
        ++blocks;
      }
    }
  }
  if (corpus->block.empty()) {
    corpus->block.push_back(std::string(64, 'b'));
  }
  if (corpus->sealed_manifest.empty()) {
    corpus->sealed_manifest.push_back(std::string(64, 'm'));
  }
  return fixture;
}

void add_corpus_directory(const fs::path& dir, std::size_t max_input, Corpus* corpus) {
  std::error_code ec;
  if (!fs::is_directory(dir, ec)) return;
  std::size_t added = 0;
  for (const auto& entry :
       fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
    if (added >= 64) break;
    if (const auto bytes = read_file_capped(entry.path(), max_input)) {
      corpus->extra.push_back(*bytes);
      ++added;
    }
  }
}

// ---- mutation -------------------------------------------------------------

const std::vector<std::string>& dictionary() {
  static const std::vector<std::string> kTokens = {
      "{",          "}",        "[",          "]",          "\"",       "\\",
      ":",          ",",        "0",          "-1",         "..",       "/",
      "%2e",        "\r\n",     "\r\n\r\n",   "HTTP/1.1 ",   "GET ",     "Content-Length: ",
      "999999999999999999999",  "skipta://v1/", "http://", "https://",  "\x00",     "\x7f",
      "\xE2\x80\xAE",           "{[]}",      "null",       "true",       "argon2id", "v",
  };
  return kTokens;
}

std::string random_bytes(Rng* rng, std::size_t size) {
  std::string out(size, '\0');
  for (char& c : out) c = static_cast<char>(rng->next() & 0xff);
  return out;
}

void enforce_cap(std::string* data, std::size_t max) {
  if (data->size() > max) data->resize(max);
}

void mutate(std::string* data, Rng* rng, const std::vector<std::string>& pool,
            std::size_t max_input) {
  const auto& tokens = dictionary();
  const int operations = 1 + static_cast<int>(rng->below(6));
  for (int op = 0; op < operations; ++op) {
    switch (rng->below(11)) {
      case 0: {  // flip one bit
        if (data->empty()) break;
        const std::size_t at = rng->below(data->size());
        (*data)[at] = static_cast<char>((*data)[at] ^ (1u << rng->below(8)));
        break;
      }
      case 1: {  // replace one byte
        if (data->empty()) break;
        (*data)[rng->below(data->size())] = static_cast<char>(rng->next() & 0xff);
        break;
      }
      case 2: {  // insert a run
        const std::size_t at = rng->below(data->size() + 1);
        const std::size_t len = 1 + rng->below(64);
        const unsigned char fill = static_cast<unsigned char>(
            rng->below(4) == 0 ? 0 : (rng->below(4) == 0 ? 0xff : (rng->next() & 0xff)));
        data->insert(at, std::string(len, static_cast<char>(fill)));
        break;
      }
      case 3: {  // erase a range
        if (data->empty()) break;
        const std::size_t at = rng->below(data->size());
        const std::size_t len = 1 + rng->below(std::min<std::size_t>(64, data->size() - at));
        data->erase(at, len);
        break;
      }
      case 4: {  // duplicate a range
        if (data->empty()) break;
        const std::size_t at = rng->below(data->size());
        const std::size_t len = 1 + rng->below(std::min<std::size_t>(128, data->size() - at));
        data->insert(at, data->substr(at, len));
        break;
      }
      case 5: {  // truncate
        data->resize(rng->below(data->size() + 1));
        break;
      }
      case 6: {  // append random bytes
        const std::size_t len = 1 + rng->below(64);
        data->append(random_bytes(rng, len));
        break;
      }
      case 7: {  // splice from another seed or random bytes
        if (pool.empty()) break;
        const std::string& other = pool[rng->below(pool.size())];
        if (other.empty()) break;
        const std::size_t from = rng->below(other.size());
        const std::size_t len = 1 + rng->below(std::min<std::size_t>(128, other.size() - from));
        data->insert(rng->below(data->size() + 1), other.substr(from, len));
        break;
      }
      case 8: {  // overwrite with a token
        const std::string& token = tokens[rng->below(tokens.size())];
        const std::size_t at = rng->below(data->size() + 1);
        if (at + token.size() <= max_input) {
          data->replace(at, std::min(token.size(), data->size() - std::min(at, data->size())), token);
        }
        break;
      }
      case 9: {  // pathological repetition
        const char c = "{[\"\\/0-"[rng->below(7)];
        data->assign(std::min<std::size_t>(max_input, 1 + rng->below(max_input)), c);
        break;
      }
      case 10: {  // wholesale random
        data->assign(random_bytes(rng, 1 + rng->below(1024)));
        break;
      }
    }
    enforce_cap(data, max_input);
  }
}

// ---- main loop ------------------------------------------------------------

struct Options {
  std::uint64_t iterations = 2000000;
  std::uint64_t seed = 1;
  int timeout_seconds = kDefaultTimeoutSeconds;
  std::size_t max_input = kDefaultMaxInput;
  std::string only;
  std::string corpus_dir;
  bool selftest_timeout = false;
};

[[noreturn]] void usage(const char* argv0) {
  std::cerr << "usage: " << argv0
            << " [--iterations N] [--seed N] [--timeout SECONDS] [--max-input BYTES]\n"
               "       [--only PARSER] [--artifacts DIR] [--corpus DIR]\n"
               "       [--selftest-timeout]\n"
               "parsers: pointer signed-pointer manifest name relative-path sealed-manifest\n"
               "         block link base64 hex store-name http-request http-route\n"
               "         http-response store-url legacy-identity keywrap-envelope\n";
  std::exit(2);
}

std::uint64_t parse_u64(const char* text) {
  char* end = nullptr;
  const unsigned long long value = std::strtoull(text, &end, 10);
  if (end == text || *end != '\0' || value == 0) usage("skipta-fuzz");
  return static_cast<std::uint64_t>(value);
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--iterations" && i + 1 < argc) {
      options.iterations = parse_u64(argv[++i]);
    } else if (arg == "--seed" && i + 1 < argc) {
      options.seed = std::strtoull(argv[++i], nullptr, 0);
    } else if (arg == "--timeout" && i + 1 < argc) {
      options.timeout_seconds = static_cast<int>(parse_u64(argv[++i]));
    } else if (arg == "--max-input" && i + 1 < argc) {
      options.max_input = static_cast<std::size_t>(parse_u64(argv[++i]));
    } else if (arg == "--only" && i + 1 < argc) {
      options.only = argv[++i];
    } else if (arg == "--corpus" && i + 1 < argc) {
      options.corpus_dir = argv[++i];
    } else if (arg == "--artifacts" && i + 1 < argc) {
      const std::string dir = argv[++i];
      if (dir.size() >= sizeof(g_artifact_dir)) usage(argv[0]);
      std::memcpy(g_artifact_dir, dir.c_str(), dir.size() + 1);
    } else if (arg == "--selftest-timeout") {
      options.selftest_timeout = true;
    } else if (arg == "--help" || arg == "-h") {
      usage(argv[0]);
    } else {
      usage(argv[0]);
    }
  }

  if (g_artifact_dir[0] == '\0') usage(argv[0]);
  install_sanitizer_hooks();
  std::error_code ec;
  fs::create_directories(g_artifact_dir, ec);

  if (options.selftest_timeout) {
    std::snprintf(g_meta, sizeof(g_meta), "selftest=timeout\n");
    g_meta_size = static_cast<sig_atomic_t>(std::strlen(g_meta));
    const char input[] = "selftest hang input";
    g_input = reinterpret_cast<const unsigned char*>(input);
    g_input_size = sizeof(input) - 1;
    std::cerr << "skipta-fuzz: self-test: expecting SIGALRM after 1s\n";
    ::alarm(1);
    for (;;) ::pause();
  }

  const fs::path base = fs::temp_directory_path() /
                        ("skipta-fuzz-" + std::to_string(static_cast<long long>(::getpid())));
  Corpus corpus;
  Fixture fixture;
  try {
    fixture = make_fixture(base, &corpus, options.max_input);
    if (!options.corpus_dir.empty()) {
      add_corpus_directory(options.corpus_dir, options.max_input, &corpus);
    }
  } catch (const std::exception& e) {
    std::cerr << "skipta-fuzz: fixture failed: " << e.what() << "\n";
    fs::remove_all(base, ec);
    return 1;
  }

  std::vector<std::string> all_seeds;
  for (std::size_t p = 0; p < kParserCount; ++p) {
    std::vector<std::string>& values = seeds_for(corpus, kParsers[p]);
    all_seeds.insert(all_seeds.end(), values.begin(), values.end());
  }
  all_seeds.insert(all_seeds.end(), corpus.extra.begin(), corpus.extra.end());

  Parser selected = Parser::Pointer;
  bool only_set = false;
  if (!options.only.empty()) {
    for (std::size_t p = 0; p < kParserCount; ++p) {
      if (options.only == parser_name(kParsers[p])) {
        selected = kParsers[p];
        only_set = true;
        break;
      }
    }
    if (!only_set) {
      std::cerr << "skipta-fuzz: unknown parser '" << options.only << "'\n";
      fs::remove_all(base, ec);
      return 2;
    }
    // With --only, files from --corpus are fed directly to that parser too.
    std::vector<std::string>& values = seeds_for(corpus, selected);
    values.insert(values.end(), corpus.extra.begin(), corpus.extra.end());
    all_seeds.insert(all_seeds.end(), corpus.extra.begin(), corpus.extra.end());
  }

  std::cout << "skipta-fuzz: " << options.iterations << " inputs, seed " << options.seed
            << ", max-input " << options.max_input << ", timeout " << options.timeout_seconds
            << "s, " << all_seeds.size() << " seeds";
  if (!options.corpus_dir.empty()) std::cout << " (+ corpus " << options.corpus_dir << ")";
  std::cout << "\n"
            << "skipta-fuzz: fixture drive " << hex_encode(ByteView(fixture.drive)).substr(0, 16)
            << "..., store " << (base / "store") << "\n"
            << std::flush;

  Rng rng(options.seed);
  const Clock::time_point started = Clock::now();
  std::size_t baseline_rss = 0;
  std::size_t peak_rss = 0;
  std::vector<std::uint64_t> per_parser(kParserCount, 0);
  std::uint64_t unexpected = 0;

  for (std::uint64_t iteration = 0; iteration < options.iterations; ++iteration) {
    const Parser parser =
        only_set ? selected
                 : kParsers[(iteration + rng.below(kParserCount)) % kParserCount];
    const std::size_t parser_index = static_cast<std::size_t>(
        static_cast<int>(parser) - static_cast<int>(Parser::Pointer));

    std::string input;
    std::vector<std::string>& seeds = seeds_for(corpus, parser);
    if (seeds.empty() || rng.below(100) < 2) {
      input = random_bytes(&rng, rng.below(512));
    } else {
      input = seeds[rng.below(seeds.size())];
      if (rng.below(20) != 0) {
        mutate(&input, &rng, all_seeds, options.max_input);
      }
    }

    static constexpr std::uint64_t kBlockSizes[] = {
        0, 1, format::kBlockPlaintextSize - 1, format::kBlockPlaintextSize,
        format::kBlockPlaintextSize + 1, 200000, (1ull << 40) - 1, 1ull << 40};
    static constexpr std::uint64_t kBlockIndices[] = {0, 1, 3, 4, 1000000, (1ull << 24) - 1};
    const std::uint64_t block_size = kBlockSizes[rng.below(8)];
    const std::uint64_t block_index = kBlockIndices[rng.below(6)];

    std::snprintf(g_meta, sizeof(g_meta),
                  "parser=%s iteration=%llu seed=%llu size=%zu block_size=%llu block=%llu\n",
                  parser_name(parser), static_cast<unsigned long long>(iteration),
                  static_cast<unsigned long long>(options.seed), input.size(),
                  static_cast<unsigned long long>(block_size),
                  static_cast<unsigned long long>(block_index));
    g_meta_size = static_cast<sig_atomic_t>(std::strlen(g_meta));
    g_input = reinterpret_cast<const unsigned char*>(input.data());
    g_input_size = input.size();

    ::alarm(static_cast<unsigned int>(options.timeout_seconds));
    try {
      run_parser(parser, input, fixture, block_size, block_index);
      ++per_parser[parser_index];
    } catch (const Error&) {
      ++per_parser[parser_index];  // clean rejection
    } catch (const std::exception& e) {
      save_current("unexpected");
      std::cerr << "\nskipta-fuzz: UNEXPECTED EXCEPTION after " << iteration
                << " inputs: " << parser_name(parser) << ": " << e.what()
                << "\ninput saved under " << g_artifact_dir << "/unexpected.bin\n";
      ++unexpected;
      break;
    } catch (...) {
      save_current("unexpected");
      std::cerr << "\nskipta-fuzz: UNKNOWN EXCEPTION after " << iteration << " inputs: "
                << parser_name(parser) << "\n";
      ++unexpected;
      break;
    }
    ::alarm(0);
    g_input = nullptr;
    g_input_size = 0;

    if ((iteration & 255u) == 0) {
      const std::size_t rss = read_rss_bytes();
      peak_rss = std::max(peak_rss, rss);
      if (iteration == 256) baseline_rss = rss;
      if (rss > kMemoryLimit ||
          (baseline_rss != 0 && rss > baseline_rss + kMemoryLimit / 2)) {
        save_current("memory");
        std::cerr << "\nskipta-fuzz: MEMORY GROWTH after " << iteration << " inputs: RSS "
                  << (rss >> 20) << " MiB (baseline " << (baseline_rss >> 20)
                  << " MiB); input saved under " << g_artifact_dir << "/memory.bin\n";
        ++unexpected;
        break;
      }
    }
  }

  fs::remove_all(base, ec);
  const double seconds =
      std::chrono::duration<double>(Clock::now() - started).count();
  std::cout << "skipta-fuzz: " << (unexpected == 0 ? "OK" : "FAILED") << ": "
            << options.iterations << " inputs, " << all_seeds.size() << " seeds, "
            << seconds << "s, peak RSS " << (peak_rss >> 20) << " MiB\n";
  for (std::size_t p = 0; p < kParserCount; ++p) {
    std::cout << "  " << parser_name(kParsers[p]) << ": " << per_parser[p] << "\n";
  }
  std::cout << std::flush;
  return unexpected == 0 ? 0 : 1;
}
