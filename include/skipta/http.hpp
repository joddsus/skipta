// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A deliberately small, read-only HTTP transport for the blob store.
//
// The store only ever holds opaque objects: signed pointers, sealed manifests
// and sealed blocks. Serving it over plain HTTP therefore exposes no plaintext
// and no key material; every object is authenticated by the reader after it
// arrives. The server is read-only, has no directory listing and accepts only
// the three exact object name shapes. A reader caches what it fetched in a
// local store directory and can keep browsing from that cache.
//
// Plain HTTP is not confidential on the wire: object names (which are random or
// secret-derived), sizes and timing are visible to the network, and an active
// attacker can withhold or replay objects. It cannot forge or decrypt content.
// Put a TLS tunnel or a trusted network under this; the CLI says so too.
#pragma once

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "skipta/bytes.hpp"

namespace skipta {

struct HttpServeOptions {
  /// Local store to serve. Nothing outside this directory is ever read.
  std::filesystem::path root;
  /// Interface to bind. Defaults to loopback: sharing one machine only.
  std::string bind_address = "127.0.0.1";
  /// 0 asks the operating system for an ephemeral port (useful in tests).
  std::uint16_t port = 0;
};

/// Read-only store server. One request at a time; a request may only name a
/// pointer, manifest or block object. Anything else gets 400/404/405, and
/// symlinks or non-regular files are never served.
class HttpServer {
 public:
  explicit HttpServer(HttpServeOptions options);
  ~HttpServer();
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  std::uint16_t port() const noexcept { return port_; }

  /// The URL a reader can pass to --store, for the bound interface.
  std::string origin() const;

  /// Accepts and answers connections until stop(). Blocks the calling thread.
  void run();

  /// Asks run() to return. Safe to call from another thread.
  void stop() noexcept;

 private:
  std::filesystem::path root_;
  std::string bind_address_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0;
  std::atomic<bool> stopping_{false};
};

/// Fetches one object from an absolute http:// URL. Returns nullopt for 404.
/// Throws StoreIo for transport or protocol failures (including redirects,
/// which are never followed) and TooLarge when the body would exceed `cap`.
/// The returned body is never larger than `cap`.
std::optional<Bytes> http_get_object(const std::string& url, std::size_t cap);

/// Pure wire parsers, separated from the sockets so the normal test suite and
/// the sanitizer fuzz target can exercise every untrusted byte without a
/// network. They are internal to the transport and not a stable API.
namespace http_detail {

struct RequestHead {
  std::string method;
  std::string target;
  std::string version;
};

/// Parses the request header block. Returns nullopt for anything malformed,
/// oversized, or with a method/target/version shape the server must reject with
/// 400. Header fields themselves are ignored; only the request line matters.
std::optional<RequestHead> parse_request_head(std::string_view head);

enum class RouteKind { Pointer, Manifest, Block };

struct ObjectRoute {
  RouteKind kind = RouteKind::Pointer;
  PubKey32 drive{};   ///< pointer only
  Id128 id{};         ///< manifest or file id
  std::uint64_t index = 0;  ///< block only
};

/// Parses exactly the three object target shapes. Nullopt means "not an
/// object" (404); there is no path, query or percent-decoding support.
std::optional<ObjectRoute> parse_object_target(std::string_view target);

struct ResponseHead {
  int status = 0;
  std::optional<std::uint64_t> content_length;
};

/// Parses a response header block (without the final blank line). Throws
/// StoreIo for a malformed protocol line, status, header field or unsupported
/// transfer encoding; a conflicting Content-Length is refused.
ResponseHead parse_response_head(std::string_view head);

}  // namespace http_detail

/// True when `text` starts with http:// or https:// (a store location that is
/// not a local directory). https:// is recognised so the CLI can explain that
/// this build has no TLS client instead of treating it as a path.
bool looks_like_store_url(std::string_view text);

/// Validates and canonicalises an http:// store origin: no trailing slash, no
/// query or fragment. Throws BadOptions for anything else, including https://.
std::string normalize_http_store_url(std::string_view text);

}  // namespace skipta
