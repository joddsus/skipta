// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Regression cases for the pure parsers the fuzz target attacks: HTTP request
// and response heads, object targets, the keywrap envelope and store names.
// They also pin the limits that keep deep JSON and oversized metadata cheap.
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/bytes.hpp"
#include "skipta/error.hpp"
#include "skipta/http.hpp"
#include "skipta/keywrap.hpp"
#include "skipta/manifest.hpp"
#include "skipta/store.hpp"

using namespace skipta;

TEST_CASE("HTTP request heads accept one exact shape and reject everything else") {
  const auto ok = http_detail::parse_request_head("GET /pointers/x HTTP/1.1\r\nHost: a\r\n\r\n");
  REQUIRE(ok.has_value());
  CHECK(ok->method == "GET");
  CHECK(ok->target == "/pointers/x");
  CHECK(ok->version == "HTTP/1.1");

  CHECK(http_detail::parse_request_head("GET /x HTTP/1.0\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("").has_value());
  CHECK_FALSE(http_detail::parse_request_head("GET\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("GET  /x HTTP/1.1\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("GET /x  HTTP/1.1\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("get /x HTTP/1.1\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("GET /x HTTP/2.0\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("GET x HTTP/1.1\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head("GET /x HTTP/1.1 extra\r\n\r\n").has_value());
  CHECK_FALSE(http_detail::parse_request_head(std::string("GET /x\x01 HTTP/1.1\r\n\r\n")).has_value());
  CHECK_FALSE(http_detail::parse_request_head(std::string(9000, 'G')).has_value());
}

TEST_CASE("HTTP object targets are exact and block indices cannot overflow") {
  const PubKey32 drive = skiptest::filled<32>(0x11);
  const Id128 id = skiptest::filled_id(0x22);
  const std::string drive_hex = hex_encode(ByteView(drive));
  const std::string id_hex = hex_encode(ByteView(id));

  const auto pointer = http_detail::parse_object_target("/pointers/" + drive_hex + ".ptr");
  REQUIRE(pointer.has_value());
  CHECK(pointer->kind == http_detail::RouteKind::Pointer);
  CHECK(pointer->drive == drive);

  const auto manifest = http_detail::parse_object_target("/manifests/" + id_hex + ".mf");
  REQUIRE(manifest.has_value());
  CHECK(manifest->kind == http_detail::RouteKind::Manifest);
  CHECK(manifest->id == id);

  const auto block = http_detail::parse_object_target("/blocks/" + id_hex + "/0000000000000007.blk");
  REQUIRE(block.has_value());
  CHECK(block->kind == http_detail::RouteKind::Block);
  CHECK(block->id == id);
  CHECK(block->index == 7);
  CHECK(http_detail::parse_object_target("/blocks/" + id_hex + "/7.blk")->index == 7);

  const std::vector<std::string> rejected = {
      "",
      "/",
      "/pointers/" + drive_hex,
      "/pointers/" + drive_hex + ".ptr/",
      "/pointers/" + drive_hex + ".ptrx",
      "/pointers/../" + drive_hex + ".ptr",
      "/manifests/" + id_hex,
      "/manifests/" + id_hex + ".mf?x",
      "/blocks/" + id_hex,
      "/blocks/" + id_hex + "/",
      "/blocks/" + id_hex + "/0000000000000000.blk/",
      "/blocks/" + id_hex + "/../0000000000000000.blk",
      "/blocks/" + id_hex + "//0000000000000000.blk",
      "/blocks/" + id_hex + "/+1.blk",
      "/blocks/" + id_hex + "/-1.blk",
      "/blocks/" + id_hex + "/1.5.blk",
      "/blocks/" + id_hex + "/18446744073709551616.blk",
      "/blocks/" + id_hex + "/99999999999999999999.blk",
      "/blocks/" + id_hex + "/999999999999999999999.blk",
  };
  for (const std::string& target : rejected) {
    CHECK_FALSE(http_detail::parse_object_target(target).has_value());
  }
}

TEST_CASE("HTTP response heads reject smuggling shapes and overflow") {
  using http_detail::parse_response_head;
  const auto ok = parse_response_head(
      "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: identity\r\nX: y");
  CHECK(ok.status == 200);
  REQUIRE(ok.content_length.has_value());
  CHECK(*ok.content_length == 5);

  const auto not_found = parse_response_head("HTTP/1.0 404 Not Found\r\nContent-Length: 0");
  CHECK(not_found.status == 404);
  CHECK(not_found.content_length == 0);

  // Repeated identical Content-Length is harmless; conflicting values are not.
  CHECK(parse_response_head("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1")
            .content_length == 1);

  const char* rejected[] = {
      "",
      "ICY 200 OK",
      "HTTP/2 200 OK",
      "HTTP/1.1 20 OK",
      "HTTP/1.1 2000 OK",
      "HTTP/1.1 200 OK\r\nContent-Length: -1",
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2",
      "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616",
      "HTTP/1.1 200 OK\r\nContent-Length: 999999999999999999999",
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked",
      "HTTP/1.1 200 OK\r\n folded: value",
      "HTTP/1.1 200 OK\r\nNoColon",
      "HTTP/1.1 200 OK\r\nBad Name: value",
      "HTTP/1.1 200 OK\r\nX: \x01",
  };
  for (const char* head : rejected) {
    CHECK(skiptest::code_of([&] { (void)parse_response_head(head); }) == ErrorCode::StoreIo);
  }
  CHECK(skiptest::code_of([&] {
          (void)parse_response_head(std::string(17 * 1024, 'H'));
        }) == ErrorCode::StoreIo);
}

TEST_CASE("the keywrap envelope enforces every KDF and length limit") {
  const Bytes salt = crypto::random_bytes(16);
  const Bytes nonce = crypto::random_bytes(format::kNonceSize);
  const Bytes ct = crypto::random_bytes(32 + format::kAeadTagSize);
  const std::string envelope = "{\"v\":1,\"kdf\":\"argon2id\",\"opslimit\":3,"
                               "\"memlimit\":67108864,\"salt\":\"" +
                               base64url_encode(ByteView(salt)) + "\",\"nonce\":\"" +
                               base64url_encode(ByteView(nonce)) + "\",\"ct\":\"" +
                               base64url_encode(ByteView(ct)) + "\"}";

  const KeywrapEnvelope parsed = parse_keywrap_envelope(ByteView(envelope));
  CHECK(parsed.params.opslimit == 3);
  CHECK(parsed.params.memlimit == 67108864);
  CHECK(parsed.salt == salt);
  CHECK(parsed.nonce == nonce);
  CHECK(parsed.ciphertext == ct);

  const auto replace = [&](std::string_view from, std::string_view to) {
    std::string copy = envelope;
    const std::size_t at = copy.find(from);
    REQUIRE(at != std::string::npos);
    copy.replace(at, from.size(), to);
    return copy;
  };

  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(ByteView(replace("\"opslimit\":3", "\"opslimit\":0")));
        }) == ErrorCode::BadKdfParams);
  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(ByteView(replace("\"opslimit\":3", "\"opslimit\":11")));
        }) == ErrorCode::BadKdfParams);
  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(
              ByteView(replace("\"memlimit\":67108864", "\"memlimit\":1073741825")));
        }) == ErrorCode::BadKdfParams);
  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(ByteView(replace("\"kdf\":\"argon2id\"", "\"kdf\":\"pbkdf2\"")));
        }) == ErrorCode::BadKdfParams);
  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(ByteView(replace("\"v\":1", "\"v\":2")));
        }) == ErrorCode::BadVersion);
  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(ByteView(replace("\"kdf\"", "\"extra\":1,\"kdf\"")));
        }) == ErrorCode::UnknownField);
  CHECK(skiptest::code_of([&] {
          (void)parse_keywrap_envelope(ByteView(std::string(5000, 'x')));
        }) == ErrorCode::TooLarge);
}

TEST_CASE("deep or duplicated JSON is rejected before it can exhaust the stack") {
  const std::string deep(1024 * 1024, '[');
  CHECK(skiptest::code_of([&] { (void)Manifest::parse(ByteView(deep)); }) ==
        ErrorCode::TooDeep);

  const std::string duplicate =
      "{\"v\":1,\"v\":1,\"id\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"seq\":1,\"entries\":[]}";
  CHECK(skiptest::code_of([&] { (void)Manifest::parse(ByteView(duplicate)); }) ==
        ErrorCode::DuplicateKey);

  // A million nested arrays in a small input must be caught by the depth guard,
  // not by a stack overflow.
  CHECK(skiptest::code_of([&] {
          (void)Manifest::parse(ByteView(std::string(2000, '[')));
        }) == ErrorCode::TooDeep);
}

TEST_CASE("store filenames are classified by exact shape only") {
  const std::string id = std::string(32, 'a');
  CHECK(classify_stored_object_name(id) == StoredObjectName::FileDirectory);
  CHECK(classify_stored_object_name(id + ".mf") == StoredObjectName::Manifest);
  CHECK(classify_stored_object_name(std::string(64, 'b') + ".ptr") ==
        StoredObjectName::Pointer);
  CHECK(classify_stored_object_name(std::string(16, '0') + ".blk") ==
        StoredObjectName::Block);

  const char* rejected[] = {
      "",
      ".",
      "..",
      ".mf",
      ".ptr",
      ".blk",
      "A0000000000000000000000000000000",
      "a000000000000000000000000000000g",
      "0000000000000000.blkx",
      "000000000000000.blk",
      "../../etc/passwd",
      "/tmp/x",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.mf",
  };
  for (const char* name : rejected) {
    CHECK(classify_stored_object_name(name) == StoredObjectName::Other);
  }
}
