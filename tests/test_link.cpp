// SPDX-License-Identifier: AGPL-3.0-or-later
#include "doctest/doctest.h"
#include "helpers.hpp"
#include "nlohmann/json.hpp"
#include "skipta/error.hpp"
#include "skipta/link.hpp"

using namespace skipta;

namespace {

ShareLink sample_link() {
  ShareLink link;
  link.version = 1;
  link.drive = skiptest::filled<32>(0xa1);
  link.key = skiptest::filled_key(0xb2);
  link.bootstrap = {"udp://tracker.example:6969", "seed:club.example:7000"};
  return link;
}

}  // namespace

TEST_CASE("share links round-trip, with and without bootstrap hints") {
  const ShareLink link = sample_link();
  const std::string encoded = encode_link(link);
  CHECK(encoded.rfind("skipta://v1/", 0) == 0);
  CHECK(encoded.size() < format::kMaxLinkChars);

  const ShareLink decoded = decode_link(encoded);
  CHECK(decoded.version == 1);
  CHECK(decoded.drive == link.drive);
  CHECK(decoded.key == link.key);
  CHECK(decoded.bootstrap == link.bootstrap);

  ShareLink bare = sample_link();
  bare.bootstrap.clear();
  const ShareLink decoded_bare = decode_link(encode_link(bare));
  CHECK(decoded_bare.bootstrap.empty());
}

TEST_CASE("links tolerate surrounding whitespace from chat clients") {
  const std::string encoded = encode_link(sample_link());
  const ShareLink decoded = decode_link("\n  " + encoded + "\r\n");
  CHECK(decoded.key == sample_link().key);
}

TEST_CASE("links reject everything that is not a v1 link") {
  CHECK(skiptest::code_of([] { decode_link(""); }) == ErrorCode::BadLink);
  CHECK(skiptest::code_of([] { decode_link("https://example.com/x"); }) == ErrorCode::BadScheme);
  CHECK(skiptest::code_of([] { decode_link("skipta://v2/abc"); }) == ErrorCode::BadScheme);
  CHECK(skiptest::code_of([] {
          decode_link("skipta://v1/" + std::string(format::kMaxLinkChars, 'A'));
        }) == ErrorCode::TooLarge);
  CHECK(skiptest::code_of([] { decode_link("skipta://v1/!!!!"); }) == ErrorCode::BadBase64);

  // Structurally valid base64 that is not our payload.
  CHECK(skiptest::code_of([] {
          decode_link("skipta://v1/" + base64url_encode(ByteView(std::string_view("not json"))));
        }) == ErrorCode::BadJson);

  const auto payload = [](const std::string& text) {
    return "skipta://v1/" + base64url_encode(ByteView(text));
  };
  CHECK(skiptest::code_of([&] { decode_link(payload(R"({"v":2})")); }) == ErrorCode::BadVersion);
  CHECK(skiptest::code_of([&] {
          decode_link(payload(R"({"v":1,"drive":"AAAA","key":"AAAA"})"));
        }) == ErrorCode::WrongType);
  CHECK(skiptest::code_of([&] {
          decode_link(payload(R"({"v":1,"drive":"AAAA","key":"AAAA","extra":1})"));
        }) == ErrorCode::UnknownField);
  CHECK(skiptest::code_of([&] { decode_link(payload(R"({"v":1})")); }) ==
        ErrorCode::MissingField);
}

TEST_CASE("bootstrap hints are constrained") {
  ShareLink too_many = sample_link();
  too_many.bootstrap = {"udp://a:1", "udp://b:2", "udp://c:3", "udp://d:4", "udp://e:5"};
  CHECK(skiptest::code_of([&] { encode_link(too_many); }) == ErrorCode::BadBootstrapHint);

  ShareLink odd = sample_link();
  odd.bootstrap = {"javascript:alert(1)"};
  CHECK(skiptest::code_of([&] { encode_link(odd); }) == ErrorCode::BadBootstrapHint);

  ShareLink empty = sample_link();
  empty.bootstrap = {""};
  CHECK(skiptest::code_of([&] { encode_link(empty); }) == ErrorCode::BadBootstrapHint);
}

TEST_CASE("a zero drive key or zero drive public key is never a valid link") {
  ShareLink zero_key = sample_link();
  zero_key.key = skiptest::filled_key(0);
  CHECK(skiptest::code_of([&] { encode_link(zero_key); }) == ErrorCode::ZeroId);

  ShareLink zero_drive = sample_link();
  zero_drive.drive = skiptest::filled<32>(0x00);
  CHECK(skiptest::code_of([&] { encode_link(zero_drive); }) == ErrorCode::ZeroId);
}

TEST_CASE("swarm names are secret-derived, stable and generation-scoped") {
  const ShareLink link = sample_link();
  const auto salt = swarm_salt(link);
  const auto id0 = swarm_id(link, 0);
  const auto id1 = swarm_id(link, 1);

  CHECK(salt == swarm_salt(sample_link()));
  CHECK(id0 == swarm_id(sample_link(), 0));
  CHECK_FALSE(salt == id0);
  CHECK_FALSE(id0 == id1);
  // The names must not be the key and must not embed it (T2: no enumeration
  // and nothing secret on the DHT).
  CHECK_FALSE(constant_time_equal(ByteView(salt), ByteView(link.key)));
  CHECK_FALSE(constant_time_equal(ByteView(id0), ByteView(link.key)));
  CHECK(to_string(ByteView(salt)).find(to_string(ByteView(link.key))) == std::string::npos);

  ShareLink other = sample_link();
  other.key = skiptest::filled_key(0xb3);
  CHECK_FALSE(swarm_salt(other) == salt);
  CHECK_FALSE(swarm_id(other, 0) == id0);
}
