// SPDX-License-Identifier: AGPL-3.0-or-later
#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/bytes.hpp"
#include "skipta/error.hpp"
#include "skipta/manifest.hpp"

using namespace skipta;

TEST_CASE("hex is strict and round-trips") {
  const Bytes data = {0x00, 0x01, 0x7f, 0x80, 0xff};
  CHECK(hex_encode(ByteView(data)) == "00017f80ff");
  CHECK(hex_decode("00017f80ff", "test") == data);
  CHECK(hex_decode("ABCDEF", "test") == Bytes{0xab, 0xcd, 0xef});
  CHECK(skiptest::code_of([] { hex_decode("abc", "test"); }) == ErrorCode::BadHex);
  CHECK(skiptest::code_of([] { hex_decode("zz", "test"); }) == ErrorCode::BadHex);
}

TEST_CASE("base64url is unpadded, url-safe and strictly decoded") {
  for (std::size_t n = 0; n <= 40; ++n) {
    const Bytes data = skiptest::pattern(n, 1);
    const std::string text = base64url_encode(ByteView(data));
    CHECK(text.find('+') == std::string::npos);
    CHECK(text.find('/') == std::string::npos);
    CHECK(text.find('=') == std::string::npos);
    CHECK(base64url_decode(text, "test") == data);
  }
  CHECK(base64url_encode(ByteView(std::string_view("hello"))) == "aGVsbG8");
  CHECK(skiptest::code_of([] { base64url_decode("a+b/", "test"); }) == ErrorCode::BadBase64);
  CHECK(skiptest::code_of([] { base64url_decode("aGVsbG8=", "test"); }) == ErrorCode::BadBase64);
  CHECK(skiptest::code_of([] { base64url_decode("aGVsbG8!", "test"); }) == ErrorCode::BadBase64);
}

TEST_CASE("constant-time comparison and zero detection") {
  const Bytes a = {1, 2, 3};
  const Bytes b = {1, 2, 3};
  const Bytes c = {1, 2, 4};
  CHECK(constant_time_equal(ByteView(a), ByteView(b)));
  CHECK_FALSE(constant_time_equal(ByteView(a), ByteView(c)));
  CHECK_FALSE(constant_time_equal(ByteView(a), ByteView(Bytes{1, 2})));
  CHECK(is_zero(ByteView(Bytes{0, 0, 0})));
  CHECK_FALSE(is_zero(ByteView(a)));
}

TEST_CASE("UTF-8 validation rejects overlong, surrogate and truncated forms") {
  CHECK(is_valid_utf8(ByteView(std::string_view("plain ascii"))));
  CHECK(is_valid_utf8(ByteView(std::string_view("caf\xc3\xa9"))));
  CHECK(is_valid_utf8(ByteView(std::string_view("\xf0\x9f\x93\x81"))));  // U+1F4C1

  const auto invalid = [](const char* s, std::size_t n) {
    return !is_valid_utf8(ByteView(reinterpret_cast<const unsigned char*>(s), n));
  };
  CHECK(invalid("\x80", 1));              // continuation byte alone
  CHECK(invalid("\xc0\x80", 2));          // overlong NUL
  CHECK(invalid("\xe0\x80\x80", 3));      // overlong
  CHECK(invalid("\xed\xa0\x80", 3));      // surrogate half
  CHECK(invalid("\xf4\x90\x80\x80", 4));  // beyond U+10FFFF
  CHECK(invalid("\xe2\x82", 2));          // truncated
  CHECK(invalid("\xff", 1));              // never valid
}
