// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/bytes.hpp"

#include <sodium.h>

#include <cstring>
#include <string>

#include "skipta/crypto.hpp"
#include "skipta/error.hpp"

namespace skipta {
namespace {

int hex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

Bytes to_bytes(ByteView v) {
  if (v.size == 0) return {};
  return Bytes(v.data, v.data + v.size);
}

Bytes to_bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }

std::string to_string(ByteView v) {
  if (v.size == 0) return std::string();
  return std::string(reinterpret_cast<const char*>(v.data), v.size);
}

bool is_zero(ByteView v) {
  if (v.size == 0) return true;
  return sodium_is_zero(v.data, v.size) != 0;
}

bool constant_time_equal(ByteView a, ByteView b) {
  if (a.size != b.size) return false;
  if (a.size == 0) return true;
  return sodium_memcmp(a.data, b.data, a.size) == 0;
}

std::string base64url_encode(ByteView v) {
  crypto::init();
  const std::size_t needed =
      sodium_base64_ENCODED_LEN(v.size, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  std::string out(needed + 1, '\0');
  sodium_bin2base64(out.data(), out.size(), v.data, v.size,
                    sodium_base64_VARIANT_URLSAFE_NO_PADDING);
  out.resize(std::strlen(out.c_str()));
  return out;
}

Bytes base64url_decode(std::string_view text, const char* what) {
  crypto::init();
  if (text.empty()) return {};
  Bytes out(text.size() / 4 * 3 + 3);
  std::size_t bin_len = 0;
  const char* end = nullptr;
  if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &bin_len, &end,
                        sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
    fail(ErrorCode::BadBase64, std::string(what) + ": invalid base64url");
  }
  if (end != text.data() + text.size()) {
    fail(ErrorCode::BadBase64, std::string(what) + ": trailing data after base64url");
  }
  out.resize(bin_len);
  return out;
}

std::string hex_encode(ByteView v) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.resize(v.size * 2);
  for (std::size_t i = 0; i < v.size; ++i) {
    out[2 * i] = digits[(v.data[i] >> 4) & 0x0f];
    out[2 * i + 1] = digits[v.data[i] & 0x0f];
  }
  return out;
}

Bytes hex_decode(std::string_view text, const char* what) {
  if (text.size() % 2 != 0) {
    fail(ErrorCode::BadHex, std::string(what) + ": odd hex length");
  }
  Bytes out(text.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int hi = hex_digit(text[2 * i]);
    const int lo = hex_digit(text[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      fail(ErrorCode::BadHex, std::string(what) + ": invalid hex digit");
    }
    out[i] = static_cast<unsigned char>((hi << 4) | lo);
  }
  return out;
}

}  // namespace skipta
