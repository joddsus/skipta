// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Basic byte types and encodings. Nothing in here decodes untrusted input
// without a size limit; callers pass a label so errors name the field.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace skipta {

using Bytes = std::vector<unsigned char>;

/// Non-owning view of bytes. Contents are untrusted whenever they came from
/// the network or from a link. No implicit NUL terminator.
struct ByteView {
  const unsigned char* data = nullptr;
  std::size_t size = 0;

  ByteView() = default;
  ByteView(const unsigned char* d, std::size_t n) : data(d), size(n) {}
  ByteView(const Bytes& b) : data(b.data()), size(b.size()) {}
  ByteView(std::string_view s)
      : data(reinterpret_cast<const unsigned char*>(s.data())), size(s.size()) {}

  template <std::size_t N>
  ByteView(const std::array<unsigned char, N>& a) : data(a.data()), size(N) {}

  bool empty() const { return size == 0; }
};

using Key32 = std::array<unsigned char, 32>;    ///< symmetric key
using PubKey32 = std::array<unsigned char, 32>; ///< Ed25519 public key
using Id128 = std::array<unsigned char, 16>;    ///< random opaque id
using Sig64 = std::array<unsigned char, 64>;    ///< Ed25519 signature

Bytes to_bytes(ByteView v);
Bytes to_bytes(const std::string& text);
std::string to_string(ByteView v);
bool is_zero(ByteView v);
bool constant_time_equal(ByteView a, ByteView b);

/// URL-safe base64 without padding (libsodium variant). Strict decoder.
std::string base64url_encode(ByteView v);
Bytes base64url_decode(std::string_view text, const char* what);

std::string hex_encode(ByteView v);
Bytes hex_decode(std::string_view text, const char* what);

}  // namespace skipta
