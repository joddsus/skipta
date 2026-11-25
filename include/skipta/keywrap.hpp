// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Passphrase protection for the drive key at rest (Argon2id + AEAD).
// Plan for key loss: an unwrapped drive key cannot be recovered by anyone.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "skipta/bytes.hpp"
#include "skipta/format.hpp"

namespace skipta {

struct Argon2Params {
  std::uint64_t opslimit = 3;
  std::size_t memlimit = 256u * 1024u * 1024u;  ///< 256 MiB

  static Argon2Params moderate();
  static Argon2Params interactive();  ///< 64 MiB, for tests and low-end devices
};

/// Serialises {"v":1,"kdf":"argon2id",...} with the wrapped secret. This is
/// the same container used for the drive key and for the whole drive identity
/// (drive key + signing seed + seq), so one reviewed format covers both.
/// `salt` and `nonce` overrides exist only so test vectors are reproducible.
Bytes wrap_secret(ByteView secret, std::string_view passphrase,
                  const Argon2Params& params = Argon2Params{}, const Id128* salt = nullptr,
                  const std::array<unsigned char, format::kNonceSize>* nonce = nullptr);

struct KeywrapEnvelope {
  Argon2Params params;
  Bytes salt;
  Bytes nonce;
  Bytes ciphertext;
};

/// Parses and validates the JSON envelope, including every length and KDF
/// limit, but does not run Argon2 or decrypt. `unwrap_secret` uses it; it is
/// exposed so tests and the fuzz target can attack the envelope cheaply.
KeywrapEnvelope parse_keywrap_envelope(ByteView blob);

/// Wrong passphrase and tampered blob are indistinguishable: both throw
/// ErrorCode::BadPassphrase.
Bytes unwrap_secret(ByteView blob, std::string_view passphrase);

/// Serialises {"v":1,"kdf":"argon2id",...} with the wrapped key.
Bytes wrap_drive_key(const Key32& drive_key, std::string_view passphrase,
                     const Argon2Params& params = Argon2Params{}, const Id128* salt = nullptr,
                     const std::array<unsigned char, format::kNonceSize>* nonce = nullptr);

/// Wrong passphrase and tampered blob are indistinguishable: both throw
/// ErrorCode::BadPassphrase.
Key32 unwrap_drive_key(ByteView blob, std::string_view passphrase);

}  // namespace skipta
