// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Thin, auditable wrapper around libsodium. No primitive is invented here:
// every operation is a direct call to libsodium with fixed, versioned
// parameters. See docs/adr/0002-container-format-v1.md.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "skipta/bytes.hpp"

namespace skipta::crypto {

/// Idempotent, thread-safe sodium_init().
void init();

Key32 random_key();
Id128 random_id();
Bytes random_bytes(std::size_t n);

/// BLAKE2b-256, keyed. key must be <= 64 bytes; empty key = unkeyed.
Key32 blake2b256_keyed(ByteView key, ByteView msg);

/// Ed25519 signing. Detached signatures, deterministic in libsodium.
struct SigningKeyPair {
  std::array<unsigned char, 64> secret{};
  PubKey32 pub{};

  static SigningKeyPair generate();
  /// Deterministic key from a 32-byte seed; used for test vectors only.
  static SigningKeyPair from_seed(const Key32& seed);

  Sig64 sign(ByteView msg) const;
};

bool verify(const PubKey32& pub, ByteView msg, const Sig64& sig);

/// XChaCha20-Poly1305 (IETF). nonce is fixed at 24 bytes to match the format.
Bytes aead_seal(const Key32& key, ByteView nonce24, ByteView aad, ByteView plaintext);
Bytes aead_open(const Key32& key, ByteView nonce24, ByteView aad, ByteView ciphertext);

/// Streaming SHA-256, used to verify a partially downloaded file against its
/// resume state. `digest()` does not consume the stream.
class Sha256 {
 public:
  Sha256();
  ~Sha256();
  Sha256(Sha256&&) noexcept;
  Sha256& operator=(Sha256&&) noexcept;
  Sha256(const Sha256&) = delete;
  Sha256& operator=(const Sha256&) = delete;

  void update(ByteView data);
  std::array<unsigned char, 32> digest() const;

 private:
  struct State;
  std::unique_ptr<State> state_;
};

std::array<unsigned char, 32> sha256(ByteView data);

/// Argon2id, 32-byte output. Parameters are caller-supplied and bounded by the
/// caller (see keywrap.hpp); libsodium's minimums are enforced here.
Key32 argon2id(std::string_view passphrase, ByteView salt16, std::uint64_t opslimit,
               std::size_t memlimit);

/// Best-effort zeroisation; not a substitute for not keeping secrets around.
void wipe(void* data, std::size_t size);

}  // namespace skipta::crypto
