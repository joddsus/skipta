// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/crypto.hpp"

#include <sodium.h>

#include <memory>
#include <mutex>

#include "skipta/error.hpp"

namespace skipta::crypto {
namespace {

std::once_flag g_init;

void ensure_init() {
  std::call_once(g_init, [] {
    if (sodium_init() < 0) {
      fail(ErrorCode::CryptoInit, "libsodium failed to initialise");
    }
  });
}

/// libsodium accepts a null pointer only for zero-length input in some builds;
/// pass a valid pointer anyway.
unsigned char g_dummy = 0;

const unsigned char* safe_ptr(ByteView v) { return v.size == 0 ? &g_dummy : v.data; }

}  // namespace

void init() { ensure_init(); }

Key32 random_key() {
  ensure_init();
  Key32 key{};
  randombytes_buf(key.data(), key.size());
  return key;
}

Id128 random_id() {
  ensure_init();
  Id128 id{};
  randombytes_buf(id.data(), id.size());
  return id;
}

Bytes random_bytes(std::size_t n) {
  ensure_init();
  Bytes out(n);
  if (n != 0) randombytes_buf(out.data(), n);
  return out;
}

Key32 blake2b256_keyed(ByteView key, ByteView msg) {
  ensure_init();
  if (key.size > crypto_generichash_KEYBYTES_MAX) {
    fail(ErrorCode::WrongKeyLength, "blake2b key longer than 64 bytes");
  }
  Key32 out{};
  if (crypto_generichash(out.data(), out.size(), safe_ptr(msg), msg.size, key.data, key.size) != 0) {
    fail(ErrorCode::CryptoInit, "blake2b failed");
  }
  return out;
}

SigningKeyPair SigningKeyPair::generate() {
  ensure_init();
  static_assert(crypto_sign_SECRETKEYBYTES == 64, "unexpected Ed25519 secret key size");
  SigningKeyPair pair;
  if (crypto_sign_keypair(pair.pub.data(), pair.secret.data()) != 0) {
    fail(ErrorCode::CryptoInit, "ed25519 keypair generation failed");
  }
  return pair;
}

SigningKeyPair SigningKeyPair::from_seed(const Key32& seed) {
  ensure_init();
  static_assert(crypto_sign_SEEDBYTES == 32, "unexpected Ed25519 seed size");
  SigningKeyPair pair;
  if (crypto_sign_seed_keypair(pair.pub.data(), pair.secret.data(), seed.data()) != 0) {
    fail(ErrorCode::CryptoInit, "ed25519 seed keypair failed");
  }
  return pair;
}

Sig64 SigningKeyPair::sign(ByteView msg) const {
  ensure_init();
  Sig64 sig{};
  unsigned long long sig_len = 0;
  if (crypto_sign_detached(sig.data(), &sig_len, safe_ptr(msg), msg.size, secret.data()) != 0) {
    fail(ErrorCode::CryptoInit, "ed25519 signing failed");
  }
  return sig;
}

bool verify(const PubKey32& pub, ByteView msg, const Sig64& sig) {
  ensure_init();
  return crypto_sign_verify_detached(sig.data(), safe_ptr(msg), msg.size, pub.data()) == 0;
}

Bytes aead_seal(const Key32& key, ByteView nonce24, ByteView aad, ByteView plaintext) {
  ensure_init();
  static_assert(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES == 24, "unexpected nonce size");
  if (nonce24.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
    fail(ErrorCode::BadNonce, "XChaCha20-Poly1305 nonce must be 24 bytes");
  }
  Bytes out(plaintext.size + crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long written = 0;
  if (crypto_aead_xchacha20poly1305_ietf_encrypt(out.data(), &written, safe_ptr(plaintext),
                                                plaintext.size, safe_ptr(aad), aad.size, nullptr,
                                                nonce24.data, key.data()) != 0) {
    fail(ErrorCode::AuthFailed, "aead encryption failed");
  }
  out.resize(static_cast<std::size_t>(written));
  return out;
}

Bytes aead_open(const Key32& key, ByteView nonce24, ByteView aad, ByteView ciphertext) {
  ensure_init();
  if (nonce24.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
    fail(ErrorCode::BadNonce, "XChaCha20-Poly1305 nonce must be 24 bytes");
  }
  if (ciphertext.size < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
    fail(ErrorCode::ShortInput, "aead ciphertext shorter than the tag");
  }
  Bytes out(ciphertext.size - crypto_aead_xchacha20poly1305_ietf_ABYTES);
  unsigned long long written = 0;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &written, nullptr, safe_ptr(ciphertext),
                                                ciphertext.size, safe_ptr(aad), aad.size,
                                                nonce24.data, key.data()) != 0) {
    fail(ErrorCode::AuthFailed, "aead authentication failed");
  }
  out.resize(static_cast<std::size_t>(written));
  return out;
}

Key32 argon2id(std::string_view passphrase, ByteView salt16, std::uint64_t opslimit,
               std::size_t memlimit) {
  ensure_init();
  static_assert(crypto_pwhash_SALTBYTES == 16, "unexpected Argon2 salt size");
  if (salt16.size != crypto_pwhash_SALTBYTES) {
    fail(ErrorCode::BadKdfParams, "argon2id salt must be 16 bytes");
  }
  if (opslimit < crypto_pwhash_OPSLIMIT_MIN || opslimit > crypto_pwhash_OPSLIMIT_MAX) {
    fail(ErrorCode::BadKdfParams, "argon2id opslimit out of range");
  }
  if (memlimit < crypto_pwhash_MEMLIMIT_MIN || memlimit > crypto_pwhash_MEMLIMIT_MAX) {
    fail(ErrorCode::BadKdfParams, "argon2id memlimit out of range");
  }
  Key32 out{};
  if (crypto_pwhash(out.data(), out.size(), passphrase.data(),
                    static_cast<unsigned long long>(passphrase.size()), salt16.data, opslimit,
                    memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
    fail(ErrorCode::BadKdfParams, "argon2id failed (out of memory?)");
  }
  return out;
}

struct Sha256::State {
  crypto_hash_sha256_state inner{};
};

Sha256::Sha256() : state_(std::make_unique<State>()) {
  ensure_init();
  if (crypto_hash_sha256_init(&state_->inner) != 0) {
    fail(ErrorCode::CryptoInit, "sha256 init failed");
  }
}

Sha256::~Sha256() = default;
Sha256::Sha256(Sha256&&) noexcept = default;
Sha256& Sha256::operator=(Sha256&&) noexcept = default;

void Sha256::update(ByteView data) {
  if (data.size == 0) return;
  if (crypto_hash_sha256_update(&state_->inner, data.data, data.size) != 0) {
    fail(ErrorCode::CryptoInit, "sha256 update failed");
  }
}

std::array<unsigned char, 32> Sha256::digest() const {
  // Hashing a copy leaves the stream usable for further updates.
  crypto_hash_sha256_state copy = state_->inner;
  std::array<unsigned char, 32> out{};
  if (crypto_hash_sha256_final(&copy, out.data()) != 0) {
    fail(ErrorCode::CryptoInit, "sha256 final failed");
  }
  return out;
}

std::array<unsigned char, 32> sha256(ByteView data) {
  Sha256 hasher;
  hasher.update(data);
  return hasher.digest();
}

void wipe(void* data, std::size_t size) {
  if (data != nullptr && size != 0) sodium_memzero(data, size);
}

}  // namespace skipta::crypto
