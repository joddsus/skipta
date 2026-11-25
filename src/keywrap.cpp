// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/keywrap.hpp"

#include <sodium.h>

#include <algorithm>
#include <string>

#include "skipta/error.hpp"
#include "skipta/json.hpp"

namespace skipta {
namespace {

constexpr std::uint64_t kMaxOpslimit = 10;
constexpr std::size_t kMaxMemlimit = 1024u * 1024u * 1024u;
constexpr std::size_t kMaxPassphraseChars = 1024;
constexpr std::size_t kMaxBlobBytes = 4096;
constexpr std::size_t kMaxSecretBytes = 256;

void put_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
  }
}

/// Binds the KDF parameters to the ciphertext: raising the work factor on an
/// existing blob invalidates it instead of silently decrypting.
Bytes wrap_aad(const Argon2Params& params) {
  Bytes aad(format::kKeyWrapTag.begin(), format::kKeyWrapTag.end());
  put_u64(aad, format::kVersion);
  put_u64(aad, params.opslimit);
  put_u64(aad, static_cast<std::uint64_t>(params.memlimit));
  return aad;
}

void check_params(const Argon2Params& params) {
  if (params.opslimit < crypto_pwhash_OPSLIMIT_MIN || params.opslimit > kMaxOpslimit) {
    fail(ErrorCode::BadKdfParams, "argon2id opslimit must be between 1 and 10");
  }
  if (params.memlimit < crypto_pwhash_MEMLIMIT_MIN || params.memlimit > kMaxMemlimit) {
    fail(ErrorCode::BadKdfParams, "argon2id memlimit must be between libsodium's minimum and 1 GiB");
  }
}

void check_passphrase(std::string_view passphrase) {
  if (passphrase.empty()) {
    fail(ErrorCode::BadPassphrase, "passphrase must not be empty");
  }
  if (passphrase.size() > kMaxPassphraseChars) {
    fail(ErrorCode::BadPassphrase, "passphrase longer than 1024 bytes");
  }
}

void check_secret(ByteView secret) {
  if (secret.size == 0) {
    fail(ErrorCode::WrongKeyLength, "keywrap: secret must not be empty");
  }
  if (secret.size > kMaxSecretBytes) {
    fail(ErrorCode::TooLarge, "keywrap: secret larger than 256 bytes");
  }
}

}  // namespace

Argon2Params Argon2Params::moderate() { return Argon2Params{}; }

Argon2Params Argon2Params::interactive() {
  Argon2Params params;
  params.opslimit = 2;
  params.memlimit = 64u * 1024u * 1024u;
  return params;
}

Bytes wrap_secret(ByteView secret, std::string_view passphrase, const Argon2Params& params,
                  const Id128* salt, const std::array<unsigned char,
                  format::kNonceSize>* nonce) {
  check_passphrase(passphrase);
  check_params(params);
  check_secret(secret);

  const Id128 actual_salt = salt != nullptr ? *salt : crypto::random_id();
  const auto actual_nonce = nonce != nullptr ? *nonce : [&] {
    std::array<unsigned char, format::kNonceSize> random{};
    const Bytes bytes = crypto::random_bytes(format::kNonceSize);
    std::copy(bytes.begin(), bytes.end(), random.begin());
    return random;
  }();

  Key32 kek = crypto::argon2id(passphrase, ByteView(actual_salt), params.opslimit, params.memlimit);
  const Bytes aad = wrap_aad(params);
  Bytes ciphertext = crypto::aead_seal(kek, ByteView(actual_nonce), ByteView(aad), secret);
  crypto::wipe(kek.data(), kek.size());

  jsonx::Json j;
  j["v"] = format::kVersion;
  j["kdf"] = "argon2id";
  j["opslimit"] = params.opslimit;
  j["memlimit"] = params.memlimit;
  j["salt"] = base64url_encode(ByteView(actual_salt));
  j["nonce"] = base64url_encode(ByteView(actual_nonce));
  j["ct"] = base64url_encode(ByteView(ciphertext));
  Bytes blob = to_bytes(jsonx::dump(j, "keywrap"));
  crypto::wipe(ciphertext.data(), ciphertext.size());
  return blob;
}

Bytes wrap_drive_key(const Key32& drive_key, std::string_view passphrase,
                     const Argon2Params& params, const Id128* salt,
                     const std::array<unsigned char, format::kNonceSize>* nonce) {
  return wrap_secret(ByteView(drive_key), passphrase, params, salt, nonce);
}

KeywrapEnvelope parse_keywrap_envelope(ByteView blob) {
  auto j = jsonx::parse_strict(to_string(blob), kMaxBlobBytes, "keywrap");
  jsonx::require_object(j, "keywrap");
  jsonx::reject_unknown(j, {"v", "kdf", "opslimit", "memlimit", "salt", "nonce", "ct"}, "keywrap");

  const std::uint64_t version = jsonx::req_uint(j, "v", "keywrap");
  if (version != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported keywrap version");
  }
  if (jsonx::req_string(j, "kdf", 16, "keywrap") != "argon2id") {
    fail(ErrorCode::BadKdfParams, "keywrap: only argon2id is supported");
  }

  KeywrapEnvelope envelope;
  envelope.params.opslimit = jsonx::req_uint(j, "opslimit", "keywrap");
  const std::uint64_t memlimit = jsonx::req_uint(j, "memlimit", "keywrap");
  if (memlimit > kMaxMemlimit) {
    fail(ErrorCode::BadKdfParams, "keywrap: memlimit above the 1 GiB safety cap");
  }
  envelope.params.memlimit = static_cast<std::size_t>(memlimit);
  check_params(envelope.params);

  envelope.salt = jsonx::req_b64(j, "salt", 16, "keywrap");
  envelope.nonce = jsonx::req_b64(j, "nonce", format::kNonceSize, "keywrap");
  envelope.ciphertext = jsonx::req_b64(j, "ct", static_cast<std::size_t>(-1), "keywrap");
  if (envelope.ciphertext.size() < format::kAeadTagSize ||
      envelope.ciphertext.size() > kMaxSecretBytes + format::kAeadTagSize) {
    fail(ErrorCode::WrongKeyLength, "keywrap: ciphertext has an unsupported length");
  }
  return envelope;
}

Bytes unwrap_secret(ByteView blob, std::string_view passphrase) {
  check_passphrase(passphrase);
  const KeywrapEnvelope envelope = parse_keywrap_envelope(blob);
  Key32 kek = crypto::argon2id(passphrase, ByteView(envelope.salt), envelope.params.opslimit,
                                envelope.params.memlimit);
  Bytes plain;
  try {
    plain = crypto::aead_open(kek, ByteView(envelope.nonce), ByteView(wrap_aad(envelope.params)),
                              ByteView(envelope.ciphertext));
  } catch (const Error&) {
    crypto::wipe(kek.data(), kek.size());
    // Wrong passphrase and a tampered blob look the same on purpose.
    fail(ErrorCode::BadPassphrase, "wrong passphrase or damaged key file");
  }
  crypto::wipe(kek.data(), kek.size());
  if (plain.size() > kMaxSecretBytes) {
    crypto::wipe(plain.data(), plain.size());
    fail(ErrorCode::WrongKeyLength, "keywrap: unwrapped secret is too large");
  }
  return plain;
}

Key32 unwrap_drive_key(ByteView blob, std::string_view passphrase) {
  Bytes plain = unwrap_secret(blob, passphrase);
  if (plain.size() != 32) {
    crypto::wipe(plain.data(), plain.size());
    fail(ErrorCode::WrongKeyLength, "keywrap: unwrapped key has the wrong length");
  }
  Key32 out{};
  std::copy(plain.begin(), plain.end(), out.begin());
  crypto::wipe(plain.data(), plain.size());
  return out;
}

}  // namespace skipta
