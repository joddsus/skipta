// SPDX-License-Identifier: AGPL-3.0-or-later
#include <limits>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"

using namespace skipta;

namespace {

const std::size_t kStride = format::kBlockPlaintextSize + format::kAeadTagSize;

Bytes slice(const Bytes& source, std::size_t offset, std::size_t length) {
  REQUIRE(offset + length <= source.size());
  return Bytes(source.begin() + static_cast<std::ptrdiff_t>(offset),
               source.begin() + static_cast<std::ptrdiff_t>(offset + length));
}

}  // namespace

TEST_CASE("XChaCha20-Poly1305 round-trip and tamper detection") {
  const Key32 key = crypto::random_key();
  const Bytes raw_nonce = crypto::random_bytes(format::kNonceSize);
  std::array<unsigned char, format::kNonceSize> nonce{};
  std::copy(raw_nonce.begin(), raw_nonce.end(), nonce.begin());
  const Bytes message = skiptest::pattern(300, 7);
  const std::string aad = "skipta/v1/block";

  const Bytes sealed = crypto::aead_seal(key, ByteView(nonce), ByteView(aad), ByteView(message));
  CHECK(sealed.size() == message.size() + format::kAeadTagSize);
  CHECK(crypto::aead_open(key, ByteView(nonce), ByteView(aad), ByteView(sealed)) == message);

  Bytes tampered = sealed;
  tampered.back() ^= 0x01;
  CHECK(skiptest::code_of([&] {
          crypto::aead_open(key, ByteView(nonce), ByteView(aad), ByteView(tampered));
        }) == ErrorCode::AuthFailed);

  CHECK(skiptest::code_of([&] {
          crypto::aead_open(key, ByteView(nonce), ByteView("other aad"), ByteView(sealed));
        }) == ErrorCode::AuthFailed);

  const Key32 other_key = crypto::random_key();
  CHECK(skiptest::code_of([&] {
          crypto::aead_open(other_key, ByteView(nonce), ByteView(aad), ByteView(sealed));
        }) == ErrorCode::AuthFailed);

  CHECK(skiptest::code_of([&] {
          crypto::aead_open(key, ByteView(Bytes{1, 2, 3}), ByteView(aad), ByteView(sealed));
        }) == ErrorCode::BadNonce);

  CHECK(skiptest::code_of([&] {
          crypto::aead_open(key, ByteView(nonce), ByteView(aad), ByteView(Bytes{1, 2, 3}));
        }) == ErrorCode::ShortInput);
}

TEST_CASE("file blocks are random-access: one block decrypts without the others") {
  const Key32 drive_key = crypto::random_key();
  const Id128 file_id = crypto::random_id();
  const std::uint64_t file_size = 3 * format::kBlockPlaintextSize + 1234;
  const Bytes plaintext = skiptest::pattern(static_cast<std::size_t>(file_size), 3);
  const Bytes ciphertext = format::encrypt_file(drive_key, file_id, ByteView(plaintext));

  CHECK(format::block_count(file_size) == 4);
  CHECK(ciphertext.size() == file_size + 4 * format::kAeadTagSize);

  // Only block 2 is fetched and decrypted: no whole-file download involved.
  const Bytes block2 = slice(ciphertext, 2 * kStride, kStride);
  const Bytes block2_plain = format::decrypt_block(drive_key, file_id, file_size, 2, ByteView(block2));
  CHECK(block2_plain == slice(plaintext, 2 * format::kBlockPlaintextSize,
                              format::kBlockPlaintextSize));

  // The whole-file helper must agree with the per-block one.
  CHECK(format::decrypt_file(drive_key, file_id, file_size, ByteView(ciphertext)) == plaintext);

  // Block 0 does not decrypt in slot 2: index is in both nonce and AAD.
  const Bytes block0 = slice(ciphertext, 0, kStride);
  CHECK(skiptest::code_of([&] {
          format::decrypt_block(drive_key, file_id, file_size, 2, ByteView(block0));
        }) == ErrorCode::AuthFailed);
}

TEST_CASE("block index and size are validated before touching the cipher") {
  const Key32 drive_key = crypto::random_key();
  const Id128 file_id = crypto::random_id();
  CHECK(skiptest::code_of([&] {
          format::decrypt_block(drive_key, file_id, 10, 1, ByteView(Bytes(26, 0)));
        }) == ErrorCode::BadBlockIndex);
  CHECK(skiptest::code_of([&] {
          format::decrypt_block(drive_key, file_id, 10, 0, ByteView(Bytes(4, 0)));
        }) == ErrorCode::SizeMismatch);
  CHECK(skiptest::code_of([&] {
          format::encrypt_block(drive_key, file_id, 10, 0, ByteView(Bytes(5, 'x')));
        }) == ErrorCode::SizeMismatch);
  CHECK(format::block_count(0) == 0);
  CHECK(format::block_count(format::kBlockPlaintextSize) == 1);
  CHECK(format::block_count(format::kBlockPlaintextSize + 1) == 2);
}

TEST_CASE("empty and exactly-one-block files round-trip") {
  const Key32 drive_key = crypto::random_key();
  const Id128 empty_id = crypto::random_id();
  CHECK(format::encrypt_file(drive_key, empty_id, ByteView(Bytes{})).empty());
  CHECK(format::decrypt_file(drive_key, empty_id, 0, ByteView(Bytes{})).empty());

  const Id128 full_id = crypto::random_id();
  const Bytes full = skiptest::pattern(format::kBlockPlaintextSize, 9);
  const Bytes sealed = format::encrypt_file(drive_key, full_id, ByteView(full));
  CHECK(sealed.size() == full.size() + format::kAeadTagSize);
  CHECK(format::decrypt_file(drive_key, full_id, full.size(), ByteView(sealed)) == full);
}

TEST_CASE("Ed25519 signatures") {
  const auto pair = crypto::SigningKeyPair::generate();
  const std::string message = "skipta pointer";
  const Sig64 sig = pair.sign(ByteView(message));
  CHECK(crypto::verify(pair.pub, ByteView(message), sig));

  const std::string changed = "skipta pointeR";
  CHECK_FALSE(crypto::verify(pair.pub, ByteView(changed), sig));

  const auto other = crypto::SigningKeyPair::generate();
  CHECK_FALSE(crypto::verify(other.pub, ByteView(message), sig));

  // Deterministic seeds give stable vectors.
  const auto seeded_a = crypto::SigningKeyPair::from_seed(skiptest::filled_key(0x42));
  const auto seeded_b = crypto::SigningKeyPair::from_seed(skiptest::filled_key(0x42));
  CHECK(seeded_a.pub == seeded_b.pub);
  CHECK(seeded_a.sign(ByteView(message)) == seeded_b.sign(ByteView(message)));
}

TEST_CASE("block framing counts blocks without overflow at any file size") {
  using format::block_count;
  CHECK(block_count(0) == 0);
  CHECK(block_count(1) == 1);
  CHECK(block_count(format::kBlockPlaintextSize) == 1);
  CHECK(block_count(format::kBlockPlaintextSize + 1) == 2);

  // The old `(size + block - 1) / block` wrapped here and under-counted.
  const std::uint64_t huge = std::numeric_limits<std::uint64_t>::max();
  const std::uint64_t count = block_count(huge);
  CHECK(count == huge / format::kBlockPlaintextSize + 1);
  CHECK(format::plaintext_block_len(huge, 0) == format::kBlockPlaintextSize);
  CHECK(format::plaintext_block_len(huge, count - 1) ==
        huge - (count - 1) * format::kBlockPlaintextSize);
  CHECK(skiptest::code_of([&] { format::plaintext_block_len(huge, count); }) ==
        ErrorCode::BadBlockIndex);
}

TEST_CASE("Argon2id is deterministic per salt and parameter-bounded") {
  const Id128 salt = skiptest::filled_id(0x77);
  const Key32 a = crypto::argon2id("passphrase", ByteView(salt), 2, 64u * 1024u * 1024u);
  const Key32 b = crypto::argon2id("passphrase", ByteView(salt), 2, 64u * 1024u * 1024u);
  CHECK(a == b);
  const Key32 c = crypto::argon2id("passphrase", ByteView(skiptest::filled_id(0x78)), 2,
                                   64u * 1024u * 1024u);
  CHECK_FALSE(a == c);

  CHECK(skiptest::code_of([&] {
          crypto::argon2id("x", ByteView(salt), 0, 64u * 1024u * 1024u);
        }) == ErrorCode::BadKdfParams);
  CHECK(skiptest::code_of([&] {
          crypto::argon2id("x", ByteView(Bytes{1, 2}), 2, 64u * 1024u * 1024u);
        }) == ErrorCode::BadKdfParams);
}
