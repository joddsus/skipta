// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/format.hpp"

#include <algorithm>
#include <cstring>

#include "skipta/error.hpp"

namespace skipta::format {
namespace {

void put_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
  }
}

Bytes tagged(std::string_view tag, const Id128& id) {
  Bytes out;
  out.reserve(tag.size() + id.size());
  out.insert(out.end(), tag.begin(), tag.end());
  out.insert(out.end(), id.begin(), id.end());
  return out;
}

}  // namespace

Key32 derive_file_key(const Key32& drive_key, const Id128& file_id) {
  return crypto::blake2b256_keyed(ByteView(drive_key), ByteView(tagged(kFileKeyTag, file_id)));
}

Key32 derive_manifest_key(const Key32& drive_key, const Id128& manifest_id) {
  return crypto::blake2b256_keyed(ByteView(drive_key),
                                  ByteView(tagged(kManifestKeyTag, manifest_id)));
}

std::array<unsigned char, kNonceSize> block_nonce(const Id128& file_id, std::uint64_t index) {
  std::array<unsigned char, kNonceSize> nonce{};
  std::copy(file_id.begin(), file_id.end(), nonce.begin());
  for (int i = 0; i < 8; ++i) {
    nonce[kNonceSize - 1 - i] = static_cast<unsigned char>((index >> (8 * i)) & 0xff);
  }
  return nonce;
}

std::array<unsigned char, kNonceSize> manifest_nonce(const Id128& manifest_id) {
  std::array<unsigned char, kNonceSize> nonce{};
  std::copy(manifest_id.begin(), manifest_id.end(), nonce.begin());
  // The remaining 8 bytes stay zero: exactly one sealed blob per manifest id.
  return nonce;
}

Bytes block_aad(const Id128& file_id, std::uint64_t index, std::uint64_t file_size) {
  Bytes aad;
  aad.reserve(kBlockAadTag.size() + file_id.size() + 16);
  aad.insert(aad.end(), kBlockAadTag.begin(), kBlockAadTag.end());
  aad.insert(aad.end(), file_id.begin(), file_id.end());
  put_u64(aad, index);
  put_u64(aad, file_size);
  return aad;
}

Bytes manifest_aad(const Id128& manifest_id) { return tagged(kManifestAadTag, manifest_id); }

std::uint64_t block_count(std::uint64_t file_size) {
  // Divide first: `file_size + kBlockPlaintextSize - 1` overflows for values
  // near UINT64_MAX, which would under-count blocks in the framing helpers.
  const std::uint64_t full = file_size / kBlockPlaintextSize;
  const std::uint64_t remainder = file_size % kBlockPlaintextSize;
  return full + (remainder == 0 ? 0 : 1);
}

std::size_t plaintext_block_len(std::uint64_t file_size, std::uint64_t index) {
  if (index >= block_count(file_size)) {
    fail(ErrorCode::BadBlockIndex, "block index " + std::to_string(index) +
                                       " is outside a file of " + std::to_string(file_size) +
                                       " bytes");
  }
  const std::uint64_t start = index * static_cast<std::uint64_t>(kBlockPlaintextSize);
  return static_cast<std::size_t>(std::min<std::uint64_t>(kBlockPlaintextSize, file_size - start));
}

Bytes encrypt_block(const Key32& drive_key, const Id128& file_id, std::uint64_t file_size,
                    std::uint64_t index, ByteView plaintext) {
  const std::size_t expected = plaintext_block_len(file_size, index);
  if (plaintext.size != expected) {
    fail(ErrorCode::SizeMismatch, "block " + std::to_string(index) + " must be " +
                                      std::to_string(expected) + " plaintext bytes");
  }
  Key32 file_key = derive_file_key(drive_key, file_id);
  const auto nonce = block_nonce(file_id, index);
  const Bytes aad = block_aad(file_id, index, file_size);
  Bytes sealed = crypto::aead_seal(file_key, ByteView(nonce), ByteView(aad), plaintext);
  crypto::wipe(file_key.data(), file_key.size());
  return sealed;
}

Bytes decrypt_block(const Key32& drive_key, const Id128& file_id, std::uint64_t file_size,
                    std::uint64_t index, ByteView ciphertext) {
  const std::size_t expected = plaintext_block_len(file_size, index);
  if (ciphertext.size != expected + kAeadTagSize) {
    fail(ErrorCode::SizeMismatch,
         "block " + std::to_string(index) + " must be " +
             std::to_string(expected + kAeadTagSize) + " ciphertext bytes, got " +
             std::to_string(ciphertext.size));
  }
  Key32 file_key = derive_file_key(drive_key, file_id);
  const auto nonce = block_nonce(file_id, index);
  const Bytes aad = block_aad(file_id, index, file_size);
  Bytes plain;
  try {
    plain = crypto::aead_open(file_key, ByteView(nonce), ByteView(aad), ciphertext);
  } catch (const Error&) {
    crypto::wipe(file_key.data(), file_key.size());
    throw;
  }
  crypto::wipe(file_key.data(), file_key.size());
  return plain;
}

Bytes encrypt_file(const Key32& drive_key, const Id128& file_id, ByteView plaintext) {
  Bytes out;
  const std::uint64_t size = plaintext.size;
  out.reserve(plaintext.size + static_cast<std::size_t>(block_count(size)) * kAeadTagSize);
  for (std::uint64_t index = 0; index < block_count(size); ++index) {
    const std::size_t length = plaintext_block_len(size, index);
    const std::size_t offset = static_cast<std::size_t>(index) * kBlockPlaintextSize;
    Bytes block = encrypt_block(drive_key, file_id, size, index,
                                ByteView(plaintext.data + offset, length));
    out.insert(out.end(), block.begin(), block.end());
  }
  return out;
}

Bytes decrypt_file(const Key32& drive_key, const Id128& file_id, std::uint64_t file_size,
                   ByteView ciphertext) {
  const std::uint64_t count = block_count(file_size);
  const std::uint64_t expected_total =
      file_size + static_cast<std::uint64_t>(count) * kAeadTagSize;
  if (ciphertext.size != expected_total) {
    fail(ErrorCode::SizeMismatch, "file ciphertext must be " + std::to_string(expected_total) +
                                      " bytes, got " + std::to_string(ciphertext.size));
  }
  Bytes out;
  out.reserve(file_size);
  std::size_t offset = 0;
  for (std::uint64_t index = 0; index < count; ++index) {
    const std::size_t length = plaintext_block_len(file_size, index);
    const std::size_t sealed_len = length + kAeadTagSize;
    Bytes block = decrypt_block(drive_key, file_id, file_size, index,
                                ByteView(ciphertext.data + offset, sealed_len));
    out.insert(out.end(), block.begin(), block.end());
    offset += sealed_len;
  }
  return out;
}

}  // namespace skipta::format
