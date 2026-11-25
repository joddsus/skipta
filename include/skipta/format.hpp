// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Format v1: the single place where key derivation, nonce construction and
// associated data are defined. Nothing else in the codebase may build a nonce
// or an AAD by hand.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"

namespace skipta::format {

inline constexpr std::uint64_t kVersion = 1;

/// Fixed plaintext block size. Random access and streaming depend on it.
inline constexpr std::size_t kBlockPlaintextSize = 64 * 1024;
inline constexpr std::size_t kAeadTagSize = 16;
inline constexpr std::size_t kNonceSize = 24;

/// Links are short enough to paste into chat; longer input is rejected unparsed.
inline constexpr std::size_t kMaxLinkChars = 4096;

inline constexpr std::string_view kScheme = "skipta://v1/";

// Domain separation tags. Changing any of these is a new format version.
inline constexpr std::string_view kFileKeyTag = "skipta/v1/file-key";
inline constexpr std::string_view kManifestKeyTag = "skipta/v1/manifest-key";
inline constexpr std::string_view kBlockAadTag = "skipta/v1/block";
inline constexpr std::string_view kManifestAadTag = "skipta/v1/manifest";
inline constexpr std::string_view kSwarmSaltTag = "skipta/v1/swarm-salt";
inline constexpr std::string_view kSwarmIdTag = "skipta/v1/swarm";
inline constexpr std::string_view kKeyWrapTag = "skipta/v1/keywrap";

/// file_key = BLAKE2b-256(key=drive_key, "skipta/v1/file-key" || file_id)
/// A new content version MUST get a new random file_id.
Key32 derive_file_key(const Key32& drive_key, const Id128& file_id);

/// manifest_key = BLAKE2b-256(key=drive_key, "skipta/v1/manifest-key" || manifest_id)
Key32 derive_manifest_key(const Key32& drive_key, const Id128& manifest_id);

/// nonce = file_id (16 bytes) || block_index (8 bytes, big endian)
/// Uniqueness follows from file_id uniqueness per content version.
std::array<unsigned char, kNonceSize> block_nonce(const Id128& file_id, std::uint64_t index);

/// nonce = manifest_id (16 bytes) || 8 zero bytes. Exactly one sealed blob per
/// manifest id, so the counter bytes are never reused.
std::array<unsigned char, kNonceSize> manifest_nonce(const Id128& manifest_id);

/// magic || file_id || block_index || file_size, all fixed width.
Bytes block_aad(const Id128& file_id, std::uint64_t index, std::uint64_t file_size);

/// magic || manifest_id
Bytes manifest_aad(const Id128& manifest_id);

std::uint64_t block_count(std::uint64_t file_size);

/// Plaintext length of block `index`; throws BadBlockIndex if out of range.
std::size_t plaintext_block_len(std::uint64_t file_size, std::uint64_t index);

Bytes encrypt_block(const Key32& drive_key, const Id128& file_id, std::uint64_t file_size,
                    std::uint64_t index, ByteView plaintext);

Bytes decrypt_block(const Key32& drive_key, const Id128& file_id, std::uint64_t file_size,
                    std::uint64_t index, ByteView ciphertext);

/// Convenience only; the real path encrypts and fetches block by block.
Bytes encrypt_file(const Key32& drive_key, const Id128& file_id, ByteView plaintext);
Bytes decrypt_file(const Key32& drive_key, const Id128& file_id, std::uint64_t file_size,
                   ByteView ciphertext);

}  // namespace skipta::format
