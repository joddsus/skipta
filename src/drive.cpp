// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/drive.hpp"

#include <algorithm>
#include <utility>

#include "skipta/error.hpp"

namespace skipta {

Drive Drive::create() { return Drive(crypto::random_key(), crypto::SigningKeyPair::generate()); }

Drive::Drive(Key32 drive_key, crypto::SigningKeyPair signing)
    : drive_key_(drive_key), signing_(std::move(signing)) {}

Manifest Drive::new_manifest(std::uint64_t seq) const { return Manifest::create(seq); }

Bytes Drive::seal_manifest(const Manifest& manifest, const Limits& limits) const {
  const Bytes plaintext = manifest.serialize(limits);
  Key32 manifest_key = format::derive_manifest_key(drive_key_, manifest.id);
  const auto nonce = format::manifest_nonce(manifest.id);
  const Bytes aad = format::manifest_aad(manifest.id);
  Bytes sealed = crypto::aead_seal(manifest_key, ByteView(nonce), ByteView(aad),
                                   ByteView(plaintext));
  crypto::wipe(manifest_key.data(), manifest_key.size());
  // Metadata (names, sizes) must not linger in heap memory any longer than needed.
  Bytes mutable_plain = plaintext;
  crypto::wipe(mutable_plain.data(), mutable_plain.size());
  return sealed;
}

RootPointer Drive::root_pointer(const Manifest& root, std::uint64_t issued_at) const {
  RootPointer pointer;
  pointer.version = format::kVersion;
  pointer.drive = signing_.pub;
  pointer.seq = root.seq;
  pointer.root = root.id;
  pointer.issued_at = issued_at;
  return pointer;
}

SignedPointer Drive::sign_root(const RootPointer& pointer) const {
  return sign_pointer(signing_, pointer);
}

ShareLink Drive::share_link(std::vector<std::string> bootstrap) const {
  ShareLink link;
  link.version = format::kVersion;
  link.drive = signing_.pub;
  link.key = drive_key_;
  link.bootstrap = std::move(bootstrap);
  return link;
}

Manifest open_manifest(const Key32& drive_key, const Id128& manifest_id, ByteView sealed,
                       const Limits& limits) {
  if (is_zero(ByteView(manifest_id))) {
    fail(ErrorCode::ZeroId, "manifest id must not be all zero");
  }
  if (sealed.size > limits.max_manifest_bytes + format::kAeadTagSize) {
    fail(ErrorCode::TooLarge, "sealed manifest larger than the configured limit");
  }
  Key32 manifest_key = format::derive_manifest_key(drive_key, manifest_id);
  const auto nonce = format::manifest_nonce(manifest_id);
  const Bytes aad = format::manifest_aad(manifest_id);
  Bytes plaintext;
  try {
    plaintext = crypto::aead_open(manifest_key, ByteView(nonce), ByteView(aad), sealed);
  } catch (const Error&) {
    crypto::wipe(manifest_key.data(), manifest_key.size());
    throw;
  }
  crypto::wipe(manifest_key.data(), manifest_key.size());
  Manifest manifest = Manifest::parse(ByteView(plaintext), limits);
  crypto::wipe(plaintext.data(), plaintext.size());
  if (!constant_time_equal(ByteView(manifest.id), ByteView(manifest_id))) {
    fail(ErrorCode::SizeMismatch, "sealed manifest does not match the requested id");
  }
  return manifest;
}

std::vector<Entry> list_directory(const Key32& drive_key, const Id128& manifest_id,
                                  ByteView sealed, const Limits& limits) {
  return open_manifest(drive_key, manifest_id, sealed, limits).entries;
}

}  // namespace skipta
