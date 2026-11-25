// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Publisher-side facade: one drive = one key + one signing identity.
// Read-side helpers are free functions so a reader only needs what a link gives
// it (drive key + drive public key), never a local secret.
#pragma once

#include <string>
#include <vector>

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/format.hpp"
#include "skipta/link.hpp"
#include "skipta/manifest.hpp"
#include "skipta/pointer.hpp"

namespace skipta {

class Drive {
 public:
  static Drive create();
  Drive(Key32 drive_key, crypto::SigningKeyPair signing);

  const PubKey32& public_key() const noexcept { return signing_.pub; }
  const Key32& drive_key() const noexcept { return drive_key_; }

  Manifest new_manifest(std::uint64_t seq) const;
  Bytes seal_manifest(const Manifest& manifest, const Limits& limits = Limits{}) const;
  RootPointer root_pointer(const Manifest& root, std::uint64_t issued_at) const;
  SignedPointer sign_root(const RootPointer& pointer) const;
  ShareLink share_link(std::vector<std::string> bootstrap = {}) const;

 private:
  Key32 drive_key_{};
  crypto::SigningKeyPair signing_{};
};

/// Decrypts and validates a fetched directory manifest.
Manifest open_manifest(const Key32& drive_key, const Id128& manifest_id, ByteView sealed,
                       const Limits& limits = Limits{});

/// Lists a directory from fetched ciphertext, verifying every entry.
std::vector<Entry> list_directory(const Key32& drive_key, const Id128& manifest_id,
                                  ByteView sealed, const Limits& limits = Limits{});

}  // namespace skipta
