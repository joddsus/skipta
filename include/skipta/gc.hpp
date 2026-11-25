// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Store housekeeping: remove sealed manifests and blocks that no current root
// pointer reaches. A republish writes a new tree and pointer, and a file removed
// from the folder is gone from the new manifest, but its old ciphertext stays in
// the store forever. That ciphertext is still decryptable by anyone holding the
// link, so leaving it is both a growth problem and a privacy problem.
//
// Collection is deliberately conservative: it works only from current pointers,
// and refuses unless the caller supplies an identity for every drive in the
// store. Anything it cannot account for stays.
#pragma once

#include <cstdint>
#include <vector>

#include "skipta/identity.hpp"
#include "skipta/store.hpp"

namespace skipta {

struct GcResult {
  std::uint64_t drives = 0;
  std::uint64_t reachable_manifests = 0;
  std::uint64_t reachable_files = 0;  ///< file ids: one block directory each
  std::uint64_t removable_manifests = 0;
  std::uint64_t removable_blocks = 0;
  std::uint64_t removable_bytes = 0;
  std::uint64_t removed_manifests = 0;
  std::uint64_t removed_blocks = 0;
  std::uint64_t removed_bytes = 0;
  std::uint64_t ignored = 0;  ///< entries that are not objects this tool wrote
};

/// Walks the current root pointer of every drive in `drives`, marks every
/// manifest and block directory it reaches, and removes (or with `apply ==
/// false` only reports) every manifest and block directory that nothing
/// reaches.
///
/// `drives` must contain exactly one identity for every stored pointer and no
/// others. The pointer set is compared first; a mismatch is UnsafeStore and
/// nothing is touched, because objects of a drive that was not walked would
/// otherwise look like garbage. A missing or unauthenticated current object is
/// also an error before any deletion. The store lock is held throughout, so a
/// concurrent publish cannot have its not-yet-referenced blocks collected.
///
/// Only files and directories named exactly like store objects are considered;
/// symlinks and unknown entries are counted as `ignored` and left alone. A
/// reader that is still downloading a superseded pointer can lose access to the
/// collected objects, so call this when no download is in progress.
GcResult collect_garbage(const FileStore& store, const std::vector<DriveIdentity>& drives,
                         bool apply);

}  // namespace skipta
