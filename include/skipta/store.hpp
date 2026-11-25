// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A local, content-addressed blob store: the phase 3 stand-in for the swarm.
// It holds exactly the opaque pieces a peer would exchange — sealed manifests,
// sealed blocks and signed root pointers — and never plaintext or keys.
//
// Layout under root:
//   .lock                                advisory lock for publish/gc
//   pointers/<drive pubkey hex>.ptr      signed root pointer (opaque bytes)
//   manifests/<manifest id hex>.mf       sealed directory manifest
//   blocks/<file id hex>/<index>.blk     one sealed block
//
// Writes go to a sibling temp file and are renamed into place, so an interrupted
// publish cannot leave a torn blob under a final name. Reads are capped at the
// format's maximum object sizes and refuse non-regular files, so a corrupt or
// hostile store cannot make the reader allocate without bound.
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "skipta/bytes.hpp"

namespace skipta {

/// Exclusive, non-blocking advisory lock on a store root. `publish` and `gc`
/// take it so their object sets cannot interleave: gc deletes everything no
/// current pointer references, which must not overlap objects being committed.
/// A second holder fails with StoreBusy rather than waiting. Platforms without
/// flock() get no locking (the Windows build has no passphrase prompt either).
class StoreLock {
 public:
  explicit StoreLock(const std::filesystem::path& store_root);
  ~StoreLock();
  StoreLock(const StoreLock&) = delete;
  StoreLock& operator=(const StoreLock&) = delete;

 private:
  int fd_ = -1;
};

/// What a filename found inside a store directory claims to be. Nothing is
/// opened or trusted: names are matched against the exact shapes this tool
/// writes, using lowercase hex only. Everything else is Other.
enum class StoredObjectName { Pointer, Manifest, FileDirectory, Block, Other };
StoredObjectName classify_stored_object_name(std::string_view name);

class FileStore {
 public:
  /// A local store, or a local cache backed by a read-only HTTP store. With a
  /// `remote_origin` (http://host:port[/prefix]), a missing object is fetched
  /// from the origin, written into `root` and returned; objects already cached
  /// are used without touching the network. Object bytes are still authenticated
  /// by the caller, so a hostile origin cannot forge content. A remote store is
  /// read-only: put_* refuses.
  explicit FileStore(std::filesystem::path root, std::string remote_origin = {});

  const std::filesystem::path& root() const noexcept { return root_; }
  const std::string& remote_origin() const noexcept { return remote_origin_; }
  bool is_remote() const noexcept { return !remote_origin_.empty(); }

  /// Writes the pointer durably (flushed before the rename): it is the commit
  /// point of a publish. Missing means the drive is unknown.
  /// Creates `root/relative` as owner-only directories, refusing a symlink or
  /// non-directory in any existing component below the store root. Store
  /// writes must not be redirected outside the store by a hostile copy.
  void ensure_writable_directory(const std::filesystem::path& relative) const;

  void put_pointer(const PubKey32& drive, ByteView signed_pointer);
  std::optional<Bytes> get_pointer(const PubKey32& drive) const;

  /// Every drive with a stored root pointer, sorted. Used by gc to check that
  /// it knows every drive in the store before deleting anything.
  std::vector<PubKey32> pointer_drives() const;

  void put_manifest(const Id128& manifest_id, ByteView sealed_manifest);
  std::optional<Bytes> get_manifest(const Id128& manifest_id) const;

  void put_block(const Id128& file_id, std::uint64_t index, ByteView sealed_block);
  std::optional<Bytes> get_block(const Id128& file_id, std::uint64_t index) const;

 private:
  std::optional<Bytes> get_object(const std::filesystem::path& relative, std::size_t cap,
                                  const char* what) const;

  std::filesystem::path root_;
  std::string remote_origin_;
};

}  // namespace skipta
