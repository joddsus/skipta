// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/gc.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "skipta/drive.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/pointer.hpp"

namespace skipta {
namespace {

namespace fs = std::filesystem;

struct Reachable {
  std::set<std::string> manifests;  ///< hex manifest ids
  std::set<std::string> files;      ///< hex file ids (one block directory each)
};

struct Candidate {
  fs::path path;
  std::uint64_t size = 0;
};

bool is_manifest_name(const std::string& name) {
  return classify_stored_object_name(name) == StoredObjectName::Manifest;
}

bool is_file_id_name(const std::string& name) {
  return classify_stored_object_name(name) == StoredObjectName::FileDirectory;
}

bool is_block_name(const std::string& name) {
  return classify_stored_object_name(name) == StoredObjectName::Block;
}

void mark_manifest(const FileStore& store, const Key32& drive_key, const Id128& manifest_id,
                   Reachable* reachable, std::size_t depth) {
  // The publisher refuses deeper trees, so anything deeper is corrupt or hostile.
  if (depth > Limits{}.max_depth) {
    fail(ErrorCode::TooDeep, "manifest tree is deeper than the format allows: " +
                                 hex_encode(ByteView(manifest_id)));
  }
  const std::string name = hex_encode(ByteView(manifest_id));
  if (!reachable->manifests.insert(name).second) return;  // already walked

  const std::optional<Bytes> sealed = store.get_manifest(manifest_id);
  if (!sealed) {
    fail(ErrorCode::NotFound,
         "manifest " + name + " is named by a current pointer but missing from the store");
  }
  const Manifest manifest = open_manifest(drive_key, manifest_id, ByteView(*sealed));
  for (const Entry& entry : manifest.entries) {
    if (entry.kind == EntryKind::File) {
      reachable->files.insert(hex_encode(ByteView(entry.file_id)));
    } else {
      mark_manifest(store, drive_key, entry.manifest_id, reachable, depth + 1);
    }
  }
}

void add_manifest_candidates(const fs::path& directory, const Reachable& reachable,
                             std::vector<Candidate>* out, GcResult* result) {
  std::error_code ec;
  fs::directory_iterator it(directory, ec);
  if (ec) return;  // nothing was ever written there
  for (const auto& entry : it) {
    const std::string name = entry.path().filename().string();
    if (!is_manifest_name(name)) {
      ++result->ignored;
      continue;
    }
    if (reachable.manifests.count(name.substr(0, 32)) != 0) continue;

    std::error_code sec;
    const fs::file_status status = fs::symlink_status(entry.path(), sec);
    if (sec || !fs::is_regular_file(status)) {
      ++result->ignored;  // never open, follow or delete a link or a directory here
      continue;
    }
    const std::uintmax_t size = fs::file_size(entry.path(), sec);
    if (sec) fail(ErrorCode::StoreIo, "cannot size " + entry.path().string());
    out->push_back({entry.path(), static_cast<std::uint64_t>(size)});
  }
}

void add_block_candidates(const fs::path& directory, const Reachable& reachable,
                          std::vector<Candidate>* out, std::vector<fs::path>* emptied,
                          GcResult* result) {
  std::error_code ec;
  fs::directory_iterator it(directory, ec);
  if (ec) return;
  for (const auto& entry : it) {
    const std::string name = entry.path().filename().string();
    if (!is_file_id_name(name)) {
      ++result->ignored;
      continue;
    }
    std::error_code sec;
    const fs::file_status status = fs::symlink_status(entry.path(), sec);
    if (sec || !fs::is_directory(status)) {
      ++result->ignored;  // a symlink named like a file id is not followed
      continue;
    }
    if (reachable.files.count(name) != 0) continue;

    std::error_code iec;
    fs::directory_iterator inner(entry.path(), iec);
    if (iec) fail(ErrorCode::StoreIo, "cannot read " + entry.path().string());
    for (const auto& block : inner) {
      const std::string block_name = block.path().filename().string();
      if (!is_block_name(block_name)) {
        ++result->ignored;
        continue;
      }
      std::error_code bec;
      const fs::file_status block_status = fs::symlink_status(block.path(), bec);
      if (bec || !fs::is_regular_file(block_status)) {
        ++result->ignored;
        continue;
      }
      const std::uintmax_t size = fs::file_size(block.path(), bec);
      if (bec) fail(ErrorCode::StoreIo, "cannot size " + block.path().string());
      out->push_back({block.path(), static_cast<std::uint64_t>(size)});
    }
    // Removed only if the directory is empty afterwards; an ignored entry keeps
    // it and its contents untouched.
    emptied->push_back(entry.path());
  }
}

void remove_object(const Candidate& candidate, std::uint64_t* removed_bytes) {
  std::error_code ec;
  fs::remove(candidate.path, ec);
  if (ec) {
    fail(ErrorCode::StoreIo,
         "cannot remove " + candidate.path.string() + ": " + ec.message());
  }
  *removed_bytes += candidate.size;
}

}  // namespace

GcResult collect_garbage(const FileStore& store, const std::vector<DriveIdentity>& drives,
                         bool apply) {
  // Serialise with publish: gc deletes everything the current pointers do not
  // name, and a publish writes objects before it writes the pointer that names
  // them. Running at the same time would collect that publish's fresh blocks.
  const StoreLock lock(store.root());
  GcResult result;
  result.drives = drives.size();

  std::set<std::string> known;
  for (const DriveIdentity& identity : drives) {
    known.insert(hex_encode(ByteView(identity.public_key())));
  }
  std::set<std::string> stored;
  for (const PubKey32& drive : store.pointer_drives()) {
    stored.insert(hex_encode(ByteView(drive)));
  }
  if (known != stored) {
    for (const std::string& name : stored) {
      if (known.count(name) != 0) continue;
      fail(ErrorCode::UnsafeStore,
           "refusing to collect garbage: the store has a drive " + name +
               " with no identity file in " + (store.root() / "identities").string() +
               ", so its objects cannot be told apart from garbage. Nothing was deleted");
    }
    for (const std::string& name : known) {
      if (stored.count(name) != 0) continue;
      fail(ErrorCode::UnsafeStore,
           "refusing to collect garbage: an identity names drive " + name +
               " but the store has no root pointer for it (an interrupted first publish?). "
               "Publish that folder again, or remove the stale identity and its objects. "
               "Nothing was deleted");
    }
    fail(ErrorCode::UnsafeStore, "refusing to collect garbage: drive set mismatch");
  }

  // Walk first: every current object is authenticated before anything is
  // deleted, so a corrupt store fails without losing the remainder.
  Reachable reachable;
  for (const DriveIdentity& identity : drives) {
    const PubKey32& drive = identity.public_key();
    const std::optional<Bytes> raw = store.get_pointer(drive);
    if (!raw) {
      fail(ErrorCode::NotFound, "root pointer for drive " + hex_encode(ByteView(drive)) +
                                    " vanished during garbage collection");
    }
    const SignedPointer signed_pointer = decode_signed_pointer(ByteView(*raw));
    const RootPointer pointer = verify_pointer(drive, signed_pointer, 0);
    mark_manifest(store, identity.drive_key, pointer.root, &reachable, 1);
  }
  result.reachable_manifests = reachable.manifests.size();
  result.reachable_files = reachable.files.size();

  std::vector<Candidate> manifests;
  std::vector<Candidate> blocks;
  std::vector<fs::path> block_dirs;
  add_manifest_candidates(store.root() / "manifests", reachable, &manifests, &result);
  add_block_candidates(store.root() / "blocks", reachable, &blocks, &block_dirs, &result);
  result.removable_manifests = manifests.size();
  result.removable_blocks = blocks.size();
  for (const Candidate& candidate : manifests) result.removable_bytes += candidate.size;
  for (const Candidate& candidate : blocks) result.removable_bytes += candidate.size;

  if (!apply) return result;

  for (const Candidate& candidate : manifests) {
    remove_object(candidate, &result.removed_bytes);
    ++result.removed_manifests;
  }
  for (const Candidate& candidate : blocks) {
    remove_object(candidate, &result.removed_bytes);
    ++result.removed_blocks;
  }
  for (const fs::path& directory : block_dirs) {
    std::error_code ec;
    fs::remove(directory, ec);  // empty only; leftovers are kept
  }
  return result;
}

}  // namespace skipta
