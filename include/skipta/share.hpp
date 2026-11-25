// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase 3 data path: publish a directory as one drive into a blob store, then
// open a link and browse/fetch from it. No networking: the store is a local
// stand-in for the swarm, and swapping it for a real transport later must not
// change anything above this API.
#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "skipta/drive.hpp"
#include "skipta/manifest.hpp"
#include "skipta/pointer.hpp"
#include "skipta/store.hpp"

namespace skipta {

struct PublishResult {
  std::string link;
  PubKey32 drive{};
  std::uint64_t seq = 0;  ///< seq of the published pointer
  std::uint64_t files = 0;
  std::uint64_t directories = 0;  ///< subdirectories, not counting the root
  std::uint64_t bytes = 0;
  std::vector<std::string> skipped;  ///< symlinks and other non-regular entries
};

struct PublishOptions {
  Limits limits{};
  std::uint64_t issued_at = 0;  ///< 0 means "now"
  /// Reuse an existing drive (and therefore the same link) instead of minting a
  /// new one. Null means a brand-new drive; see DriveIdentity.
  const Drive* identity = nullptr;
  /// Sequence number of the signed pointer. Must increase on every publish of
  /// the same drive: readers refuse a pointer older than the last they accepted.
  std::uint64_t seq = 1;
};

/// Encrypts a directory tree, writes sealed blobs and the signed root pointer,
/// and returns the share link. Without `options.identity` each call mints a new
/// drive; with a stored identity it updates that drive in place, keeping the
/// link stable while `options.seq` advances.
PublishResult publish_directory(const std::filesystem::path& source, FileStore& store,
                                const PublishOptions& options = PublishOptions{});

struct ShareSession {
  ShareLink link{};
  RootPointer pointer{};
  Manifest root{};
};

/// Decodes the link, loads and verifies the signed pointer, opens the root
/// manifest. `min_seq` is the highest seq this node already accepted for the
/// drive; a pointer at or below it is refused as StalePointer (rollback guard).
ShareSession open_share(const FileStore& store, std::string_view link_text,
                        std::uint64_t min_seq = 0);

/// Highest pointer seq this node has accepted for `drive`, 0 if none. Recorded
/// beside the blobs in `<store>/accepted`; unreadable state counts as none.
std::uint64_t accepted_pointer_seq(const FileStore& store, const PubKey32& drive);

/// Remembers an accepted seq, never lowering the recorded value.
void remember_pointer_seq(const FileStore& store, const PubKey32& drive, std::uint64_t seq);

/// Resolves a relative path inside the share. Returns nullopt if any component is
/// missing or is not a directory on the way down.
std::optional<Entry> resolve_path(const FileStore& store, const ShareSession& session,
                                  std::string_view relative_path);

/// Entries of the directory at `relative_path` ("" lists the root).
std::vector<Entry> list_path(const FileStore& store, const ShareSession& session,
                             std::string_view relative_path);

/// Returns the decrypted plaintext of one block. This is the seam a real
/// transport plugs into: today it reads a blob from the store.
using BlockFetcher = std::function<Bytes(std::uint64_t block_index)>;

struct FetchOptions {
  /// Blocks fetched concurrently; also the prefetch depth, because the reader
  /// keeps the pipeline full. This is the hard bound on blocks held in memory.
  /// 1 = strictly serial, no threads.
  std::size_t max_in_flight = 4;

  /// Attempts per block, including the first one. A transient store or transport
  /// error (NotFound, StoreIo) is retried; bad signatures and malformed data are
  /// not, because asking again cannot change them. 1 disables retrying.
  std::size_t max_attempts = 3;

  /// Wait before the first retry; doubles for each further attempt.
  std::chrono::microseconds backoff{25000};
};

inline constexpr std::uint64_t kToEndOfFile = static_cast<std::uint64_t>(-1);

/// Fetches a byte range, writing blocks in ascending order no matter in which
/// order they arrive. Reads only blocks overlapping the range; `length` is
/// clamped to what remains in the file, so `kToEndOfFile` means "the rest".
std::uint64_t fetch_file_range(const FileStore& store, const ShareSession& session,
                               const Entry& entry, std::uint64_t offset, std::uint64_t length,
                               std::ostream& sink, const FetchOptions& options = FetchOptions{});

/// Same pipeline over an arbitrary block source, for transports and tests.
std::uint64_t fetch_blocks(const Entry& entry, std::uint64_t offset, std::uint64_t length,
                           const BlockFetcher& fetch, std::ostream& sink,
                           const FetchOptions& options = FetchOptions{});

/// Streams a whole file. Returns the number of plaintext bytes written.
std::uint64_t fetch_file(const FileStore& store, const ShareSession& session, const Entry& entry,
                         std::ostream& sink, const FetchOptions& options = FetchOptions{});

struct VerifyResult {
  std::uint64_t files = 0;
  std::uint64_t directories = 0;  ///< subdirectories below the verified path
  std::uint64_t blocks = 0;
  std::uint64_t bytes = 0;
};

/// Decrypts every manifest and every block below `relative_path` ("" is the
/// whole share), checking that each authenticates and every file is exactly the
/// size its manifest promises. Throws on the first failure, so a store copy can
/// be trusted only when this returns. Reads all content, so it costs one full
/// pass over the share.
VerifyResult verify_path(const FileStore& store, const ShareSession& session,
                         std::string_view relative_path = "",
                         const FetchOptions& options = FetchOptions{});

}  // namespace skipta
