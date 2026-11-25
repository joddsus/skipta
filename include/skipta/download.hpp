// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Resumable download of one file entry.
//
// Progress is kept beside the target as `<path>.skipta-resume`: how many bytes
// are on disk and the SHA-256 of exactly those bytes. Because blocks are written
// in order, that prefix is all the state a resume needs. The digest lets a later
// run verify the reused bytes locally before sending anything, so a truncated or
// modified partial file is never silently extended.
#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

#include "skipta/bytes.hpp"
#include "skipta/share.hpp"

namespace skipta {

struct DownloadOptions {
  /// Continue a partial file. Requires usable resume state next to it, unless
  /// the target is already complete: right size with no state, or state that
  /// covers every byte. Either way that is a no-op (`skipped`).
  bool resume = false;
  /// Discard any existing target and its state, then download from the start.
  /// Takes precedence over `resume`.
  bool overwrite = false;
  /// Bytes between resume-state updates while downloading. A crash repeats at
  /// most this much work.
  std::uint64_t checkpoint_bytes = 1u << 20;
  FetchOptions fetch{};
};

struct DownloadOutcome {
  std::uint64_t written_now = 0;  ///< bytes written by this call
  std::uint64_t reused = 0;       ///< bytes kept: verified prefix, or whole file when skipped
  std::uint64_t file_size = 0;    ///< entry size
  bool skipped = false;           ///< target was already complete; left untouched
};

/// Path of the resume state file for `target`.
std::filesystem::path resume_state_path(const std::filesystem::path& target);

/// Downloads `entry` into `target` block by block. Keeps resume state while the
/// file is incomplete and removes it once the file is complete and verified.
DownloadOutcome download_file(const FileStore& store, const ShareSession& session,
                              const Entry& entry, const std::filesystem::path& target,
                              const DownloadOptions& options = DownloadOptions{});

/// Downloads the byte range [offset, offset + length) of `entry` into `target`
/// and returns the number of plaintext bytes written. The range is clipped to
/// the file, so `kToEndOfFile` means "the rest". There is no resume state; the
/// whole range is fetched in one run. An existing target is refused unless
/// `overwrite` is set, and a symlink, device or directory is never written
/// through. A failed fetch removes the partial target.
std::uint64_t download_file_range(const FileStore& store, const ShareSession& session,
                                  const Entry& entry, std::uint64_t offset,
                                  std::uint64_t length, const std::filesystem::path& target,
                                  bool overwrite = false,
                                  const FetchOptions& options = FetchOptions{});

struct DirectoryProgress {
  std::string path;         ///< relative path inside the share, '/'-separated
  std::uint64_t size = 0;   ///< file size from the manifest
  std::uint64_t reused = 0; ///< bytes kept (whole file when skipped)
  std::uint64_t written = 0;
  bool skipped = false;     ///< already complete and left untouched
};

struct DirectoryOptions {
  DownloadOptions file{};
  /// Called once per file, in published order. Empty means no progress.
  std::function<void(const DirectoryProgress&)> on_file;
};

struct DirectoryOutcome {
  std::uint64_t files = 0;
  std::uint64_t directories = 0;  ///< subdirectories visited (and created)
  std::uint64_t skipped = 0;      ///< files that were already complete
  std::uint64_t resumed = 0;      ///< files continued from a partial download
  std::uint64_t written_now = 0;  ///< bytes fetched by this call
  std::uint64_t reused = 0;       ///< bytes kept from earlier runs
};

/// Downloads the directory at `relative_path` ("" is the share root) into
/// `target`, creating the tree. Files are handled depth-first in the order the
/// manifests publish them, so an interrupted run leaves a deterministic prefix.
/// With `options.file.resume` each file continues from its own resume state.
DirectoryOutcome download_directory(const FileStore& store, const ShareSession& session,
                                    std::string_view relative_path,
                                    const std::filesystem::path& target,
                                    const DirectoryOptions& options = DirectoryOptions{});

}  // namespace skipta
