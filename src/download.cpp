// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/download.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <functional>
#include <optional>
#include <ostream>
#include <sstream>
#include <streambuf>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/json.hpp"

namespace skipta {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxStateBytes = 4096;

struct ResumeState {
  Id128 file_id{};
  std::uint64_t size = 0;
  std::uint64_t written = 0;
  std::array<unsigned char, 32> digest{};
};

fs::path state_path_for(const fs::path& target) {
  return fs::path(target.string() + ".skipta-resume");
}

/// Any unreadable or malformed state is reported as "none": the caller then
/// refuses to resume instead of guessing. Only a small regular file is read, so
/// a planted directory, device or huge file cannot stall or exhaust the reader.
std::optional<ResumeState> read_state(const fs::path& path) {
  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) return std::nullopt;
  const std::uintmax_t size = fs::file_size(path, ec);
  if (ec || size > kMaxStateBytes) return std::nullopt;
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  std::string text(static_cast<std::size_t>(size), '\0');
  if (!text.empty()) {
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (static_cast<std::size_t>(in.gcount()) != text.size()) return std::nullopt;
  }
  // parse_strict enforces the size cap, duplicate keys and unknown fields; any
  // rejection below becomes "no usable state".
  try {
    auto j = jsonx::parse_strict(text, kMaxStateBytes, "resume state");
    jsonx::require_object(j, "resume state");
    jsonx::reject_unknown(j, {"v", "file_id", "size", "written", "sha256"}, "resume state");
    if (jsonx::req_uint(j, "v", "resume state") != format::kVersion) return std::nullopt;

    ResumeState state;
    const Bytes id = jsonx::req_b64(j, "file_id", 16, "resume state");
    std::copy(id.begin(), id.end(), state.file_id.begin());
    state.size = jsonx::req_uint(j, "size", "resume state");
    state.written = jsonx::req_uint(j, "written", "resume state");
    const Bytes digest = jsonx::req_b64(j, "sha256", 32, "resume state");
    std::copy(digest.begin(), digest.end(), state.digest.begin());
    return state;
  } catch (const Error&) {
    return std::nullopt;
  }
}

void write_state(const fs::path& path, const ResumeState& state) {
  jsonx::Json j;
  j["v"] = format::kVersion;
  j["file_id"] = base64url_encode(ByteView(state.file_id));
  j["size"] = state.size;
  j["written"] = state.written;
  j["sha256"] = base64url_encode(ByteView(state.digest));
  const Bytes text = to_bytes(jsonx::dump(j, "resume state"));

  const fs::path temp = fs::path(path.string() + ".tmp");
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) fail(ErrorCode::StoreIo, "cannot write " + temp.string());
    out.write(reinterpret_cast<const char*>(text.data()),
              static_cast<std::streamsize>(text.size()));
    if (!out) fail(ErrorCode::StoreIo, "short write to " + temp.string());
  }
  std::error_code ec;
  fs::rename(temp, path, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot replace " + path.string());
}

/// Feeds the first `bytes` of `file` into `hasher` and returns the digest.
std::array<unsigned char, 32> hash_prefix(const fs::path& file, std::uint64_t bytes,
                                         crypto::Sha256& hasher) {
  std::ifstream in(file, std::ios::binary);
  if (!in) fail(ErrorCode::StoreIo, "cannot read " + file.string());
  Bytes buffer(format::kBlockPlaintextSize);
  std::uint64_t remaining = bytes;
  while (remaining > 0) {
    const std::size_t want =
        static_cast<std::size_t>(std::min<std::uint64_t>(buffer.size(), remaining));
    in.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(want));
    if (static_cast<std::size_t>(in.gcount()) != want) {
      fail(ErrorCode::BadResumeState, "partial file ended early: " + file.string());
    }
    hasher.update(ByteView(buffer.data(), want));
    remaining -= want;
  }
  return hasher.digest();
}

/// Writes to the target, hashes what it wrote, and records resumable progress.
/// Resume points are block boundaries only, and the block pipeline emits whole
/// blocks, so `xsputn` calls line up with them.
class DownloadSink : public std::streambuf {
 public:
  DownloadSink(std::ofstream& file, crypto::Sha256& hasher, std::uint64_t base,
               std::uint64_t total_size, std::uint64_t interval,
               std::function<void(std::uint64_t)> checkpoint)
      : file_(file),
        hasher_(hasher),
        base_(base),
        total_size_(total_size),
        interval_(interval),
        checkpoint_(std::move(checkpoint)) {}

  std::uint64_t written() const { return base_ + written_; }

  /// Records progress now; used when a fetch fails part-way so the work done so
  /// far is not lost.
  void checkpoint_now() {
    file_.flush();
    checkpoint_(written());
    last_checkpoint_ = written();
  }

 protected:
  std::streamsize xsputn(const char* data, std::streamsize count) override {
    if (count <= 0) return 0;
    file_.write(data, count);
    if (!file_) return 0;
    hasher_.update(ByteView(reinterpret_cast<const unsigned char*>(data),
                            static_cast<std::size_t>(count)));
    written_ += static_cast<std::uint64_t>(count);
    const std::uint64_t total = written();
    const bool block_boundary = total % format::kBlockPlaintextSize == 0;
    if (total - last_checkpoint_ >= interval_ && (block_boundary || total == total_size_)) {
      checkpoint_now();
    }
    return count;
  }

  int sync() override {
    file_.flush();
    return file_ ? 0 : -1;
  }

 private:
  std::ofstream& file_;
  crypto::Sha256& hasher_;
  const std::uint64_t base_;
  const std::uint64_t total_size_;
  const std::uint64_t interval_;
  std::function<void(std::uint64_t)> checkpoint_;
  std::uint64_t written_ = 0;
  std::uint64_t last_checkpoint_ = 0;
};

/// What is at a destination path, without following a symlink.
struct TargetStatus {
  bool exists = false;
  bool symlink = false;
  bool regular = false;
  bool directory = false;
};

TargetStatus probe_target(const fs::path& path) {
  std::error_code ec;
  const fs::file_status status = fs::symlink_status(path, ec);
  if (ec) {
    if (ec == std::errc::no_such_file_or_directory) return TargetStatus{};
    fail(ErrorCode::StoreIo, "cannot stat " + path.string() + ": " + ec.message());
  }
  TargetStatus out;
  out.exists = status.type() != fs::file_type::not_found;
  out.symlink = fs::is_symlink(status);
  out.regular = fs::is_regular_file(status);
  out.directory = fs::is_directory(status);
  return out;
}

/// A fresh target that received no bytes (for example the first block failed
/// authentication) is removed again: an empty file from a rejected artifact is
/// noise, not resumable progress. Targets with bytes, and targets that existed
/// before the call, are left for the resume logic.
void drop_empty_fresh_target(const fs::path& target, const fs::path& state_path) {
  std::error_code ec;
  const std::uintmax_t size = fs::file_size(target, ec);
  if (ec || size != 0) return;
  fs::remove(target, ec);
  fs::remove(state_path, ec);
}

bool state_exists(const fs::path& target) {
  return probe_target(state_path_for(target)).exists;
}

/// Refuses a file destination that would send the write somewhere other than the
/// name the user chose. A symlink is followed silently by an append, and a FIFO
/// or device is not a file we may write into at all; `overwrite` may replace
/// either because that unlinks the entry itself, but it never replaces a
/// directory.
void check_file_target(const TargetStatus& status, const fs::path& path, bool overwrite) {
  if (status.directory) {
    fail(ErrorCode::FileExists, "target is a directory: " + path.string());
  }
  if (!status.exists) return;
  if (status.symlink && !overwrite) {
    fail(ErrorCode::UnsafeTarget, "refusing to write through the symlink " + path.string() +
                                       " (use --force to replace the link)");
  }
  if (!status.symlink && !status.regular && !overwrite) {
    fail(ErrorCode::UnsafeTarget,
         "refusing to write to " + path.string() +
             ": not a regular file (use --force to replace it)");
  }
}

/// True when `path` holds a complete file: a regular file (not a symlink) of the
/// right size with no resume state.
bool looks_complete(const fs::path& path, std::uint64_t size) {
  const TargetStatus status = probe_target(path);
  if (!status.exists || status.symlink || !status.regular) return false;
  if (state_exists(path)) return false;
  std::error_code ec;
  return fs::file_size(path, ec) == size && !ec;
}

void report(const DirectoryOptions& options, DirectoryOutcome& outcome, DirectoryProgress progress) {
  ++outcome.files;
  outcome.written_now += progress.written;
  outcome.reused += progress.reused;
  if (progress.skipped) {
    ++outcome.skipped;
  } else if (progress.reused > 0) {
    ++outcome.resumed;
  }
  if (options.on_file) options.on_file(progress);
}

void download_tree(const FileStore& store, const ShareSession& session, const std::string& rel_dir,
                  const fs::path& target, const DirectoryOptions& options,
                  DirectoryOutcome& outcome) {
  for (const Entry& entry : list_path(store, session, rel_dir)) {
    const std::string rel = rel_dir.empty() ? entry.name : rel_dir + "/" + entry.name;
    const fs::path destination = target / entry.name;
    std::error_code ec;

    if (entry.kind == EntryKind::Directory) {
      const TargetStatus status = probe_target(destination);
      if (status.symlink) {
        fail(ErrorCode::UnsafeTarget,
             "refusing to follow the symlink " + destination.string());
      }
      if (status.exists && !status.directory) {
        fail(ErrorCode::FileExists, destination.string() + " is not a directory");
      }
      fs::create_directories(destination, ec);
      if (ec) fail(ErrorCode::StoreIo, "cannot create " + destination.string());
      ++outcome.directories;
      download_tree(store, session, rel, destination, options, outcome);
      continue;
    }

    DirectoryProgress progress;
    progress.path = rel;
    progress.size = entry.size;
    const TargetStatus status = probe_target(destination);
    check_file_target(status, destination, options.file.overwrite);
    if (!options.file.overwrite && looks_complete(destination, entry.size)) {
      // Already the right size with no resume state: nothing to fetch. An
      // explicit overwrite means the caller wants every byte fetched again.
      // Without `resume`, download_file refuses an existing target, so this
      // skip policy has to live here rather than in the per-file call.
      progress.skipped = true;
      progress.reused = entry.size;
      report(options, outcome, std::move(progress));
      continue;
    }

    DownloadOptions file_options = options.file;
    if (status.exists && !state_exists(destination)) {
      // Something else is at the destination; replace it instead of appending.
      file_options.overwrite = true;
    }
    const DownloadOutcome done =
        download_file(store, session, entry, destination, file_options);
    progress.reused = done.reused;
    progress.written = done.written_now;
    progress.skipped = done.skipped;
    report(options, outcome, std::move(progress));
  }
}

}  // namespace

std::filesystem::path resume_state_path(const std::filesystem::path& target) {
  return state_path_for(target);
}

std::uint64_t download_file_range(const FileStore& store, const ShareSession& session,
                                  const Entry& entry, std::uint64_t offset,
                                  std::uint64_t length, const fs::path& target, bool overwrite,
                                  const FetchOptions& options) {
  if (entry.kind != EntryKind::File) {
    fail(ErrorCode::WrongType, "'" + entry.name + "' is not a file");
  }
  if (offset > entry.size) {
    fail(ErrorCode::BadRange, "offset " + std::to_string(offset) +
                                  " is past the end of '" + entry.name + "' (" +
                                  std::to_string(entry.size) + " bytes)");
  }

  std::error_code ec;
  if (target.has_parent_path()) {
    fs::create_directories(target.parent_path(), ec);
    if (ec) fail(ErrorCode::StoreIo, "cannot create " + target.parent_path().string());
  }

  const TargetStatus status = probe_target(target);
  check_file_target(status, target, overwrite);
  if (status.exists && !overwrite) {
    fail(ErrorCode::FileExists, "target already exists: " + target.string());
  }
  if (overwrite && status.exists) {
    fs::remove(target, ec);  // replaces a file, symlink or device, never a directory
    if (ec) fail(ErrorCode::StoreIo, "cannot replace " + target.string());
  }

  const std::uint64_t wanted = std::min(length, entry.size - offset);
  std::ofstream file(target, std::ios::binary | std::ios::trunc);
  if (!file) fail(ErrorCode::StoreIo, "cannot write " + target.string());

  std::uint64_t written = 0;
  try {
    written = fetch_file_range(store, session, entry, offset, length, file, options);
    file.flush();
    if (!file) fail(ErrorCode::StoreIo, "failed while writing '" + entry.name + "'");
  } catch (...) {
    file.close();
    std::error_code ignored;
    fs::remove(target, ignored);
    throw;
  }
  file.close();
  if (!file) fail(ErrorCode::StoreIo, "failed while writing '" + entry.name + "'");
  if (written != wanted) {
    fail(ErrorCode::SizeMismatch, "'" + entry.name + "' produced " + std::to_string(written) +
                                     " bytes, expected " + std::to_string(wanted));
  }
  return written;
}

DownloadOutcome download_file(const FileStore& store, const ShareSession& session,
                              const Entry& entry, const std::filesystem::path& target,
                              const DownloadOptions& options) {
  if (entry.kind != EntryKind::File) {
    fail(ErrorCode::WrongType, "'" + entry.name + "' is not a file");
  }
  if (options.checkpoint_bytes == 0) {
    fail(ErrorCode::BadOptions, "checkpoint_bytes must be positive");
  }

  DownloadOutcome outcome;
  outcome.file_size = entry.size;
  const fs::path state_path = state_path_for(target);
  std::error_code ec;

  if (target.has_parent_path()) {
    fs::create_directories(target.parent_path(), ec);
    if (ec) fail(ErrorCode::StoreIo, "cannot create " + target.parent_path().string());
  }

  const TargetStatus status = probe_target(target);
  check_file_target(status, target, options.overwrite);
  const bool existed = status.exists;
  if (options.overwrite && existed) {
    fs::remove(target, ec);  // its resume state is dropped by the fresh-start path below
    if (ec) fail(ErrorCode::StoreIo, "cannot replace " + target.string());
  } else if (existed && !options.resume) {
    fail(ErrorCode::FileExists, "target already exists: " + target.string());
  }

  // overwrite wins over resume: after the removals above this is a fresh start.
  const bool resuming = options.resume && !options.overwrite && existed;
  bool fresh_target = false;
  std::uint64_t start = 0;
  crypto::Sha256 hasher;

  if (resuming) {
    const std::optional<ResumeState> state = read_state(state_path);
    if (!state && looks_complete(target, entry.size)) {
      // Complete already (right size, no state): nothing to fetch, as with a
      // directory download. A state file that exists but cannot be read is not
      // "no state", and a wrong size is refused just below.
      outcome.reused = entry.size;
      outcome.skipped = true;
      return outcome;
    }
    if (!state) {
      fail(ErrorCode::BadResumeState,
           "no usable resume state for '" + target.string() + "' (use overwrite to start over)");
    }
    if (!constant_time_equal(ByteView(state->file_id), ByteView(entry.file_id)) ||
        state->size != entry.size) {
      fail(ErrorCode::BadResumeState,
           "resume state for '" + target.string() + "' belongs to a different file");
    }
    if (state->written > entry.size) {
      fail(ErrorCode::BadResumeState, "resume state is larger than the file");
    }
    const std::uint64_t on_disk = fs::file_size(target, ec);
    if (ec) fail(ErrorCode::StoreIo, "cannot size " + target.string());
    if (on_disk < state->written) {
      fail(ErrorCode::BadResumeState, "partial file is shorter than its resume state");
    }
    if (on_disk > state->written) {
      // Bytes beyond the recorded point were never verified: drop them.
      fs::resize_file(target, state->written, ec);
      if (ec) fail(ErrorCode::StoreIo, "cannot truncate " + target.string());
    }
    const auto digest = hash_prefix(target, state->written, hasher);
    if (!constant_time_equal(ByteView(digest), ByteView(state->digest))) {
      fail(ErrorCode::BadResumeState,
           "partial file does not match its resume state (use overwrite to start over)");
    }
    start = state->written;
    outcome.reused = start;
    if (start == entry.size) {
      // The sidecar already covers every byte: the file is complete, not a
      // resume, so report it the same way as a complete file without state.
      outcome.skipped = true;
      fs::remove(state_path, ec);
      return outcome;
    }
  } else {
    fs::remove(state_path, ec);
    std::ofstream truncate(target, std::ios::binary | std::ios::trunc);
    if (!truncate) fail(ErrorCode::StoreIo, "cannot write " + target.string());
    fresh_target = true;
  }

  std::ofstream file(target, std::ios::binary | std::ios::app);
  if (!file) fail(ErrorCode::StoreIo, "cannot write " + target.string());

  ResumeState state;
  state.file_id = entry.file_id;
  state.size = entry.size;
  state.written = start;
  state.digest = hasher.digest();

  DownloadSink buffer(file, hasher, start, entry.size, options.checkpoint_bytes,
                      [&](std::uint64_t written) {
                        state.written = written;
                        state.digest = hasher.digest();
                        write_state(state_path, state);
                      });
  std::ostream sink(&buffer);

  std::uint64_t wrote = 0;
  try {
    wrote = fetch_file_range(store, session, entry, start, kToEndOfFile, sink, options.fetch);
    // A full disk surfaces at the final flush. Without this check a short file
    // would be reported as complete and its resume state deleted.
    sink.flush();
    if (!sink) fail(ErrorCode::StoreIo, "failed while writing '" + entry.name + "'");
  } catch (...) {
    // Keep what did reach the disk so the next run can resume, unless this call
    // created the file and nothing authenticated ever reached it.
    try {
      buffer.checkpoint_now();
    } catch (...) {
    }
    if (fresh_target) drop_empty_fresh_target(target, state_path);
    throw;
  }

  if (wrote != entry.size - start) {
    if (fresh_target && wrote == 0) drop_empty_fresh_target(target, state_path);
    fail(ErrorCode::SizeMismatch, "'" + entry.name + "' produced " + std::to_string(start + wrote) +
                                     " bytes, expected " + std::to_string(entry.size));
  }
  file.close();
  fs::remove(state_path, ec);
  outcome.written_now = wrote;
  return outcome;
}

DirectoryOutcome download_directory(const FileStore& store, const ShareSession& session,
                                   std::string_view relative_path,
                                   const std::filesystem::path& target,
                                   const DirectoryOptions& options) {
  std::error_code ec;
  if (fs::exists(target, ec) && !fs::is_directory(target, ec)) {
    fail(ErrorCode::FileExists, "target is not a directory: " + target.string());
  }
  fs::create_directories(target, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot create " + target.string());

  // Lists first, so a missing or non-directory path fails before writing anything.
  const std::vector<Entry> entries = list_path(store, session, relative_path);
  (void)entries;

  DirectoryOutcome outcome;
  download_tree(store, session, std::string(relative_path), target, options, outcome);
  return outcome;
}

}  // namespace skipta
