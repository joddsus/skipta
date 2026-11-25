// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/share.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <deque>
#include <future>
#include <fstream>
#include <chrono>
#include <functional>
#include <memory>
#include <ostream>
#include <streambuf>
#include <string>
#include <thread>
#include <system_error>
#include <utility>

#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/private_file.hpp"

namespace skipta {
namespace {

namespace fs = std::filesystem;

Bytes require_blob(std::optional<Bytes> blob, const std::string& what) {
  if (!blob) {
    fail(ErrorCode::NotFound, what + " is not in the store");
  }
  return *std::move(blob);
}

std::uint64_t mtime_of(const fs::path& path) {
  std::error_code ec;
  const auto stamp = fs::last_write_time(path, ec);
  if (ec) return 0;
  const auto seconds =
      std::chrono::duration_cast<std::chrono::seconds>(stamp.time_since_epoch()).count();
  return seconds > 0 ? static_cast<std::uint64_t>(seconds) : 0;
}

std::vector<fs::path> sorted_children(const fs::path& directory) {
  std::vector<fs::path> children;
  std::error_code ec;
  fs::directory_iterator it(directory, ec);
  if (ec) {
    fail(ErrorCode::StoreIo, "cannot read directory " + directory.string());
  }
  for (const auto& entry : it) children.push_back(entry.path());
  std::sort(children.begin(), children.end(),
            [](const fs::path& a, const fs::path& b) { return a.filename() < b.filename(); });
  return children;
}

/// Encrypts one regular file straight from disk, block by block, so publishing
/// never holds a whole file in memory.
void encrypt_file_into_store(const Key32& drive_key, const Id128& file_id,
                             const fs::path& path, FileStore& store, std::uint64_t size) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail(ErrorCode::StoreIo, "cannot read " + path.string());

  Bytes chunk(format::kBlockPlaintextSize);
  std::uint64_t remaining = size;
  std::uint64_t index = 0;
  while (remaining > 0) {
    const std::size_t want = static_cast<std::size_t>(
        std::min<std::uint64_t>(format::kBlockPlaintextSize, remaining));
    in.read(reinterpret_cast<char*>(chunk.data()), static_cast<std::streamsize>(want));
    if (!in || static_cast<std::size_t>(in.gcount()) != want) {
      fail(ErrorCode::StoreIo, "short read from " + path.string());
    }
    const Bytes sealed = format::encrypt_block(drive_key, file_id, size, index,
                                               ByteView(chunk.data(), want));
    store.put_block(file_id, index, ByteView(sealed));
    remaining -= want;
    ++index;
  }
}

constexpr std::uint64_t max_backoff_us = 60u * 1000u * 1000u;

/// Errors that may disappear on the next attempt. Content errors (a bad tag, a
/// wrong length) and format errors cannot, so those surface immediately.
bool retryable(ErrorCode code) {
  return code == ErrorCode::NotFound || code == ErrorCode::StoreIo;
}

fs::path accepted_seq_path(const FileStore& store, const PubKey32& drive) {
  return store.root() / "accepted" / (hex_encode(ByteView(drive)) + ".seq");
}

/// Sink that drops verified plaintext: verify only needs the decryption to run.
class NullStreambuf : public std::streambuf {
 protected:
  std::streamsize xsputn(const char*, std::streamsize count) override { return count; }
  int overflow(int c) override { return c; }
};

void verify_entries(const FileStore& store, const ShareSession& session,
                    const std::vector<Entry>& entries, std::string_view parent,
                    const FetchOptions& options, VerifyResult& out) {
  for (const Entry& entry : entries) {
    const std::string relative =
        parent.empty() ? entry.name : std::string(parent) + "/" + entry.name;
    if (entry.kind == EntryKind::Directory) {
      ++out.directories;
      verify_entries(store, session, list_path(store, session, relative), relative, options, out);
      continue;
    }
    NullStreambuf null;
    std::ostream sink(&null);
    fetch_file(store, session, entry, sink, options);
    ++out.files;
    out.blocks += format::block_count(entry.size);
    out.bytes += entry.size;
  }
}

}  // namespace

namespace {

bool is_within(const fs::path& child, const fs::path& parent) {
  auto inner = child.begin();
  for (auto outer = parent.begin(); outer != parent.end(); ++outer, ++inner) {
    if (inner == child.end() || *inner != *outer) return false;
  }
  return true;
}

/// Absolute and canonical where possible. `weakly_canonical` leaves a relative
/// path with a missing first component untouched, so the CLI's default relative
/// store ("skipta-store") would otherwise escape the containment check.
fs::path resolve_for_compare(const fs::path& path) {
  std::error_code ec;
  const fs::path absolute = fs::absolute(path, ec);
  if (ec) return path.lexically_normal();
  ec.clear();
  const fs::path canonical = fs::weakly_canonical(absolute, ec);
  return ec ? absolute.lexically_normal() : canonical;
}

}  // namespace

PublishResult publish_directory(const fs::path& source, FileStore& store,
                               const PublishOptions& options) {
  std::error_code ec;
  if (!fs::is_directory(source, ec)) {
    fail(ErrorCode::StoreIo, "not a directory: " + source.string());
  }
  if (options.seq == 0) {
    fail(ErrorCode::BadOptions, "pointer seq must be at least 1");
  }

  // The store holds this drive's identity (<store>/identities: drive key and
  // signing seed) and the sealed blobs. Publishing a folder that contains the
  // store would seal that identity into the share, handing every reader the
  // signing seed; refuse instead of doing something surprising and unsafe.
  {
    const fs::path resolved_source = resolve_for_compare(source);
    const fs::path resolved_store = resolve_for_compare(store.root());
    if (is_within(resolved_store, resolved_source)) {
      fail(ErrorCode::BadOptions,
           "the store (" + resolved_store.string() +
               ") is inside the folder being published; that would put the store's "
               "identity secret and ciphertext into the share. Use a store outside "
               "the folder, e.g. --store ~/.local/share/skipta");
    }
  }
  // Serialise with gc and with other publishers. gc keeps only what current
  // pointers name, so it must not run between a publish writing objects and
  // naming them in the pointer. Taken after the containment refusal above, so a
  // rejected publish does not create the store.
  const StoreLock lock(store.root());

  const Limits limits = options.limits;
  std::unique_ptr<Drive> owned;
  const Drive* drive = options.identity;
  if (drive == nullptr) {
    owned = std::make_unique<Drive>(Drive::create());
    drive = owned.get();
  }
  PublishResult result;
  result.drive = drive->public_key();

  // Depth is tracked explicitly because a recursive tree can be arbitrarily deep
  // and the format caps it.
  std::function<Manifest(const fs::path&, std::size_t)> build =
      [&](const fs::path& directory, std::size_t depth) -> Manifest {
    if (depth > limits.max_depth) {
      fail(ErrorCode::TooDeep, "directory tree deeper than " +
                                   std::to_string(limits.max_depth) + " levels at " +
                                   directory.string());
    }
    Manifest manifest = drive->new_manifest(1);

    for (const fs::path& child : sorted_children(directory)) {
      const std::string name = child.filename().string();
      const auto status = fs::symlink_status(child, ec);
      if (ec) fail(ErrorCode::StoreIo, "cannot stat " + child.string());

      try {
        if (fs::is_symlink(status)) {
          // Spec §8: never follow symlinks out of a share.
          result.skipped.push_back(child.string() + " (symlink)");
          continue;
        }
        if (fs::is_directory(status)) {
          Manifest sub = build(child, depth + 1);
          const Bytes sealed = drive->seal_manifest(sub, limits);
          store.put_manifest(sub.id, ByteView(sealed));
          manifest.add_directory(name, sub.id, mtime_of(child));
          ++result.directories;
          continue;
        }
        if (fs::is_regular_file(status)) {
          const std::uint64_t size = fs::file_size(child, ec);
          if (ec) fail(ErrorCode::StoreIo, "cannot size " + child.string());
          if (size > limits.max_file_size) {
            fail(ErrorCode::FileTooLarge,
                 "file larger than the " + std::to_string(limits.max_file_size) + " byte limit");
          }
          const Id128 file_id = crypto::random_id();
          encrypt_file_into_store(drive->drive_key(), file_id, child, store, size);
          manifest.add_file(name, size, file_id, mtime_of(child));
          ++result.files;
          result.bytes += size;
          continue;
        }
        result.skipped.push_back(child.string() + " (not a regular file)");
      } catch (const Error& e) {
        // Re-throw with the offending path, which the format alone cannot know.
        fail(e.code(), child.string() + ": " + e.what());
      }
    }
    return manifest;
  };

  Manifest root = build(source, 1);
  const Bytes sealed_root = drive->seal_manifest(root, limits);
  store.put_manifest(root.id, ByteView(sealed_root));

  RootPointer pointer = drive->root_pointer(
      root, options.issued_at != 0 ? options.issued_at
                                   : static_cast<std::uint64_t>(std::time(nullptr)));
  pointer.seq = options.seq;
  const SignedPointer signed_pointer = drive->sign_root(pointer);
  const Bytes wire_pointer = encode_signed_pointer(signed_pointer);
  store.put_pointer(drive->public_key(), ByteView(wire_pointer));

  result.link = encode_link(drive->share_link({}));
  result.seq = pointer.seq;
  return result;
}

ShareSession open_share(const FileStore& store, std::string_view link_text,
                        std::uint64_t min_seq) {
  ShareSession session;
  session.link = decode_link(link_text);

  const Bytes raw_pointer = require_blob(store.get_pointer(session.link.drive), "root pointer");
  const SignedPointer signed_pointer = decode_signed_pointer(ByteView(raw_pointer));
  session.pointer = verify_pointer(session.link.drive, signed_pointer, min_seq);

  const Bytes sealed_root =
      require_blob(store.get_manifest(session.pointer.root), "root manifest");
  session.root = open_manifest(session.link.key, session.pointer.root, ByteView(sealed_root));
  return session;
}

std::uint64_t accepted_pointer_seq(const FileStore& store, const PubKey32& drive) {
  const fs::path path = accepted_seq_path(store, drive);
  std::error_code ec;
  // A small regular file, read through a fixed buffer: a planted device or a
  // huge file must not be able to allocate or block here.
  if (!fs::is_regular_file(path, ec)) return 0;
  const std::uintmax_t size = fs::file_size(path, ec);
  if (ec || size == 0 || size > 32) return 0;
  std::ifstream in(path, std::ios::binary);
  if (!in) return 0;
  char buffer[32];
  in.read(buffer, static_cast<std::streamsize>(size));
  const std::streamsize got = in.gcount();
  if (got <= 0) return 0;

  std::uint64_t value = 0;
  std::size_t digits = 0;
  for (std::streamsize i = 0; i < got; ++i) {
    const char c = buffer[i];
    if (c >= '0' && c <= '9') {
      if (++digits > 19) return 0;
      value = value * 10 + static_cast<std::uint64_t>(c - '0');
      continue;
    }
    // Trailing whitespace ends the number; anything else is not a seq file.
    for (std::streamsize rest = i; rest < got; ++rest) {
      const char tail = buffer[rest];
      if (tail != ' ' && tail != '\t' && tail != '\r' && tail != '\n') return 0;
    }
    break;
  }
  return digits == 0 ? 0 : value;
}

void remember_pointer_seq(const FileStore& store, const PubKey32& drive, std::uint64_t seq) {
  if (seq <= accepted_pointer_seq(store, drive)) return;
  store.ensure_writable_directory("accepted");
  const fs::path path = accepted_seq_path(store, drive);
  const std::string text = std::to_string(seq) + "\n";
  write_private_file(path, ByteView(text), false);
}

std::optional<Entry> resolve_path(const FileStore& store, const ShareSession& session,
                                 std::string_view relative_path) {
  if (relative_path.empty()) return std::nullopt;
  validate_relative_path(relative_path);

  Manifest current = session.root;
  std::size_t start = 0;
  while (true) {
    const std::size_t slash = relative_path.find('/', start);
    const std::string_view component = relative_path.substr(
        start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
    const Entry* found = current.find(component);
    if (found == nullptr) return std::nullopt;
    if (slash == std::string_view::npos) return *found;
    if (found->kind != EntryKind::Directory) return std::nullopt;

    const Bytes sealed =
        require_blob(store.get_manifest(found->manifest_id), "directory manifest");
    current = open_manifest(session.link.key, found->manifest_id, ByteView(sealed));
    start = slash + 1;
  }
}

std::vector<Entry> list_path(const FileStore& store, const ShareSession& session,
                             std::string_view relative_path) {
  if (relative_path.empty()) return session.root.entries;
  const std::optional<Entry> entry = resolve_path(store, session, relative_path);
  if (!entry) {
    fail(ErrorCode::NotFound, "'" + std::string(relative_path) + "' is not in the share");
  }
  if (entry->kind != EntryKind::Directory) {
    fail(ErrorCode::WrongType, "'" + std::string(relative_path) + "' is not a directory");
  }
  const Bytes sealed =
      require_blob(store.get_manifest(entry->manifest_id), "directory manifest");
  return open_manifest(session.link.key, entry->manifest_id, ByteView(sealed)).entries;
}

std::uint64_t fetch_blocks(const Entry& entry, std::uint64_t offset, std::uint64_t length,
                           const BlockFetcher& fetch, std::ostream& sink,
                           const FetchOptions& options) {
  if (entry.kind != EntryKind::File) {
    fail(ErrorCode::WrongType, "'" + entry.name + "' is not a file");
  }
  if (options.max_in_flight < 1 || options.max_in_flight > 32) {
    fail(ErrorCode::BadOptions, "max_in_flight must be between 1 and 32");
  }
  if (options.max_attempts < 1 || options.max_attempts > 10) {
    fail(ErrorCode::BadOptions, "max_attempts must be between 1 and 10");
  }
  if (options.backoff.count() < 0 ||
      options.backoff > std::chrono::microseconds(max_backoff_us)) {
    fail(ErrorCode::BadOptions, "backoff must be between 0 and 60 seconds");
  }
  if (offset > entry.size) {
    fail(ErrorCode::BadRange, "offset " + std::to_string(offset) +
                                  " is past the end of '" + entry.name + "' (" +
                                  std::to_string(entry.size) + " bytes)");
  }
  const std::uint64_t available = entry.size - offset;
  const std::uint64_t wanted = std::min(length, available);
  if (wanted == 0) return 0;

  // Only blocks overlapping [offset, offset + wanted) are fetched.
  const std::uint64_t first_block = offset / format::kBlockPlaintextSize;
  const std::uint64_t last_block = (offset + wanted - 1) / format::kBlockPlaintextSize;

  std::uint64_t written = 0;
  const auto emit = [&](const Bytes& plain, std::uint64_t index) {
    const std::size_t expected = format::plaintext_block_len(entry.size, index);
    if (plain.size() != expected) {
      fail(ErrorCode::SizeMismatch, "block " + std::to_string(index) + " of '" + entry.name +
                                        "' has the wrong length");
    }
    const std::uint64_t block_start = index * format::kBlockPlaintextSize;
    const std::uint64_t skip = offset > block_start ? offset - block_start : 0;
    const std::uint64_t take =
        std::min<std::uint64_t>(plain.size() - skip, wanted - written);
    if (take != 0) {
      sink.write(reinterpret_cast<const char*>(plain.data() + skip),
                 static_cast<std::streamsize>(take));
      if (!sink) fail(ErrorCode::StoreIo, "failed while writing '" + entry.name + "'");
      written += take;
    }
  };

  // Ordered, bounded pipeline: futures are launched in ascending block order and
  // consumed in that same order, so a slow block cannot reorder output, and at
  // most `window` blocks exist at once. When only one block is in flight, the
  // task is deferred and runs inline on get(): no thread is created at all.
  const std::uint64_t blocks_in_range = last_block - first_block + 1;
  const std::size_t window = blocks_in_range < options.max_in_flight
                                 ? static_cast<std::size_t>(blocks_in_range)
                                 : options.max_in_flight;
  const std::launch policy = window > 1 ? std::launch::async : std::launch::deferred;

  // Retrying happens inside the block's own task, so a retry can never reorder
  // output, and a block that fails every attempt raises its last error exactly
  // where it did before. Slots stay occupied while a block backs off, which is
  // the bounded cost of not dropping the pipeline.
  const auto fetch_block = [&fetch, attempts = options.max_attempts,
                            backoff = options.backoff](std::uint64_t index) {
    std::chrono::microseconds delay = backoff;
    for (std::size_t attempt = 1;; ++attempt) {
      try {
        return fetch(index);
      } catch (const Error& e) {
        if (attempt >= attempts || !retryable(e.code())) throw;
        if (delay.count() > 0) std::this_thread::sleep_for(delay);
        const std::chrono::microseconds doubled = delay * 2;
        delay = doubled > std::chrono::microseconds(max_backoff_us)
                    ? std::chrono::microseconds(max_backoff_us)
                    : doubled;
      }
    }
  };
  const auto launch = [&fetch_block, policy](std::uint64_t index) {
    return std::async(policy, [&fetch_block, index] { return fetch_block(index); });
  };

  std::deque<std::future<Bytes>> in_flight;
  for (std::uint64_t i = 0; i < window; ++i) {
    in_flight.push_back(launch(first_block + i));
  }
  for (std::uint64_t index = first_block; index <= last_block; ++index) {
    Bytes plain = in_flight.front().get();  // oldest submission first: byte order
    in_flight.pop_front();
    emit(plain, index);
    const std::uint64_t next = index + window;
    if (next <= last_block) in_flight.push_back(launch(next));
  }
  return written;
}

std::uint64_t fetch_file_range(const FileStore& store, const ShareSession& session,
                               const Entry& entry, std::uint64_t offset, std::uint64_t length,
                               std::ostream& sink, const FetchOptions& options) {
  const BlockFetcher fetch = [&store, &session, &entry](std::uint64_t index) {
    const Bytes sealed = require_blob(store.get_block(entry.file_id, index),
                                      "block " + std::to_string(index) + " of '" +
                                          entry.name + "'");
    return format::decrypt_block(session.link.key, entry.file_id, entry.size, index,
                                 ByteView(sealed));
  };
  return fetch_blocks(entry, offset, length, fetch, sink, options);
}

std::uint64_t fetch_file(const FileStore& store, const ShareSession& session, const Entry& entry,
                        std::ostream& sink, const FetchOptions& options) {
  const std::uint64_t written =
      fetch_file_range(store, session, entry, 0, kToEndOfFile, sink, options);
  if (written != entry.size) {
    fail(ErrorCode::SizeMismatch, "'" + entry.name + "' produced " + std::to_string(written) +
                                     " bytes, expected " + std::to_string(entry.size));
  }
  return written;
}

VerifyResult verify_path(const FileStore& store, const ShareSession& session,
                         std::string_view relative_path, const FetchOptions& options) {
  VerifyResult out;
  if (relative_path.empty()) {
    verify_entries(store, session, session.root.entries, "", options, out);
    return out;
  }

  const std::optional<Entry> entry = resolve_path(store, session, relative_path);
  if (!entry) {
    fail(ErrorCode::NotFound, "'" + std::string(relative_path) + "' is not in the share");
  }
  if (entry->kind == EntryKind::File) {
    NullStreambuf null;
    std::ostream sink(&null);
    fetch_file(store, session, *entry, sink, options);
    out.files = 1;
    out.blocks = format::block_count(entry->size);
    out.bytes = entry->size;
    return out;
  }
  verify_entries(store, session, list_path(store, session, relative_path), relative_path, options,
                 out);
  return out;
}

}  // namespace skipta
