// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/store.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/http.hpp"
#include "skipta/manifest.hpp"
#include "skipta/private_file.hpp"

namespace skipta {
namespace {

namespace fs = std::filesystem;

// Hard caps for anything the store reads back. A blob larger than the format
// allows is corrupt or hostile; refuse it instead of allocating its size.
constexpr std::size_t kMaxPointerBytes = 4096;
constexpr std::size_t kMaxManifestBytes = Limits{}.max_manifest_bytes + format::kAeadTagSize;
constexpr std::size_t kMaxBlockBytes = format::kBlockPlaintextSize + format::kAeadTagSize;

std::string index_name(std::uint64_t index) {
  std::string name = std::to_string(index);
  // Zero-padded so a directory listing sorts and looks like a real block store.
  if (name.size() < 16) name.insert(0, 16 - name.size(), '0');
  return name;
}

/// Writes one store object through the owner-only atomic writer: the file is
/// created 0600 and its directory 0700, whatever the process umask is.
void write_atomic(const fs::path& path, ByteView data, bool durable) {
  write_private_file(path, data, durable);
}

#if !defined(_WIN32)
/// Opens `root/relative` while refusing to follow a symlink in any component
/// below the store root. A hostile store cannot then direct a reader (or the
/// serving daemon) at a file outside it. Returns -1 with errno set.
int open_object(const fs::path& root, const fs::path& relative) {
  const int root_fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (root_fd < 0) return -1;
  std::vector<fs::path> parts;
  for (const fs::path& part : relative) parts.push_back(part);
  if (parts.empty()) {
    ::close(root_fd);
    errno = EINVAL;
    return -1;
  }
  int dir = root_fd;
  for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
    const int next =
        ::openat(dir, parts[i].c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int saved = errno;
    ::close(dir);
    if (next < 0) {
      errno = saved;
      return -1;
    }
    dir = next;
  }
  const int fd = ::openat(dir, parts.back().c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  const int saved = errno;
  ::close(dir);
  errno = saved;
  return fd;
}
#endif

/// Reads a whole blob relative to the store root, refusing anything that is not
/// a regular file reached without symlinks and of at most `cap` bytes. The size
/// is checked before reading, so a planted huge file (or a device that never
/// ends) cannot exhaust memory.
std::optional<Bytes> read_capped(const fs::path& root, const fs::path& relative,
                                 std::size_t cap, const char* what) {
#if !defined(_WIN32)
  const int fd = open_object(root, relative);
  if (fd < 0) {
    if (errno == ENOENT) return std::nullopt;
    if (errno == ELOOP || errno == ENOTDIR) {
      fail(ErrorCode::UnsupportedFileType,
           std::string(what) + " is not reached through plain directories: " +
               (root / relative).string());
    }
    fail(ErrorCode::StoreIo,
         "cannot open " + (root / relative).string() + ": " + std::strerror(errno));
  }
  struct CloseFd {
    int fd;
    ~CloseFd() { ::close(fd); }
  } closer{fd};

  struct stat info {};
  if (::fstat(fd, &info) != 0) {
    fail(ErrorCode::StoreIo, "cannot size " + (root / relative).string());
  }
  if (!S_ISREG(info.st_mode)) {
    fail(ErrorCode::UnsupportedFileType,
         std::string(what) + " is not a regular file: " + (root / relative).string());
  }
  if (info.st_size < 0 || static_cast<std::uint64_t>(info.st_size) > cap) {
    fail(ErrorCode::TooLarge,
         std::string(what) + " is " + std::to_string(info.st_size) +
             " bytes, more than the " + std::to_string(cap) +
             "-byte maximum: " + (root / relative).string());
  }

  Bytes out(static_cast<std::size_t>(info.st_size));
  std::size_t got = 0;
  while (got < out.size()) {
    const ssize_t n = ::read(fd, out.data() + got, out.size() - got);
    if (n < 0) {
      if (errno == EINTR) continue;
      fail(ErrorCode::StoreIo, "cannot read " + (root / relative).string());
    }
    if (n == 0) break;
    got += static_cast<std::size_t>(n);
  }
  if (got != out.size()) {
    fail(ErrorCode::StoreIo, "short read from " + (root / relative).string());
  }
  return out;
#else
  const fs::path path = root / relative;
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;

  std::error_code ec;
  if (!fs::is_regular_file(path, ec)) {
    fail(ErrorCode::UnsupportedFileType,
         std::string(what) + " is not a regular file: " + path.string());
  }
  const std::uintmax_t size = fs::file_size(path, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot size " + path.string());
  if (size > cap) {
    fail(ErrorCode::TooLarge, std::string(what) + " is " + std::to_string(size) +
                                  " bytes, more than the " + std::to_string(cap) +
                                  "-byte maximum: " + path.string());
  }

  Bytes out(static_cast<std::size_t>(size));
  if (!out.empty()) {
    in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
    if (!in || static_cast<std::size_t>(in.gcount()) != out.size()) {
      fail(ErrorCode::StoreIo, "short read from " + path.string());
    }
  }
  return out;
#endif
}

}  // namespace

StoreLock::StoreLock(const std::filesystem::path& store_root) {
#if !defined(_WIN32)
  make_private_directory(store_root);
  const fs::path path = store_root / ".lock";
  // Repair a lock file made unreadable by an extreme umask in an earlier run;
  // the owner may chmod it even when it cannot open it. Never chmod through a
  // symlink or touch a FIFO/device planted by a hostile store.
  std::error_code pec;
  const fs::file_status lock_status = fs::symlink_status(path, pec);
  if (!pec && lock_status.type() != fs::file_type::not_found) {
    if (fs::is_symlink(lock_status) || !fs::is_regular_file(lock_status)) {
      fail(ErrorCode::UnsupportedFileType,
           "store lock is not a regular file: " + path.string());
    }
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace, pec);
  }
  // A hostile store must not be able to point the lock at an arbitrary file, a
  // FIFO that blocks open(), or a device. O_NOFOLLOW refuses a final symlink;
  // O_NONBLOCK plus the fstat check refuses a FIFO without waiting for a peer.
  fd_ = ::open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
  if (fd_ < 0) {
    fail(ErrorCode::UnsupportedFileType,
         "cannot open store lock without following a link: " + path.string());
  }
  struct stat lock_info {};
  if (::fstat(fd_, &lock_info) != 0 || !S_ISREG(lock_info.st_mode)) {
    ::close(fd_);
    fd_ = -1;
    fail(ErrorCode::UnsupportedFileType,
         "store lock is not a regular file: " + path.string());
  }
  if (::fchmod(fd_, 0600) != 0) {
    ::close(fd_);
    fd_ = -1;
    fail(ErrorCode::StoreIo, "cannot protect store lock " + path.string());
  }
  if (::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
    ::close(fd_);
    fd_ = -1;
    fail(ErrorCode::StoreBusy, "another publish or gc is using " + store_root.string() +
                                   "; try again when it has finished");
  }
#else
  (void)store_root;
#endif
}

StoreLock::~StoreLock() {
#if !defined(_WIN32)
  if (fd_ >= 0) {
    ::flock(fd_, LOCK_UN);
    ::close(fd_);
  }
#endif
}

StoredObjectName classify_stored_object_name(std::string_view name) {
  const auto lower_hex = [](std::string_view text) {
    for (char c : text) {
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
  };
  if (name.size() == 64 + 4 && name.substr(64) == ".ptr" &&
      lower_hex(name.substr(0, 64))) {
    return StoredObjectName::Pointer;
  }
  if (name.size() == 32 + 3 && name.substr(32) == ".mf" && lower_hex(name.substr(0, 32))) {
    return StoredObjectName::Manifest;
  }
  if (name.size() == 32 && lower_hex(name)) return StoredObjectName::FileDirectory;
  if (name.size() == 16 + 4 && name.substr(16) == ".blk" &&
      lower_hex(name.substr(0, 16))) {
    return StoredObjectName::Block;
  }
  return StoredObjectName::Other;
}

FileStore::FileStore(std::filesystem::path root, std::string remote_origin)
    : root_(std::move(root)), remote_origin_(std::move(remote_origin)) {
  if (!remote_origin_.empty()) remote_origin_ = normalize_http_store_url(remote_origin_);
}

std::optional<Bytes> FileStore::get_object(const std::filesystem::path& relative,
                                           std::size_t cap, const char* what) const {
  const std::optional<Bytes> cached = read_capped(root_, relative, cap, what);
  if (cached || remote_origin_.empty()) return cached;

  const std::optional<Bytes> fetched =
      http_get_object(remote_origin_ + "/" + relative.generic_string(), cap);
  if (!fetched) return std::nullopt;
  // Cache what the origin served. The caller authenticates it before use; the
  // cache is a convenience, never a source of trust. Every directory the cache
  // creates is owner-only, just like a local store, and a hostile cache layout
  // cannot redirect the write through a symlink.
  ensure_writable_directory(relative.parent_path());
  write_atomic(root_ / relative, *fetched, false);
  return fetched;
}

void FileStore::ensure_writable_directory(const fs::path& relative) const {
  make_private_directory(root_);
  fs::path current = root_;
  for (const fs::path& part : relative) {
    if (part.empty() || part == "." || part == "..") {
      fail(ErrorCode::BadOptions, "invalid store directory component");
    }
    current /= part;
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(current, ec);
    if (ec && ec != std::errc::no_such_file_or_directory) {
      fail(ErrorCode::StoreIo, "cannot inspect " + current.string() + ": " + ec.message());
    }
    if (status.type() != fs::file_type::not_found) {
      if (fs::is_symlink(status)) {
        fail(ErrorCode::UnsupportedFileType,
             "refusing a symlinked store directory: " + current.string());
      }
      if (!fs::is_directory(status)) {
        fail(ErrorCode::StoreIo, "store path is not a directory: " + current.string());
      }
      continue;
    }
    fs::create_directory(current, ec);
    if (ec) fail(ErrorCode::StoreIo, "cannot create " + current.string() + ": " + ec.message());
    fs::permissions(current, fs::perms::owner_all, fs::perm_options::replace, ec);
    if (ec) fail(ErrorCode::StoreIo, "cannot protect " + current.string() + ": " + ec.message());
  }
}

void FileStore::put_pointer(const PubKey32& drive, ByteView signed_pointer) {
  if (is_remote()) fail(ErrorCode::BadOptions, "cannot write to a read-only remote store");
  ensure_writable_directory("pointers");
  write_atomic(root_ / "pointers" / (hex_encode(ByteView(drive)) + ".ptr"), signed_pointer, true);
}

std::optional<Bytes> FileStore::get_pointer(const PubKey32& drive) const {
  return get_object(fs::path("pointers") / (hex_encode(ByteView(drive)) + ".ptr"),
                    kMaxPointerBytes, "stored root pointer");
}

void FileStore::put_manifest(const Id128& manifest_id, ByteView sealed_manifest) {
  if (is_remote()) fail(ErrorCode::BadOptions, "cannot write to a read-only remote store");
  ensure_writable_directory("manifests");
  write_atomic(root_ / "manifests" / (hex_encode(ByteView(manifest_id)) + ".mf"), sealed_manifest,
               false);
}

std::vector<PubKey32> FileStore::pointer_drives() const {
  std::vector<PubKey32> drives;
  std::error_code ec;
  fs::directory_iterator it(root_ / "pointers", ec);
  if (ec) return drives;  // no pointers directory means nothing is published
  for (const auto& entry : it) {
    const std::string name = entry.path().filename().string();
    if (name.size() != 64 + 4 || name.compare(64, 4, ".ptr") != 0) continue;
    try {
      const Bytes raw = hex_decode(name.substr(0, 64), "drive pointer name");
      if (raw.size() != sizeof(PubKey32)) continue;
      PubKey32 drive{};
      std::copy(raw.begin(), raw.end(), drive.begin());
      drives.push_back(drive);
    } catch (const Error&) {
      continue;  // not a pointer this tool wrote
    }
  }
  std::sort(drives.begin(), drives.end());
  return drives;
}

std::optional<Bytes> FileStore::get_manifest(const Id128& manifest_id) const {
  return get_object(fs::path("manifests") / (hex_encode(ByteView(manifest_id)) + ".mf"),
                    kMaxManifestBytes, "stored manifest");
}

void FileStore::put_block(const Id128& file_id, std::uint64_t index, ByteView sealed_block) {
  if (is_remote()) fail(ErrorCode::BadOptions, "cannot write to a read-only remote store");
  ensure_writable_directory(fs::path("blocks") / hex_encode(ByteView(file_id)));
  write_atomic(root_ / "blocks" / hex_encode(ByteView(file_id)) / (index_name(index) + ".blk"),
               sealed_block, false);
}

std::optional<Bytes> FileStore::get_block(const Id128& file_id, std::uint64_t index) const {
  return get_object(fs::path("blocks") / hex_encode(ByteView(file_id)) /
                        (index_name(index) + ".blk"),
                    kMaxBlockBytes, "stored block");
}

}  // namespace skipta
