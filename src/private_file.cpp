// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/private_file.hpp"

#include <cstddef>
#include <fstream>
#include <string>
#include <system_error>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "skipta/crypto.hpp"
#include "skipta/error.hpp"

namespace skipta {
namespace {

namespace fs = std::filesystem;

std::string temp_name(const fs::path& path) {
  const Id128 id = crypto::random_id();
  return path.string() + ".tmp-" + hex_encode(ByteView(id)).substr(0, 16);
}

#if !defined(_WIN32)
void write_all(int fd, ByteView data, const fs::path& path) {
  std::size_t offset = 0;
  while (offset < data.size) {
    const ssize_t written = ::write(fd, data.data + offset, data.size - offset);
    if (written <= 0) fail(ErrorCode::StoreIo, "short write to " + path.string());
    offset += static_cast<std::size_t>(written);
  }
}
#endif

}  // namespace

void make_private_directory(const fs::path& dir) {
  if (dir.empty()) return;
  std::error_code ec;
  fs::create_directories(dir, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot create " + dir.string() + ": " + ec.message());
  // Explicit, because create_directories applies 0777 & ~umask.
  fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot protect " + dir.string() + ": " + ec.message());
}

void write_private_file(const fs::path& path, ByteView data, bool durable) {
  make_private_directory(path.parent_path());
  const fs::path temp = temp_name(path);
  std::error_code ec;

#if !defined(_WIN32)
  const int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) fail(ErrorCode::StoreIo, "cannot create " + temp.string());
  try {
    // umask can only clear bits, and 0600 & ~umask might be 0000; set it back.
    if (::fchmod(fd, 0600) != 0) fail(ErrorCode::StoreIo, "cannot protect " + temp.string());
    write_all(fd, data, temp);
    if (durable && ::fsync(fd) != 0) fail(ErrorCode::StoreIo, "cannot flush " + temp.string());
  } catch (...) {
    ::close(fd);
    fs::remove(temp, ec);
    throw;
  }
  if (::close(fd) != 0) {
    fs::remove(temp, ec);
    fail(ErrorCode::StoreIo, "cannot close " + temp.string());
  }
#else
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) fail(ErrorCode::StoreIo, "cannot create " + temp.string());
    if (!data.empty()) {
      out.write(reinterpret_cast<const char*>(data.data),
                static_cast<std::streamsize>(data.size));
    }
    out.flush();
    if (!out) {
      fs::remove(temp, ec);
      fail(ErrorCode::StoreIo, "short write to " + temp.string());
    }
  }
  fs::permissions(temp, fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, ec);
  if (ec) {
    fs::remove(temp, ec);
    fail(ErrorCode::StoreIo, "cannot protect " + temp.string());
  }
#endif

  fs::rename(temp, path, ec);
  if (ec) {
    // Some platforms cannot replace an existing file by rename. Removing the
    // old file first leaves a window with no file, never a torn one.
    fs::remove(path, ec);
    ec.clear();
    fs::rename(temp, path, ec);
    if (ec) {
      fs::remove(temp, ec);
      fail(ErrorCode::StoreIo, "cannot replace " + path.string());
    }
  }
}

}  // namespace skipta
