// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The store is the boundary between this process and bytes it did not create:
// a downloaded store copy, a half-finished publish or a hostile peer can put
// anything there. These tests pin the two rules that keep it safe to read:
// writes are atomic, and reads are bounded and only ever of regular files.
#include <filesystem>
#include <fstream>
#include <string>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/private_file.hpp"
#include "skipta/store.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

std::size_t temp_files_under(const fs::path& root) {
  std::size_t count = 0;
  std::error_code ec;
  for (const auto& entry : fs::recursive_directory_iterator(root, ec)) {
    if (entry.path().filename().string().find(".tmp-") != std::string::npos) ++count;
  }
  return count;
}

void write_blob(const fs::path& path, std::size_t size) {
  std::error_code ec;
  fs::create_directories(path.parent_path(), ec);
  const Bytes data(size, 0x5a);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!data.empty()) {
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
}

}  // namespace

TEST_CASE("store blobs are written atomically and replaced in place") {
  skiptest::TempDir work("store");
  FileStore store(work.path() / "store");
  const Id128 id = crypto::random_id();

  const Bytes first = skiptest::pattern(40);
  store.put_block(id, 7, ByteView(first));
  CHECK(*store.get_block(id, 7) == first);
  CHECK(temp_files_under(store.root()) == 0);

  const Bytes second = skiptest::pattern(70, 3);
  store.put_block(id, 7, ByteView(second));
  CHECK(*store.get_block(id, 7) == second);
  CHECK(temp_files_under(store.root()) == 0);

  const Id128 manifest_id = crypto::random_id();
  store.put_manifest(manifest_id, ByteView(std::string("sealed manifest")));
  CHECK(to_string(ByteView(*store.get_manifest(manifest_id))) == "sealed manifest");

  PubKey32 drive{};
  drive.fill(9);
  store.put_pointer(drive, ByteView(std::string("signed pointer")));
  CHECK(to_string(ByteView(*store.get_pointer(drive))) == "signed pointer");
  CHECK(temp_files_under(store.root()) == 0);

  // A missing blob is absent, not an error.
  PubKey32 other{};
  other.fill(4);
  CHECK_FALSE(store.get_pointer(other).has_value());
}

TEST_CASE("store writes refuse symlinked store directories") {
  skiptest::TempDir work("store");
  skiptest::TempDir outside("outside");
  FileStore store(work.path() / "store");
  make_private_directory(store.root());
  std::error_code ec;
  const Id128 id = crypto::random_id();

  const auto outside_entries = [&] {
    std::size_t count = 0;
    for (const auto& entry : fs::directory_iterator(outside.path())) {
      (void)entry;
      ++count;
    }
    return count;
  };

  const fs::path blocks = store.root() / "blocks";
  fs::create_symlink(outside.path(), blocks, ec);
  REQUIRE_FALSE(ec);
  CHECK(skiptest::code_of([&] { store.put_block(id, 0, ByteView(std::string_view("block"))); }) ==
        ErrorCode::UnsupportedFileType);
  CHECK(outside_entries() == 0);
  REQUIRE(fs::remove(blocks));

  const fs::path manifests = store.root() / "manifests";
  fs::create_symlink(outside.path(), manifests, ec);
  REQUIRE_FALSE(ec);
  CHECK(skiptest::code_of(
            [&] { store.put_manifest(id, ByteView(std::string_view("manifest"))); }) ==
        ErrorCode::UnsupportedFileType);
  CHECK(outside_entries() == 0);
  REQUIRE(fs::remove(manifests));

  const fs::path pointers = store.root() / "pointers";
  fs::create_symlink(outside.path(), pointers, ec);
  REQUIRE_FALSE(ec);
  PubKey32 drive{};
  CHECK(skiptest::code_of(
            [&] { store.put_pointer(drive, ByteView(std::string_view("pointer"))); }) ==
        ErrorCode::UnsupportedFileType);
  CHECK(outside_entries() == 0);
  REQUIRE(fs::remove(pointers));
}

TEST_CASE("the store lock never follows a link or waits on a FIFO") {
#if !defined(_WIN32)
  skiptest::TempDir work("store");
  FileStore store(work.path() / "store");
  make_private_directory(store.root());
  const fs::path victim = work.path() / "victim";
  skiptest::write_text(victim, "do not touch");
  const fs::path lock = store.root() / ".lock";
  std::error_code ec;
  fs::create_symlink(victim, lock, ec);
  REQUIRE_FALSE(ec);
  CHECK(skiptest::code_of([&] { StoreLock held(store.root()); }) ==
        ErrorCode::UnsupportedFileType);
  CHECK(skiptest::read_all(victim) == "do not touch");
  REQUIRE(fs::remove(lock));

  REQUIRE(::mkfifo(lock.c_str(), 0600) == 0);
  CHECK(skiptest::code_of([&] { StoreLock held(store.root()); }) ==
        ErrorCode::UnsupportedFileType);
  REQUIRE(fs::remove(lock));

  StoreLock held(store.root());  // an ordinary lock still works
#endif
}

TEST_CASE("the store refuses oversized and non-regular blobs") {
  skiptest::TempDir work("store");
  FileStore store(work.path() / "store");
  const Id128 id = crypto::random_id();
  const fs::path block_path =
      store.root() / "blocks" / hex_encode(ByteView(id)) / skiptest::block_name(0);

  // One byte over the largest legal sealed block: rejected before reading.
  write_blob(block_path, format::kBlockPlaintextSize + format::kAeadTagSize + 1);
  CHECK(skiptest::code_of([&] { (void)store.get_block(id, 0); }) == ErrorCode::TooLarge);

  // A directory where a blob should be is not bytes.
  REQUIRE(fs::remove(block_path));
  fs::create_directories(block_path);
  CHECK(skiptest::code_of([&] { (void)store.get_block(id, 0); }) ==
        ErrorCode::UnsupportedFileType);

  const fs::path pointer_path =
      store.root() / "pointers" / (hex_encode(ByteView(PubKey32{})) + ".ptr");
  write_blob(pointer_path, 4097);
  CHECK(skiptest::code_of([&] { (void)store.get_pointer(PubKey32{}); }) == ErrorCode::TooLarge);

  const fs::path manifest_path =
      store.root() / "manifests" / (hex_encode(ByteView(id)) + ".mf");
  write_blob(manifest_path, Limits{}.max_manifest_bytes + format::kAeadTagSize + 1);
  CHECK(skiptest::code_of([&] { (void)store.get_manifest(id); }) == ErrorCode::TooLarge);

  // A legal-size blob still reads normally.
  write_blob(manifest_path, 32);
  const std::optional<Bytes> blob = store.get_manifest(id);
  REQUIRE(blob.has_value());
  CHECK(blob->size() == 32);
}
