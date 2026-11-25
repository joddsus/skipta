// SPDX-License-Identifier: AGPL-3.0-or-later
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/share.hpp"

using namespace skipta;
namespace fs = std::filesystem;

TEST_CASE("publish a tree, then list and fetch it through a link") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "hello skipta");
  skiptest::write_pattern(source.path() / "big.bin", 200000, 5);
  skiptest::write_text(source.path() / "empty", "");
  skiptest::write_text(source.path() / "docs" / "readme.md", "docs");
  skiptest::write_text(source.path() / "docs" / "nested" / "deep.txt", "deep");

  bool symlinked = false;
  {
    std::error_code ec;
    fs::create_symlink(source.path() / "a.txt", source.path() / "link.txt", ec);
    symlinked = !ec;
  }

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  CHECK(published.files == 5);
  CHECK(published.directories == 2);
  CHECK(published.bytes == 12 + 200000 + 0 + 4 + 4);
  CHECK(published.link.rfind("skipta://v1/", 0) == 0);
  CHECK(published.skipped.size() == (symlinked ? 1u : 0u));

  const ShareSession session = open_share(store, published.link);
  CHECK(session.pointer.seq == 1);
  CHECK(session.pointer.drive == published.drive);

  const std::vector<Entry> root = list_path(store, session, "");
  REQUIRE(root.size() == 4);
  CHECK(root[0].name == "a.txt");  // published in sorted order
  CHECK(root[1].name == "big.bin");
  CHECK(root[2].name == "docs");
  CHECK(root[3].name == "empty");

  const std::vector<Entry> docs = list_path(store, session, "docs");
  REQUIRE(docs.size() == 2);
  CHECK(docs[0].name == "nested");
  CHECK(docs[1].name == "readme.md");

  // Nested resolution and a full file fetch, block by block from the store.
  const std::optional<Entry> deep = resolve_path(store, session, "docs/nested/deep.txt");
  REQUIRE(deep.has_value());
  std::ostringstream fetched;
  CHECK(fetch_file(store, session, *deep, fetched) == 4);
  CHECK(fetched.str() == "deep");

  // Multi-block file: 4 blocks, fetched one at a time.
  const std::optional<Entry> big = resolve_path(store, session, "big.bin");
  REQUIRE(big.has_value());
  CHECK(big->size == 200000);
  std::ostringstream big_out;
  CHECK(fetch_file(store, session, *big, big_out) == 200000);
  CHECK(big_out.str() == to_string(ByteView(skiptest::pattern(200000, 5))));

  // Empty file: a valid entry with no blocks.
  const std::optional<Entry> empty = resolve_path(store, session, "empty");
  REQUIRE(empty.has_value());
  std::ostringstream empty_out;
  CHECK(fetch_file(store, session, *empty, empty_out) == 0);
  CHECK(empty_out.str().empty());
}

TEST_CASE("a missing pointer, a bad pointer and a bad blob each fail distinctly") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "hello");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);

  // Unknown drive: the pointer is simply absent.
  const FileStore empty(work.path() / "empty-store");
  CHECK(skiptest::code_of([&] { open_share(empty, published.link); }) == ErrorCode::NotFound);

  // Pointer bytes that are not a pointer at all.
  {
    const std::string garbage = "definitely not a signed pointer";
    store.put_pointer(published.drive, ByteView(garbage));
    CHECK(skiptest::code_of([&] { open_share(store, published.link); }) == ErrorCode::BadJson);
  }

  // Undamaged publish: corrupting the sealed root manifest is an auth failure.
  {
    skiptest::write_text(source.path() / "b.txt", "second");
    const PublishResult second = publish_directory(source.path(), store);
    const ShareSession session = open_share(store, second.link);
    Bytes broken = *store.get_manifest(session.pointer.root);
    broken[0] ^= 0x01;
    store.put_manifest(session.pointer.root, ByteView(broken));
    CHECK(skiptest::code_of([&] { open_share(store, second.link); }) == ErrorCode::AuthFailed);
  }

  // Missing block is reported as NotFound, not as a decryption failure.
  {
    const PublishResult third = publish_directory(source.path(), store);
    const ShareSession session = open_share(store, third.link);
    const std::optional<Entry> file = resolve_path(store, session, "a.txt");
    REQUIRE(file.has_value());
    const fs::path block_path =
        store.root() / "blocks" / hex_encode(ByteView(file->file_id)) / skiptest::block_name(0);
    REQUIRE(fs::exists(block_path));
    fs::remove(block_path);
    std::ostringstream sink;
    CHECK(skiptest::code_of([&] { fetch_file(store, session, *file, sink); }) ==
          ErrorCode::NotFound);
  }
}

TEST_CASE("a range request reads only the blocks it overlaps") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_pattern(source.path() / "big.bin", 200000, 5);  // blocks 0..3, last is 3392 bytes
  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "big.bin");
  REQUIRE(entry.has_value());

  const std::string full = to_string(ByteView(skiptest::pattern(200000, 5)));
  const fs::path block_dir = store.root() / "blocks" / hex_encode(ByteView(entry->file_id));

  // Remove a block this test must never touch; every query below still succeeds.
  REQUIRE(fs::exists(block_dir / skiptest::block_name(0)));
  fs::remove(block_dir / skiptest::block_name(0));

  // Inside a single block.
  std::ostringstream inside;
  CHECK(fetch_file_range(store, session, *entry, 70000, 1000, inside) == 1000);
  CHECK(inside.str() == full.substr(70000, 1000));

  // Spanning a block boundary (block 1 -> block 2).
  std::ostringstream across;
  CHECK(fetch_file_range(store, session, *entry, 131060, 20, across) == 20);
  CHECK(across.str() == full.substr(131060, 20));

  // To the end of the file, clamped by the real size.
  std::ostringstream tail;
  CHECK(fetch_file_range(store, session, *entry, 100000, kToEndOfFile, tail) == 100000);
  CHECK(tail.str() == full.substr(100000));

  // Length past the end is clamped, not an error.
  std::ostringstream clamped;
  CHECK(fetch_file_range(store, session, *entry, 199900, 100000, clamped) == 100);
  CHECK(clamped.str() == full.substr(199900));

  // An empty range at EOF is valid and reads nothing.
  std::ostringstream empty;
  CHECK(fetch_file_range(store, session, *entry, 200000, 10, empty) == 0);
  CHECK(empty.str().empty());

  // Past the end is an error, before any blob is touched.
  CHECK(skiptest::code_of([&] {
          std::ostringstream sink;
          fetch_file_range(store, session, *entry, 200001, 10, sink);
        }) == ErrorCode::BadRange);

  // The whole file would need the deleted blocks: NotFound proves laziness.
  std::ostringstream whole;
  CHECK(skiptest::code_of([&] { fetch_file(store, session, *entry, whole); }) ==
        ErrorCode::NotFound);
}

TEST_CASE("path traversal and wrong kinds are rejected while browsing") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "hello");
  skiptest::write_text(source.path() / "docs" / "readme.md", "docs");
  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);

  CHECK(resolve_path(store, session, "missing.txt") == std::nullopt);
  CHECK(skiptest::code_of([&] { resolve_path(store, session, "../../etc/passwd"); }) ==
        ErrorCode::DotName);
  CHECK(skiptest::code_of([&] { resolve_path(store, session, "/etc/passwd"); }) ==
        ErrorCode::PathSeparator);
  CHECK(skiptest::code_of([&] { list_path(store, session, "a.txt"); }) == ErrorCode::WrongType);

  const std::optional<Entry> docs = resolve_path(store, session, "docs");
  REQUIRE(docs.has_value());
  std::ostringstream sink;
  CHECK(skiptest::code_of([&] { fetch_file(store, session, *docs, sink); }) ==
        ErrorCode::WrongType);
}

TEST_CASE("each publish creates a new drive, so re-publishing is not an update") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "one");
  FileStore store(work.path() / "store");
  const PublishResult first = publish_directory(source.path(), store);
  const PublishResult second = publish_directory(source.path(), store);
  CHECK_FALSE(first.link == second.link);
  CHECK_FALSE(first.drive == second.drive);
  CHECK(open_share(store, first.link).pointer.drive == first.drive);
  CHECK(open_share(store, second.link).pointer.drive == second.drive);
}

TEST_CASE("a store inside the published folder is refused") {
  skiptest::TempDir source("src");
  skiptest::write_text(source.path() / "a.txt", "hello");

  // Publishing the folder that holds the store would seal <store>/identities
  // (drive key and signing seed) into the share.
  FileStore inside(source.path() / "store");
  CHECK(skiptest::code_of([&] { publish_directory(source.path(), inside); }) ==
        ErrorCode::BadOptions);
  CHECK_FALSE(fs::exists(source.path() / "store" / "pointers"));

  skiptest::TempDir work("store");
  FileStore outside(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), outside);
  CHECK(published.files == 1);
}

TEST_CASE("a relative store path inside the published folder is refused") {
  skiptest::TempDir source("src");
  skiptest::write_text(source.path() / "a.txt", "hello");

  // Exactly `skipta publish .` with the default `./skipta-store`: a relative
  // path whose first component does not exist yet.
  const fs::path original = fs::current_path();
  struct RestoreCwd {
    fs::path path;
    ~RestoreCwd() {
      std::error_code ec;
      fs::current_path(path, ec);
    }
  } restore{original};
  fs::current_path(source.path());

  FileStore relative("skipta-store");
  CHECK(skiptest::code_of([&] { publish_directory(".", relative); }) == ErrorCode::BadOptions);
  CHECK_FALSE(fs::exists(source.path() / "skipta-store"));
}

TEST_CASE("verify authenticates every block of a share and reports tampering") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "hello");              // 1 block
  skiptest::write_pattern(source.path() / "big.bin", 200000, 2);        // 4 blocks
  skiptest::write_text(source.path() / "docs" / "deep.txt", "deep");  // 1 block

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);

  const VerifyResult whole = verify_path(store, session);
  CHECK(whole.files == 3);
  CHECK(whole.directories == 1);
  CHECK(whole.blocks == 6);
  CHECK(whole.bytes == 5 + 200000 + 4);

  // A subdirectory and a single file can be checked on their own.
  const VerifyResult docs = verify_path(store, session, "docs");
  CHECK(docs.files == 1);
  CHECK(docs.directories == 0);
  const VerifyResult one = verify_path(store, session, "a.txt");
  CHECK(one.files == 1);
  CHECK(one.blocks == 1);

  // One flipped byte in any block is an authentication failure, not silent data.
  const std::optional<Entry> big = resolve_path(store, session, "big.bin");
  REQUIRE(big.has_value());
  const fs::path block_path =
      store.root() / "blocks" / hex_encode(ByteView(big->file_id)) / skiptest::block_name(2);
  std::string sealed = skiptest::read_all(block_path);
  REQUIRE(sealed.size() > 0);
  sealed[0] = static_cast<char>(sealed[0] ^ 0x01);
  skiptest::write_text(block_path, sealed);
  CHECK(skiptest::code_of([&] { verify_path(store, session); }) == ErrorCode::AuthFailed);

  // A missing block is reported as NotFound.
  REQUIRE(fs::remove(block_path));
  CHECK(skiptest::code_of([&] { verify_path(store, session); }) == ErrorCode::NotFound);
}

TEST_CASE("published blobs contain no plaintext names or contents") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "distinctive-name.txt", "distinctive-content-12345");
  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);

  std::size_t scanned = 0;
  for (const auto& entry : fs::recursive_directory_iterator(store.root())) {
    if (!entry.is_regular_file()) continue;
    // The advisory lock is store metadata, not a blob; it is empty anyway.
    if (entry.path().filename() == ".lock") continue;
    const std::string blob = skiptest::read_all(entry.path());
    CHECK(blob.find("distinctive-name") == std::string::npos);
    CHECK(blob.find("distinctive-content") == std::string::npos);
    ++scanned;
  }
  CHECK(scanned == 3);  // pointer + root manifest + one block
  CHECK(published.files == 1);
}
