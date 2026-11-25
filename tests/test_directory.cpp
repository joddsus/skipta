// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A directory download walks the share depth-first in the order the manifests
// publish entries, and resumes each file from its own state, so an interrupted
// run continues where it stopped and produces the same tree as a full one.
#include <filesystem>
#include <string>
#include <vector>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/download.hpp"
#include "skipta/error.hpp"
#include "skipta/share.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

/// a.txt, bdir/ (empty), cdir/{d.txt, sub/e.txt}, f.txt — published order is
/// the manifest order: sorted by name, with each directory listed as one entry.
void write_tree(const fs::path& root) {
  skiptest::write_text(root / "a.txt", "first");
  fs::create_directories(root / "bdir");
  skiptest::write_text(root / "cdir" / "d.txt", std::string(70000, 'd'));
  skiptest::write_text(root / "cdir" / "sub" / "e.txt", std::string(20000, 'e'));
  skiptest::write_text(root / "f.txt", "last");
}

}  // namespace

TEST_CASE("a directory download walks the share in published order") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  write_tree(source.path());

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> root_entry = resolve_path(store, session, "cdir");
  REQUIRE(root_entry.has_value());
  CHECK(root_entry->kind == EntryKind::Directory);

  std::vector<std::string> order;
  DirectoryOptions options;
  options.on_file = [&](const DirectoryProgress& file) { order.push_back(file.path); };

  const fs::path target = work.path() / "out";
  const DirectoryOutcome outcome = download_directory(store, session, "", target, options);
  CHECK(outcome.files == 4);
  CHECK(outcome.directories == 3);  // bdir, cdir, cdir/sub
  CHECK(outcome.skipped == 0);
  CHECK(outcome.resumed == 0);

  // Depth-first, in manifest order: a.txt, cdir/d.txt, cdir/sub/e.txt, f.txt.
  const std::vector<std::string> expected = {"a.txt", "cdir/d.txt", "cdir/sub/e.txt", "f.txt"};
  CHECK(order == expected);

  CHECK(skiptest::read_all(target / "a.txt") == "first");
  CHECK(skiptest::read_all(target / "f.txt") == "last");
  CHECK(skiptest::read_all(target / "cdir" / "d.txt") == std::string(70000, 'd'));
  CHECK(skiptest::read_all(target / "cdir" / "sub" / "e.txt") == std::string(20000, 'e'));
  CHECK(fs::is_directory(target / "bdir"));  // empty directories are recreated

  // Downloading a subdirectory only walks that subtree.
  std::vector<std::string> sub_order;
  options.on_file = [&](const DirectoryProgress& file) { sub_order.push_back(file.path); };
  const DirectoryOutcome sub =
      download_directory(store, session, "cdir", work.path() / "sub", options);
  CHECK(sub.files == 2);
  CHECK(sub_order == std::vector<std::string>{"cdir/d.txt", "cdir/sub/e.txt"});
  CHECK(skiptest::read_all(work.path() / "sub" / "d.txt") == std::string(70000, 'd'));
}

TEST_CASE("an interrupted directory download resumes file by file") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "small first file");
  skiptest::write_pattern(source.path() / "b.bin", 200000, 7);  // 4 blocks
  skiptest::write_text(source.path() / "c.txt", "small last file");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> b = resolve_path(store, session, "b.bin");
  REQUIRE(b.has_value());

  // Drop the last block of the second file: a.txt completes, b.bin is partial.
  const std::uint64_t missing = format::block_count(b->size) - 1;
  const Bytes saved = *store.get_block(b->file_id, missing);
  const fs::path block_path =
      store.root() / "blocks" / hex_encode(ByteView(b->file_id)) / skiptest::block_name(missing);
  REQUIRE(fs::exists(block_path));
  fs::remove(block_path);

  DirectoryOptions options;
  options.file.resume = true;
  options.file.checkpoint_bytes = 1;
  const fs::path target = work.path() / "out";

  CHECK(skiptest::code_of([&] { download_directory(store, session, "", target, options); }) ==
        ErrorCode::NotFound);
  CHECK(fs::exists(target / "a.txt"));
  CHECK(fs::file_size(target / "b.bin") == 3 * format::kBlockPlaintextSize);
  CHECK(fs::exists(resume_state_path(target / "b.bin")));
  CHECK_FALSE(fs::exists(target / "c.txt"));

  // Put the block back and continue: a.txt is skipped, b.bin resumes, c.txt is new.
  store.put_block(b->file_id, missing, ByteView(saved));

  std::vector<std::string> order;
  std::vector<DirectoryProgress> seen;
  options.on_file = [&](const DirectoryProgress& file) {
    order.push_back(file.path);
    seen.push_back(file);
  };
  const DirectoryOutcome outcome = download_directory(store, session, "", target, options);
  CHECK(outcome.files == 3);
  CHECK(outcome.skipped == 1);   // a.txt
  CHECK(outcome.resumed == 1);   // b.bin
  CHECK(outcome.written_now ==
        b->size - 3 * format::kBlockPlaintextSize + std::string("small last file").size());
  CHECK(order == std::vector<std::string>{"a.txt", "b.bin", "c.txt"});
  REQUIRE(seen.size() == 3);
  CHECK(seen[0].skipped);
  CHECK_FALSE(seen[1].skipped);
  CHECK(seen[1].reused == 3 * format::kBlockPlaintextSize);
  CHECK_FALSE(seen[2].skipped);
  CHECK(seen[2].reused == 0);

  CHECK_FALSE(fs::exists(resume_state_path(target / "b.bin")));  // cleaned up
  CHECK(skiptest::read_all(target / "a.txt") == "small first file");
  CHECK(skiptest::read_all(target / "b.bin") ==
        to_string(ByteView(skiptest::pattern(200000, 7))));
  CHECK(skiptest::read_all(target / "c.txt") == "small last file");

  // The resumed tree is identical to a fresh, uninterrupted download.
  const fs::path fresh = work.path() / "fresh";
  download_directory(store, session, "", fresh);
  CHECK(skiptest::read_all(fresh / "b.bin") == skiptest::read_all(target / "b.bin"));
  CHECK(skiptest::read_all(fresh / "a.txt") == skiptest::read_all(target / "a.txt"));
  CHECK(skiptest::read_all(fresh / "c.txt") == skiptest::read_all(target / "c.txt"));
}

TEST_CASE("a directory download skips complete files and restarts the rest") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "alpha");
  skiptest::write_text(source.path() / "b.txt", "bravo");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const fs::path target = work.path() / "out";

  const DirectoryOutcome first = download_directory(store, session, "", target);
  CHECK(first.written_now == 10);

  // A second run with no changes fetches nothing.
  const DirectoryOutcome again = download_directory(store, session, "", target);
  CHECK(again.files == 2);
  CHECK(again.skipped == 2);
  CHECK(again.written_now == 0);

  // A sidecar that already covers the whole file is complete, not a resume: it
  // is reported as skipped like any other complete file.
  const std::optional<Entry> a = resolve_path(store, session, "a.txt");
  REQUIRE(a.has_value());
  const std::string state =
      "{\"v\":1,\"file_id\":\"" + base64url_encode(ByteView(a->file_id)) +
      "\",\"size\":" + std::to_string(a->size) + ",\"written\":" +
      std::to_string(a->size) + ",\"sha256\":\"" +
      base64url_encode(ByteView(crypto::sha256(ByteView(std::string("alpha"))))) + "\"}";
  skiptest::write_text(resume_state_path(target / "a.txt"), state);
  DirectoryOptions resume;
  resume.file.resume = true;
  const DirectoryOutcome covered = download_directory(store, session, "", target, resume);
  CHECK(covered.skipped == 2);
  CHECK(covered.resumed == 0);
  CHECK(covered.written_now == 0);
  CHECK_FALSE(fs::exists(resume_state_path(target / "a.txt")));

  // A file with no resume state and the wrong size is replaced, not appended.
  REQUIRE(fs::remove(target / "b.txt"));
  skiptest::write_text(target / "b.txt", "ju");
  const DirectoryOutcome repaired = download_directory(store, session, "", target);
  CHECK(repaired.skipped == 1);
  CHECK(repaired.written_now == 5);
  CHECK(skiptest::read_all(target / "b.txt") == "bravo");

  // overwrite re-fetches everything.
  DirectoryOptions force;
  force.file.overwrite = true;
  const DirectoryOutcome overwritten = download_directory(store, session, "", target, force);
  CHECK(overwritten.skipped == 0);
  CHECK(overwritten.written_now == 10);

  // A path that is not a directory cannot become the target.
  skiptest::write_text(work.path() / "file", "x");
  CHECK(skiptest::code_of([&] {
          download_directory(store, session, "", work.path() / "file");
        }) == ErrorCode::FileExists);
}

TEST_CASE("a directory download never writes through a symlink") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "alpha");
  skiptest::write_text(source.path() / "sub" / "b.txt", "beta");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);

  // A manifest name can land on a symlink someone left in the destination.
  // Appending through it would write outside the directory the user chose.
  const fs::path outside = work.path() / "outside.txt";
  skiptest::write_text(outside, "keep");
  const fs::path target = work.path() / "out";
  fs::create_directories(target);
  std::error_code ec;
  fs::create_symlink(outside, target / "a.txt", ec);
  REQUIRE_FALSE(ec);

  CHECK(skiptest::code_of([&] { download_directory(store, session, "", target); }) ==
        ErrorCode::UnsafeTarget);
  CHECK(skiptest::read_all(outside) == "keep");
  CHECK_FALSE(fs::exists(target / "sub"));

  // --force replaces the link itself; it never follows it.
  DirectoryOptions force;
  force.file.overwrite = true;
  const DirectoryOutcome outcome = download_directory(store, session, "", target, force);
  CHECK(outcome.written_now == 9);
  CHECK_FALSE(fs::is_symlink(target / "a.txt"));
  CHECK(skiptest::read_all(target / "a.txt") == "alpha");
  CHECK(skiptest::read_all(target / "sub" / "b.txt") == "beta");
  CHECK(skiptest::read_all(outside) == "keep");

  // A symlinked directory is refused rather than followed.
  const fs::path target2 = work.path() / "out2";
  const fs::path outside_dir = work.path() / "outside-dir";
  fs::create_directories(target2);
  fs::create_directories(outside_dir);
  fs::create_symlink(outside_dir, target2 / "sub", ec);
  REQUIRE_FALSE(ec);
  CHECK(skiptest::code_of([&] { download_directory(store, session, "", target2); }) ==
        ErrorCode::UnsafeTarget);
  CHECK(fs::is_empty(outside_dir));

  // A file entry may not overwrite a directory, even with --force.
  const fs::path target3 = work.path() / "out3";
  fs::create_directories(target3 / "a.txt");
  CHECK(skiptest::code_of([&] {
          download_directory(store, session, "", target3, force);
        }) == ErrorCode::FileExists);
}
