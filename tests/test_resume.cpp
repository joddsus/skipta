// SPDX-License-Identifier: AGPL-3.0-or-later
//
// An interrupted download must be resumable to byte-identical output, and the
// reuse must be verified rather than trusted.
#include <filesystem>
#include <fstream>
#include <string>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/download.hpp"
#include "skipta/error.hpp"
#include "skipta/share.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

constexpr std::uint64_t kBlock = format::kBlockPlaintextSize;

/// Downloads with the last block missing, so the fetch fails after writing the
/// blocks before it, then puts the block back. Leaves a partial file + state.
void interrupt_download(FileStore& store, const ShareSession& session, const Entry& entry,
                        const fs::path& target) {
  const std::uint64_t missing = format::block_count(entry.size) - 1;
  const Bytes saved = *store.get_block(entry.file_id, missing);
  const fs::path block_path =
      store.root() / "blocks" / hex_encode(ByteView(entry.file_id)) / skiptest::block_name(missing);
  REQUIRE(fs::exists(block_path));
  fs::remove(block_path);

  DownloadOptions options;
  options.resume = true;
  options.checkpoint_bytes = 1;  // record every block: the crash window is tiny
  CHECK(skiptest::code_of([&] { download_file(store, session, entry, target, options); }) ==
        ErrorCode::NotFound);

  store.put_block(entry.file_id, missing, ByteView(saved));
}

}  // namespace

TEST_CASE("resume after an interruption produces the same file as a full download") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_pattern(source.path() / "payload.bin", 200000, 9);  // 4 blocks, last short

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "payload.bin");
  REQUIRE(entry.has_value());

  const fs::path target = work.path() / "download.bin";
  const fs::path state = resume_state_path(target);

  const std::string original = to_string(ByteView(skiptest::pattern(200000, 9)));

  interrupt_download(store, session, *entry, target);
  REQUIRE(fs::exists(target));
  CHECK(fs::file_size(target) == 3 * kBlock);  // three whole blocks on disk
  CHECK(skiptest::read_all(target) == original.substr(0, 3 * kBlock));  // a real prefix
  REQUIRE(fs::exists(state));

  DownloadOptions options;
  options.resume = true;
  options.checkpoint_bytes = 1;
  const DownloadOutcome outcome = download_file(store, session, *entry, target, options);
  CHECK(outcome.reused == 3 * kBlock);
  CHECK(outcome.written_now == entry->size - outcome.reused);
  CHECK(outcome.file_size == entry->size);
  CHECK(skiptest::read_all(target) == original);
  CHECK_FALSE(fs::exists(state));  // completed: no state left behind

  // The same bytes as an uninterrupted download.
  const fs::path fresh = work.path() / "fresh.bin";
  const DownloadOutcome full = download_file(store, session, *entry, fresh);
  CHECK(full.reused == 0);
  CHECK(full.written_now == entry->size);
  CHECK(skiptest::read_all(fresh) == skiptest::read_all(target));
}

TEST_CASE("resume refuses a partial file it cannot verify") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_pattern(source.path() / "payload.bin", 140000, 3);  // 3 blocks

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "payload.bin");
  REQUIRE(entry.has_value());

  const fs::path target = work.path() / "download.bin";
  const fs::path state = resume_state_path(target);

  DownloadOptions options;
  options.resume = true;
  options.checkpoint_bytes = 1;

  SUBCASE("a modified prefix") {
    interrupt_download(store, session, *entry, target);
    {
      std::fstream file(target, std::ios::binary | std::ios::in | std::ios::out);
      REQUIRE(file.good());
      file.seekp(10);
      file.put('\x00');
    }
    CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, options); }) ==
          ErrorCode::BadResumeState);
  }

  SUBCASE("a file shorter than its state") {
    interrupt_download(store, session, *entry, target);
    fs::resize_file(target, kBlock);
    CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, options); }) ==
          ErrorCode::BadResumeState);
  }

  SUBCASE("missing state") {
    interrupt_download(store, session, *entry, target);
    fs::remove(state);
    CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, options); }) ==
          ErrorCode::BadResumeState);
  }

  SUBCASE("state from a different file") {
    skiptest::write_pattern(source.path() / "other.bin", 140000, 4);
    const PublishResult again = publish_directory(source.path(), store);
    const ShareSession other_session = open_share(store, again.link);
    const std::optional<Entry> other = resolve_path(store, other_session, "other.bin");
    REQUIRE(other.has_value());

    interrupt_download(store, session, *entry, target);
    // Same target, but the state describes payload.bin, not other.bin.
    CHECK(skiptest::code_of([&] {
            download_file(store, other_session, *other, target, options);
          }) == ErrorCode::BadResumeState);
  }

  SUBCASE("overwrite repairs a damaged download") {
    interrupt_download(store, session, *entry, target);
    {
      std::fstream file(target, std::ios::binary | std::ios::in | std::ios::out);
      REQUIRE(file.good());
      file.seekp(0);
      file.put('X');
    }
    DownloadOptions repair;
    repair.overwrite = true;
    const DownloadOutcome outcome = download_file(store, session, *entry, target, repair);
    CHECK(outcome.reused == 0);
    CHECK(outcome.written_now == entry->size);
    CHECK(skiptest::read_all(target) == to_string(ByteView(skiptest::pattern(140000, 3))));
  }
}

TEST_CASE("an existing target is refused unless resume or overwrite is asked for") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "small.txt", "hello");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "small.txt");
  REQUIRE(entry.has_value());

  const fs::path target = work.path() / "small.txt";
  skiptest::write_text(target, "something else");

  CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target); }) ==
        ErrorCode::FileExists);

  // Resume with no state is refused rather than clobbering the file.
  DownloadOptions resume;
  resume.resume = true;
  CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, resume); }) ==
        ErrorCode::BadResumeState);
  CHECK(skiptest::read_all(target) == "something else");

  // Overwrite replaces it.
  DownloadOptions overwrite;
  overwrite.overwrite = true;
  const DownloadOutcome outcome = download_file(store, session, *entry, target, overwrite);
  CHECK(outcome.written_now == 5);
  CHECK(skiptest::read_all(target) == "hello");
  CHECK_FALSE(fs::exists(resume_state_path(target)));
}

TEST_CASE("resume state that already covers the file finishes without fetching") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  const std::string content = "complete content";
  skiptest::write_text(source.path() / "notes.txt", content);

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "notes.txt");
  REQUIRE(entry.has_value());

  // A crash right after the final checkpoint leaves state that already covers
  // the whole file. Resuming must recognise that instead of refusing.
  const fs::path target = work.path() / "out.txt";
  skiptest::write_text(target, content);
  const std::string state =
      "{\"v\":1,\"file_id\":\"" + base64url_encode(ByteView(entry->file_id)) +
      "\",\"size\":" + std::to_string(entry->size) + ",\"written\":" +
      std::to_string(entry->size) + ",\"sha256\":\"" +
      base64url_encode(ByteView(crypto::sha256(ByteView(content)))) + "\"}";
  skiptest::write_text(resume_state_path(target), state);

  DownloadOptions options;
  options.resume = true;

  // The sidecar is verified locally, so no blocks are read at all.
  fs::remove_all(store.root() / "blocks");
  const DownloadOutcome outcome = download_file(store, session, *entry, target, options);
  CHECK(outcome.skipped);  // complete, reported like a no-op resume
  CHECK(outcome.reused == entry->size);
  CHECK(outcome.written_now == 0);
  CHECK(skiptest::read_all(target) == content);
  CHECK_FALSE(fs::exists(resume_state_path(target)));
}

TEST_CASE("resume on a complete file does nothing") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  const std::string content = "already here";
  skiptest::write_text(source.path() / "notes.txt", content);

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "notes.txt");
  REQUIRE(entry.has_value());

  const fs::path target = work.path() / "out.txt";
  skiptest::write_text(target, content);

  DownloadOptions options;
  options.resume = true;

  // A no-op resume must not read the share at all.
  fs::remove_all(store.root() / "blocks");
  const DownloadOutcome outcome = download_file(store, session, *entry, target, options);
  CHECK(outcome.skipped);
  CHECK(outcome.reused == entry->size);
  CHECK(outcome.written_now == 0);
  CHECK(skiptest::read_all(target) == content);
  CHECK_FALSE(fs::exists(resume_state_path(target)));

  // Without state, only a complete file is accepted: a different size is still
  // refused, as before, and the refusal leaves the file as it was.
  fs::resize_file(target, entry->size - 1);
  CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, options); }) ==
        ErrorCode::BadResumeState);
  CHECK(fs::file_size(target) == entry->size - 1);

  // A sidecar that exists but cannot be read is not "no state": even a file of
  // the right size is refused rather than silently accepted.
  skiptest::write_text(target, content);
  skiptest::write_text(resume_state_path(target), "{\"v\":1");
  CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, options); }) ==
        ErrorCode::BadResumeState);
  CHECK(skiptest::read_all(target) == content);
}

TEST_CASE("resume refuses to write through a symlink") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "notes.txt", "notes");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "notes.txt");
  REQUIRE(entry.has_value());

  // The partial file is a link to something the user did not name: appending to
  // it would extend whatever it points at.
  const fs::path victim = work.path() / "victim.txt";
  skiptest::write_text(victim, "do not touch");
  const fs::path target = work.path() / "out.txt";
  std::error_code ec;
  fs::create_symlink(victim, target, ec);
  REQUIRE_FALSE(ec);

  DownloadOptions resume;
  resume.resume = true;
  CHECK(skiptest::code_of([&] { download_file(store, session, *entry, target, resume); }) ==
        ErrorCode::UnsafeTarget);
  CHECK(skiptest::read_all(victim) == "do not touch");
  CHECK(fs::is_symlink(target));

  // An explicit overwrite replaces the link itself, not its target.
  DownloadOptions force;
  force.overwrite = true;
  const DownloadOutcome outcome = download_file(store, session, *entry, target, force);
  CHECK(outcome.written_now == 5);
  CHECK(skiptest::read_all(target) == "notes");
  CHECK(skiptest::read_all(victim) == "do not touch");
}

TEST_CASE("a range download writes exactly the requested range") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_pattern(source.path() / "payload.bin", 200000, 5);  // 4 blocks, last short

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "payload.bin");
  REQUIRE(entry.has_value());
  const std::string original = to_string(ByteView(skiptest::pattern(200000, 5)));

  const fs::path inside = work.path() / "inside.bin";
  CHECK(download_file_range(store, session, *entry, 70000, 1000, inside) == 1000);
  CHECK(skiptest::read_all(inside) == original.substr(70000, 1000));

  // A range that starts and ends inside different blocks is still clipped.
  const fs::path across = work.path() / "across.bin";
  CHECK(download_file_range(store, session, *entry, 65530, 20, across) == 20);
  CHECK(skiptest::read_all(across) == original.substr(65530, 20));

  // A range may extend past EOF; only the bytes that exist are written.
  const fs::path tail = work.path() / "tail.bin";
  CHECK(download_file_range(store, session, *entry, 199900, 100000, tail) == 100);
  CHECK(skiptest::read_all(tail) == original.substr(199900));

  // An empty range at EOF is valid and writes an empty file.
  const fs::path empty = work.path() / "empty.bin";
  CHECK(download_file_range(store, session, *entry, 200000, 10, empty) == 0);
  CHECK(fs::exists(empty));
  CHECK(fs::file_size(empty) == 0);

  // An existing target is never silently overwritten; --force replaces it.
  skiptest::write_text(inside, "keep me");
  CHECK(skiptest::code_of([&] {
          download_file_range(store, session, *entry, 0, 10, inside);
        }) == ErrorCode::FileExists);
  CHECK(skiptest::read_all(inside) == "keep me");
  CHECK(download_file_range(store, session, *entry, 0, 10, inside, true) == 10);
  CHECK(skiptest::read_all(inside) == original.substr(0, 10));

  // A symlink is refused unless an explicit overwrite replaces the link itself.
  const fs::path victim = work.path() / "victim.txt";
  skiptest::write_text(victim, "do not touch");
  const fs::path link = work.path() / "link.bin";
  std::error_code ec;
  fs::create_symlink(victim, link, ec);
  REQUIRE_FALSE(ec);
  CHECK(skiptest::code_of([&] {
          download_file_range(store, session, *entry, 5, 5, link);
        }) == ErrorCode::UnsafeTarget);
  CHECK(skiptest::read_all(victim) == "do not touch");
  CHECK(fs::is_symlink(link));
  CHECK(download_file_range(store, session, *entry, 5, 5, link, true) == 5);
  CHECK_FALSE(fs::is_symlink(link));
  CHECK(skiptest::read_all(link) == original.substr(5, 5));
  CHECK(skiptest::read_all(victim) == "do not touch");

  // A failed fetch removes the partial target instead of leaving it behind.
  const fs::path block = store.root() / "blocks" /
                         hex_encode(ByteView(entry->file_id)) / skiptest::block_name(1);
  REQUIRE(fs::exists(block));
  fs::remove(block);
  const fs::path broken = work.path() / "broken.bin";
  CHECK(skiptest::code_of([&] {
          download_file_range(store, session, *entry, 70000, 1000, broken);
        }) == ErrorCode::NotFound);
  CHECK_FALSE(fs::exists(broken));
}

TEST_CASE("an empty file downloads and leaves no resume state") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "empty", "");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const std::optional<Entry> entry = resolve_path(store, session, "empty");
  REQUIRE(entry.has_value());

  const fs::path target = work.path() / "empty";
  const DownloadOutcome outcome = download_file(store, session, *entry, target);
  CHECK(outcome.written_now == 0);
  CHECK(outcome.reused == 0);
  CHECK(fs::exists(target));
  CHECK(fs::file_size(target) == 0);
  CHECK_FALSE(fs::exists(resume_state_path(target)));
}
