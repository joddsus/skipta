// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A republish leaves the previous version's manifests and blocks in the store.
// They are still decryptable with the link, so old content survives a "delete
// and republish" until gc removes it. These tests pin what gc may delete, what
// it must keep, and when it must refuse rather than guess.
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/drive.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/gc.hpp"
#include "skipta/identity.hpp"
#include "skipta/pointer.hpp"
#include "skipta/share.hpp"
#include "skipta/store.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

const std::string kPassphrase = "gc test passphrase";
const Argon2Params kFast = Argon2Params::interactive();

struct Published {
  DriveIdentity identity;
  PublishResult result;
};

/// One publish as the CLI does it: reuse the folder's identity, publish at
/// `seq`, then store the wrapped identity back.
Published publish_next(const fs::path& source, FileStore& store, const IdentityStore& identities,
                       std::uint64_t seq) {
  std::optional<DriveIdentity> identity;
  if (identities.format(source) != IdentityFormat::Missing) {
    identity = identities.load(source, kPassphrase);
  }
  if (!identity) identity = DriveIdentity::create();
  Drive drive(identity->drive_key, identity->signing);
  PublishOptions options;
  options.identity = &drive;
  options.seq = seq;
  const PublishResult result = publish_directory(source, store, options);
  identity->seq = result.seq;
  identities.save(source, *identity, kPassphrase, kFast);
  return {*identity, result};
}

std::size_t regular_files(const fs::path& root) {
  std::size_t count = 0;
  for (const auto& entry : fs::recursive_directory_iterator(root)) {
    if (entry.is_regular_file()) ++count;
  }
  return count;
}

std::string fetch_text(const FileStore& store, const ShareSession& session,
                       const std::string& name) {
  const Entry* entry = session.root.find(name);
  if (entry == nullptr) fail(ErrorCode::NotFound, name + " is not in the share");
  std::ostringstream out;
  fetch_file(store, session, *entry, out);
  return out.str();
}

}  // namespace

TEST_CASE("gc removes superseded objects and keeps the current share") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "keep.txt", "first version");
  skiptest::write_text(source.path() / "gone.bin",
                       std::string(2 * format::kBlockPlaintextSize + 7, 'b'));

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  const Published first = publish_next(source.path(), store, identities, 1);
  REQUIRE(first.result.seq == 1);

  // Delete one file and change the other: everything the first version wrote is
  // now unreachable, and the deleted file's bytes must not survive collection.
  fs::remove(source.path() / "gone.bin");
  skiptest::write_text(source.path() / "keep.txt", "second version");
  const Published second = publish_next(source.path(), store, identities, 2);
  CHECK(second.result.link == first.result.link);

  const std::size_t objects_after = regular_files(store.root());

  // Dry run first: it reports and changes nothing.
  const GcResult dry = collect_garbage(store, {second.identity}, false);
  CHECK(dry.drives == 1);
  CHECK(dry.removable_manifests == 1);  // the superseded root manifest
  CHECK(dry.removable_blocks == 4);     // 3 blocks of gone.bin + old keep.txt
  CHECK(dry.removable_bytes > 0);
  CHECK(dry.removed_manifests == 0);
  CHECK(dry.removed_blocks == 0);
  CHECK(regular_files(store.root()) == objects_after);

  const ShareSession before = open_share(store, second.result.link);
  CHECK(before.pointer.seq == 2);
  CHECK(list_path(store, before, "").size() == 1);
  verify_path(store, before);

  // Apply: exactly the objects the dry run named go away.
  const GcResult done = collect_garbage(store, {second.identity}, true);
  CHECK(done.removed_manifests == dry.removable_manifests);
  CHECK(done.removed_blocks == dry.removable_blocks);
  CHECK(done.removed_bytes == dry.removable_bytes);
  CHECK(regular_files(store.root()) < objects_after);

  // Publisher state is not garbage, and the current share still reads.
  CHECK(fs::exists(identities.path_for(source.path())));
  CHECK(store.get_pointer(second.result.drive).has_value());
  const ShareSession after = open_share(store, second.result.link);
  CHECK(fetch_text(store, after, "keep.txt") == "second version");
  verify_path(store, after);

  // A second pass has nothing left to do.
  const GcResult idle = collect_garbage(store, {second.identity}, true);
  CHECK(idle.removable_manifests == 0);
  CHECK(idle.removable_blocks == 0);
  CHECK(regular_files(store.root()) == objects_after - done.removed_manifests -
                                           done.removed_blocks);
}

TEST_CASE("gc keeps every drive when a store holds more than one") {
  skiptest::TempDir one("one");
  skiptest::TempDir two("two");
  skiptest::TempDir work("store");
  skiptest::write_text(one.path() / "a.txt", "drive one");
  skiptest::write_text(two.path() / "b.txt", std::string(70000, 'c'));

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  const Published first = publish_next(one.path(), store, identities, 1);
  const Published second = publish_next(two.path(), store, identities, 1);
  CHECK(first.result.link != second.result.link);

  // Knowing only one drive means the other drive's objects look unreachable.
  // gc must refuse instead of deleting them.
  CHECK(skiptest::code_of([&] {
          collect_garbage(store, {first.identity}, true);
        }) == ErrorCode::UnsafeStore);
  CHECK(store.get_pointer(second.result.drive).has_value());
  CHECK(fetch_text(store, open_share(store, second.result.link), "b.txt") ==
        std::string(70000, 'c'));

  // With both drives accounted for, nothing current is removable.
  const GcResult result = collect_garbage(store, {first.identity, second.identity}, true);
  CHECK(result.drives == 2);
  CHECK(result.reachable_manifests >= 2);
  CHECK(result.reachable_files == 2);
  CHECK(result.removable_manifests == 0);
  CHECK(result.removable_blocks == 0);
  verify_path(store, open_share(store, first.result.link));
  verify_path(store, open_share(store, second.result.link));
}

TEST_CASE("gc refuses a store it cannot account for") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "a");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  const Published published = publish_next(source.path(), store, identities, 1);
  const std::size_t objects = regular_files(store.root());

  // A drive with a pointer but no identity cannot be walked; nothing is deleted.
  CHECK(skiptest::code_of([&] {
          collect_garbage(store, {}, true);
        }) == ErrorCode::UnsafeStore);
  CHECK(regular_files(store.root()) == objects);
  CHECK(open_share(store, published.result.link).pointer.seq == 1);

  // An identity with no pointer (an interrupted first publish) is refused too.
  fs::remove(identities.path_for(source.path()));
  const DriveIdentity orphan = DriveIdentity::create();
  identities.save(source.path(), orphan, kPassphrase, kFast);
  CHECK(skiptest::code_of([&] {
          collect_garbage(store, {orphan}, true);
        }) == ErrorCode::UnsafeStore);
  CHECK(regular_files(store.root()) == objects);
}

TEST_CASE("gc keeps links and names it does not own") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "first");
  skiptest::write_text(source.path() / "b.txt", std::string(70000, 'd'));

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  publish_next(source.path(), store, identities, 1);
  fs::remove(source.path() / "b.txt");
  const Published second = publish_next(source.path(), store, identities, 2);

  // A symlink shaped like a block directory and an unknown file name are not
  // store objects: they are ignored, never followed, never removed.
  const fs::path outside = work.path() / "outside";
  fs::create_directories(outside);
  skiptest::write_text(outside / "precious.bin", "do not delete");
  const fs::path link = store.root() / "blocks" / std::string(32, 'a');
  std::error_code ec;
  fs::create_symlink(outside, link, ec);
  REQUIRE_FALSE(ec);
  skiptest::write_text(store.root() / "manifests" / "notes.txt", "a human note");

  const GcResult result = collect_garbage(store, {second.identity}, true);
  CHECK(result.ignored >= 2);
  CHECK(fs::exists(outside / "precious.bin"));
  CHECK(fs::is_symlink(link));
  CHECK(fs::exists(store.root() / "manifests" / "notes.txt"));
  verify_path(store, open_share(store, second.result.link));
}

TEST_CASE("gc deletes nothing when a current object is unreadable") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "a");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  const Published published = publish_next(source.path(), store, identities, 1);

  const SignedPointer signed_pointer =
      decode_signed_pointer(ByteView(*store.get_pointer(published.result.drive)));
  const RootPointer pointer = verify_pointer(published.result.drive, signed_pointer, 0);
  const fs::path root_manifest =
      store.root() / "manifests" / (hex_encode(ByteView(pointer.root)) + ".mf");
  REQUIRE(fs::exists(root_manifest));
  skiptest::write_text(root_manifest, "not a sealed manifest");

  const std::size_t objects = regular_files(store.root());
  CHECK(skiptest::code_of([&] {
          collect_garbage(store, {published.identity}, true);
        }) != static_cast<ErrorCode>(-1));
  CHECK(regular_files(store.root()) == objects);
}

TEST_CASE("gc on an empty store reports nothing") {
  skiptest::TempDir work("store");
  const FileStore store(work.path() / "empty");

  const GcResult result = collect_garbage(store, {}, false);
  CHECK(result.drives == 0);
  CHECK(result.reachable_manifests == 0);
  CHECK(result.removable_manifests == 0);
  CHECK(result.removable_blocks == 0);
  CHECK(result.removed_bytes == 0);
  CHECK(fs::exists(work.path() / "empty" / ".lock"));
}
