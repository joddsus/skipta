// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The trust boundary of the CLI, exercised with real sealed artifacts and real
// filesystem objects rather than assumptions:
//
//   * a manifest is untrusted metadata, so a hostile name must be rejected
//     before extraction can name a file at all;
//   * a source folder is untrusted input, so links and special files must never
//     be followed out of it;
//   * every stored object is untrusted, so a flipped, truncated or swapped
//     object must fail authentication and never be emitted as content;
//   * the store and identity are secrets on disk, so they must be owner-only
//     regardless of umask, and a failed write must leave no temp key behind.
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <sys/types.h>
#if defined(__linux__)
#include <sys/sysmacros.h>
#endif
#include <unistd.h>
#endif

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/download.hpp"
#include "skipta/drive.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/identity.hpp"
#include "skipta/json.hpp"
#include "skipta/manifest.hpp"
#include "skipta/pointer.hpp"
#include "skipta/share.hpp"
#include "skipta/store.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

const Argon2Params kFast = Argon2Params::interactive();

jsonx::Json file_entry(const std::string& name) {
  jsonx::Json entry;
  entry["name"] = name;
  entry["kind"] = "file";
  entry["mtime"] = 0;
  entry["size"] = 0;
  entry["file_id"] = base64url_encode(ByteView(crypto::random_id()));
  return entry;
}

jsonx::Json dir_entry(const std::string& name, const Id128& manifest_id) {
  jsonx::Json entry;
  entry["name"] = name;
  entry["kind"] = "dir";
  entry["mtime"] = 0;
  entry["manifest_id"] = base64url_encode(ByteView(manifest_id));
  return entry;
}

/// Plaintext manifest JSON with whatever entries the caller wants. Publishing
/// would reject these; an attacker sealing their own manifest is not bound by it.
std::string manifest_text(const Id128& id, jsonx::Json entries) {
  jsonx::Json j;
  j["v"] = 1;
  j["id"] = base64url_encode(ByteView(id));
  j["seq"] = 1;
  j["entries"] = std::move(entries);
  return jsonx::dump(j, "manifest");
}

/// Seal arbitrary bytes exactly as a hostile publisher would: the manifest key
/// and nonce come from the format, but the plaintext never passes validation.
Bytes seal_raw_manifest(const Drive& drive, const Id128& id, const std::string& text) {
  Key32 key = format::derive_manifest_key(drive.drive_key(), id);
  const auto nonce = format::manifest_nonce(id);
  const Bytes aad = format::manifest_aad(id);
  Bytes sealed = crypto::aead_seal(key, ByteView(nonce), ByteView(aad), ByteView(text));
  crypto::wipe(key.data(), key.size());
  return sealed;
}

/// Installs `text` as the root manifest of `drive` and signs a pointer to it.
std::string install_hostile_root(FileStore& store, const Drive& drive, const Id128& id,
                                 const std::string& text) {
  store.put_manifest(id, ByteView(seal_raw_manifest(drive, id, text)));
  RootPointer pointer;
  pointer.drive = drive.public_key();
  pointer.seq = 1;
  pointer.root = id;
  pointer.issued_at = 0;
  const SignedPointer signed_pointer = drive.sign_root(pointer);
  store.put_pointer(drive.public_key(), ByteView(encode_signed_pointer(signed_pointer)));
  return encode_link(drive.share_link({}));
}

bool has_tmp_name(const fs::path& root) {
  for (const auto& entry : fs::recursive_directory_iterator(root)) {
    if (entry.path().filename().string().find(".tmp-") != std::string::npos) return true;
  }
  return false;
}

#if !defined(_WIN32)
void check_owner_only_dir(const fs::path& path) {
  const fs::perms perms = fs::status(path).permissions();
  CHECK((perms & fs::perms::group_all) == fs::perms::none);
  CHECK((perms & fs::perms::others_all) == fs::perms::none);
  CHECK((perms & fs::perms::owner_all) == fs::perms::owner_all);
}

void check_owner_only_file(const fs::path& path) {
  const fs::perms perms = fs::status(path).permissions();
  CHECK((perms & fs::perms::group_all) == fs::perms::none);
  CHECK((perms & fs::perms::others_all) == fs::perms::none);
  CHECK((perms & fs::perms::owner_read) == fs::perms::owner_read);
  CHECK((perms & fs::perms::owner_write) == fs::perms::owner_write);
}
#endif

}  // namespace

TEST_CASE("hostile manifest names are rejected before any extraction") {
  struct Attack {
    std::string name;
    ErrorCode expected;
  };
  const std::vector<Attack> attacks = {
      {"../escape", ErrorCode::PathSeparator},
      {"../../etc/evil", ErrorCode::PathSeparator},
      {"/tmp/evil", ErrorCode::PathSeparator},
      {"a/../../b", ErrorCode::PathSeparator},
      {"", ErrorCode::EmptyName},
      {".", ErrorCode::DotName},
      {"..", ErrorCode::DotName},
      {std::string("nul\0byte", 8), ErrorCode::NulByte},
      {"new\nline", ErrorCode::ControlChar},
  };

  for (const Attack& attack : attacks) {
    skiptest::TempDir work("attack");
    FileStore store(work.path() / "store");
    const Drive drive = Drive::create();
    const Id128 root_id = crypto::random_id();
    jsonx::Json entries = jsonx::Json::array();
    entries.push_back(file_entry(attack.name));
    const std::string link =
        install_hostile_root(store, drive, root_id, manifest_text(root_id, std::move(entries)));

    // The session never opens, so there is nothing to extract. Whatever the
    // caller does next cannot name a destination outside its own folder.
    CHECK(skiptest::code_of([&] { (void)open_share(store, link); }) == attack.expected);

    // The refused manifest is not silently rewritten or removed.
    CHECK(store.get_manifest(root_id).has_value());
  }
}

TEST_CASE("duplicate and case-colliding manifest names are rejected") {
  skiptest::TempDir work("attack");
  FileStore store(work.path() / "store");
  const Drive drive = Drive::create();

  const Id128 duplicate_id = crypto::random_id();
  jsonx::Json duplicate = jsonx::Json::array();
  duplicate.push_back(file_entry("same.txt"));
  duplicate.push_back(file_entry("same.txt"));
  const std::string duplicate_link = install_hostile_root(
      store, drive, duplicate_id, manifest_text(duplicate_id, std::move(duplicate)));
  // The parser reports a repeated name as either DuplicateName or, because the
  // case-insensitive set sees it first, CaseCollision; both refuse the manifest.
  const ErrorCode duplicate_code =
      skiptest::code_of([&] { (void)open_share(store, duplicate_link); });
  CHECK((duplicate_code == ErrorCode::DuplicateName ||
         duplicate_code == ErrorCode::CaseCollision));

  const Id128 case_id = crypto::random_id();
  jsonx::Json collision = jsonx::Json::array();
  collision.push_back(file_entry("Photo.JPG"));
  collision.push_back(file_entry("photo.jpg"));
  const std::string case_link =
      install_hostile_root(store, drive, case_id, manifest_text(case_id, std::move(collision)));
  CHECK(skiptest::code_of([&] { (void)open_share(store, case_link); }) ==
        ErrorCode::CaseCollision);
}

TEST_CASE("a hostile name in a child manifest cannot escape the destination") {
  skiptest::TempDir work("attack");
  FileStore store(work.path() / "store");
  const Drive drive = Drive::create();

  // The root is valid; the hostile name is one level down, so extraction has
  // already started when the child manifest is opened.
  const Id128 child_id = crypto::random_id();
  jsonx::Json child_entries = jsonx::Json::array();
  child_entries.push_back(file_entry("../escape"));
  store.put_manifest(
      child_id, ByteView(seal_raw_manifest(drive, child_id,
                                           manifest_text(child_id, std::move(child_entries)))));

  const Id128 root_id = crypto::random_id();
  jsonx::Json root_entries = jsonx::Json::array();
  root_entries.push_back(dir_entry("sub", child_id));
  const std::string link =
      install_hostile_root(store, drive, root_id, manifest_text(root_id, std::move(root_entries)));

  const ShareSession session = open_share(store, link);
  REQUIRE(session.root.entries.size() == 1);

  const fs::path destination = work.path() / "dest";
  CHECK(skiptest::code_of([&] {
          download_directory(store, session, "", destination);
        }) == ErrorCode::PathSeparator);

  // The child directory exists because the valid root entry created it, but no
  // hostile name was turned into a file, inside or outside the destination.
  CHECK(fs::exists(destination / "sub"));
  CHECK(fs::is_empty(destination / "sub"));
  CHECK_FALSE(fs::exists(destination / "escape"));
  CHECK_FALSE(fs::exists(work.path() / "escape"));
}

TEST_CASE("extraction refuses to clobber unrelated files and directories") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "alpha");
  skiptest::write_text(source.path() / "sub" / "beta.txt", "beta");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);

  // A file entry must not replace a directory, even one with content.
  const fs::path dir_clash = work.path() / "dir-clash";
  fs::create_directories(dir_clash / "a.txt");
  skiptest::write_text(dir_clash / "a.txt" / "sentinel.txt", "keep");
  CHECK(skiptest::code_of([&] {
          download_directory(store, session, "", dir_clash);
        }) == ErrorCode::FileExists);
  CHECK(skiptest::read_all(dir_clash / "a.txt" / "sentinel.txt") == "keep");

  // A directory entry must not replace a regular file, even with --force.
  const fs::path file_clash = work.path() / "file-clash";
  fs::create_directories(file_clash);
  skiptest::write_text(file_clash / "sub", "sentinel");
  DirectoryOptions force;
  force.file.overwrite = true;
  CHECK(skiptest::code_of([&] {
          download_directory(store, session, "", file_clash, force);
        }) == ErrorCode::FileExists);
  CHECK(skiptest::read_all(file_clash / "sub") == "sentinel");

  // A file whose name is not in the manifest is never touched, while the
  // manifest's own target is replaced (that is the extraction destination).
  const fs::path mixed = work.path() / "mixed";
  fs::create_directories(mixed);
  skiptest::write_text(mixed / "unrelated.txt", "keep me");
  // A same-size file would count as complete (size is the skip check); a
  // different size is what the extractor replaces for that manifest entry.
  skiptest::write_text(mixed / "a.txt", "stale-content");
  const DirectoryOutcome outcome = download_directory(store, session, "", mixed);
  CHECK(outcome.written_now == 9);
  CHECK(skiptest::read_all(mixed / "unrelated.txt") == "keep me");
  CHECK(skiptest::read_all(mixed / "a.txt") == "alpha");
  CHECK(skiptest::read_all(mixed / "sub" / "beta.txt") == "beta");
}

TEST_CASE("publishing never follows links or special files out of the folder") {
  skiptest::TempDir source("source");
  skiptest::TempDir work("store");
  skiptest::TempDir outside("outside");
  const std::string secret = "TOP-SECRET-OUTSIDE-CONTENT";
  skiptest::write_text(outside.path() / "secret.txt", secret);
  skiptest::write_text(source.path() / "inside.txt", "inside content");
  skiptest::write_text(source.path() / "realdir" / "nested.txt", "nested content");

  std::error_code ec;
  fs::create_symlink(outside.path() / "secret.txt", source.path() / "file-link", ec);
  REQUIRE_FALSE(ec);
  fs::create_symlink(source.path(), source.path() / "dir-loop", ec);
  REQUIRE_FALSE(ec);
  fs::create_symlink(outside.path(), source.path() / "outside-dir", ec);
  REQUIRE_FALSE(ec);

  unsigned special = 3;
#if !defined(_WIN32)
  REQUIRE(::mkfifo((source.path() / "pipe").c_str(), 0600) == 0);
  ++special;
  // A device node usually needs privileges; when it exists, it must be skipped.
  const bool device = ::mknod((source.path() / "device").c_str(), S_IFCHR | 0600,
                              makedev(1, 3)) == 0;
  if (device) ++special;
#endif

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);

  CHECK(published.files == 2);
  CHECK(published.directories == 1);
  CHECK(published.skipped.size() >= special);

  const ShareSession session = open_share(store, published.link);
  CHECK(session.root.find("inside.txt") != nullptr);
  CHECK(session.root.find("realdir") != nullptr);
  CHECK(session.root.find("file-link") == nullptr);
  CHECK(session.root.find("dir-loop") == nullptr);
  CHECK(session.root.find("outside-dir") == nullptr);
  CHECK(session.root.find("pipe") == nullptr);
#if !defined(_WIN32)
  if (device) CHECK(session.root.find("device") == nullptr);
#endif

  // Decrypt everything that did make it in: the outside content is nowhere.
  for (const Entry& entry : session.root.entries) {
    if (entry.kind != EntryKind::File) continue;
    std::ostringstream out;
    fetch_file(store, session, entry, out);
    CHECK(out.str().find(secret) == std::string::npos);
  }
  for (const auto& entry : fs::recursive_directory_iterator(store.root())) {
    if (!entry.is_regular_file()) continue;
    CHECK(skiptest::read_all(entry.path()).find(secret) == std::string::npos);
  }
}

TEST_CASE("an unreadable source file fails the publish before a pointer exists") {
#if !defined(_WIN32)
  if (::geteuid() == 0) return;  // root reads everything; the case cannot be staged
#endif
  skiptest::TempDir source("source");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a-readable.txt", "ok");
  const fs::path blocked = source.path() / "z-unreadable.txt";
  skiptest::write_text(blocked, "cannot read this");
  fs::permissions(blocked, fs::perms::none);

  FileStore store(work.path() / "store");
  const ErrorCode code = skiptest::code_of([&] { (void)publish_directory(source.path(), store); });
  fs::permissions(blocked, fs::perms::owner_read | fs::perms::owner_write);
  REQUIRE(code == ErrorCode::StoreIo);

  // A publish commits by writing the pointer; without one, no reader can see
  // the half-written tree, and no key or manifest survives under a final name.
  CHECK_FALSE(fs::exists(store.root() / "pointers"));
  CHECK_FALSE(has_tmp_name(store.root()));
}

TEST_CASE("a too-deep source tree is refused without hanging") {
  skiptest::TempDir source("source");
  skiptest::TempDir work("store");
  fs::path deep = source.path();
  for (int i = 0; i < 40; ++i) {
    deep /= "d" + std::to_string(i);
    fs::create_directories(deep);
  }
  skiptest::write_text(deep / "leaf.txt", "leaf");

  FileStore store(work.path() / "store");
  CHECK(skiptest::code_of([&] { (void)publish_directory(source.path(), store); }) ==
        ErrorCode::TooDeep);
  CHECK_FALSE(fs::exists(store.root() / "pointers"));
  CHECK_FALSE(has_tmp_name(store.root()));
}

TEST_CASE("corrupted blocks are rejected and never emitted as content") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "big.bin",
                       std::string(2 * format::kBlockPlaintextSize, 'q'));

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);
  const Entry* big = session.root.find("big.bin");
  REQUIRE(big != nullptr);
  REQUIRE(big->size == 2 * format::kBlockPlaintextSize);

  const fs::path dir = store.root() / "blocks" / hex_encode(ByteView(big->file_id));
  const fs::path first = dir / skiptest::block_name(0);
  const fs::path second = dir / skiptest::block_name(1);
  const std::string good_first = skiptest::read_all(first);
  const std::string good_second = skiptest::read_all(second);
  REQUIRE(good_first.size() > 1);

  const auto fetch_rejected = [&](ErrorCode expected) {
    std::ostringstream out;
    CHECK(skiptest::code_of([&] { fetch_file(store, session, *big, out); }) == expected);
    CHECK(out.str().empty());  // no partial plaintext on the way to the caller

    // A fresh download must fail and leave no output file or resume state.
    const fs::path target = work.path() / "out.bin";
    fs::remove(target);
    fs::remove(resume_state_path(target));
    CHECK(skiptest::code_of([&] { download_file(store, session, *big, target); }) == expected);
    CHECK_FALSE(fs::exists(target));
    CHECK_FALSE(fs::exists(resume_state_path(target)));
  };

  // One flipped byte in the first block.
  std::string flipped = good_first;
  flipped[0] = static_cast<char>(flipped[0] ^ 0x01);
  skiptest::write_text(first, flipped);
  fetch_rejected(ErrorCode::AuthFailed);
  skiptest::write_text(first, good_first);

  // A truncated block fails the fixed-size check before decryption.
  skiptest::write_text(first, good_first.substr(0, 5));
  fetch_rejected(ErrorCode::SizeMismatch);
  skiptest::write_text(first, good_first);

  // Swapping two blocks keeps the bytes valid but the index in the AAD wrong.
  skiptest::write_text(first, good_second);
  skiptest::write_text(second, good_first);
  fetch_rejected(ErrorCode::AuthFailed);
  skiptest::write_text(first, good_first);
  skiptest::write_text(second, good_second);

  // The store is back to a valid state and still reads.
  std::ostringstream out;
  fetch_file(store, session, *big, out);
  CHECK(out.str() == std::string(2 * format::kBlockPlaintextSize, 'q'));
}

TEST_CASE("corrupted manifests, pointers and wrong-drive manifests are rejected") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "alpha");

  FileStore store(work.path() / "store");
  const PublishResult published = publish_directory(source.path(), store);
  const ShareSession session = open_share(store, published.link);

  const fs::path manifest_path =
      store.root() / "manifests" / (hex_encode(ByteView(session.pointer.root)) + ".mf");
  const std::string good_manifest = skiptest::read_all(manifest_path);
  REQUIRE(good_manifest.size() > 1);

  // A flipped byte in the sealed manifest fails authentication.
  std::string flipped = good_manifest;
  flipped[0] = static_cast<char>(flipped[0] ^ 0x01);
  skiptest::write_text(manifest_path, flipped);
  CHECK(skiptest::code_of([&] { (void)open_share(store, published.link); }) ==
        ErrorCode::AuthFailed);
  skiptest::write_text(manifest_path, good_manifest);

  // A truncated manifest cannot be authenticated either.
  skiptest::write_text(manifest_path, good_manifest.substr(0, good_manifest.size() / 2));
  CHECK(skiptest::code_of([&] { (void)open_share(store, published.link); }) ==
        ErrorCode::AuthFailed);
  skiptest::write_text(manifest_path, good_manifest);

  // A manifest sealed under another drive key is not readable with this link.
  const Drive other = Drive::create();
  Manifest impostor = Manifest::create(1);
  impostor.id = session.pointer.root;
  store.put_manifest(impostor.id, ByteView(other.seal_manifest(impostor)));
  CHECK(skiptest::code_of([&] { (void)open_share(store, published.link); }) ==
        ErrorCode::AuthFailed);
  skiptest::write_text(manifest_path, good_manifest);

  // A corrupted pointer signature is BadSignature, not a content error.
  const std::optional<Bytes> raw_pointer = store.get_pointer(published.drive);
  REQUIRE(raw_pointer.has_value());
  SignedPointer signed_pointer = decode_signed_pointer(ByteView(*raw_pointer));
  signed_pointer.signature[0] = static_cast<unsigned char>(signed_pointer.signature[0] ^ 0x01);
  store.put_pointer(published.drive, ByteView(encode_signed_pointer(signed_pointer)));
  CHECK(skiptest::code_of([&] { (void)open_share(store, published.link); }) ==
        ErrorCode::BadSignature);

  // Restored, the same store opens and fetches the content again.
  store.put_pointer(published.drive, ByteView(*raw_pointer));
  const ShareSession restored = open_share(store, published.link);
  std::ostringstream out;
  fetch_file(store, restored, *restored.root.find("a.txt"), out);
  CHECK(out.str() == "alpha");
}

TEST_CASE("store files and the identity are owner-only even with umask 0") {
#if !defined(_WIN32)
  const mode_t previous = ::umask(0);
  struct RestoreUmask {
    mode_t mode;
    ~RestoreUmask() { ::umask(mode); }
  } restore{previous};

  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "alpha");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  DriveIdentity identity = DriveIdentity::create();
  Drive drive(identity.drive_key, identity.signing);
  PublishOptions options;
  options.identity = &drive;
  options.seq = 1;
  const PublishResult published = publish_directory(source.path(), store, options);
  identity.seq = published.seq;
  identities.save(source.path(), identity, "passphrase", kFast);
  remember_pointer_seq(store, published.drive, published.seq);

  const ShareSession session = open_share(store, published.link);
  const Entry* entry = session.root.find("a.txt");
  REQUIRE(entry != nullptr);

  check_owner_only_dir(store.root());
  check_owner_only_dir(store.root() / "pointers");
  check_owner_only_dir(store.root() / "manifests");
  check_owner_only_dir(store.root() / "blocks");
  check_owner_only_dir(store.root() / "blocks" / hex_encode(ByteView(entry->file_id)));
  check_owner_only_dir(store.root() / "identities");
  check_owner_only_dir(store.root() / "accepted");

  check_owner_only_file(store.root() / "pointers" /
                        (hex_encode(ByteView(published.drive)) + ".ptr"));
  check_owner_only_file(store.root() / "manifests" /
                        (hex_encode(ByteView(session.pointer.root)) + ".mf"));
  check_owner_only_file(store.root() / "blocks" / hex_encode(ByteView(entry->file_id)) /
                        skiptest::block_name(0));
  check_owner_only_file(identities.path_for(source.path()));
  check_owner_only_file(store.root() / "accepted" /
                        (hex_encode(ByteView(published.drive)) + ".seq"));

  // No temp file from an interrupted or successful write is left behind.
  CHECK_FALSE(has_tmp_name(store.root()));
#endif
}
