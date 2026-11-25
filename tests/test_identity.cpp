// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A drive identity is kept between publishing runs, so a republish updates the
// same link and advances the pointer's seq instead of forking a new share. A
// reader that remembers the seq it accepted refuses the previous pointer.
//
// The identity is a publisher secret. These tests pin that the stored file is
// wrapped with the passphrase, that a legacy plaintext file is migrated without
// leaving the seed behind, and that a wrong passphrase is refused.
#include <array>
#include <cstdint>
#include <filesystem>
#include <sstream>
#include <string>
#include <system_error>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/identity.hpp"
#include "skipta/keywrap.hpp"
#include "skipta/pointer.hpp"
#include "skipta/share.hpp"

using namespace skipta;
namespace fs = std::filesystem;

namespace {

const std::string kPassphrase = "correct horse battery staple";
const Argon2Params kFast = Argon2Params::interactive();  // test speed only

std::array<unsigned char, 32> seed_of(const DriveIdentity& identity) {
  std::array<unsigned char, 32> seed{};
  std::copy(identity.signing.secret.begin(), identity.signing.secret.begin() + 32, seed.begin());
  return seed;
}

/// One publish as the CLI does it: load (with the passphrase) or create the
/// identity, publish with the next seq, then store the wrapped identity back.
PublishResult publish_as_next_run(const fs::path& source, FileStore& store,
                                  const IdentityStore& identities,
                                  const std::string& passphrase = kPassphrase) {
  const IdentityFormat format = identities.format(source);
  std::optional<DriveIdentity> stored;
  if (format != IdentityFormat::Missing) stored = identities.load(source, passphrase);
  if (!stored) stored = DriveIdentity::create();
  const Drive drive(stored->drive_key, stored->signing);
  PublishOptions options;
  options.identity = &drive;
  options.seq = stored->seq + 1;
  const PublishResult result = publish_directory(source, store, options);
  stored->seq = result.seq;
  identities.save(source, *stored, passphrase, kFast);
  return result;
}

/// Writes the pre-upgrade on-disk form: the v1 plaintext file, owner-only.
void write_legacy_identity(const IdentityStore& identities, const fs::path& source,
                           const DriveIdentity& identity) {
  const fs::path path = identities.path_for(source);
  fs::create_directories(path.parent_path());
  skiptest::write_text(path, to_string(ByteView(encode_identity(identity))));
  std::error_code ec;
  fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, ec);
  REQUIRE_FALSE(ec);
}

bool file_contains(const std::string& haystack, ByteView needle) {
  if (needle.size == 0) return false;
  return haystack.find(to_string(needle)) != std::string::npos;
}

}  // namespace

TEST_CASE("a drive identity round-trips through its legacy file format") {
  const DriveIdentity identity = DriveIdentity::create();
  const DriveIdentity restored = decode_identity(ByteView(encode_identity(identity)));
  CHECK(restored.drive_key == identity.drive_key);
  CHECK(restored.signing.pub == identity.signing.pub);
  CHECK(restored.signing.secret == identity.signing.secret);
  CHECK(restored.seq == identity.seq);

  // A recorded public key that does not belong to the seed is refused rather
  // than silently becoming another drive.
  std::string text = to_string(ByteView(encode_identity(identity)));
  const std::string pub_b64 = base64url_encode(ByteView(identity.signing.pub));
  const std::string other_b64 =
      base64url_encode(ByteView(crypto::SigningKeyPair::generate().pub));
  const std::size_t at = text.find(pub_b64);
  REQUIRE(at != std::string::npos);
  text.replace(at, pub_b64.size(), other_b64);
  CHECK(skiptest::code_of([&] { decode_identity(ByteView(text)); }) == ErrorCode::DriveMismatch);

  const std::string with_extra =
      to_string(ByteView(encode_identity(identity))).substr(0, 1) + "\"extra\":1," +
      to_string(ByteView(encode_identity(identity))).substr(1);
  CHECK(skiptest::code_of([&] { decode_identity(ByteView(with_extra)); }) ==
        ErrorCode::UnknownField);
}

TEST_CASE("the wrapped identity round-trips and hides the drive key and seed") {
  DriveIdentity identity = DriveIdentity::create();
  identity.seq = 7;

  const Bytes wrapped = encode_wrapped_identity(identity, kPassphrase, kFast);
  const DriveIdentity restored = decode_wrapped_identity(ByteView(wrapped), kPassphrase);
  CHECK(restored.drive_key == identity.drive_key);
  CHECK(restored.signing.secret == identity.signing.secret);
  CHECK(restored.signing.pub == identity.signing.pub);
  CHECK(restored.seq == 7);

  // The file is a v2 envelope and contains no form of either secret.
  const std::string text = to_string(ByteView(wrapped));
  CHECK(text.find("\"v\":2") != std::string::npos);
  CHECK_FALSE(file_contains(text, ByteView(identity.drive_key)));
  CHECK_FALSE(file_contains(text, ByteView(seed_of(identity))));
  CHECK(text.find(base64url_encode(ByteView(identity.drive_key))) == std::string::npos);
  CHECK(text.find(base64url_encode(ByteView(seed_of(identity)))) == std::string::npos);
  CHECK(text.find(hex_encode(ByteView(identity.drive_key))) == std::string::npos);
  CHECK(text.find(hex_encode(ByteView(seed_of(identity)))) == std::string::npos);
  CHECK(text.find("signing_seed") == std::string::npos);
  CHECK(text.find("drive_key") == std::string::npos);

  // Wrong passphrase and tampered ciphertext are both BadPassphrase.
  CHECK(skiptest::code_of([&] { decode_wrapped_identity(ByteView(wrapped), "wrong"); }) ==
        ErrorCode::BadPassphrase);
  std::string tampered = text;
  const std::size_t ct = tampered.find("\"ct\":\"");
  REQUIRE(ct != std::string::npos);
  tampered[ct + 7] = tampered[ct + 7] == 'A' ? 'B' : 'A';
  CHECK(skiptest::code_of([&] {
          decode_wrapped_identity(ByteView(tampered), kPassphrase);
        }) == ErrorCode::BadPassphrase);

  // The two formats never stand in for each other.
  CHECK(skiptest::code_of([&] {
          decode_wrapped_identity(ByteView(encode_identity(identity)), kPassphrase);
        }) == ErrorCode::UnsupportedIdentity);
  CHECK(skiptest::code_of([&] { decode_identity(ByteView(wrapped)); }) ==
        ErrorCode::BadVersion);
}

TEST_CASE("republishing from a saved wrapped identity keeps the link and advances seq") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "notes.txt", "first version");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");

  // ---- run 1: a fresh identity is created, wrapped, and saved -------------
  const PublishResult first = publish_as_next_run(source.path(), store, identities);
  REQUIRE(first.seq == 1);
  const Bytes old_pointer = *store.get_pointer(first.drive);
  CHECK(identities.format(source.path()) == IdentityFormat::Wrapped);
  REQUIRE(identities.load(source.path(), kPassphrase).has_value());
  CHECK(identities.load(source.path(), kPassphrase)->seq == 1);

  // Only the passphrase opens it.
  CHECK(skiptest::code_of([&] { (void)identities.load(source.path(), "wrong"); }) ==
        ErrorCode::BadPassphrase);
  CHECK(skiptest::code_of([&] { (void)identities.load(source.path(), ""); }) ==
        ErrorCode::BadPassphrase);

  // The file is owner-only and contains neither secret.
  const fs::path identity_path = identities.path_for(source.path());
  const fs::perms perms = fs::status(identity_path).permissions();
  CHECK((perms & fs::perms::group_all) == fs::perms::none);
  CHECK((perms & fs::perms::others_all) == fs::perms::none);
  const std::string on_disk = skiptest::read_all(identity_path);
  const DriveIdentity loaded = *identities.load(source.path(), kPassphrase);
  CHECK_FALSE(file_contains(on_disk, ByteView(loaded.drive_key)));
  CHECK_FALSE(file_contains(on_disk, ByteView(seed_of(loaded))));

  const ShareSession first_session = open_share(store, first.link);
  CHECK(first_session.pointer.seq == 1);
  REQUIRE(first_session.root.find("notes.txt") != nullptr);

  // ---- run 2: same folder, changed content, reloaded identity ------------
  skiptest::write_text(source.path() / "notes.txt", "second version");
  skiptest::write_text(source.path() / "extra.txt", "new file");
  const PublishResult second = publish_as_next_run(source.path(), store, identities);

  CHECK(second.link == first.link);  // the link is stable across runs
  CHECK(second.drive == first.drive);
  CHECK(second.seq == 2);
  CHECK(identities.load(source.path(), kPassphrase)->seq == 2);

  const ShareSession session = open_share(store, second.link);
  CHECK(session.pointer.seq == 2);
  CHECK(session.pointer.root != first_session.pointer.root);  // content did change
  CHECK(session.root.find("extra.txt") != nullptr);

  const Bytes new_pointer = *store.get_pointer(second.drive);

  // ---- a replayed older pointer is refused ------------------------------
  CHECK(accepted_pointer_seq(store, second.drive) == 0);
  remember_pointer_seq(store, second.drive, session.pointer.seq);
  CHECK(accepted_pointer_seq(store, second.drive) == 2);

  store.put_pointer(second.drive, ByteView(old_pointer));
  CHECK(skiptest::code_of([&] {
          open_share(store, second.link, accepted_pointer_seq(store, second.drive));
        }) == ErrorCode::StalePointer);
  // Without a remembered seq the same replay looks like a normal, older drive.
  CHECK(open_share(store, second.link).pointer.seq == 1);

  // The current pointer is still accepted, and the memory never goes backwards.
  store.put_pointer(second.drive, ByteView(new_pointer));
  CHECK(open_share(store, second.link, accepted_pointer_seq(store, second.drive))
            .pointer.seq == 2);
  remember_pointer_seq(store, second.drive, 1);
  CHECK(accepted_pointer_seq(store, second.drive) == 2);

  // ---- run 3: seq keeps increasing ---------------------------------------
  const PublishResult third = publish_as_next_run(source.path(), store, identities);
  CHECK(third.link == first.link);
  CHECK(third.seq == 3);
  CHECK(open_share(store, third.link, 2).pointer.seq == 3);
}

TEST_CASE("a legacy plaintext identity migrates without leaving the seed") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "old.txt", "published before the upgrade");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");

  // Build the pre-upgrade state: a plaintext identity and a seq 1 share made
  // with it, exactly as an older build would have left the store.
  DriveIdentity legacy = DriveIdentity::create();
  Drive drive(legacy.drive_key, legacy.signing);
  PublishOptions options;
  options.identity = &drive;
  options.seq = 1;
  const PublishResult before = publish_directory(source.path(), store, options);
  legacy.seq = 1;
  write_legacy_identity(identities, source.path(), legacy);

  REQUIRE(identities.format(source.path()) == IdentityFormat::Plaintext);
  CHECK(identities.load(source.path(), "a passphrase is not needed yet")->drive_key ==
        legacy.drive_key);

  // The share published before the migration is readable now.
  {
    const ShareSession session = open_share(store, before.link);
    const std::optional<Entry> entry = resolve_path(store, session, "old.txt");
    REQUIRE(entry.has_value());
    std::ostringstream out;
    fetch_file(store, session, *entry, out);
    CHECK(out.str() == "published before the upgrade");
  }

  // The next publish sets a passphrase and rewrites the same path as v2.
  const PublishResult after = publish_as_next_run(source.path(), store, identities);
  CHECK(after.link == before.link);  // the link a reader already has still works
  CHECK(after.seq == 2);
  CHECK(identities.format(source.path()) == IdentityFormat::Wrapped);

  const fs::path identity_path = identities.path_for(source.path());
  const std::string on_disk = skiptest::read_all(identity_path);
  CHECK(on_disk.find("\"v\":2") != std::string::npos);
  CHECK(on_disk.find("signing_seed") == std::string::npos);
  CHECK(on_disk.find("drive_key") == std::string::npos);
  const std::array<unsigned char, 32> legacy_seed = seed_of(legacy);
  for (const ByteView secret : {ByteView(legacy.drive_key), ByteView(legacy_seed)}) {
    CHECK_FALSE(file_contains(on_disk, secret));
    CHECK(on_disk.find(base64url_encode(secret)) == std::string::npos);
    CHECK(on_disk.find(hex_encode(secret)) == std::string::npos);
  }

  // The seed survived the migration, but only behind the passphrase.
  const DriveIdentity migrated = *identities.load(source.path(), kPassphrase);
  CHECK(migrated.drive_key == legacy.drive_key);
  CHECK(migrated.signing.secret == legacy.signing.secret);
  CHECK(migrated.seq == 2);
  CHECK(skiptest::code_of([&] { (void)identities.load(source.path(), "wrong"); }) ==
        ErrorCode::BadPassphrase);

  // The pre-migration share is still downloadable from the same store.
  {
    const ShareSession session = open_share(store, before.link);
    const std::optional<Entry> entry = resolve_path(store, session, "old.txt");
    REQUIRE(entry.has_value());
    std::ostringstream out;
    fetch_file(store, session, *entry, out);
    CHECK(out.str() == "published before the upgrade");
  }

  // Nothing else in the identities directory still holds the plaintext seed.
  for (const auto& entry : fs::recursive_directory_iterator(identities.dir())) {
    if (!entry.is_regular_file()) continue;
    const std::string blob = skiptest::read_all(entry.path());
    CHECK_FALSE(file_contains(blob, ByteView(seed_of(legacy))));
    CHECK_FALSE(file_contains(blob, ByteView(legacy.drive_key)));
  }
}

TEST_CASE("an identity file that is neither wrapped nor legacy is unusable") {
  skiptest::TempDir work("identity");
  const fs::path source = work.path() / "share";
  fs::create_directories(source);
  const IdentityStore identities(work.path() / "identities");
  const fs::path path = identities.path_for(source);

  const auto unusable = [&] {
    CHECK(skiptest::code_of([&] { (void)identities.format(source); }) ==
          ErrorCode::UnsupportedIdentity);
    CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
          ErrorCode::UnsupportedIdentity);
  };

  skiptest::write_text(path, "{\"v\":3,\"something\":\"new\"}");
  unusable();

  skiptest::write_text(path, "not json at all");
  unusable();

  // Claims to be wrapped but has no wrapped secret: the version is recognised,
  // the file is not usable.
  skiptest::write_text(path, "{\"v\":2}");
  CHECK(identities.format(source) == IdentityFormat::Wrapped);
  CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
        ErrorCode::UnsupportedIdentity);

  // A wrapped envelope whose inner keywrap blob is malformed.
  skiptest::write_text(path, "{\"v\":2,\"wrap\":{\"v\":1,\"kdf\":\"argon2id\"}}");
  CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
        ErrorCode::UnsupportedIdentity);

  // A legacy file that is structurally broken is unusable too.
  skiptest::write_text(path, "{\"v\":1,\"drive\":\"AAAA\"}");
  CHECK(identities.format(source) == IdentityFormat::Plaintext);
  CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
        ErrorCode::UnsupportedIdentity);
}

TEST_CASE("identities are kept per published folder") {
  skiptest::TempDir first("one");
  skiptest::TempDir second("two");
  skiptest::TempDir work("store");
  skiptest::write_text(first.path() / "a.txt", "a");
  skiptest::write_text(second.path() / "b.txt", "b");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  CHECK_FALSE(identities.load(first.path(), kPassphrase).has_value());
  CHECK(identities.format(first.path()) == IdentityFormat::Missing);

  const PublishResult one = publish_as_next_run(first.path(), store, identities);
  const PublishResult two = publish_as_next_run(second.path(), store, identities);
  CHECK(one.link != two.link);

  // A trailing slash names the same folder, so it finds the same identity.
  CHECK(identities.path_for(first.path()) ==
        identities.path_for(fs::path(first.path().string() + "/")));
  CHECK(identities.load(first.path(), kPassphrase)->drive_key ==
        identities.load(first.path(), kPassphrase).value().drive_key);
  CHECK(identities.path_for(first.path()) != identities.path_for(second.path()));
}

TEST_CASE("an identity file does not leak into the published blobs") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "hello");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  const PublishResult published = publish_as_next_run(source.path(), store, identities);

  // The link is the only thing a reader needs; it carries the drive key, never
  // the signing seed.
  const ShareLink link = decode_link(published.link);
  CHECK(link.drive == published.drive);
  CHECK(link.key == identities.load(source.path(), kPassphrase)->drive_key);

  const DriveIdentity identity = *identities.load(source.path(), kPassphrase);
  const std::string seed = to_string(ByteView(seed_of(identity)));
  for (const auto& entry : fs::recursive_directory_iterator(store.root())) {
    if (!entry.is_regular_file()) continue;
    const std::string blob = skiptest::read_all(entry.path());
    CHECK(blob.find(seed) == std::string::npos);
    CHECK(blob.find(base64url_encode(ByteView(seed_of(identity)))) == std::string::npos);
  }
  CHECK_FALSE(identities.path_for(source.path()).string().find("blocks") != std::string::npos);
}

TEST_CASE("an identity path that is not a small regular file is refused") {
  skiptest::TempDir work("identity");
  const fs::path source = work.path() / "share";
  fs::create_directories(source);
  const IdentityStore identities(work.path() / "identities");
  const fs::path path = identities.path_for(source);

  // A directory where the identity belongs is not read as bytes.
  fs::create_directories(path);
  CHECK(skiptest::code_of([&] { (void)identities.format(source); }) ==
        ErrorCode::UnsupportedFileType);
  CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
        ErrorCode::UnsupportedFileType);

  // An oversized file is rejected before it is read.
  fs::remove_all(path);
  skiptest::write_text(path, std::string(5000, 'x'));
  CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
        ErrorCode::StoreIo);

  // A symlink is not followed, even if it points at a valid identity.
  fs::remove(path);
  const fs::path real = work.path() / "real.id";
  skiptest::write_text(real, to_string(ByteView(encode_identity(DriveIdentity::create()))));
  std::error_code ec;
  fs::create_symlink(real, path, ec);
  REQUIRE_FALSE(ec);
  CHECK(skiptest::code_of([&] { (void)identities.load(source, kPassphrase); }) ==
        ErrorCode::UnsupportedFileType);

  // A source that was never published simply has no identity.
  const fs::path unpublished = work.path() / "unpublished";
  fs::create_directories(unpublished);
  CHECK_FALSE(identities.load(unpublished, kPassphrase).has_value());
  CHECK(identities.format(unpublished) == IdentityFormat::Missing);
}

TEST_CASE("changing the passphrase re-wraps the same drive secret") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  skiptest::write_text(source.path() / "a.txt", "unchanged content");

  FileStore store(work.path() / "store");
  const IdentityStore identities(store.root() / "identities");
  const PublishResult published = publish_as_next_run(source.path(), store, identities);

  const std::string kNewPassphrase = "a different, longer passphrase";
  const fs::path identity_path = identities.path_for(source.path());
  const DriveIdentity before = *identities.load(source.path(), kPassphrase);
  const Bytes pointer_before = *store.get_pointer(published.drive);
  const std::string identity_before = skiptest::read_all(identity_path);

  // A wrong current passphrase is refused and the file is not touched at all.
  CHECK(skiptest::code_of([&] {
          identities.rewrap(source.path(), "wrong passphrase", kNewPassphrase, kFast);
        }) == ErrorCode::BadPassphrase);
  CHECK(skiptest::read_all(identity_path) == identity_before);
  CHECK(identities.load(source.path(), kPassphrase).has_value());
  CHECK(skiptest::read_all(identity_path) == identity_before);

  // An empty replacement is refused before anything is written.
  CHECK(skiptest::code_of([&] {
          identities.rewrap(source.path(), kPassphrase, "", kFast);
        }) == ErrorCode::BadPassphrase);
  CHECK(skiptest::read_all(identity_path) == identity_before);

  identities.rewrap(source.path(), kPassphrase, kNewPassphrase, kFast);

  // The old passphrase is gone; the new one opens the very same drive.
  CHECK(skiptest::code_of([&] { (void)identities.load(source.path(), kPassphrase); }) ==
        ErrorCode::BadPassphrase);
  const DriveIdentity after = *identities.load(source.path(), kNewPassphrase);
  CHECK(after.drive_key == before.drive_key);
  CHECK(after.signing.secret == before.signing.secret);
  CHECK(after.signing.pub == before.signing.pub);
  CHECK(after.seq == before.seq);

  // Nothing else moved: the pointer bytes, the link and the content are the
  // same, so readers cannot tell that the passphrase changed.
  CHECK(*store.get_pointer(published.drive) == pointer_before);
  const ShareSession session = open_share(store, published.link);
  CHECK(session.pointer.seq == published.seq);
  REQUIRE(session.root.find("a.txt") != nullptr);

  // The identity itself is a new envelope with a fresh salt and nonce, still
  // hiding both secrets and still owner-only.
  const std::string identity_after = skiptest::read_all(identity_path);
  CHECK(identity_after != identity_before);
  CHECK(identity_after.find("\"v\":2") != std::string::npos);
  CHECK_FALSE(file_contains(identity_after, ByteView(after.drive_key)));
  CHECK_FALSE(file_contains(identity_after, ByteView(seed_of(after))));
  CHECK(identity_after.find(base64url_encode(ByteView(after.drive_key))) == std::string::npos);
  CHECK(identity_after.find(base64url_encode(ByteView(seed_of(after)))) == std::string::npos);
  CHECK(identity_after.find("signing_seed") == std::string::npos);
  CHECK((fs::status(identity_path).permissions() & fs::perms::group_all) == fs::perms::none);
  CHECK((fs::status(identity_path).permissions() & fs::perms::others_all) == fs::perms::none);

  // The drive is still usable: publishing with the new passphrase keeps the
  // link and advances seq as if nothing happened.
  const PublishResult next =
      publish_as_next_run(source.path(), store, identities, kNewPassphrase);
  CHECK(next.link == published.link);
  CHECK(next.drive == published.drive);
  CHECK(next.seq == published.seq + 1);
  CHECK(open_share(store, next.link, published.seq).pointer.seq == next.seq);
}

TEST_CASE("a passphrase change refuses an identity it cannot re-wrap") {
  skiptest::TempDir source("src");
  skiptest::TempDir work("store");
  const IdentityStore identities(work.path() / "identities");

  // A folder that was never published has no identity to re-wrap.
  CHECK(skiptest::code_of([&] {
          identities.rewrap(source.path(), kPassphrase, "new passphrase", kFast);
        }) == ErrorCode::NotFound);

  // A legacy plaintext identity is left for publish to migrate, untouched.
  const fs::path path = identities.path_for(source.path());
  skiptest::write_text(path, to_string(ByteView(encode_identity(DriveIdentity::create()))));
  const std::string plaintext = skiptest::read_all(path);
  CHECK(skiptest::code_of([&] {
          identities.rewrap(source.path(), kPassphrase, "new passphrase", kFast);
        }) == ErrorCode::UnsupportedIdentity);
  CHECK(skiptest::read_all(path) == plaintext);
}
