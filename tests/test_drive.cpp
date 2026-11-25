// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase 3 shape without a network: publish one drive, hand the reader only a
// link, then list and lazily fetch. Transport is a later phase; this proves the
// data path and the key hierarchy end to end.
#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/drive.hpp"
#include "skipta/error.hpp"

using namespace skipta;

TEST_CASE("publish and read one drive over a secret link, in memory") {
  const Drive publisher = Drive::create();
  const Id128 file_id = crypto::random_id();
  const Bytes content = skiptest::pattern(200000, 5);  // 4 blocks: 3 full + 3392 bytes
  const Bytes sealed_file =
      format::encrypt_file(publisher.drive_key(), file_id, ByteView(content));

  Manifest root = publisher.new_manifest(1);
  root.add_file("notes.txt", content.size(), file_id, 1700000000);

  Manifest docs = publisher.new_manifest(1);
  const Bytes docs_sealed = publisher.seal_manifest(docs);
  root.add_directory("docs", docs.id, 1700000001);

  const Bytes root_sealed = publisher.seal_manifest(root);
  const SignedPointer pointer = publisher.sign_root(publisher.root_pointer(root, 1700000000));
  const std::string link = encode_link(publisher.share_link({"seed:club.example:7000"}));

  // ---- reader side: the link and the signed pointer are all it gets -------
  const ShareLink share = decode_link(link);
  CHECK(share.drive == publisher.public_key());
  const SignedPointer wire_pointer = decode_signed_pointer(ByteView(encode_signed_pointer(pointer)));
  const RootPointer verified = verify_pointer(share.drive, wire_pointer);
  CHECK(verified.root == root.id);

  const Manifest listed = open_manifest(share.key, verified.root, ByteView(root_sealed));
  REQUIRE(listed.entries.size() == 2);
  const Entry* notes = listed.find("notes.txt");
  REQUIRE(notes != nullptr);
  CHECK(notes->kind == EntryKind::File);
  CHECK(notes->size == content.size());

  // Lazy read: fetch and decrypt only block 2.
  const std::size_t stride = format::kBlockPlaintextSize + format::kAeadTagSize;
  const Bytes block2(sealed_file.begin() + static_cast<std::ptrdiff_t>(2 * stride),
                     sealed_file.begin() + static_cast<std::ptrdiff_t>(3 * stride));
  const Bytes block2_plain =
      format::decrypt_block(share.key, notes->file_id, notes->size, 2, ByteView(block2));
  CHECK(block2_plain == Bytes(content.begin() + 2 * static_cast<std::ptrdiff_t>(format::kBlockPlaintextSize),
                             content.begin() + 3 * static_cast<std::ptrdiff_t>(format::kBlockPlaintextSize)));

  // Full read through the manifest entry.
  CHECK(format::decrypt_file(share.key, notes->file_id, notes->size, ByteView(sealed_file)) ==
        content);

  // Subdirectory listing needs only its own manifest.
  const Entry* docs_entry = listed.find("docs");
  REQUIRE(docs_entry != nullptr);
  CHECK(docs_entry->kind == EntryKind::Directory);
  CHECK(list_directory(share.key, docs_entry->manifest_id, ByteView(docs_sealed)).empty());

  // ---- tampering ----------------------------------------------------------
  Bytes bad_manifest = root_sealed;
  bad_manifest[5] ^= 0x01;
  CHECK(skiptest::code_of([&] {
          open_manifest(share.key, verified.root, ByteView(bad_manifest));
        }) == ErrorCode::AuthFailed);

  Bytes bad_block = sealed_file;
  bad_block[10] ^= 0x01;
  CHECK(skiptest::code_of([&] {
          const Bytes block0(bad_block.begin(),
                             bad_block.begin() + static_cast<std::ptrdiff_t>(stride));
          format::decrypt_block(share.key, file_id, content.size(), 0, ByteView(block0));
        }) == ErrorCode::AuthFailed);

  // The wrong drive key cannot open the manifest even with the right id.
  const Drive other = Drive::create();
  CHECK(skiptest::code_of([&] {
          open_manifest(other.drive_key(), verified.root, ByteView(root_sealed));
        }) == ErrorCode::AuthFailed);

  // Browser-side path validation; traversal never reaches a manifest lookup.
  CHECK(skiptest::code_of([] { validate_relative_path("docs/../../etc/passwd"); }) ==
        ErrorCode::DotName);
}

TEST_CASE("sealed metadata does not leak names on the wire") {
  const Drive publisher = Drive::create();
  Manifest root = publisher.new_manifest(1);
  root.add_file("very-distinctive-name.txt", 3, crypto::random_id());
  const Bytes sealed = publisher.seal_manifest(root);
  CHECK(to_string(ByteView(sealed)).find("very-distinctive-name") == std::string::npos);
  CHECK(to_string(ByteView(sealed)).find("entries") == std::string::npos);
}
