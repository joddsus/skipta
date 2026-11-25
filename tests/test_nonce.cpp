// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Spec §5: "Never reuse a (key, nonce) pair. Every new content version of a
// file gets a new file id and key. Write a test that fails if this is
// violated." These tests are that check, plus the API rule that enforces it.
#include <set>
#include <string>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/manifest.hpp"

using namespace skipta;

namespace {

/// Records every (key, nonce) pair and reports duplicates, exactly what a
/// real nonce-misuse detector does.
class NonceRegistry {
 public:
  bool record(const Key32& key, const std::array<unsigned char, format::kNonceSize>& nonce) {
    std::string tag(reinterpret_cast<const char*>(key.data()), key.size());
    tag.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    return seen_.insert(tag).second;
  }

 private:
  std::set<std::string> seen_;
};

}  // namespace

TEST_CASE("no (key, nonce) pair repeats while the format is used correctly") {
  const Key32 drive_key = crypto::random_key();
  NonceRegistry registry;
  for (int content_version = 0; content_version < 200; ++content_version) {
    const Id128 file_id = crypto::random_id();  // new content version => new id
    const Key32 file_key = format::derive_file_key(drive_key, file_id);
    for (std::uint64_t index = 0; index < 4; ++index) {
      CHECK(registry.record(file_key, format::block_nonce(file_id, index)));
    }
  }
}

TEST_CASE("the guard does catch a reused file id: that is why content versions mint ids") {
  const Key32 drive_key = crypto::random_key();
  const Id128 file_id = crypto::random_id();
  const Key32 file_key = format::derive_file_key(drive_key, file_id);

  NonceRegistry registry;
  CHECK(registry.record(file_key, format::block_nonce(file_id, 0)));
  // Rewriting a file's content under the same id reuses key and nonce:
  // the same pair appears twice and the guard must flag it.
  CHECK_FALSE(registry.record(file_key, format::block_nonce(file_id, 0)));

  // Fresh ids for the rewrite avoid the pair entirely.
  const Id128 new_file_id = crypto::random_id();
  CHECK(registry.record(format::derive_file_key(drive_key, new_file_id),
                        format::block_nonce(new_file_id, 0)));
}

TEST_CASE("manifest nonces are unique per manifest id and never repeat within a drive") {
  NonceRegistry registry;
  const Key32 drive_key = crypto::random_key();
  for (int version = 0; version < 200; ++version) {
    const Id128 manifest_id = crypto::random_id();
    CHECK(registry.record(format::derive_manifest_key(drive_key, manifest_id),
                          format::manifest_nonce(manifest_id)));
  }
}

TEST_CASE("file ids, keys and nonces all change with the content version") {
  const Key32 drive_key = crypto::random_key();
  const Id128 first = crypto::random_id();
  const Id128 second = crypto::random_id();
  CHECK_FALSE(format::derive_file_key(drive_key, first) == format::derive_file_key(drive_key, second));
  CHECK_FALSE(format::block_nonce(first, 0) == format::block_nonce(second, 0));
  // Block index changes the nonce, not the key.
  CHECK_FALSE(format::block_nonce(first, 0) == format::block_nonce(first, 1));
  CHECK(format::derive_file_key(drive_key, first) == format::derive_file_key(drive_key, first));

  // Same bytes under two ids must not produce the same ciphertext.
  const Bytes content = skiptest::pattern(100, 4);
  CHECK_FALSE(format::encrypt_file(drive_key, first, ByteView(content)) ==
              format::encrypt_file(drive_key, second, ByteView(content)));
}

TEST_CASE("a manifest refuses to reuse a file id, even under another name") {
  Manifest manifest = Manifest::create(1);
  const Id128 file_id = crypto::random_id();
  manifest.add_file("a.txt", 10, file_id);
  CHECK(skiptest::code_of([&] { manifest.add_file("b.txt", 10, file_id); }) ==
        ErrorCode::DuplicateFileId);
}
