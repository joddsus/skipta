// SPDX-License-Identifier: AGPL-3.0-or-later
#include "doctest/doctest.h"
#include "helpers.hpp"
#include "nlohmann/json.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/keywrap.hpp"

#include <limits>

using namespace skipta;

namespace {

const Argon2Params kFast = Argon2Params::interactive();  // 2 ops, 64 MiB: test-speed only
const std::string kPassphrase = "correct horse battery staple";

}  // namespace

TEST_CASE("arbitrary small secrets wrap and unwrap with the same container") {
  const Bytes secret = skiptest::pattern(72, 3);  // the identity payload size
  const Bytes blob = wrap_secret(ByteView(secret), kPassphrase, kFast);
  CHECK(unwrap_secret(ByteView(blob), kPassphrase) == secret);
  CHECK(skiptest::code_of([&] { unwrap_secret(ByteView(blob), "wrong"); }) ==
        ErrorCode::BadPassphrase);

  // A drive key wrapped through the generic entry point still opens as one.
  const Key32 key = crypto::random_key();
  CHECK(unwrap_drive_key(ByteView(wrap_secret(ByteView(key), kPassphrase, kFast)), kPassphrase) ==
        key);

  // Empty and oversized secrets are refused before any KDF work.
  CHECK(skiptest::code_of([&] { wrap_secret(ByteView(Bytes{}), kPassphrase, kFast); }) ==
        ErrorCode::WrongKeyLength);
  CHECK(skiptest::code_of([&] { wrap_secret(ByteView(Bytes(257, 0)), kPassphrase, kFast); }) ==
        ErrorCode::TooLarge);
}

TEST_CASE("the drive key survives a wrap/unwrap round-trip") {
  const Key32 drive_key = crypto::random_key();
  const Bytes blob = wrap_drive_key(drive_key, kPassphrase, kFast);
  CHECK(unwrap_drive_key(ByteView(blob), kPassphrase) == drive_key);

  // A blob for the same key is different every time (fresh salt and nonce).
  CHECK_FALSE(wrap_drive_key(drive_key, kPassphrase, kFast) == blob);
}

TEST_CASE("wrong passphrase and tampered blob are both rejected indistinguishably") {
  const Key32 drive_key = crypto::random_key();
  const Bytes blob = wrap_drive_key(drive_key, kPassphrase, kFast);
  CHECK(skiptest::code_of([&] { unwrap_drive_key(ByteView(blob), "wrong"); }) ==
        ErrorCode::BadPassphrase);

  // Flip one character inside the ciphertext field.
  std::string text = to_string(ByteView(blob));
  const std::size_t ct_at = text.find("\"ct\":\"");
  REQUIRE(ct_at != std::string::npos);
  const std::size_t flip_at = ct_at + 8;
  text[flip_at] = text[flip_at] == 'A' ? 'B' : 'A';
  CHECK(skiptest::code_of([&] { unwrap_drive_key(ByteView(text), kPassphrase); }) ==
        ErrorCode::BadPassphrase);

  // A truncated blob never parses.
  CHECK(skiptest::code_of([&] {
          unwrap_drive_key(ByteView(text.substr(0, text.size() / 2)), kPassphrase);
        }) == ErrorCode::BadJson);
}

TEST_CASE("kdf parameters are bounded and bound to the ciphertext") {
  const Key32 drive_key = crypto::random_key();
  CHECK(skiptest::code_of([&] { wrap_drive_key(drive_key, "", kFast); }) ==
        ErrorCode::BadPassphrase);
  CHECK(skiptest::code_of([&] {
          Argon2Params absurd;
          absurd.memlimit = std::numeric_limits<std::size_t>::max();
          wrap_drive_key(drive_key, kPassphrase, absurd);
        }) == ErrorCode::BadKdfParams);
  CHECK(skiptest::code_of([&] {
          Argon2Params absurd;
          absurd.opslimit = 0;
          wrap_drive_key(drive_key, kPassphrase, absurd);
        }) == ErrorCode::BadKdfParams);

  const Bytes blob = wrap_drive_key(drive_key, kPassphrase, kFast);
  std::string text = to_string(ByteView(blob));
  const std::string from = "\"opslimit\":2";
  const std::size_t at = text.find(from);
  REQUIRE(at != std::string::npos);
  text.replace(at, from.size(), "\"opslimit\":3");
  // Changing the stated work factor must break the blob, not silently decrypt it.
  CHECK(skiptest::code_of([&] { unwrap_drive_key(ByteView(text), kPassphrase); }) ==
        ErrorCode::BadPassphrase);

  const Bytes unknown_field = [&] {
    std::string copy = to_string(ByteView(blob));
    copy.insert(copy.size() - 1, ",\"extra\":1");
    return to_bytes(ByteView(copy));
  }();
  CHECK(skiptest::code_of([&] { unwrap_drive_key(ByteView(unknown_field), kPassphrase); }) ==
        ErrorCode::UnknownField);
}

TEST_CASE("a blob claiming a huge memory limit is refused before any work is done") {
  const auto hostile_blob = [](const std::string& kdf, std::uint64_t memlimit) {
    nlohmann::json j;
    j["v"] = 1;
    j["kdf"] = kdf;
    j["opslimit"] = 2;
    j["memlimit"] = memlimit;
    j["salt"] = base64url_encode(ByteView(skiptest::filled_id(0x00)));
    j["nonce"] = base64url_encode(ByteView(skiptest::filled<format::kNonceSize>(0x00)));
    j["ct"] = base64url_encode(ByteView(skiptest::filled<48>(0x00)));
    return j.dump();
  };

  const std::string hostile = hostile_blob("argon2id", 4ull * 1024 * 1024 * 1024);
  CHECK(skiptest::code_of([&] { unwrap_drive_key(ByteView(hostile), kPassphrase); }) ==
        ErrorCode::BadKdfParams);

  const std::string wrong_kdf = hostile_blob("scrypt", 64u * 1024u * 1024u);
  CHECK(skiptest::code_of([&] { unwrap_drive_key(ByteView(wrong_kdf), kPassphrase); }) ==
        ErrorCode::BadKdfParams);
}
