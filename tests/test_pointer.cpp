// SPDX-License-Identifier: AGPL-3.0-or-later
#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/pointer.hpp"

using namespace skipta;

namespace {

RootPointer sample_pointer(const crypto::SigningKeyPair& signing) {
  RootPointer pointer;
  pointer.version = 1;
  pointer.drive = signing.pub;
  pointer.seq = 3;
  pointer.root = skiptest::filled_id(0x11);
  pointer.issued_at = 1700000000;
  return pointer;
}

}  // namespace

TEST_CASE("root pointers are signed over the exact bytes that travel") {
  const auto signing = crypto::SigningKeyPair::generate();
  const SignedPointer signed_pointer = sign_pointer(signing, sample_pointer(signing));

  const RootPointer verified = verify_pointer(signing.pub, signed_pointer);
  CHECK(verified.drive == signing.pub);
  CHECK(verified.seq == 3);
  CHECK(verified.root == skiptest::filled_id(0x11));

  const Bytes encoded = encode_signed_pointer(signed_pointer);
  const SignedPointer decoded = decode_signed_pointer(ByteView(encoded));
  CHECK(decoded.pointer == signed_pointer.pointer);
  CHECK(decoded.signature == signed_pointer.signature);
  CHECK(verify_pointer(signing.pub, decoded).seq == 3);
}

TEST_CASE("a tampered pointer never verifies") {
  const auto signing = crypto::SigningKeyPair::generate();
  SignedPointer signed_pointer = sign_pointer(signing, sample_pointer(signing));

  // Rewrite the sequence number (a rollback / rewind attempt) without re-signing.
  Bytes tampered = signed_pointer.pointer;
  const std::string from = "\"seq\":3";
  const std::string to = "\"seq\":9";
  const std::string text = to_string(ByteView(tampered));
  const std::size_t at = text.find(from);
  REQUIRE(at != std::string::npos);
  std::string rewritten = text;
  rewritten.replace(at, from.size(), to);
  tampered = to_bytes(ByteView(rewritten));

  SignedPointer bad;
  bad.pointer = tampered;
  bad.signature = signed_pointer.signature;
  CHECK(skiptest::code_of([&] { verify_pointer(signing.pub, bad); }) == ErrorCode::BadSignature);
}

TEST_CASE("a pointer signed by another key is rejected") {
  const auto signer = crypto::SigningKeyPair::generate();
  const auto other = crypto::SigningKeyPair::generate();
  const SignedPointer signed_pointer = sign_pointer(signer, sample_pointer(signer));
  CHECK(skiptest::code_of([&] { verify_pointer(other.pub, signed_pointer); }) ==
        ErrorCode::BadSignature);
}

TEST_CASE("a validly signed pointer that names a different drive is a drive mismatch") {
  const auto attacker = crypto::SigningKeyPair::generate();
  const auto victim = crypto::SigningKeyPair::generate();
  RootPointer pointer = sample_pointer(attacker);
  pointer.drive = victim.pub;  // claims to belong to the victim drive
  SignedPointer signed_pointer = sign_pointer(attacker, pointer);

  // Verified against the drive the reader expects; the signature is by the
  // attacker key so it fails as a signature first.
  CHECK(skiptest::code_of([&] { verify_pointer(victim.pub, signed_pointer); }) ==
        ErrorCode::BadSignature);
}

TEST_CASE("rollback protection rejects an older seq") {
  const auto signing = crypto::SigningKeyPair::generate();
  const SignedPointer signed_pointer = sign_pointer(signing, sample_pointer(signing));
  CHECK(verify_pointer(signing.pub, signed_pointer, 3).seq == 3);
  CHECK(skiptest::code_of([&] { verify_pointer(signing.pub, signed_pointer, 4); }) ==
        ErrorCode::StalePointer);
}

TEST_CASE("pointer payloads are strict") {
  const auto signing = crypto::SigningKeyPair::generate();
  const RootPointer pointer = sample_pointer(signing);
  const std::string text = to_string(ByteView(serialize_pointer(pointer)));
  CHECK(skiptest::code_of([&] { parse_pointer(ByteView(text)); }) == static_cast<ErrorCode>(-1));
  CHECK(skiptest::code_of([&] { parse_pointer(ByteView(text + "x")); }) == ErrorCode::BadJson);

  const std::string unknown = text.substr(0, text.size() - 1) + ",\"extra\":1}";
  CHECK(skiptest::code_of([&] { parse_pointer(ByteView(unknown)); }) == ErrorCode::UnknownField);

  RootPointer future = pointer;
  future.version = 99;
  CHECK(skiptest::code_of([&] { serialize_pointer(future); }) == ErrorCode::BadVersion);

  RootPointer zero_root = pointer;
  zero_root.root = skiptest::filled_id(0);
  const std::string zero_text = to_string(ByteView(serialize_pointer(zero_root)));
  CHECK(skiptest::code_of([&] { parse_pointer(ByteView(zero_text)); }) == ErrorCode::ZeroId);
}
