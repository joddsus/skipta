// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/pointer.hpp"

#include <algorithm>
#include <string>

#include "skipta/error.hpp"
#include "skipta/json.hpp"

namespace skipta {
namespace {

constexpr std::size_t kMaxPointerBytes = 4096;

}  // namespace

Bytes serialize_pointer(const RootPointer& pointer) {
  if (pointer.version != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported pointer version");
  }
  jsonx::Json j;
  j["v"] = pointer.version;
  j["drive"] = base64url_encode(ByteView(pointer.drive));
  j["seq"] = pointer.seq;
  j["root"] = base64url_encode(ByteView(pointer.root));
  j["issued_at"] = pointer.issued_at;
  return to_bytes(jsonx::dump(j, "pointer"));
}

RootPointer parse_pointer(ByteView plaintext) {
  auto j = jsonx::parse_strict(to_string(plaintext), kMaxPointerBytes, "pointer");
  jsonx::require_object(j, "pointer");
  jsonx::reject_unknown(j, {"v", "drive", "seq", "root", "issued_at"}, "pointer");

  RootPointer pointer;
  pointer.version = jsonx::req_uint(j, "v", "pointer");
  if (pointer.version != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported pointer version " +
                                    std::to_string(pointer.version));
  }
  const Bytes drive = jsonx::req_b64(j, "drive", 32, "pointer");
  std::copy(drive.begin(), drive.end(), pointer.drive.begin());
  pointer.seq = jsonx::req_uint(j, "seq", "pointer");
  const Bytes root = jsonx::req_b64(j, "root", 16, "pointer");
  std::copy(root.begin(), root.end(), pointer.root.begin());
  pointer.issued_at = jsonx::req_uint(j, "issued_at", "pointer");

  if (is_zero(ByteView(pointer.root))) {
    fail(ErrorCode::ZeroId, "pointer root id must not be all zero");
  }
  return pointer;
}

SignedPointer sign_pointer(const crypto::SigningKeyPair& signing, const RootPointer& pointer) {
  SignedPointer out;
  out.pointer = serialize_pointer(pointer);
  out.signature = signing.sign(ByteView(out.pointer));
  return out;
}

RootPointer verify_pointer(const PubKey32& expected_drive, const SignedPointer& signed_pointer,
                           std::uint64_t min_seq) {
  // Signature first: nothing in the pointer is interpreted before it is authentic.
  if (!crypto::verify(expected_drive, ByteView(signed_pointer.pointer), signed_pointer.signature)) {
    fail(ErrorCode::BadSignature, "root pointer signature does not verify");
  }
  const RootPointer pointer = parse_pointer(ByteView(signed_pointer.pointer));
  if (!constant_time_equal(ByteView(pointer.drive), ByteView(expected_drive))) {
    fail(ErrorCode::DriveMismatch, "root pointer names a different drive");
  }
  if (pointer.seq < min_seq) {
    fail(ErrorCode::StalePointer, "root pointer seq " + std::to_string(pointer.seq) +
                                      " is older than the accepted " + std::to_string(min_seq));
  }
  return pointer;
}

Bytes encode_signed_pointer(const SignedPointer& signed_pointer) {
  jsonx::Json j;
  j["p"] = base64url_encode(ByteView(signed_pointer.pointer));
  j["s"] = base64url_encode(ByteView(signed_pointer.signature));
  return to_bytes(jsonx::dump(j, "signed pointer"));
}

SignedPointer decode_signed_pointer(ByteView text) {
  auto j = jsonx::parse_strict(to_string(text), kMaxPointerBytes, "signed pointer");
  jsonx::require_object(j, "signed pointer");
  jsonx::reject_unknown(j, {"p", "s"}, "signed pointer");

  SignedPointer out;
  out.pointer = jsonx::req_b64(j, "p", static_cast<std::size_t>(-1), "signed pointer");
  if (out.pointer.empty() || out.pointer.size() > kMaxPointerBytes) {
    fail(ErrorCode::TooLarge, "signed pointer: embedded pointer has bad length");
  }
  const Bytes signature = jsonx::req_b64(j, "s", 64, "signed pointer");
  std::copy(signature.begin(), signature.end(), out.signature.begin());
  return out;
}

}  // namespace skipta
