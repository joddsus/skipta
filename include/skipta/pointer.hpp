// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The mutable root pointer of a drive. It is the only signed, updatable item;
// everything below it is content-addressed by random id.
#pragma once

#include <cstdint>

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/format.hpp"

namespace skipta {

struct RootPointer {
  std::uint64_t version = format::kVersion;
  PubKey32 drive{};       ///< publisher identity; equals the signing key
  std::uint64_t seq = 0;  ///< monotonically increasing
  Id128 root{};           ///< manifest id of the root directory
  std::uint64_t issued_at = 0;
};

Bytes serialize_pointer(const RootPointer& pointer);
RootPointer parse_pointer(ByteView plaintext);

struct SignedPointer {
  Bytes pointer;  ///< exact bytes that were signed (never re-canonicalised)
  Sig64 signature{};
};

SignedPointer sign_pointer(const crypto::SigningKeyPair& signing, const RootPointer& pointer);

/// Verifies the signature over the exact received bytes, checks that the
/// pointer names `expected_drive`, and rejects seq < min_seq (rollback).
RootPointer verify_pointer(const PubKey32& expected_drive, const SignedPointer& signed_pointer,
                           std::uint64_t min_seq = 0);

Bytes encode_signed_pointer(const SignedPointer& signed_pointer);
SignedPointer decode_signed_pointer(ByteView text);

}  // namespace skipta
