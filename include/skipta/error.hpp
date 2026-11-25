// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Every rejection path in libskipta reports a code, so callers and tests can
// distinguish "hostile input" from "programming error". Errors never carry
// secret material.
#pragma once

#include <stdexcept>
#include <string>

namespace skipta {

enum class ErrorCode {
  // container / crypto
  AuthFailed,
  BadNonce,
  WrongKeyLength,
  ShortInput,
  BadBlockIndex,
  SizeMismatch,
  CryptoInit,

  // encodings and parsers
  BadBase64,
  BadHex,
  BadJson,
  DuplicateKey,
  TooDeep,
  UnknownField,
  MissingField,
  WrongType,
  BadVersion,
  TooLarge,

  // links, pointers, signatures
  BadScheme,
  BadLink,
  BadSignature,
  StalePointer,
  DriveMismatch,

  // manifests, names, paths
  EmptyName,
  DotName,
  PathSeparator,
  NulByte,
  ControlChar,
  TrailingDotOrSpace,
  ReservedName,
  UnsafeChar,  ///< invisible, bidi or line-breaking character in a name
  NameTooLong,
  PathTooLong,
  InvalidUtf8,
  DuplicateName,
  CaseCollision,
  DuplicateFileId,
  TooManyEntries,
  FileTooLarge,
  InvalidKind,
  BadSizeForKind,
  ZeroId,
  BadBootstrapHint,

  // key wrapping
  BadPassphrase,
  BadKdfParams,

  // local store and blob lookup (phase 3 stand-in for the swarm)
  NotFound,
  StoreIo,
  UnsupportedFileType,
  BadRange,
  BadOptions,
  BadResumeState,
  FileExists,
  UnsafeTarget,       ///< a download destination would write somewhere else (symlink, device)
  MissingPassphrase,  ///< no passphrase supplied and no terminal to ask on
  UnsupportedIdentity,  ///< identity file is neither wrapped nor legacy plaintext
  StoreBusy,          ///< another publish or gc holds the store lock
  UnsafeStore,        ///< gc cannot account for every drive in the store
};

class Error : public std::runtime_error {
 public:
  Error(ErrorCode code, const std::string& message);
  ErrorCode code() const noexcept { return code_; }

 private:
  ErrorCode code_;
};

[[noreturn]] void fail(ErrorCode code, const std::string& message);

/// Stable identifier for logs, test vectors and documentation.
const char* error_code_name(ErrorCode code);

}  // namespace skipta
