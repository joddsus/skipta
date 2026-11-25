// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/error.hpp"

namespace skipta {

Error::Error(ErrorCode code, const std::string& message)
    : std::runtime_error(message), code_(code) {}

void fail(ErrorCode code, const std::string& message) { throw Error(code, message); }

const char* error_code_name(ErrorCode code) {
  switch (code) {
    case ErrorCode::AuthFailed: return "AuthFailed";
    case ErrorCode::BadNonce: return "BadNonce";
    case ErrorCode::WrongKeyLength: return "WrongKeyLength";
    case ErrorCode::ShortInput: return "ShortInput";
    case ErrorCode::BadBlockIndex: return "BadBlockIndex";
    case ErrorCode::SizeMismatch: return "SizeMismatch";
    case ErrorCode::CryptoInit: return "CryptoInit";
    case ErrorCode::BadBase64: return "BadBase64";
    case ErrorCode::BadHex: return "BadHex";
    case ErrorCode::BadJson: return "BadJson";
    case ErrorCode::DuplicateKey: return "DuplicateKey";
    case ErrorCode::TooDeep: return "TooDeep";
    case ErrorCode::UnknownField: return "UnknownField";
    case ErrorCode::MissingField: return "MissingField";
    case ErrorCode::WrongType: return "WrongType";
    case ErrorCode::BadVersion: return "BadVersion";
    case ErrorCode::TooLarge: return "TooLarge";
    case ErrorCode::BadScheme: return "BadScheme";
    case ErrorCode::BadLink: return "BadLink";
    case ErrorCode::BadSignature: return "BadSignature";
    case ErrorCode::StalePointer: return "StalePointer";
    case ErrorCode::DriveMismatch: return "DriveMismatch";
    case ErrorCode::EmptyName: return "EmptyName";
    case ErrorCode::DotName: return "DotName";
    case ErrorCode::PathSeparator: return "PathSeparator";
    case ErrorCode::NulByte: return "NulByte";
    case ErrorCode::ControlChar: return "ControlChar";
    case ErrorCode::TrailingDotOrSpace: return "TrailingDotOrSpace";
    case ErrorCode::ReservedName: return "ReservedName";
    case ErrorCode::UnsafeChar: return "UnsafeChar";
    case ErrorCode::NameTooLong: return "NameTooLong";
    case ErrorCode::PathTooLong: return "PathTooLong";
    case ErrorCode::InvalidUtf8: return "InvalidUtf8";
    case ErrorCode::DuplicateName: return "DuplicateName";
    case ErrorCode::CaseCollision: return "CaseCollision";
    case ErrorCode::DuplicateFileId: return "DuplicateFileId";
    case ErrorCode::TooManyEntries: return "TooManyEntries";
    case ErrorCode::FileTooLarge: return "FileTooLarge";
    case ErrorCode::InvalidKind: return "InvalidKind";
    case ErrorCode::BadSizeForKind: return "BadSizeForKind";
    case ErrorCode::ZeroId: return "ZeroId";
    case ErrorCode::BadBootstrapHint: return "BadBootstrapHint";
    case ErrorCode::BadPassphrase: return "BadPassphrase";
    case ErrorCode::BadKdfParams: return "BadKdfParams";
    case ErrorCode::NotFound: return "NotFound";
    case ErrorCode::StoreIo: return "StoreIo";
    case ErrorCode::UnsupportedFileType: return "UnsupportedFileType";
    case ErrorCode::BadRange: return "BadRange";
    case ErrorCode::BadOptions: return "BadOptions";
    case ErrorCode::BadResumeState: return "BadResumeState";
    case ErrorCode::FileExists: return "FileExists";
    case ErrorCode::UnsafeTarget: return "UnsafeTarget";
    case ErrorCode::MissingPassphrase: return "MissingPassphrase";
    case ErrorCode::UnsupportedIdentity: return "UnsupportedIdentity";
    case ErrorCode::StoreBusy: return "StoreBusy";
    case ErrorCode::UnsafeStore: return "UnsafeStore";
  }
  return "Unknown";
}

}  // namespace skipta
