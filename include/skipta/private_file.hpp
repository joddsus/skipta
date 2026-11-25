// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Owner-only files and directories, independent of the process umask.
//
// Everything the store and the identity keep on disk is either key material or
// ciphertext that the link can decrypt, so none of it belongs to other users on
// the machine. Creating a file with the usual 0666 default and tightening it
// afterwards leaves a window where it is readable, and a umask of 0777 creates
// it unreadable even to its owner. These helpers set the mode at creation.
#pragma once

#include <filesystem>

#include "skipta/bytes.hpp"

namespace skipta {

/// Creates `dir` (and missing parents) and sets `dir` itself to 0700. Ancestors
/// above it keep their mode: the store only tightens directories it owns.
void make_private_directory(const std::filesystem::path& dir);

/// Writes `data` to a fresh sibling temp file created 0600, optionally flushes
/// it to stable storage, and renames it over `path`. The parent directory is
/// created and tightened to 0700 first. A failed write removes the temp file;
/// no partial file is left under `path`.
void write_private_file(const std::filesystem::path& path, ByteView data, bool durable);

}  // namespace skipta
