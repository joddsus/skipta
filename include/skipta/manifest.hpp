// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Directory manifests and the untrusted-input rules from spec §8.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "skipta/bytes.hpp"
#include "skipta/format.hpp"

namespace skipta {

/// Hard limits. Every value is enforced on parse, not just on write.
struct Limits {
  std::size_t max_manifest_bytes = 1024 * 1024;  ///< plaintext JSON
  std::size_t max_entries = 4096;
  std::size_t max_name_bytes = 255;
  std::size_t max_path_bytes = 4096;
  std::size_t max_depth = 32;
  std::size_t max_bootstrap_hints = 4;
  std::uint64_t max_file_size = 1ull << 40;  ///< 1 TiB

  static Limits defaults() { return Limits{}; }
};

enum class EntryKind { File, Directory };

const char* to_string(EntryKind kind);  ///< "file" | "dir"
EntryKind entry_kind_from(std::string_view text);

struct Entry {
  std::string name;
  EntryKind kind = EntryKind::File;
  std::uint64_t size = 0;   ///< files only
  Id128 file_id{};          ///< files only
  Id128 manifest_id{};      ///< directories only
  std::uint64_t mtime = 0;  ///< unix seconds, informational only
};

/// One path component. Throws on `..`, separators, NUL, control characters,
/// trailing dot/space, Windows reserved names, invalid UTF-8, over-length.
void validate_name(std::string_view name, const Limits& limits = Limits{});

/// Slash-separated relative path as used by the browser and `skipta://`.
/// Rejects leading/trailing slashes, empty components, and depth over the limit.
void validate_relative_path(std::string_view path, const Limits& limits = Limits{});

bool is_valid_utf8(ByteView text);
std::string fold_ascii_case(std::string_view name);
bool is_reserved_windows_name(std::string_view name);

struct Manifest {
  std::uint64_t version = format::kVersion;
  Id128 id{};
  std::uint64_t seq = 0;
  std::vector<Entry> entries;

  static Manifest create(std::uint64_t seq = 0);

  /// Throws on any validation failure; never trusts the input.
  static Manifest parse(ByteView plaintext, const Limits& limits = Limits{});

  Bytes serialize(const Limits& limits = Limits{}) const;
  void validate(const Limits& limits = Limits{}) const;

  const Entry* find(std::string_view name) const;
  void add_file(std::string_view name, std::uint64_t size, const Id128& file_id,
                std::uint64_t mtime = 0);
  void add_directory(std::string_view name, const Id128& manifest_id, std::uint64_t mtime = 0);
};

}  // namespace skipta
