// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/manifest.hpp"

#include <algorithm>
#include <cstdio>
#include <set>
#include <string>

#include "skipta/crypto.hpp"
#include "skipta/error.hpp"
#include "skipta/json.hpp"

namespace skipta {
namespace {

char ascii_lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool is_reserved_base(const std::string& base) {
  static const char* kReserved[] = {"CON",  "PRN",  "AUX",  "NUL",  "CLOCK$", "COM1", "COM2",
                                    "COM3", "COM4", "COM5", "COM6", "COM7",   "COM8", "COM9",
                                    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",   "LPT6", "LPT7",
                                    "LPT8", "LPT9"};
  std::string upper;
  upper.reserve(base.size());
  for (char c : base) {
    upper.push_back(static_cast<char>((c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c));
  }
  for (const char* reserved : kReserved) {
    if (upper == reserved) return true;
  }
  return false;
}

/// Characters that print as nothing, or that reorder what surrounds them. A
/// listing is read in a terminal, and a publisher chooses the names, so these
/// are a spoofing vector: "pay\u202Efdp.exe" displays as "payexe.pdf".
bool is_invisible_format_char(std::uint32_t cp) {
  return (cp >= 0x80 && cp <= 0x9f) ||  // C1 controls (terminals act on some)
         cp == 0x061c ||                 // Arabic letter mark
         cp == 0x200b || cp == 0x200c || cp == 0x200d ||
         cp == 0x200e || cp == 0x200f ||  // zero-width and directional marks
         (cp >= 0x202a && cp <= 0x202e) ||  // bidi embedding/override
         (cp >= 0x2060 && cp <= 0x2064) ||  // invisible operators
         (cp >= 0x2066 && cp <= 0x206f) ||  // bidi isolates and deprecated controls
         cp == 0x2028 || cp == 0x2029 ||    // line and paragraph separators
         cp == 0xfeff ||                    // byte-order mark
         (cp >= 0xfff9 && cp <= 0xfffb);    // interlinear annotation
}

/// Decodes one UTF-8 code point. The caller has already validated the string.
std::uint32_t decode_utf8(std::string_view text, std::size_t index, std::size_t* length) {
  const unsigned char lead = static_cast<unsigned char>(text[index]);
  if (lead < 0x80) {
    *length = 1;
    return lead;
  }
  if ((lead & 0xe0) == 0xc0) {
    *length = 2;
    return (static_cast<std::uint32_t>(lead & 0x1f) << 6) |
           (static_cast<unsigned char>(text[index + 1]) & 0x3f);
  }
  if ((lead & 0xf0) == 0xe0) {
    *length = 3;
    return (static_cast<std::uint32_t>(lead & 0x0f) << 12) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[index + 1]) & 0x3f) << 6) |
           (static_cast<unsigned char>(text[index + 2]) & 0x3f);
  }
  *length = 4;
  return (static_cast<std::uint32_t>(lead & 0x07) << 18) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(text[index + 1]) & 0x3f) << 12) |
         (static_cast<std::uint32_t>(static_cast<unsigned char>(text[index + 2]) & 0x3f) << 6) |
         (static_cast<unsigned char>(text[index + 3]) & 0x3f);
}

void require_free_name(const std::vector<Entry>& entries, std::string_view name) {
  const std::string folded = fold_ascii_case(name);
  for (const Entry& entry : entries) {
    if (entry.name == name) {
      fail(ErrorCode::DuplicateName, "duplicate entry name '" + std::string(name) + "'");
    }
    if (fold_ascii_case(entry.name) == folded) {
      fail(ErrorCode::CaseCollision,
           "entry name '" + std::string(name) + "' collides with '" + entry.name +
               "' when case is folded");
    }
  }
}

}  // namespace

bool is_valid_utf8(ByteView text) {
  const unsigned char* p = text.data;
  const std::size_t n = text.size;
  std::size_t i = 0;
  while (i < n) {
    const unsigned char c = p[i];
    if (c < 0x80) {
      ++i;
      continue;
    }
    std::size_t extra = 0;
    unsigned char lo = 0x80;
    unsigned char hi = 0xBF;
    if ((c & 0xE0) == 0xC0) {
      extra = 1;
      if (c < 0xC2) return false;  // overlong
    } else if ((c & 0xF0) == 0xE0) {
      extra = 2;
      if (c == 0xE0) lo = 0xA0;  // overlong
      if (c == 0xED) hi = 0x9F;  // surrogates
    } else if ((c & 0xF8) == 0xF0) {
      extra = 3;
      if (c == 0xF0) lo = 0x90;  // overlong
      if (c > 0xF4) return false;
      if (c == 0xF4) hi = 0x8F;  // > U+10FFFF
    } else {
      return false;
    }
    if (i + extra >= n) return false;
    for (std::size_t k = 1; k <= extra; ++k) {
      const unsigned char cc = p[i + k];
      const unsigned char l = (k == 1) ? lo : 0x80;
      const unsigned char h = (k == 1) ? hi : 0xBF;
      if (cc < l || cc > h) return false;
    }
    i += extra + 1;
  }
  return true;
}

std::string fold_ascii_case(std::string_view name) {
  std::string out;
  out.reserve(name.size());
  for (char c : name) out.push_back(ascii_lower(c));
  return out;
}

bool is_reserved_windows_name(std::string_view name) {
  const std::size_t dot = name.find('.');
  const std::string base(name.substr(0, dot == std::string_view::npos ? name.size() : dot));
  return is_reserved_base(base);
}

void validate_name(std::string_view name, const Limits& limits) {
  if (name.empty()) {
    fail(ErrorCode::EmptyName, "empty path component");
  }
  if (name.size() > limits.max_name_bytes) {
    fail(ErrorCode::NameTooLong, "path component longer than " +
                                     std::to_string(limits.max_name_bytes) + " bytes");
  }
  if (name == "." || name == "..") {
    fail(ErrorCode::DotName, "'.' and '..' are not allowed in names");
  }
  if (!is_valid_utf8(ByteView(name))) {
    fail(ErrorCode::InvalidUtf8, "path component is not valid UTF-8");
  }
  for (char c : name) {
    if (c == '\0') {
      fail(ErrorCode::NulByte, "NUL byte in path component");
    }
    if (c == '/' || c == '\\') {
      fail(ErrorCode::PathSeparator, "path separator inside a path component");
    }
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7f) {
      fail(ErrorCode::ControlChar, "control character in path component");
    }
    if (c == ':') {
      // Windows alternate data streams and drive letters; also confusing on POSIX.
      fail(ErrorCode::ReservedName, "':' is not allowed in names");
    }
  }
  // Valid UTF-8 is already established, so this walk only looks for code points
  // that a listing cannot show honestly.
  for (std::size_t i = 0; i < name.size();) {
    std::size_t length = 0;
    const std::uint32_t cp = decode_utf8(name, i, &length);
    if (is_invisible_format_char(cp)) {
      char label[16];
      std::snprintf(label, sizeof label, "U+%04X", static_cast<unsigned>(cp));
      fail(ErrorCode::UnsafeChar,
           "name contains an invisible, directional or line-breaking character (" +
               std::string(label) + ")");
    }
    i += length;
  }
  if (name.back() == '.' || name.back() == ' ') {
    fail(ErrorCode::TrailingDotOrSpace, "name may not end with a dot or a space");
  }
  if (is_reserved_windows_name(name)) {
    fail(ErrorCode::ReservedName,
         "name '" + std::string(name) + "' is reserved on Windows");
  }
}

void validate_relative_path(std::string_view path, const Limits& limits) {
  if (path.empty()) {
    fail(ErrorCode::EmptyName, "empty path");
  }
  if (path.size() > limits.max_path_bytes) {
    fail(ErrorCode::PathTooLong, "path longer than " + std::to_string(limits.max_path_bytes) +
                                     " bytes");
  }
  if (path.front() == '/') {
    fail(ErrorCode::PathSeparator, "absolute paths are not allowed");
  }
  std::size_t depth = 0;
  std::size_t start = 0;
  while (true) {
    const std::size_t slash = path.find('/', start);
    const std::string_view component =
        path.substr(start, slash == std::string_view::npos ? std::string_view::npos : slash - start);
    ++depth;
    if (depth > limits.max_depth) {
      fail(ErrorCode::TooDeep, "path deeper than " + std::to_string(limits.max_depth) + " levels");
    }
    validate_name(component, limits);
    if (slash == std::string_view::npos) break;
    start = slash + 1;
  }
}

const char* to_string(EntryKind kind) {
  return kind == EntryKind::File ? "file" : "dir";
}

EntryKind entry_kind_from(std::string_view text) {
  if (text == "file") return EntryKind::File;
  if (text == "dir") return EntryKind::Directory;
  fail(ErrorCode::InvalidKind, "unknown entry kind '" + std::string(text) + "'");
}

Manifest Manifest::create(std::uint64_t seq) {
  Manifest manifest;
  manifest.version = format::kVersion;
  manifest.id = crypto::random_id();
  manifest.seq = seq;
  return manifest;
}

Manifest Manifest::parse(ByteView plaintext, const Limits& limits) {
  auto j = jsonx::parse_strict(to_string(plaintext), limits.max_manifest_bytes, "manifest");
  jsonx::require_object(j, "manifest");
  jsonx::reject_unknown(j, {"v", "id", "seq", "entries"}, "manifest");

  Manifest manifest;
  manifest.version = jsonx::req_uint(j, "v", "manifest");
  if (manifest.version != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported manifest version " +
                                    std::to_string(manifest.version));
  }
  const Bytes id = jsonx::req_b64(j, "id", 16, "manifest");
  std::copy(id.begin(), id.end(), manifest.id.begin());
  manifest.seq = jsonx::req_uint(j, "seq", "manifest");

  const auto entries_it = j.find("entries");
  if (entries_it == j.end()) {
    fail(ErrorCode::MissingField, "manifest: missing field 'entries'");
  }
  if (!entries_it->is_array()) {
    fail(ErrorCode::WrongType, "manifest: 'entries' must be an array");
  }
  if (entries_it->size() > limits.max_entries) {
    fail(ErrorCode::TooManyEntries, "manifest has more than " +
                                        std::to_string(limits.max_entries) + " entries");
  }
  manifest.entries.reserve(entries_it->size());
  for (const auto& raw : *entries_it) {
    jsonx::require_object(raw, "manifest entry");
    const std::string kind_text = jsonx::req_string(raw, "kind", 8, "manifest entry");
    Entry entry;
    entry.kind = entry_kind_from(kind_text);
    entry.name = jsonx::req_string(raw, "name", limits.max_name_bytes, "manifest entry");
    entry.mtime = jsonx::req_uint(raw, "mtime", "manifest entry");
    if (entry.kind == EntryKind::File) {
      jsonx::reject_unknown(raw, {"kind", "name", "mtime", "size", "file_id"}, "manifest entry");
      entry.size = jsonx::req_uint(raw, "size", "manifest entry");
      const Bytes file_id = jsonx::req_b64(raw, "file_id", 16, "manifest entry");
      std::copy(file_id.begin(), file_id.end(), entry.file_id.begin());
    } else {
      jsonx::reject_unknown(raw, {"kind", "name", "mtime", "manifest_id"}, "manifest entry");
      const Bytes manifest_id = jsonx::req_b64(raw, "manifest_id", 16, "manifest entry");
      std::copy(manifest_id.begin(), manifest_id.end(), entry.manifest_id.begin());
    }
    manifest.entries.push_back(std::move(entry));
  }

  manifest.validate(limits);
  return manifest;
}

Bytes Manifest::serialize(const Limits& limits) const {
  validate(limits);
  jsonx::Json j;
  j["v"] = version;
  j["id"] = base64url_encode(ByteView(id));
  j["seq"] = seq;
  jsonx::Json entries_json = jsonx::Json::array();
  for (const Entry& entry : entries) {
    jsonx::Json e;
    e["name"] = entry.name;
    e["kind"] = to_string(entry.kind);
    e["mtime"] = entry.mtime;
    if (entry.kind == EntryKind::File) {
      e["size"] = entry.size;
      e["file_id"] = base64url_encode(ByteView(entry.file_id));
    } else {
      e["manifest_id"] = base64url_encode(ByteView(entry.manifest_id));
    }
    entries_json.push_back(std::move(e));
  }
  j["entries"] = std::move(entries_json);
  Bytes out = to_bytes(jsonx::dump(j, "manifest"));
  if (out.size() > limits.max_manifest_bytes) {
    fail(ErrorCode::TooLarge, "serialised manifest exceeds " +
                                  std::to_string(limits.max_manifest_bytes) + " bytes");
  }
  return out;
}

void Manifest::validate(const Limits& limits) const {
  if (version != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported manifest version " + std::to_string(version));
  }
  if (is_zero(ByteView(id))) {
    fail(ErrorCode::ZeroId, "manifest id must not be all zero");
  }
  if (entries.size() > limits.max_entries) {
    fail(ErrorCode::TooManyEntries,
         "manifest has more than " + std::to_string(limits.max_entries) + " entries");
  }
  std::set<std::string> folded_names;
  std::set<std::string> file_ids;
  for (const Entry& entry : entries) {
    validate_name(entry.name, limits);
    if (!folded_names.insert(fold_ascii_case(entry.name)).second) {
      fail(ErrorCode::CaseCollision,
           "entry name '" + entry.name + "' is duplicated when case is folded");
    }
    if (entry.kind == EntryKind::File) {
      if (entry.size > limits.max_file_size) {
        fail(ErrorCode::FileTooLarge, "file '" + entry.name + "' is larger than the limit");
      }
      if (is_zero(ByteView(entry.file_id))) {
        fail(ErrorCode::ZeroId, "file '" + entry.name + "' has an all-zero file id");
      }
      if (!is_zero(ByteView(entry.manifest_id))) {
        fail(ErrorCode::BadSizeForKind,
             "file '" + entry.name + "' must not carry a manifest id");
      }
      if (!file_ids.insert(hex_encode(ByteView(entry.file_id))).second) {
        fail(ErrorCode::DuplicateFileId,
             "file id reused inside one directory ('" + entry.name + "'); a new content "
             "version must mint a new file id");
      }
    } else {
      if (entry.size != 0) {
        fail(ErrorCode::BadSizeForKind, "directory '" + entry.name + "' must have size 0");
      }
      if (!is_zero(ByteView(entry.file_id))) {
        fail(ErrorCode::BadSizeForKind,
             "directory '" + entry.name + "' must not carry a file id");
      }
      if (is_zero(ByteView(entry.manifest_id))) {
        fail(ErrorCode::ZeroId, "directory '" + entry.name + "' has an all-zero manifest id");
      }
    }
  }
}

const Entry* Manifest::find(std::string_view name) const {
  for (const Entry& entry : entries) {
    if (entry.name == name) return &entry;
  }
  return nullptr;
}

void Manifest::add_file(std::string_view name, std::uint64_t size, const Id128& file_id,
                        std::uint64_t mtime) {
  validate_name(name);
  require_free_name(entries, name);
  if (is_zero(ByteView(file_id))) {
    fail(ErrorCode::ZeroId, "file id must not be all zero");
  }
  for (const Entry& entry : entries) {
    if (entry.kind == EntryKind::File && constant_time_equal(ByteView(entry.file_id),
                                                             ByteView(file_id))) {
      fail(ErrorCode::DuplicateFileId,
           "file id already used in this directory; mint a new id for new content");
    }
  }
  Entry entry;
  entry.kind = EntryKind::File;
  entry.name = std::string(name);
  entry.size = size;
  entry.file_id = file_id;
  entry.mtime = mtime;
  entries.push_back(std::move(entry));
}

void Manifest::add_directory(std::string_view name, const Id128& manifest_id,
                             std::uint64_t mtime) {
  validate_name(name);
  require_free_name(entries, name);
  if (is_zero(ByteView(manifest_id))) {
    fail(ErrorCode::ZeroId, "manifest id must not be all zero");
  }
  Entry entry;
  entry.kind = EntryKind::Directory;
  entry.name = std::string(name);
  entry.manifest_id = manifest_id;
  entry.mtime = mtime;
  entries.push_back(std::move(entry));
}

}  // namespace skipta
