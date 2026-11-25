// SPDX-License-Identifier: AGPL-3.0-or-later
#include <vector>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "nlohmann/json.hpp"
#include "skipta/error.hpp"
#include "skipta/manifest.hpp"

using namespace skipta;
using nlohmann::json;

namespace {

const std::string kManifestIdB64 = base64url_encode(ByteView(skiptest::filled_id(0x11)));
const std::string kFileIdB64 = base64url_encode(ByteView(skiptest::filled_id(0x22)));
const std::string kDirIdB64 = base64url_encode(ByteView(skiptest::filled_id(0x33)));

json file_entry(const std::string& name = "a.txt") {
  json entry;
  entry["kind"] = "file";
  entry["name"] = name;
  entry["mtime"] = 0;
  entry["size"] = 3;
  entry["file_id"] = kFileIdB64;
  return entry;
}

json dir_entry(const std::string& name = "docs") {
  json entry;
  entry["kind"] = "dir";
  entry["name"] = name;
  entry["mtime"] = 0;
  entry["manifest_id"] = kDirIdB64;
  return entry;
}

json document(std::initializer_list<json> entries) {
  json doc;
  doc["v"] = 1;
  doc["id"] = kManifestIdB64;
  doc["seq"] = 1;
  json array = json::array();
  for (const json& entry : entries) array.push_back(entry);
  doc["entries"] = array;
  return doc;
}

std::string text_of(const json& doc) { return doc.dump(); }

ErrorCode parse_code(const json& doc) {
  return skiptest::code_of([&] { Manifest::parse(ByteView(text_of(doc))); });
}

}  // namespace

TEST_CASE("manifest round-trips through serialisation") {
  Manifest manifest = Manifest::create(7);
  manifest.add_file("a.txt", 12, skiptest::filled_id(0x22), 1700000000);
  manifest.add_directory("docs", skiptest::filled_id(0x33), 1700000001);

  const Bytes plaintext = manifest.serialize();
  const Manifest parsed = Manifest::parse(ByteView(plaintext));
  REQUIRE(parsed.entries.size() == 2);
  CHECK(parsed.id == manifest.id);
  CHECK(parsed.seq == 7);
  CHECK(parsed.entries[0].kind == EntryKind::File);
  CHECK(parsed.entries[0].name == "a.txt");
  CHECK(parsed.entries[0].size == 12);
  CHECK(parsed.entries[0].file_id == skiptest::filled_id(0x22));
  CHECK(parsed.entries[1].kind == EntryKind::Directory);
  CHECK(parsed.entries[1].manifest_id == skiptest::filled_id(0x33));

  REQUIRE(parsed.find("docs") != nullptr);
  CHECK(parsed.find("docs")->kind == EntryKind::Directory);
  CHECK(parsed.find("missing") == nullptr);
  // Serialising the parsed manifest reproduces the exact bytes (stable vectors).
  CHECK(parsed.serialize() == plaintext);
}

TEST_CASE("manifest rejects unknown, missing and duplicate fields") {
  json unknown = document({file_entry()});
  unknown["extra"] = 1;
  CHECK(parse_code(unknown) == ErrorCode::UnknownField);

  json missing = document({file_entry()});
  missing.erase("seq");
  CHECK(parse_code(missing) == ErrorCode::MissingField);

  json entry_unknown = document({file_entry()});
  entry_unknown["entries"][0]["link_target"] = "/etc/passwd";
  CHECK(parse_code(entry_unknown) == ErrorCode::UnknownField);

  json entry_missing = document({file_entry()});
  entry_missing["entries"][0].erase("file_id");
  CHECK(parse_code(entry_missing) == ErrorCode::MissingField);

  // Duplicate object keys: nlohmann would keep the last one, we refuse.
  const std::string duplicated =
      "{\"v\":1,\"id\":\"" + kManifestIdB64 + "\",\"seq\":1,\"seq\":2,\"entries\":[]}";
  CHECK(skiptest::code_of([&] { Manifest::parse(ByteView(duplicated)); }) ==
        ErrorCode::DuplicateKey);

  json wrong_type = document({file_entry()});
  wrong_type["entries"][0]["name"] = 5;
  CHECK(parse_code(wrong_type) == ErrorCode::WrongType);

  json negative = document({file_entry()});
  negative["entries"][0]["size"] = -1;
  CHECK(parse_code(negative) == ErrorCode::WrongType);

  json float_size = document({file_entry()});
  float_size["entries"][0]["size"] = 1.5;
  CHECK(parse_code(float_size) == ErrorCode::WrongType);
}

TEST_CASE("manifest version and id are checked") {
  json bad_version = document({});
  bad_version["v"] = 2;
  CHECK(parse_code(bad_version) == ErrorCode::BadVersion);

  json zero_id = document({});
  zero_id["id"] = base64url_encode(ByteView(skiptest::filled_id(0x00)));
  CHECK(parse_code(zero_id) == ErrorCode::ZeroId);

  json short_id = document({});
  const Bytes eight(8, 0x11);
  short_id["id"] = base64url_encode(ByteView(eight));
  CHECK(parse_code(short_id) == ErrorCode::WrongType);
}

TEST_CASE("entry kind decides which fields are allowed") {
  json unknown_kind = document({file_entry()});
  unknown_kind["entries"][0]["kind"] = "symlink";
  CHECK(parse_code(unknown_kind) == ErrorCode::InvalidKind);

  json dir_with_size = document({dir_entry()});
  dir_with_size["entries"][0]["size"] = 5;
  CHECK(parse_code(dir_with_size) == ErrorCode::UnknownField);

  json file_with_dir_id = document({file_entry()});
  file_with_dir_id["entries"][0]["manifest_id"] = kDirIdB64;
  CHECK(parse_code(file_with_dir_id) == ErrorCode::UnknownField);

  json zero_file_id = document({file_entry()});
  zero_file_id["entries"][0]["file_id"] = base64url_encode(ByteView(skiptest::filled_id(0x00)));
  CHECK(parse_code(zero_file_id) == ErrorCode::ZeroId);

  // Direct construction cannot smuggle the wrong fields either.
  Manifest manifest = Manifest::create(1);
  Entry dir;
  dir.kind = EntryKind::Directory;
  dir.name = "docs";
  dir.size = 4;
  dir.manifest_id = skiptest::filled_id(0x33);
  manifest.entries.push_back(dir);
  CHECK(skiptest::code_of([&] { manifest.validate(); }) == ErrorCode::BadSizeForKind);
}

TEST_CASE("hostile names are rejected with specific codes") {
  struct Case {
    std::string name;
    ErrorCode expected;
  };
  const std::vector<Case> cases = {
      {"", ErrorCode::EmptyName},
      {".", ErrorCode::DotName},
      {"..", ErrorCode::DotName},
      {"a/b", ErrorCode::PathSeparator},
      {"a\\b", ErrorCode::PathSeparator},
      {std::string("nul\0byte", 8), ErrorCode::NulByte},
      {"ctrl\x01", ErrorCode::ControlChar},
      {"del\x7f", ErrorCode::ControlChar},
      {"trailing.", ErrorCode::TrailingDotOrSpace},
      {"trailing ", ErrorCode::TrailingDotOrSpace},
      {"con", ErrorCode::ReservedName},
      {"CON.txt", ErrorCode::ReservedName},
      {"lpt9.log", ErrorCode::ReservedName},
      {"clock$", ErrorCode::ReservedName},
      {"alt:stream", ErrorCode::ReservedName},
      {"pay\xe2\x80\xae" "fdp.exe", ErrorCode::UnsafeChar},  // U+202E RTL override
      {"iso\xe2\x81\xa6" "late", ErrorCode::UnsafeChar},     // U+2066 bidi isolate
      {"nel\xc2\x85", ErrorCode::UnsafeChar},                // U+0085 C1 control
      {"zero\xe2\x80\x8b" "width", ErrorCode::UnsafeChar},    // U+200B
      {"bom\xef\xbb\xbf" "name", ErrorCode::UnsafeChar},      // U+FEFF
      {"line\xe2\x80\xa8" "break", ErrorCode::UnsafeChar},    // U+2028
      {std::string(256, 'a'), ErrorCode::NameTooLong},
  };
  for (const Case& c : cases) {
    INFO("name: " << c.name);
    CHECK(skiptest::code_of([&] { validate_name(c.name); }) == c.expected);
  }

  // These are legitimate on all target systems and must stay accepted.
  for (const char* good : {"a.txt", "caf\xc3\xa9", "two words.txt", ".hidden", "UPPER.TXT",
                          "a-b_c", "bl\xc3\xa5" "b\xc3\xa6" "rsyltet\xc3\xb8" "y",
                          "\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e.txt",
                          "\xf0\x9f\x93\x81.txt"}) {
    INFO("name: " << good);
    CHECK(skiptest::code_of([&] { validate_name(std::string(good)); }) ==
          static_cast<ErrorCode>(-1));
  }
}

TEST_CASE("invalid UTF-8 never reaches a manifest") {
  const std::string invalid = "bad\xffname";
  CHECK(skiptest::code_of([&] { validate_name(invalid); }) == ErrorCode::InvalidUtf8);
}

TEST_CASE("names are compared case-insensitively to avoid collisions") {
  Manifest manifest = Manifest::create(1);
  manifest.add_file("Readme.TXT", 1, skiptest::filled_id(0x22));
  CHECK(skiptest::code_of([&] { manifest.add_file("README.txt", 1, skiptest::filled_id(0x44)); }) ==
        ErrorCode::CaseCollision);
  CHECK(skiptest::code_of([&] { manifest.add_file("Readme.TXT", 1, skiptest::filled_id(0x44)); }) ==
        ErrorCode::DuplicateName);
}

TEST_CASE("entries and byte limits are enforced on parse") {
  Limits tight;
  tight.max_entries = 2;
  json doc = document({file_entry("a"), file_entry("b"), file_entry("c")});
  CHECK(skiptest::code_of([&] { Manifest::parse(ByteView(text_of(doc)), tight); }) ==
        ErrorCode::TooManyEntries);

  Limits tiny;
  tiny.max_manifest_bytes = 20;
  CHECK(skiptest::code_of([&] { Manifest::parse(ByteView(text_of(document({}))), tiny); }) ==
        ErrorCode::TooLarge);

  Limits small_files;
  small_files.max_file_size = 2;
  json big = document({file_entry()});
  CHECK(skiptest::code_of([&] { Manifest::parse(ByteView(text_of(big)), small_files); }) ==
        ErrorCode::FileTooLarge);

  // Deeply nested json is refused before it can exhaust the stack.
  std::string deep = "{\"v\":1,\"id\":\"" + kManifestIdB64 + "\",\"seq\":1,\"entries\":[";
  deep += std::string(200, '[') + std::string(200, ']') + "]}";
  CHECK(skiptest::code_of([&] { Manifest::parse(ByteView(deep)); }) == ErrorCode::TooDeep);
}

TEST_CASE("browsing paths are validated, not normalised silently") {
  CHECK(skiptest::code_of([] { validate_relative_path("docs/reports/q1.txt"); }) ==
        static_cast<ErrorCode>(-1));
  CHECK(skiptest::code_of([] { validate_relative_path("/docs"); }) == ErrorCode::PathSeparator);
  CHECK(skiptest::code_of([] { validate_relative_path("docs/"); }) == ErrorCode::EmptyName);
  CHECK(skiptest::code_of([] { validate_relative_path("docs//x"); }) == ErrorCode::EmptyName);
  CHECK(skiptest::code_of([] { validate_relative_path("docs/../x"); }) == ErrorCode::DotName);
  CHECK(skiptest::code_of([] { validate_relative_path("docs\\x"); }) == ErrorCode::PathSeparator);
  CHECK(skiptest::code_of([] { validate_relative_path(""); }) == ErrorCode::EmptyName);
  CHECK(skiptest::code_of([] {
          validate_relative_path("docs/" + std::string(256, 'a'));
        }) != static_cast<ErrorCode>(-1));
}
