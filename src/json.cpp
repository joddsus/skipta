// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/json.hpp"

#include <set>
#include <string>
#include <vector>

#include "skipta/error.hpp"

namespace skipta::jsonx {
namespace {

constexpr int kMaxNesting = 64;

/// Rejects duplicate object keys and absurd nesting before the value is built.
/// nlohmann keeps the last duplicate, which is a parser-difference vector for
/// manifests: two readers can disagree about a name. We refuse instead.
struct StrictGuard {
  std::vector<std::set<std::string>> stack;

  bool operator()(int depth, Json::parse_event_t event, Json& parsed) {
    if (depth > kMaxNesting) {
      fail(ErrorCode::TooDeep, "json nesting deeper than 64 levels");
    }
    switch (event) {
      case Json::parse_event_t::object_start:
        stack.emplace_back();
        break;
      case Json::parse_event_t::object_end:
        if (!stack.empty()) stack.pop_back();
        break;
      case Json::parse_event_t::key:
        if (!stack.empty() && parsed.is_string() &&
            !stack.back().insert(parsed.get<std::string>()).second) {
          fail(ErrorCode::DuplicateKey, "duplicate json object key: " + parsed.get<std::string>());
        }
        break;
      default:
        break;
    }
    return true;
  }
};

}  // namespace

Json parse_strict(std::string_view text, std::size_t max_bytes, const char* what) {
  if (text.size() > max_bytes) {
    fail(ErrorCode::TooLarge, std::string(what) + ": input larger than " +
                                  std::to_string(max_bytes) + " bytes");
  }
  StrictGuard guard;
  try {
    return Json::parse(text.begin(), text.end(), guard, true);
  } catch (const Error&) {
    throw;
  } catch (const Json::exception& e) {
    fail(ErrorCode::BadJson, std::string(what) + ": " + e.what());
  }
}

std::string dump(const Json& value, const char* what) {
  try {
    return value.dump();
  } catch (const Json::exception& e) {
    fail(ErrorCode::BadJson, std::string(what) + ": cannot serialise: " + e.what());
  }
}

void require_object(const Json& value, const char* what) {
  if (!value.is_object()) {
    fail(ErrorCode::WrongType, std::string(what) + ": expected a json object");
  }
}

void reject_unknown(const Json& object, std::initializer_list<const char*> allowed,
                    const char* what) {
  for (auto it = object.begin(); it != object.end(); ++it) {
    bool known = false;
    for (const char* key : allowed) {
      if (it.key() == key) {
        known = true;
        break;
      }
    }
    if (!known) {
      fail(ErrorCode::UnknownField, std::string(what) + ": unknown field '" + it.key() + "'");
    }
  }
}

std::string req_string(const Json& object, const char* key, std::size_t max_bytes,
                       const char* what) {
  const auto it = object.find(key);
  if (it == object.end()) {
    fail(ErrorCode::MissingField, std::string(what) + ": missing field '" + key + "'");
  }
  if (!it->is_string()) {
    fail(ErrorCode::WrongType, std::string(what) + ": field '" + key + "' must be a string");
  }
  std::string value = it->get<std::string>();
  if (value.size() > max_bytes) {
    fail(ErrorCode::TooLarge, std::string(what) + ": field '" + key + "' is too long");
  }
  return value;
}

std::uint64_t req_uint(const Json& object, const char* key, const char* what) {
  const auto it = object.find(key);
  if (it == object.end()) {
    fail(ErrorCode::MissingField, std::string(what) + ": missing field '" + key + "'");
  }
  if (it->is_number_unsigned()) {
    return it->get<std::uint64_t>();
  }
  if (it->is_number_integer()) {
    const std::int64_t value = it->get<std::int64_t>();
    if (value < 0) {
      fail(ErrorCode::WrongType,
           std::string(what) + ": field '" + key + "' must not be negative");
    }
    return static_cast<std::uint64_t>(value);
  }
  fail(ErrorCode::WrongType,
       std::string(what) + ": field '" + key + "' must be an unsigned integer");
}

Bytes req_b64(const Json& object, const char* key, std::size_t expected_len, const char* what) {
  const std::string text = req_string(object, key, 4096, what);
  Bytes out = base64url_decode(text, (std::string(what) + ": field '" + key + "'").c_str());
  if (expected_len != static_cast<std::size_t>(-1) && out.size() != expected_len) {
    fail(ErrorCode::WrongType, std::string(what) + ": field '" + key + "' has wrong length");
  }
  return out;
}

}  // namespace skipta::jsonx
