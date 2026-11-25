// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Strict JSON for metadata that arrives from the network. Plain nlohmann
// parsing is not enough for hostile input: duplicate object keys and unbounded
// nesting are parser-difference vectors, so they are rejected here.
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>

#include "nlohmann/json.hpp"
#include "skipta/bytes.hpp"

namespace skipta::jsonx {

using Json = nlohmann::json;

/// Parse with a hard byte limit, duplicate-key rejection and a nesting limit.
Json parse_strict(std::string_view text, std::size_t max_bytes, const char* what);

std::string dump(const Json& value, const char* what);

void require_object(const Json& value, const char* what);

/// Reject any key not in `allowed` (UnknownField).
void reject_unknown(const Json& object, std::initializer_list<const char*> allowed,
                    const char* what);

std::string req_string(const Json& object, const char* key, std::size_t max_bytes,
                       const char* what);
std::uint64_t req_uint(const Json& object, const char* key, const char* what);
Bytes req_b64(const Json& object, const char* key, std::size_t expected_len, const char* what);

}  // namespace skipta::jsonx
