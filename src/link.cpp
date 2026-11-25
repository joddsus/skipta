// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/link.hpp"

#include <algorithm>
#include <cctype>
#include <string>

#include "skipta/error.hpp"
#include "skipta/json.hpp"
#include "skipta/manifest.hpp"

namespace skipta {
namespace {

constexpr std::size_t kMaxBootstrapChars = 255;

std::string_view trim(std::string_view text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  auto space = [](char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
  };
  while (begin < end && space(text[begin])) ++begin;
  while (end > begin && space(text[end - 1])) --end;
  return text.substr(begin, end - begin);
}

bool is_bootstrap_char(char c) {
  const unsigned char u = static_cast<unsigned char>(c);
  if (std::isalnum(u) != 0) return true;
  switch (c) {
    case ':':
    case '.':
    case '/':
    case '-':
    case '_':
    case '[':
    case ']':
    case '%':
      return true;
    default:
      return false;
  }
}

void validate_bootstrap(const std::vector<std::string>& hints, const Limits& limits) {
  if (hints.size() > limits.max_bootstrap_hints) {
    fail(ErrorCode::BadBootstrapHint, "too many bootstrap hints");
  }
  for (const std::string& hint : hints) {
    if (hint.empty() || hint.size() > kMaxBootstrapChars) {
      fail(ErrorCode::BadBootstrapHint, "bootstrap hint has bad length");
    }
    for (char c : hint) {
      if (!is_bootstrap_char(c)) {
        fail(ErrorCode::BadBootstrapHint, "bootstrap hint contains a disallowed character");
      }
    }
  }
}

void put_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<unsigned char>((value >> shift) & 0xff));
  }
}

Bytes tagged(std::string_view tag, const PubKey32& drive) {
  Bytes out;
  out.reserve(tag.size() + drive.size());
  out.insert(out.end(), tag.begin(), tag.end());
  out.insert(out.end(), drive.begin(), drive.end());
  return out;
}

}  // namespace

std::string encode_link(const ShareLink& link) {
  if (link.version != format::kVersion) {
    fail(ErrorCode::BadVersion, "can only encode v1 links");
  }
  if (is_zero(ByteView(link.drive))) {
    fail(ErrorCode::ZeroId, "link drive key must not be all zero");
  }
  if (is_zero(ByteView(link.key))) {
    fail(ErrorCode::ZeroId, "link drive key must not be all zero");
  }
  validate_bootstrap(link.bootstrap, Limits{});

  jsonx::Json j;
  j["v"] = link.version;
  j["drive"] = base64url_encode(ByteView(link.drive));
  j["key"] = base64url_encode(ByteView(link.key));
  if (!link.bootstrap.empty()) {
    j["bootstrap"] = link.bootstrap;
  }
  const std::string payload = jsonx::dump(j, "link");
  std::string out = std::string(format::kScheme) + base64url_encode(ByteView(payload));
  if (out.size() > format::kMaxLinkChars) {
    fail(ErrorCode::TooLarge, "link longer than " + std::to_string(format::kMaxLinkChars) +
                                  " characters");
  }
  return out;
}

ShareLink decode_link(std::string_view text) {
  const std::string_view trimmed = trim(text);
  if (trimmed.empty()) {
    fail(ErrorCode::BadLink, "empty link");
  }
  if (trimmed.size() > format::kMaxLinkChars) {
    fail(ErrorCode::TooLarge, "link longer than " + std::to_string(format::kMaxLinkChars) +
                                  " characters");
  }
  if (trimmed.substr(0, format::kScheme.size()) != format::kScheme) {
    fail(ErrorCode::BadScheme, "not a skipta://v1/ link");
  }
  const std::string_view payload_b64 = trimmed.substr(format::kScheme.size());
  const Bytes payload = base64url_decode(payload_b64, "link");

  auto j = jsonx::parse_strict(to_string(payload), format::kMaxLinkChars, "link");
  jsonx::require_object(j, "link");
  jsonx::reject_unknown(j, {"v", "drive", "key", "bootstrap"}, "link");

  ShareLink link;
  link.version = jsonx::req_uint(j, "v", "link");
  if (link.version != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported link version " + std::to_string(link.version));
  }
  const Bytes drive = jsonx::req_b64(j, "drive", 32, "link");
  std::copy(drive.begin(), drive.end(), link.drive.begin());
  const Bytes key = jsonx::req_b64(j, "key", 32, "link");
  std::copy(key.begin(), key.end(), link.key.begin());

  const auto bootstrap_it = j.find("bootstrap");
  if (bootstrap_it != j.end()) {
    if (!bootstrap_it->is_array()) {
      fail(ErrorCode::WrongType, "link: 'bootstrap' must be an array");
    }
    if (bootstrap_it->size() > Limits{}.max_bootstrap_hints) {
      fail(ErrorCode::BadBootstrapHint, "link: too many bootstrap hints");
    }
    for (const auto& hint : *bootstrap_it) {
      if (!hint.is_string() || hint.get<std::string>().size() > kMaxBootstrapChars) {
        fail(ErrorCode::BadBootstrapHint, "link: bootstrap hint must be a short string");
      }
      link.bootstrap.push_back(hint.get<std::string>());
    }
    validate_bootstrap(link.bootstrap, Limits{});
  }

  if (is_zero(ByteView(link.drive))) {
    fail(ErrorCode::ZeroId, "link: drive key is all zero");
  }
  if (is_zero(ByteView(link.key))) {
    fail(ErrorCode::ZeroId, "link: drive key is all zero");
  }
  return link;
}

std::array<unsigned char, 32> swarm_salt(const ShareLink& link) {
  return crypto::blake2b256_keyed(ByteView(link.key),
                                  ByteView(tagged(format::kSwarmSaltTag, link.drive)));
}

std::array<unsigned char, 32> swarm_id(const ShareLink& link, std::uint64_t generation) {
  Bytes msg = tagged(format::kSwarmIdTag, link.drive);
  put_u64(msg, generation);
  return crypto::blake2b256_keyed(ByteView(link.key), ByteView(msg));
}

}  // namespace skipta
