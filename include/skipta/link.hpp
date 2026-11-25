// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Share links. A link is a bearer secret: whoever holds it can read the share.
// Key material is inside the link payload and must never be sent to trackers
// or the DHT; only the opaque names below may be published there.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "skipta/bytes.hpp"
#include "skipta/format.hpp"

namespace skipta {

struct ShareLink {
  std::uint64_t version = format::kVersion;
  PubKey32 drive{};
  Key32 key{};  ///< drive key; secret
  std::vector<std::string> bootstrap;  ///< optional hints, e.g. "seed:host:6969"
};

/// "skipta://v1/" + base64url(json). Throws if any field is out of range.
std::string encode_link(const ShareLink& link);

/// Accepts surrounding whitespace; rejects everything else that is not a
/// well-formed v1 link. Length is capped before any parsing happens.
ShareLink decode_link(std::string_view text);

/// Opaque swarm names derived from the drive key, so that DHT crawlers cannot
/// enumerate shares (spec T2). Stable for a given link and generation.
std::array<unsigned char, 32> swarm_salt(const ShareLink& link);
std::array<unsigned char, 32> swarm_id(const ShareLink& link, std::uint64_t generation);

}  // namespace skipta
