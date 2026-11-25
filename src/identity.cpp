// SPDX-License-Identifier: AGPL-3.0-or-later
#include "skipta/identity.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "skipta/error.hpp"
#include "skipta/json.hpp"
#include "skipta/private_file.hpp"

namespace skipta {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxIdentityBytes = 4096;
constexpr std::uint64_t kWrappedIdentityVersion = 2;

// drive_key[32] || signing seed[32] || u64be(seq)
constexpr std::size_t kDriveKeyOffset = 0;
constexpr std::size_t kSeedOffset = 32;
constexpr std::size_t kSeqOffset = 64;
constexpr std::size_t kWrappedSecretBytes = 72;

/// Canonical form of the published folder, so "./photos" and "photos/" agree.
std::string canonical_source(const fs::path& source) {
  std::error_code ec;
  const fs::path canonical = fs::weakly_canonical(source, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot resolve " + source.string());
  return canonical.generic_string();
}

std::array<unsigned char, 32> seed_of(const crypto::SigningKeyPair& signing) {
  // libsodium's secret key is the 32-byte seed followed by the public key.
  std::array<unsigned char, 32> seed{};
  std::copy(signing.secret.begin(), signing.secret.begin() + 32, seed.begin());
  return seed;
}

void put_u64be(unsigned char* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<unsigned char>((value >> (8 * (7 - i))) & 0xff);
  }
}

std::uint64_t get_u64be(const unsigned char* in) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | in[i];
  }
  return value;
}

/// The identity is a small regular file. Checking that before reading keeps a
/// planted device or huge file from blocking or exhausting the publisher, and
/// refusing a symlink keeps the read on the file the store actually holds.
std::optional<std::string> read_identity_text(const fs::path& path) {
  std::error_code ec;
  const fs::file_status status = fs::symlink_status(path, ec);
  if (ec) {
    if (ec == std::errc::no_such_file_or_directory) return std::nullopt;
    fail(ErrorCode::StoreIo, "cannot stat identity file " + path.string() + ": " + ec.message());
  }
  if (status.type() == fs::file_type::not_found) return std::nullopt;
  if (!fs::is_regular_file(status)) {
    fail(ErrorCode::UnsupportedFileType,
         "identity file is not a regular file: " + path.string());
  }
  const std::uintmax_t size = fs::file_size(path, ec);
  if (ec) fail(ErrorCode::StoreIo, "cannot size identity file: " + path.string());
  if (size == 0 || size > kMaxIdentityBytes) {
    fail(ErrorCode::StoreIo, "identity file has a bad size: " + path.string());
  }

  std::ifstream in(path, std::ios::binary);
  if (!in) fail(ErrorCode::StoreIo, "cannot read identity file: " + path.string());
  std::string text(static_cast<std::size_t>(size), '\0');
  in.read(text.data(), static_cast<std::streamsize>(text.size()));
  if (static_cast<std::size_t>(in.gcount()) != text.size()) {
    fail(ErrorCode::StoreIo, "short read from identity file: " + path.string());
  }
  return text;
}

std::uint64_t identity_version(std::string_view text) {
  auto j = jsonx::parse_strict(text, kMaxIdentityBytes, "identity");
  jsonx::require_object(j, "identity");
  return jsonx::req_uint(j, "v", "identity");
}

/// Every unreadable or unknown identity file gets one stable, actionable error
/// so the CLI can give it a dedicated exit code.
[[noreturn]] void unsupported(const fs::path& path, const std::string& why) {
  fail(ErrorCode::UnsupportedIdentity,
       "identity file " + path.string() +
           " is neither a passphrase-wrapped identity nor a legacy plaintext identity: " + why);
}

/// Decodes one identity file's text in either format. Shared by the source-keyed
/// lookup and the direct file read so they cannot drift apart.
DriveIdentity decode_identity_text(const std::string& text, const fs::path& path,
                                   std::string_view passphrase) {
  std::uint64_t version = 0;
  try {
    version = identity_version(text);
  } catch (const Error& e) {
    unsupported(path, e.what());
  }
  if (version == format::kVersion) {
    try {
      return decode_identity(ByteView(text));
    } catch (const Error& e) {
      unsupported(path, e.what());
    }
  }
  if (version == kWrappedIdentityVersion) {
    return decode_wrapped_identity(ByteView(text), passphrase);
  }
  unsupported(path, "unsupported identity version " + std::to_string(version));
}

}  // namespace

DriveIdentity DriveIdentity::create() {
  DriveIdentity identity;
  identity.drive_key = crypto::random_key();
  identity.signing = crypto::SigningKeyPair::generate();
  identity.seq = 0;
  return identity;
}

Bytes encode_identity(const DriveIdentity& identity) {
  jsonx::Json j;
  j["v"] = format::kVersion;
  j["drive"] = base64url_encode(ByteView(identity.signing.pub));
  j["drive_key"] = base64url_encode(ByteView(identity.drive_key));
  j["signing_seed"] = base64url_encode(ByteView(seed_of(identity.signing)));
  j["seq"] = identity.seq;
  return to_bytes(jsonx::dump(j, "identity"));
}

DriveIdentity decode_identity(ByteView text) {
  auto j = jsonx::parse_strict(to_string(text), kMaxIdentityBytes, "identity");
  jsonx::require_object(j, "identity");
  // Version first: v2 has different fields and must not look like an unknown
  // field in a v1 file.
  if (jsonx::req_uint(j, "v", "identity") != format::kVersion) {
    fail(ErrorCode::BadVersion, "unsupported identity version");
  }
  jsonx::reject_unknown(j, {"v", "drive", "drive_key", "signing_seed", "seq"}, "identity");

  DriveIdentity identity;
  const Bytes key = jsonx::req_b64(j, "drive_key", 32, "identity");
  std::copy(key.begin(), key.end(), identity.drive_key.begin());
  const Bytes pub = jsonx::req_b64(j, "drive", 32, "identity");
  const Bytes seed = jsonx::req_b64(j, "signing_seed", 32, "identity");
  Key32 seed_key{};
  std::copy(seed.begin(), seed.end(), seed_key.begin());
  identity.signing = crypto::SigningKeyPair::from_seed(seed_key);
  identity.seq = jsonx::req_uint(j, "seq", "identity");

  if (is_zero(ByteView(identity.drive_key))) {
    fail(ErrorCode::ZeroId, "identity drive key must not be all zero");
  }
  if (!constant_time_equal(ByteView(identity.signing.pub), ByteView(pub))) {
    fail(ErrorCode::DriveMismatch, "identity public key does not match its signing seed");
  }
  return identity;
}

Bytes encode_wrapped_identity(const DriveIdentity& identity, std::string_view passphrase,
                              const Argon2Params& params) {
  if (is_zero(ByteView(identity.drive_key))) {
    fail(ErrorCode::ZeroId, "identity drive key must not be all zero");
  }

  Bytes secret(kWrappedSecretBytes, 0);
  std::copy(identity.drive_key.begin(), identity.drive_key.end(),
            secret.begin() + kDriveKeyOffset);
  const std::array<unsigned char, 32> seed = seed_of(identity.signing);
  std::copy(seed.begin(), seed.end(), secret.begin() + kSeedOffset);
  put_u64be(secret.data() + kSeqOffset, identity.seq);

  Bytes wrapped;
  try {
    wrapped = wrap_secret(ByteView(secret), passphrase, params);
  } catch (...) {
    crypto::wipe(secret.data(), secret.size());
    throw;
  }
  crypto::wipe(secret.data(), secret.size());

  auto inner = jsonx::parse_strict(to_string(ByteView(wrapped)), kMaxIdentityBytes,
                                   "wrapped identity");
  jsonx::Json j;
  j["v"] = kWrappedIdentityVersion;
  j["wrap"] = std::move(inner);
  return to_bytes(jsonx::dump(j, "wrapped identity"));
}

DriveIdentity decode_wrapped_identity(ByteView text, std::string_view passphrase) {
  auto j = jsonx::parse_strict(to_string(text), kMaxIdentityBytes, "identity");
  jsonx::require_object(j, "identity");
  if (jsonx::req_uint(j, "v", "identity") != kWrappedIdentityVersion) {
    fail(ErrorCode::UnsupportedIdentity,
         "identity is not a passphrase-wrapped identity (expected v2)");
  }
  jsonx::reject_unknown(j, {"v", "wrap"}, "identity");

  const auto wrap_it = j.find("wrap");
  if (wrap_it == j.end() || !wrap_it->is_object()) {
    fail(ErrorCode::UnsupportedIdentity, "identity: missing the wrapped secret");
  }
  const std::string inner = jsonx::dump(*wrap_it, "wrapped identity");

  Bytes secret;
  try {
    secret = unwrap_secret(ByteView(inner), passphrase);
  } catch (const Error& e) {
    if (e.code() == ErrorCode::BadPassphrase) throw;  // the one error worth naming
    fail(ErrorCode::UnsupportedIdentity,
         "identity: wrapped secret is unusable: " + std::string(e.what()));
  }
  if (secret.size() != kWrappedSecretBytes) {
    crypto::wipe(secret.data(), secret.size());
    fail(ErrorCode::UnsupportedIdentity, "identity: wrapped secret has the wrong size");
  }

  DriveIdentity identity;
  std::copy(secret.begin() + kDriveKeyOffset, secret.begin() + kSeedOffset,
            identity.drive_key.begin());
  Key32 seed{};
  std::copy(secret.begin() + kSeedOffset, secret.begin() + kSeqOffset, seed.begin());
  identity.signing = crypto::SigningKeyPair::from_seed(seed);
  identity.seq = get_u64be(secret.data() + kSeqOffset);
  crypto::wipe(seed.data(), seed.size());
  crypto::wipe(secret.data(), secret.size());

  if (is_zero(ByteView(identity.drive_key))) {
    fail(ErrorCode::ZeroId, "identity drive key must not be all zero");
  }
  return identity;
}

IdentityStore::IdentityStore(std::filesystem::path dir) : dir_(std::move(dir)) {}

std::filesystem::path IdentityStore::path_for(const std::filesystem::path& source) const {
  const std::string canonical = canonical_source(source);
  const auto digest = crypto::sha256(ByteView(canonical));
  return dir_ / (hex_encode(ByteView(digest)) + ".id");
}

IdentityFormat IdentityStore::format(const std::filesystem::path& source) const {
  const fs::path path = path_for(source);
  const std::optional<std::string> text = read_identity_text(path);
  if (!text) return IdentityFormat::Missing;

  std::uint64_t version = 0;
  try {
    version = identity_version(*text);
  } catch (const Error& e) {
    unsupported(path, e.what());
  }
  if (version == format::kVersion) return IdentityFormat::Plaintext;
  if (version == kWrappedIdentityVersion) return IdentityFormat::Wrapped;
  unsupported(path, "unsupported identity version " + std::to_string(version));
}

std::optional<DriveIdentity> IdentityStore::load(const std::filesystem::path& source,
                                                std::string_view passphrase) const {
  const fs::path path = path_for(source);
  const std::optional<std::string> text = read_identity_text(path);
  if (!text) return std::nullopt;
  return decode_identity_text(*text, path, passphrase);
}

std::vector<fs::path> IdentityStore::files() const {
  std::vector<fs::path> out;
  std::error_code ec;
  fs::directory_iterator it(dir_, ec);
  if (ec) return out;  // nothing published from this store yet

  for (const auto& entry : it) {
    const std::string name = entry.path().filename().string();
    // The name save() writes: SHA-256 of the folder path, hex, ".id". Anything
    // else is not ours (temp files from an interrupted save are left alone).
    if (name.size() != 64 + 3 || name.compare(64, 3, ".id") != 0) continue;
    bool hex = true;
    for (std::size_t i = 0; i < 64; ++i) {
      const char c = name[i];
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
        hex = false;
        break;
      }
    }
    if (hex) out.push_back(entry.path());
  }
  std::sort(out.begin(), out.end());
  return out;
}

DriveIdentity IdentityStore::load_file(const std::filesystem::path& path,
                                       std::string_view passphrase) const {
  const std::optional<std::string> text = read_identity_text(path);
  if (!text) fail(ErrorCode::NotFound, "identity file is missing: " + path.string());
  return decode_identity_text(*text, path, passphrase);
}

void IdentityStore::save(const std::filesystem::path& source, const DriveIdentity& identity,
                         std::string_view passphrase, const Argon2Params& params) const {
  const fs::path path = path_for(source);
  const Bytes text = encode_wrapped_identity(identity, passphrase, params);

  // 0700 directories and a 0600 file, set when each is created: a plaintext
  // seed must never sit in a world-readable temp file, even briefly. A hostile
  // store must not redirect the identity write through a symlinked directory.
  std::error_code sec;
  if (fs::is_symlink(fs::symlink_status(dir_, sec))) {
    fail(ErrorCode::UnsupportedFileType,
         "refusing a symlinked identity directory: " + dir_.string());
  }
  make_private_directory(dir_);
  if (dir_.has_parent_path() && !dir_.parent_path().empty()) {
    make_private_directory(dir_.parent_path());
  }
  write_private_file(path, ByteView(text), false);
}

void IdentityStore::rewrap(const std::filesystem::path& source,
                           std::string_view old_passphrase,
                           std::string_view new_passphrase,
                           const Argon2Params& params) const {
  const fs::path path = path_for(source);
  const std::optional<std::string> text = read_identity_text(path);
  if (!text) {
    fail(ErrorCode::NotFound, "no drive identity for " + source.string() + " in " +
                                  dir_.string() + "; publish the folder first");
  }

  // Read the version from the bytes already in hand, so the file cannot change
  // between deciding what it is and decrypting it.
  std::uint64_t version = 0;
  try {
    version = identity_version(*text);
  } catch (const Error& e) {
    unsupported(path, e.what());
  }
  if (version == skipta::format::kVersion) {
    fail(ErrorCode::UnsupportedIdentity,
         "identity file " + path.string() +
             " is a legacy plaintext identity; publish the folder once to migrate it, then "
             "change the passphrase");
  }
  if (version != kWrappedIdentityVersion) {
    unsupported(path, "unsupported identity version " + std::to_string(version));
  }

  // Unwrap first: a wrong old passphrase never reaches a write. `save` then
  // validates the new passphrase (including empty) before it creates a temp
  // file, so a rejected new passphrase also leaves the old file in place.
  const DriveIdentity identity = decode_wrapped_identity(ByteView(*text), old_passphrase);
  save(source, identity, new_passphrase, params);
}

}  // namespace skipta
