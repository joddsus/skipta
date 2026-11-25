// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Publisher-side drive identity, kept between runs.
//
// A share link carries only the drive public key and the drive key, so the same
// identity always yields the same link. Republishing from a saved identity thus
// updates the drive in place: readers keep their link and the signed root
// pointer's seq advances, which is what rollback protection compares against.
//
// The identity file holds the publisher's secrets (drive key + signing seed), so
// it is written with owner-only permissions and must never be published. Since
// v2 it is encrypted with a passphrase (Argon2id + XChaCha20-Poly1305, see
// keywrap.hpp); a stolen store copy therefore yields neither the drive key nor
// the signing seed without that passphrase. Files in the old v1 plaintext format
// are still read so an existing store keeps working; the next publish writes v2
// back over the same path.
#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>
#include <vector>

#include "skipta/bytes.hpp"
#include "skipta/crypto.hpp"
#include "skipta/format.hpp"
#include "skipta/keywrap.hpp"

namespace skipta {

struct DriveIdentity {
  Key32 drive_key{};                 ///< decrypts the share content
  crypto::SigningKeyPair signing{};  ///< signs root pointers
  std::uint64_t seq = 0;             ///< seq of the last published pointer

  static DriveIdentity create();

  const PubKey32& public_key() const noexcept { return signing.pub; }
};

/// Legacy v1 plaintext identity. Kept for migration and for the file-format test
/// only; publishing always writes the wrapped form.
/// Throws on anything malformed, including a public key that does not match the
/// seed, so a corrupted identity cannot quietly become a different drive.
Bytes encode_identity(const DriveIdentity& identity);
DriveIdentity decode_identity(ByteView text);

/// v2 identity file: {"v":2,"wrap":<keywrap blob>}. The wrapped plaintext is
/// drive_key[32] || signing seed[32] || u64be(seq), so neither the drive key nor
/// the seed appears in the file. A wrong passphrase and a damaged envelope are
/// reported as BadPassphrase; a structurally unusable file is UnsupportedIdentity.
Bytes encode_wrapped_identity(const DriveIdentity& identity, std::string_view passphrase,
                              const Argon2Params& params = Argon2Params{});
DriveIdentity decode_wrapped_identity(ByteView text, std::string_view passphrase);

/// What is on disk for one published folder.
enum class IdentityFormat {
  Missing,   ///< never published from this folder, or the identity file is gone
  Plaintext, ///< legacy v1: readable only because it predates wrapping
  Wrapped,   ///< v2: needs the passphrase
};

/// One identity per published folder, stored under a directory of its own
/// (normally `<store>/identities`). The file name is the SHA-256 of the
/// folder's canonical path, so republishing the same folder finds it again.
class IdentityStore {
 public:
  explicit IdentityStore(std::filesystem::path dir);

  const std::filesystem::path& dir() const noexcept { return dir_; }

  std::filesystem::path path_for(const std::filesystem::path& source) const;

  /// Reads only the version field; used to decide whether a passphrase must be
  /// set up (new or legacy) or only supplied (wrapped).
  IdentityFormat format(const std::filesystem::path& source) const;

  /// Missing file returns nullopt. A legacy plaintext identity is returned
  /// without using `passphrase` (migration happens on the next save). A wrapped
  /// identity needs it: a wrong or empty passphrase is BadPassphrase.
  std::optional<DriveIdentity> load(const std::filesystem::path& source,
                                    std::string_view passphrase) const;

  /// Every identity file in the directory, sorted by name. Store-wide
  /// housekeeping (gc) uses this: the folder path is not needed to open one.
  /// Entries are returned by name only; load_file() validates the contents and
  /// refuses a missing or non-regular file.
  std::vector<std::filesystem::path> files() const;

  /// Reads one identity file directly. Same formats, passphrase rules and
  /// errors as load(); a file that vanished is NotFound instead of nullopt.
  DriveIdentity load_file(const std::filesystem::path& path,
                          std::string_view passphrase) const;

  /// Always writes the wrapped v2 file, atomically and with owner-only
  /// permissions. Renaming over a legacy plaintext file is what removes the
  /// plaintext seed from the store.
  void save(const std::filesystem::path& source, const DriveIdentity& identity,
            std::string_view passphrase, const Argon2Params& params = Argon2Params{}) const;

  /// Re-encrypts an existing wrapped identity under `new_passphrase`, with a
  /// fresh salt and nonce. The drive key, signing seed and seq are kept, so the
  /// link, the signed pointer and every published file stay exactly as they
  /// were; only the identity file is rewritten (atomically, 0600).
  ///
  /// The old passphrase must open the file: a wrong or empty one is
  /// BadPassphrase and nothing is written. A missing identity is NotFound. A
  /// legacy plaintext identity is UnsupportedIdentity rather than being
  /// migrated here; publishing once does that, and keeps this command from
  /// rewriting an identity without the publish that owns it.
  void rewrap(const std::filesystem::path& source, std::string_view old_passphrase,
              std::string_view new_passphrase,
              const Argon2Params& params = Argon2Params{}) const;

 private:
  std::filesystem::path dir_;
};

}  // namespace skipta
