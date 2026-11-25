// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Writes the format v1 test vectors. Everything here is deterministic: fixed
// keys, fixed ids, fixed plaintexts, fixed Argon2id salt and nonce. If the
// output changes, the format changed and the version must be bumped.
//
//   build/gen_vectors testvectors/format-v1.json
#include <fstream>
#include <iostream>
#include <string>

#include "nlohmann/json.hpp"
#include "skipta/crypto.hpp"
#include "skipta/drive.hpp"
#include "skipta/error.hpp"
#include "skipta/keywrap.hpp"
#include "skipta/manifest.hpp"

using namespace skipta;
using nlohmann::json;

namespace {

Key32 key_from(unsigned char start) {
  Key32 key{};
  for (std::size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<unsigned char>((start + i) & 0xff);
  }
  return key;
}

Id128 id_from(unsigned char start) {
  Id128 id{};
  for (std::size_t i = 0; i < id.size(); ++i) {
    id[i] = static_cast<unsigned char>((start + i) & 0xff);
  }
  return id;
}

Bytes pattern(std::size_t n, unsigned char start) {
  Bytes out(n);
  for (std::size_t i = 0; i < n; ++i) {
    out[i] = static_cast<unsigned char>((start + i) & 0xff);
  }
  return out;
}

std::string hexs(ByteView v) { return hex_encode(v); }

}  // namespace

int main(int argc, char** argv) {
  const std::string path = argc > 1 ? argv[1] : "testvectors/format-v1.json";
  const std::string passphrase = "correct horse battery staple";

  const Key32 drive_key = key_from(0x00);
  const Key32 ed_seed = key_from(0x50);
  const Id128 file_id = id_from(0x20);
  const Id128 manifest_id = id_from(0x30);
  const Id128 child_id = id_from(0x40);
  const Id128 kdf_salt = id_from(0x60);
  const std::array<unsigned char, format::kNonceSize> kdf_nonce = [] {
    std::array<unsigned char, format::kNonceSize> nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
      nonce[i] = static_cast<unsigned char>((0x70 + i) & 0xff);
    }
    return nonce;
  }();

  try {
    json root;
    root["format"] = "skipta-format";
    root["version"] = format::kVersion;
    root["note"] =
        "Deterministic vectors for format v1 (see docs/format-v1.md). Regenerate with "
        "'make vectors'. A change here is a format change and needs a version bump.";

    // ---- encodings ---------------------------------------------------------
    json base64 = json::array();
    for (std::size_t n : {0u, 1u, 2u, 3u, 4u, 5u, 32u, 64u}) {
      const Bytes data = pattern(n, 0x00);
      json v;
      v["input_hex"] = hexs(ByteView(data));
      v["b64"] = base64url_encode(ByteView(data));
      base64.push_back(v);
    }
    root["base64url"] = base64;

    // ---- key derivation ----------------------------------------------------
    {
      const std::string message = "skipta-format-v1-test-vector";
      json v;
      v["key_hex"] = hexs(ByteView(drive_key));
      v["msg_hex"] = hexs(ByteView(std::string_view(message)));
      v["out_hex"] = hexs(ByteView(crypto::blake2b256_keyed(ByteView(drive_key),
                                                             ByteView(std::string_view(message)))));
      root["blake2b_keyed"] = json::array({v});
    }
    {
      json v;
      v["drive_key_hex"] = hexs(ByteView(drive_key));
      v["file_id_hex"] = hexs(ByteView(file_id));
      v["out_hex"] = hexs(ByteView(format::derive_file_key(drive_key, file_id)));
      root["file_key"] = json::array({v});
    }
    {
      json v;
      v["drive_key_hex"] = hexs(ByteView(drive_key));
      v["manifest_id_hex"] = hexs(ByteView(manifest_id));
      v["out_hex"] = hexs(ByteView(format::derive_manifest_key(drive_key, manifest_id)));
      root["manifest_key"] = json::array({v});
    }

    // ---- nonces and associated data ---------------------------------------
    {
      json nonces = json::array();
      for (std::uint64_t index : {0ull, 3ull}) {
        json v;
        v["file_id_hex"] = hexs(ByteView(file_id));
        v["index"] = index;
        v["nonce_hex"] = hexs(ByteView(format::block_nonce(file_id, index)));
        nonces.push_back(v);
      }
      root["block_nonce"] = nonces;
    }
    {
      const std::uint64_t file_size = 200000;
      json v;
      v["file_id_hex"] = hexs(ByteView(file_id));
      v["index"] = 1;
      v["file_size"] = file_size;
      v["aad_hex"] = hexs(ByteView(format::block_aad(file_id, 1, file_size)));
      root["block_aad"] = json::array({v});

      json mv;
      mv["manifest_id_hex"] = hexs(ByteView(manifest_id));
      mv["aad_hex"] = hexs(ByteView(format::manifest_aad(manifest_id)));
      root["manifest_aad"] = json::array({mv});
    }

    // ---- block encryption --------------------------------------------------
    {
      const std::uint64_t file_size = 200000;
      json blocks = json::array();
      struct Case {
        std::uint64_t index;
        std::size_t length;
        unsigned char start;
      };
      for (const Case& c : {Case{0, format::kBlockPlaintextSize, 0x11},
                            Case{3, 3392, 0x21}}) {
        const Bytes plaintext = pattern(c.length, c.start);
        json v;
        v["drive_key_hex"] = hexs(ByteView(drive_key));
        v["file_id_hex"] = hexs(ByteView(file_id));
        v["file_size"] = file_size;
        v["index"] = c.index;
        v["plaintext_hex"] = hexs(ByteView(plaintext));
        v["ciphertext_hex"] =
            hexs(ByteView(format::encrypt_block(drive_key, file_id, file_size, c.index,
                                                ByteView(plaintext))));
        blocks.push_back(v);
      }
      root["block"] = blocks;
    }

    // ---- sealed manifest ---------------------------------------------------
    Manifest manifest;
    manifest.version = format::kVersion;
    manifest.id = manifest_id;
    manifest.seq = 7;
    manifest.add_file("a.txt", 12, file_id, 1700000000);
    manifest.add_directory("docs", child_id, 1700000001);
    const Drive drive(drive_key, crypto::SigningKeyPair::from_seed(ed_seed));
    {
      const Bytes plaintext = manifest.serialize();
      const Bytes sealed = drive.seal_manifest(manifest);
      json v;
      v["drive_key_hex"] = hexs(ByteView(drive_key));
      v["plain_hex"] = hexs(ByteView(plaintext));
      v["sealed_hex"] = hexs(ByteView(sealed));
      root["manifest"] = json::array({v});
    }

    // ---- signatures --------------------------------------------------------
    {
      const RootPointer pointer = drive.root_pointer(manifest, 1700000000);
      const SignedPointer signed_pointer = drive.sign_root(pointer);
      json v;
      v["seed_hex"] = hexs(ByteView(ed_seed));
      v["pub_hex"] = hexs(ByteView(drive.public_key()));
      v["pointer_hex"] = hexs(ByteView(signed_pointer.pointer));
      v["sig_hex"] = hexs(ByteView(signed_pointer.signature));
      root["ed25519"] = json::array({v});
    }

    // ---- passphrase KDF ----------------------------------------------------
    {
      const Key32 derived = crypto::argon2id(passphrase, ByteView(kdf_salt), 2, 64u * 1024u * 1024u);
      json v;
      v["passphrase"] = passphrase;
      v["salt_hex"] = hexs(ByteView(kdf_salt));
      v["opslimit"] = 2;
      v["memlimit"] = 64u * 1024u * 1024u;
      v["key_hex"] = hexs(ByteView(derived));
      root["argon2id"] = json::array({v});
    }
    {
      const Bytes blob = wrap_drive_key(drive_key, passphrase, Argon2Params::interactive(),
                                        &kdf_salt, &kdf_nonce);
      json v;
      v["drive_key_hex"] = hexs(ByteView(drive_key));
      v["passphrase"] = passphrase;
      v["salt_hex"] = hexs(ByteView(kdf_salt));
      v["nonce_hex"] = hexs(ByteView(kdf_nonce));
      v["opslimit"] = 2;
      v["memlimit"] = 64u * 1024u * 1024u;
      v["blob_hex"] = hexs(ByteView(blob));
      root["keywrap"] = json::array({v});
    }

    std::ofstream out(path);
    if (!out) {
      std::cerr << "cannot open " << path << " for writing\n";
      return 1;
    }
    out << root.dump(2) << "\n";
    std::cout << "wrote " << path << "\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "vector generation failed: " << e.what() << "\n";
    return 1;
  }
}
