// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Cross-checks the checked-in test vectors against the implementation. Any
// silent change to keys, nonces, AAD, encoding or the block layout fails here.
#include <fstream>
#include <sstream>
#include <string>

#include "doctest/doctest.h"
#include "helpers.hpp"
#include "skipta/crypto.hpp"
#include "skipta/drive.hpp"
#include "skipta/error.hpp"
#include "skipta/format.hpp"
#include "skipta/json.hpp"
#include "skipta/keywrap.hpp"
#include "skipta/manifest.hpp"
#include "skipta/pointer.hpp"

using namespace skipta;

namespace {

nlohmann::json load_vectors() {
  const std::string path = std::string(TESTVECTORS_DIR) + "/format-v1.json";
  std::ifstream in(path);
  if (!in.good()) return nlohmann::json();
  std::ostringstream buffer;
  buffer << in.rdbuf();
  return jsonx::parse_strict(buffer.str(), 1024 * 1024, "test vectors");
}

const nlohmann::json& vectors() {
  static const nlohmann::json loaded = load_vectors();
  return loaded;
}

template <std::size_t N>
std::array<unsigned char, N> array_of(const std::string& hex) {
  const Bytes bytes = hex_decode(hex, "test vector");
  if (bytes.size() != N) {
    fail(ErrorCode::SizeMismatch, "test vector has the wrong length");
  }
  std::array<unsigned char, N> out{};
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

}  // namespace

TEST_CASE("test vectors are for format v1") {
  REQUIRE_MESSAGE(!vectors().is_null(),
                  "missing testvectors/format-v1.json - run 'make vectors'");
  CHECK(vectors().at("format") == "skipta-format");
  CHECK(vectors().at("version").get<int>() == 1);
}

TEST_CASE("base64url vectors") {
  for (const auto& v : vectors().at("base64url")) {
    const Bytes input = hex_decode(v.at("input_hex").get<std::string>(), "input");
    CHECK(base64url_encode(ByteView(input)) == v.at("b64").get<std::string>());
    CHECK(base64url_decode(v.at("b64").get<std::string>(), "b64") == input);
  }
}

TEST_CASE("keyed BLAKE2b vector") {
  for (const auto& v : vectors().at("blake2b_keyed")) {
    const Bytes key = hex_decode(v.at("key_hex").get<std::string>(), "key");
    const Bytes msg = hex_decode(v.at("msg_hex").get<std::string>(), "msg");
    const Key32 expected = array_of<32>(v.at("out_hex").get<std::string>());
    CHECK(crypto::blake2b256_keyed(ByteView(key), ByteView(msg)) == expected);
  }
}

TEST_CASE("file and manifest key derivation vectors") {
  for (const auto& v : vectors().at("file_key")) {
    const Key32 drive_key = array_of<32>(v.at("drive_key_hex").get<std::string>());
    const Id128 file_id = array_of<16>(v.at("file_id_hex").get<std::string>());
    CHECK(format::derive_file_key(drive_key, file_id) ==
          array_of<32>(v.at("out_hex").get<std::string>()));
  }
  for (const auto& v : vectors().at("manifest_key")) {
    const Key32 drive_key = array_of<32>(v.at("drive_key_hex").get<std::string>());
    const Id128 manifest_id = array_of<16>(v.at("manifest_id_hex").get<std::string>());
    CHECK(format::derive_manifest_key(drive_key, manifest_id) ==
          array_of<32>(v.at("out_hex").get<std::string>()));
  }
}

TEST_CASE("nonce and associated-data vectors") {
  for (const auto& v : vectors().at("block_nonce")) {
    const Id128 file_id = array_of<16>(v.at("file_id_hex").get<std::string>());
    const auto index = v.at("index").get<std::uint64_t>();
    const Bytes expected = hex_decode(v.at("nonce_hex").get<std::string>(), "nonce");
    const auto nonce = format::block_nonce(file_id, index);
    CHECK(Bytes(nonce.begin(), nonce.end()) == expected);
  }
  for (const auto& v : vectors().at("block_aad")) {
    const Id128 file_id = array_of<16>(v.at("file_id_hex").get<std::string>());
    const auto index = v.at("index").get<std::uint64_t>();
    const auto file_size = v.at("file_size").get<std::uint64_t>();
    CHECK(format::block_aad(file_id, index, file_size) ==
          hex_decode(v.at("aad_hex").get<std::string>(), "aad"));
  }
  for (const auto& v : vectors().at("manifest_aad")) {
    const Id128 manifest_id = array_of<16>(v.at("manifest_id_hex").get<std::string>());
    CHECK(format::manifest_aad(manifest_id) ==
          hex_decode(v.at("aad_hex").get<std::string>(), "aad"));
  }
}

TEST_CASE("sealed block vectors") {
  for (const auto& v : vectors().at("block")) {
    const Key32 drive_key = array_of<32>(v.at("drive_key_hex").get<std::string>());
    const Id128 file_id = array_of<16>(v.at("file_id_hex").get<std::string>());
    const auto file_size = v.at("file_size").get<std::uint64_t>();
    const auto index = v.at("index").get<std::uint64_t>();
    const Bytes plaintext = hex_decode(v.at("plaintext_hex").get<std::string>(), "plaintext");
    const Bytes ciphertext = hex_decode(v.at("ciphertext_hex").get<std::string>(), "ciphertext");

    CHECK(format::encrypt_block(drive_key, file_id, file_size, index, ByteView(plaintext)) ==
          ciphertext);
    CHECK(format::decrypt_block(drive_key, file_id, file_size, index, ByteView(ciphertext)) ==
          plaintext);
  }
}

TEST_CASE("sealed manifest vector") {
  for (const auto& v : vectors().at("manifest")) {
    const Key32 drive_key = array_of<32>(v.at("drive_key_hex").get<std::string>());
    const Bytes plaintext = hex_decode(v.at("plain_hex").get<std::string>(), "plain");
    const Bytes sealed = hex_decode(v.at("sealed_hex").get<std::string>(), "sealed");

    const Manifest manifest = Manifest::parse(ByteView(plaintext));
    CHECK(open_manifest(drive_key, manifest.id, ByteView(sealed)).serialize() == plaintext);
  }
}

TEST_CASE("signature vector") {
  for (const auto& v : vectors().at("ed25519")) {
    const Key32 seed = array_of<32>(v.at("seed_hex").get<std::string>());
    const auto pair = crypto::SigningKeyPair::from_seed(seed);
    CHECK(Bytes(pair.pub.begin(), pair.pub.end()) ==
          hex_decode(v.at("pub_hex").get<std::string>(), "pub"));

    const Bytes pointer_bytes = hex_decode(v.at("pointer_hex").get<std::string>(), "pointer");
    const Sig64 sig = array_of<64>(v.at("sig_hex").get<std::string>());
    CHECK(crypto::verify(pair.pub, ByteView(pointer_bytes), sig));

    const SignedPointer signed_pointer{pointer_bytes, sig};
    const RootPointer pointer = verify_pointer(pair.pub, signed_pointer);
    CHECK(pointer.drive == pair.pub);
    const Bytes manifest_plain =
        hex_decode(vectors().at("manifest").at(0).at("plain_hex").get<std::string>(), "plain");
    CHECK(pointer.root == Manifest::parse(ByteView(manifest_plain)).id);
  }
}

TEST_CASE("argon2id vector") {
  for (const auto& v : vectors().at("argon2id")) {
    const std::string passphrase = v.at("passphrase").get<std::string>();
    const Bytes salt = hex_decode(v.at("salt_hex").get<std::string>(), "salt");
    const auto opslimit = v.at("opslimit").get<std::uint64_t>();
    const auto memlimit = v.at("memlimit").get<std::size_t>();
    CHECK(crypto::argon2id(passphrase, ByteView(salt), opslimit, memlimit) ==
          array_of<32>(v.at("key_hex").get<std::string>()));
  }
}

TEST_CASE("keywrap vector") {
  for (const auto& v : vectors().at("keywrap")) {
    const Key32 drive_key = array_of<32>(v.at("drive_key_hex").get<std::string>());
    const std::string passphrase = v.at("passphrase").get<std::string>();
    const Bytes blob = hex_decode(v.at("blob_hex").get<std::string>(), "blob");
    CHECK(unwrap_drive_key(ByteView(blob), passphrase) == drive_key);

    const Id128 salt = array_of<16>(v.at("salt_hex").get<std::string>());
    const auto nonce = array_of<format::kNonceSize>(v.at("nonce_hex").get<std::string>());
    Argon2Params params;
    params.opslimit = v.at("opslimit").get<std::uint64_t>();
    params.memlimit = v.at("memlimit").get<std::size_t>();
    CHECK(wrap_drive_key(drive_key, passphrase, params, &salt, &nonce) == blob);
  }
}
