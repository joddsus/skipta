# Skipta format v1

Status: implemented in `libskipta`, tested headless, not externally reviewed.
This document is normative for `libskipta` and the checked-in test vectors
(`testvectors/format-v1.json`). Changing any byte layout, tag or KDF input below
is a new format version and needs new vectors.

Primitives come from libsodium only. No primitive or protocol here is invented;
the construction is borrowed from the same structure Cryptomator and gocryptfs
use (per-file keys, per-block AEAD, encrypted directory listings).

## 1. Primitives and parameters

| Purpose | Construction | Parameters |
|---|---|---|
| Content and metadata encryption | XChaCha20-Poly1305 (IETF) | 24-byte nonce, 16-byte tag |
| Key derivation | BLAKE2b-256, keyed | 32-byte key, 32-byte output |
| Signatures | Ed25519 (detached) | 32-byte public key, 64-byte signature |
| Passphrase KDF | Argon2id (libsodium `crypto_pwhash`) | ops 3, mem 256 MiB by default |
| Randomness | `randombytes_buf` | libsodium CSPRNG |

Fixed sizes: plaintext block 65 536 bytes, AEAD tag 16, nonce 24, ids 128 bit.

## 2. Key hierarchy

```
drive key  Kd   32 random bytes, delivered inside the share link
  ├── file key      Kf = BLAKE2b-256(key=Kd, "skipta/v1/file-key"     || file_id)      [32]
  ├── manifest key  Km = BLAKE2b-256(key=Kd, "skipta/v1/manifest-key" || manifest_id)  [32]
  ├── swarm salt       = BLAKE2b-256(key=Kd, "skipta/v1/swarm-salt"   || drive_pubkey)
  └── swarm id (gen g) = BLAKE2b-256(key=Kd, "skipta/v1/swarm"        || drive_pubkey || u64be(g))
```

- `file_id` is 16 random bytes minted for **one content version** of a file.
  Rewriting a file mints a new `file_id`, hence a new `Kf` and new nonces.
- `manifest_id` is 16 random bytes minted for one version of one directory
  listing; re-listing a directory mints a new id.
- A drive is identified by its Ed25519 public key. The drive key `Kd` is
  symmetric and never signs anything.

## 3. Blocks

Files are split into 65 536-byte plaintext blocks; the last block may be
shorter. Block `i` of a file of size `S`:

```
nonce = file_id[16] || u64be(i)
aad   = "skipta/v1/block" || file_id[16] || u64be(i) || u64be(S)
ct    = XChaCha20-Poly1305(Kf, nonce, aad, plaintext_i)
```

Ciphertext of block `i` starts at `i * (65536 + 16)`; therefore a client can
fetch `[i*65552, i*65552 + len_i + 16)` without any other block. `u64be` is
8-byte big-endian. `block_count(S) = ceil(S / 65536)`, and 0 for an empty file.

Random access is the point of the format: listing needs no file bytes, and
opening one file at offset X decrypts one block.

## 4. Directory manifests

A manifest is a small JSON document, encrypted as a single blob:

```
nonce = manifest_id[16] || 8 zero bytes
aad   = "skipta/v1/manifest" || manifest_id[16]
ct    = XChaCha20-Poly1305(Km, nonce, aad, json)
```

Exactly one sealed blob exists per `manifest_id`, so the zero counter is never
reused with the same key.

```json
{"v":1,"id":"<b64url 16>","seq":7,
 "entries":[
   {"kind":"file","name":"a.txt","mtime":1700000000,"size":12,"file_id":"<b64url 16>"},
   {"kind":"dir","name":"docs","mtime":1700000001,"manifest_id":"<b64url 16>"}
 ]}
```

Rules enforced on parse (`Manifest::parse`) and on write (`serialize`,
`add_file`, `add_directory`):

- `v` must be 1; `id` must be 16 bytes and not all zero; `seq` is an unsigned
  counter per directory.
- `kind` is `file` or `dir`; no other fields are permitted for that kind
  (a `dir` may not carry `size`/`file_id`, a `file` may not carry `manifest_id`).
- `mtime` is informational (unix seconds) and is never used for security.
- Names: non-empty, valid UTF-8, at most 255 bytes, no `/`, `\`, `:`, NUL or
  control characters, no `.`/`..`, no trailing dot or space, no Windows
  reserved device name (case-insensitive, also with an extension). C1 controls,
  bidi embeddings/overrides/isolates and marks, zero-width and other invisible
  characters, the BOM and line/paragraph separators are rejected too
  (`UnsafeChar`): a listing is read in a terminal, and those characters hide or
  reorder names (ADR-0012).
- No duplicate names, and no names that collide after ASCII case folding.
- One `file_id` may appear at most once per directory: this is what makes the
  nonce-uniqueness rule testable.
- Limits: 4096 entries, 1 MiB plaintext manifest, 1 TiB per file, 4096-byte
  path, 32 path components, 64 JSON nesting levels. The store additionally caps
  a stored pointer at 4 KiB, a sealed manifest at 1 MiB + 16 and a sealed block
  at 65 552 bytes, and only reads regular files (ADR-0011).

Metadata is only visible after decryption, but ciphertext length still leaks an
approximate manifest size.

## 5. Root pointer

The only mutable, signed item:

```json
{"v":1,"drive":"<b64url 32>","seq":3,"root":"<b64url 16>","issued_at":1700000000}
```

The Ed25519 signature covers **the exact JSON bytes emitted by
`serialize_pointer`**. Readers verify the received bytes and then check that
`drive` equals the key from the link and `seq >= min_seq` (rollback protection).
They never re-serialise and re-verify, so canonicalisation differences cannot
cause disagreement. On the wire:

```json
{"p":"<b64url pointer bytes>","s":"<b64url 64-byte signature>"}
```

## 6. Share links

```
skipta://v1/<base64url(no padding)( JSON payload )>
payload = {"v":1,"drive":"<b64url 32>","key":"<b64url 32>","bootstrap":["seed:host:6969"]}
```

- Links are parsed strictly: scheme, version 1, 32-byte drive key, 32-byte
  drive key that is not all zero, at most 4 bootstrap hints, each at most 255
  characters from `[A-Za-z0-9 . : / _ - [ ] %]`.
- Total length is capped at 4096 characters before any decoding.
- A link is a bearer secret. Anyone who has it can read the share; there is no
  revocation other than publishing a new version under a new key.
- Only `swarm_salt` / `swarm_id` may be published to a tracker or the DHT. They
  are derived from the secret, so crawlers cannot enumerate shares; the spec's
  requirement that key material never reaches trackers/DHT is enforced there.

## 7. Passphrase-protected drive key

```json
{"v":1,"kdf":"argon2id","opslimit":3,"memlimit":268435456,
 "salt":"<b64url 16>","nonce":"<b64url 24>","ct":"<b64url 48>"}
```

`aad = "skipta/v1/keywrap" || u64be(1) || u64be(opslimit) || u64be(memlimit)`;
`ct = XChaCha20-Poly1305(Argon2id(passphrase, salt, opslimit, memlimit), nonce, aad, Kd)`.
Parameters are bounded on read (ops ≤ 10, mem ≤ 1 GiB) so a hostile blob cannot
force an unbounded KDF cost. Changing the stated parameters invalidates the
blob instead of silently decrypting it. The `ct` above is 32 bytes + tag for a
drive key; the same container (still `v: 1`) wraps any secret up to 256 bytes,
so `ct` must be accepted up to 256 bytes + tag and rejected beyond that. The
local identity file uses it for `drive_key || signing seed || u64be(seq)`
(72 bytes) inside the envelope `{"v":2,"wrap":<this blob>}`; that envelope is
local state, not part of the share format (ADR-0013).

## 8. Test vectors

`testvectors/format-v1.json` is generated by `build/gen_vectors` (deterministic
inputs only) and checked by `build/run_tests`, which recomputes every value:
base64url, keyed BLAKE2b, file/manifest keys, block nonces, AADs, sealed blocks,
a sealed manifest, a signature and pointer, an Argon2id output, and a wrapped
drive key. It also decrypts/unwraps each vector.

## 9. Not in v1

- No DHT/BEP 44/46 publication of the root pointer yet; the signed pointer type
  is ready for it.
- No transport. Nothing here networks.
- No group roster or epoch keys yet (spec §3 level 3, phase 5).
- No whole-file hash field: every block is authenticated individually and file
  identity is the content-version id, so a swapped block set fails to decrypt.
- No forward compatibility: unknown fields are rejected, deliberately.
