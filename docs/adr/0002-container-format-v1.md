# ADR-0002: Container format v1

Status: accepted for phase 2; **requires external review before any 1.0**
(spec §5, §9.9). Flagged choices below are open for the owner to overrule.

## Context

The spec requires: per-block AEAD with fixed block size for random access, a
drive key with per-file keys derived through a KDF using a random file id, nonce
derived from block index, encrypted manifests, Ed25519 signatures on pointers
and rosters, Argon2id for keys at rest, versioning plus test vectors from day
one, and no invented primitives.

## Decision

See `docs/format-v1.md` for the normative byte layout. In summary:

1. **Primitives:** only libsodium. XChaCha20-Poly1305 for content and metadata,
   keyed BLAKE2b-256 as KDF, Ed25519 for signatures, Argon2id for key wrapping.
2. **Key hierarchy:** `Kf = BLAKE2b-256(Kd, "skipta/v1/file-key" || file_id)`,
   with a fresh random `file_id` per content version. Domain-separated tags mean
   file keys, manifest keys, swarm names and the passphrase KDF can never
   collide.
3. **Nonces:** `file_id || u64be(block_index)` for blocks (24 bytes), and
   `manifest_id || 8 zeros` for the single sealed blob per manifest id. Because
   keys are per content version, nonce uniqueness follows from id uniqueness,
   which is random 128-bit — collision probability is negligible.
4. **AAD:** binds the domain tag, the id, the block index and the file size.
   Moving a block to another slot/file or truncating a file fails
   authentication before anything is interpreted.
5. **Manifests:** one small encrypted JSON document per directory, so listing is
   lazy. One torrent/swarm per drive, not one per directory.
6. **Pointer:** a signed JSON object; the signature covers the exact bytes, and
   readers verify those bytes rather than a re-serialisation.
7. **Versioning:** `v` appears in every structure, encoded in the scheme and in
   the domain tags, so a v2 cannot be confused with v1.

## Tests that enforce the rules

- `tests/test_nonce.cpp` — a nonce registry fails the suite if a `(key, nonce)`
  pair repeats; also asserts the manifest API refuses a reused `file_id`, and
  that distinct content versions produce distinct keys, nonces and ciphertexts.
- `tests/test_crypto.cpp` — tampering with ciphertext, AAD or key; block
  reordering; index/size validation.
- `tests/test_vectors.cpp` — every byte of the format is pinned.

## Flagged decisions the owner has not explicitly approved

- **Block size 65 536 bytes.** Chosen for streaming and range requests: small
  enough to start playback quickly, large enough that per-block overhead is
  0.02%. Cryptomator uses 32 KiB; gocryptfs uses 4 KiB. Changing this is a
  format change.
- **Metadata encoding is JSON, not CBOR or a binary tree.** Simpler to audit and
  to fuzz, at the cost of size. Manifests are capped at 1 MiB.
- **Metadata is not padded**, so ciphertext length leaks approximate directory
  size (entry count and name lengths). Padding to buckets is a v2 candidate.
- **Child manifests have no version chain.** `seq` lives inside the encrypted
  manifest and is not bound to the AAD, and a child manifest id is only
  referenced by its parent. A peer holding an old child manifest can serve stale
  contents of that directory; the root pointer's `seq` protects the root only.
  Mitigation today: clients cache the last seen child id per path. A proper fix
  (parent commits to child id + seq, or a signed chain) is a v2 change.
- **Case folding is ASCII-only.** `Readme`/`readme` collide and are rejected;
  non-ASCII case pairs (e.g. Turkish dotless i, Greek final sigma) do not. On
  case-insensitive filesystems that is a residual write path issue, not a read
  path issue.
- **Argon2id defaults:** ops 3, 256 MiB. `interactive()` (2 ops, 64 MiB exists
  for tests and low-end devices and is labelled as such.

## Open items (release blockers)

- Fuzz targets for `Manifest::parse`, `decode_link`, `parse_pointer`,
  `unwrap_drive_key`. The parsers are written to be pure and bounded, but no
  fuzzing has been run yet.
- External cryptographic review (spec §9.9).
- No hardware-backed key storage; the drive key lives in process memory while a
  share is open, which is documented but not mitigated.
- Legal review of public mode (spec T7) before any wide release.
