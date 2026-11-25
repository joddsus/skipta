# ADR-0005: A local blob store stands in for the swarm in phase 3

Status: accepted for phase 3; to be replaced by the transport chosen in ADR-0004

## Context

Phase 3 says "publish and read one drive over a secret link (CLI)". The
transport is undecided (ADR-0004) and no engine can be measured here. What can
be proven now is the data path: does a folder publish into something a reader
holding only a link can browse and fetch from, with only the needed bytes?

## Decision

1. `skipta::FileStore` is a content-addressed directory of **exactly the opaque
   pieces a peer would exchange**:
   - `pointers/<drive pubkey>.ptr` — the signed root pointer, byte-exact,
   - `manifests/<manifest id>.mf` — a sealed directory manifest,
   - `blocks/<file id>/<index>.blk` — one sealed block.
   Nothing else is stored: no plaintext, no keys, no index beyond the ids.
2. `publish_directory()` walks the tree in sorted order, mints a drive, seals one
   manifest per directory, encrypts each file block by block straight from disk
   (no whole-file buffering), writes the signed pointer, and returns the link.
3. `open_share()` / `resolve_path()` / `list_path()` / `fetch_file()` are the
   read path: verify the pointer, decrypt one manifest per directory visited,
   fetch one block per 64 KiB read.
4. The CLI (`cli/main.cpp`) is a thin shell over those functions, so replacing
   `FileStore` with a real swarm client later changes no API above it.

## Consequences

- Phase 3 is demonstrable today: publish a folder, hand over the link, list,
  fetch, with only the blocks of the requested file read from the store.
- The store is **not** transport: no peers, no discovery, no seeding policy, no
  rate limits. It also has no eviction or integrity manifest of its own, so a
  missing blob surfaces as `NotFound` and a corrupt one as `AuthFailed` — both
  tested.
- Block granularity in the store matches the format (65 536-byte plaintext
  blocks), so range requests will map onto it directly once a transport exists.
- A stored identity (so a re-publish keeps the same drive and increments `seq`)
  is deliberately not implemented; every publish is a new drive. That keeps the
  CLI from creating a second, unprotected copy of a drive key on disk.
