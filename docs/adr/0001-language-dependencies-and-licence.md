# ADR-0001: C++17 core, dependency set, licence

Status: accepted (decided by the project owner, 2026-11-16)

## Context

The spec left the core language open until the transport spikes (§10), and the
working rules forbid new dependencies without asking. Before any code was
written the owner was asked and answered.

## Decision

- **Language:** C++17 throughout `libskipta` (and later `skiptad`), as a
  close companion to libtorrent-rasterbar (transport option A).
- **Dependencies:**
  - `libsodium` 1.0.20 — every cryptographic operation (XChaCha20-Poly1305,
    BLAKE2b, Ed25519, Argon2id, CSPRNG). This is the trusted computing base.
  - `nlohmann/json` 3.11.3, single header — metadata, links and vectors.
  - `doctest` 2.4.11, single header — tests only, not linked into the library.
- **Licence:** AGPL-3.0-or-later.
- **Build:** plain portable Makefile, static libsodium, no cmake, no network at
  build time. `scripts/fetch-deps.sh` provisions the dependencies reproducibly;
  the two single headers are vendored into `third_party/`.

## Consequences

- Parsers handle hostile input in C++, the language the spec's §8 calls out as
  the less safe choice. Mitigation: all metadata parsing is centralised in
  `Manifest`/`link`/`pointer`, uses bounds-checked standard containers, and is
  written to be fuzzable. Fuzz targets are still missing and are a release
  blocker (see ADR-0002, "Open items").
- libsodium is vendored as a source build rather than a system package, so the
  version in use is pinned and auditable.
- AGPL is compatible with the planned `skipta://` module in Listi under the
  dependency direction "Listi may use Skipta", not the reverse.
