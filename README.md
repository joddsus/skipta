# Skipta

Peer-to-peer, end-to-end encrypted folder sharing. Browse a shared folder like a
server folder: open a link, click through directories, open a file, and only the
data you actually need is fetched.

This repository currently contains **`libskipta`**, the format and crypto core,
the `skipta` CLI, and a small read-only HTTP transport for sharing a store
between machines. The measured swarm transport from spec §7 is still not built.

## Status

| Phase (spec §9) | State |
|---|---|
| 0. Review spec and open questions | answered: language, dependencies, licence; transport still open |
| 1. Transport spikes (A: libtorrent, B: Iroh) | **skeleton and measurement protocol only — not run** |
| 2. Crypto + manifest format with test vectors | **done** (libskipta, 128 test cases, 2274 assertions; sanitizer-fuzzed) |
| 3. Publish/read one drive over a secret link | **done over a local or read-only HTTP store**: `build/skipta publish|passwd|gc|list|get|verify|serve`; no swarm transport |
| 4. Lazy browsing and streaming fetch | lazy listings, block-by-block fetch and a read-only HTTP transport done; swarm-level ranges later |
| 5–9. Groups, public mode, browser, Listi, review | not started |

See [`docs/adr/`](docs/adr/README.md) for every decision, including the ones
that still need your sign-off.

## Build and test

Dependencies are pinned and provisioned locally; no root and no cmake needed.

```sh
./scripts/fetch-deps.sh     # libsodium 1.0.20 (static), nlohmann/json, doctest
make                        # build/libskipta.a, build/gen_vectors, build/run_tests
make test                   # 128 test cases
make vectors                # regenerate testvectors/format-v1.json (must be a no-op)
```

`.deps/`, `build/` and `build-fuzz/` are ignored; `third_party/` holds the two single-header
libraries (checked in deliberately, so a checkout builds offline).

### Platform builds

Linux x86_64 is the only platform with a native run in this repository's VMs.
The other successful builds were cross-compiled with zig 0.13.0; “run” below
means an actual execution, not just a successful link. Full details and
libsodium setup are in [`docs/platforms.md`](docs/platforms.md).

| Target | Exact project command executed | Build | Run |
|---|---|---|---|
| Linux x86_64 glibc | `make clean && make` | succeeded, 0 warnings | **native:** `make test` 128/2274; `make vectors` stable |
| Linux aarch64 glibc | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-linux-gnu' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-arm64 all` | succeeded | **not run** (no native aarch64 loader) |
| Linux aarch64 musl | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-linux-musl -static' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-arm64-musl3 all` | succeeded | **QEMU:** 128/2274; vector SHA-256 matches host |
| Linux armv7 musl | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target arm-linux-musleabihf -static' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-armv7 all` | succeeded, 0 warnings | **QEMU:** 128/2274; vector SHA-256 matches host |
| macOS x86_64 | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-macos' AR='/tmp/zig/zig ar --format=darwin' DEPS=/tmp/deps-mac all` | succeeded, 0 warnings | **not run** (no macOS host) |
| macOS arm64 | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target aarch64-macos' AR='/tmp/zig/zig ar --format=darwin' DEPS=/tmp/deps-macarm all` | succeeded, 0 warnings | **not run** (no macOS host) |
| FreeBSD 14.5 | `FBSD_SYSROOT=/tmp/freebsd-base FBSD_LLD=/tmp/llvm/usr/lib/llvm-18/bin/ld.lld FBSD_LLD_LIBDIR=/tmp/llvm/usr/lib/x86_64-linux-gnu:/tmp/llvm/usr/lib/llvm-18/lib make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-freebsd -nostdinc++ -I/tmp/freebsd-base/usr/include/c++/v1 -I/tmp/freebsd-base/usr/include' AR='/tmp/zig/zig ar' LINKER=./scripts/freebsd-link.sh DEPS=/tmp/deps-fbsd THREAD_FLAGS=-pthread all` | succeeded | **not run** (no FreeBSD host) |
| Windows x86_64 MinGW-w64 | `make -j"$(nproc)" CXX='/tmp/zig/zig c++ -target x86_64-windows-gnu' AR='/tmp/zig/zig ar' DEPS=/tmp/deps-win THREAD_FLAGS= EXTRA_LIBS=-lbcrypt all` | succeeded, 0 warnings; PE32+ | **not run** — Wine prefix creation exited 139 |
| OpenBSD / NetBSD / Haiku | `printf '#include <assert.h>\n#include <inttypes.h>\nint main(void){return 0;}\n' \| /tmp/zig/zig c++ -target x86_64-openbsd -x c++ -c - -o /tmp/openbsd.o` (`netbsd`/`haiku` likewise) | **failed:** `fatal error: 'assert.h' file not found` | **not run** (no binary) |

All passing runs generated the vector SHA-256
`3d2eb50cece2e177698238a478abc0c49da52c8a35a450ab96cae08e7a375030`.
Windows remains local-only/experimental (no HTTP, prompt or store lock); Wine
did not get far enough to run the PE tests. MSVC is not a target.

## Fuzzing the untrusted-input boundary

The parsers that touch peer, store and link bytes are also exercised by a
separate ASan + UBSan mutation fuzzer. It is deliberately outside `make` and
`make test`; `make clean` removes it.

```sh
make fuzz-build                                  # every source with ASan+UBSan
./scripts/fuzz.sh --iterations 2000000 --seed 5  # full mixed run
./scripts/fuzz.sh --iterations 100000 --seed 31 --only http-response
./scripts/fuzz.sh --iterations 100000 --seed 31 --only manifest \
                  --max-input 1048576 --corpus /path/to/adversarial/files
```

The harness publishes a real folder into a temporary store with the normal
code path and seeds itself with the resulting signed pointer, sealed manifests,
sealed blocks, link, legacy identity and a wrapped-key envelope. It then applies
bit flips, inserts, deletes, truncations, splices, dictionary tokens and
pathological repetition, plus raw random bytes, to 17 parsers:

`pointer`, `signed-pointer`, `manifest`, `name`, `relative-path`,
`sealed-manifest`, `block`, `link`, `base64`, `hex`, `store-name`,
`http-request`, `http-route`, `http-response`, `store-url`, `legacy-identity`,
`keywrap-envelope`.

Every input runs under a `SIGALRM` deadline (5 s by default); a hang saves the
input under `/tmp/skipta-fuzz-artifacts/hang.bin` and exits 124. ASan/UBSan
findings and unexpected C++ exceptions save the input too. RSS is sampled and
the run fails on growth beyond 1 GiB or 512 MiB over baseline. `--seed` makes a
run reproducible; `--only`, `--max-input`, `--corpus` and `--artifacts` narrow
it. The timeout path itself is testable with `--selftest-timeout` (expects
exit 124 and a saved input).

Runs recorded for this tree (all with ASan + UBSan + `_GLIBCXX_ASSERTIONS`,
zero crashes, sanitizer reports, timeouts or memory growth):

| Inputs | Seed | Parsers | Peak RSS |
|---|---|---|---|
| 1,800,000 | 1 | 16 | 373 MiB |
| 1,500,000 | 2 | 16 | 374 MiB |
| 500,000 | 11 | 16 | 367 MiB |
| 2,000,000 | 5 | 17 | 371 MiB |
| 600,000 | 31 | targeted, 100k each | < 380 MiB |
| 3,000 | 21 | manifest, 1 MiB inputs | < 380 MiB |

That is **6.4 million inputs** in total, all clean. The one defect this work
found was in block framing rather than through a crash: `format::block_count`
used `(size + block - 1) / block`, which overflows near `UINT64_MAX` and
under-counts blocks. It is fixed with a divide-first implementation and pinned
in `tests/test_crypto.cpp`; normal sizes and the on-disk format are unchanged.

Not fuzzed: the Argon2id execution itself (the envelope is fuzzed, the 64–256
MiB KDF deliberately is not run per input), filesystem races and `gc` directory
walks, the crypto primitives (libsodium), the full socket/body path (its wire
parsers are fuzzed; send/receive and deadline behavior have unit/e2e tests),
and the convenience `format::decrypt_file` API, which allocates the whole file
by design and is not used by the CLI. Fuzzing does not replace the external
cryptographic review the format still needs.

## CLI: publish, passwd, gc, list, get, verify, serve

The store is a local blob directory standing in for the swarm: `publish` writes
sealed blocks, sealed manifests and the signed pointer into it, and `list`/`get`
read them back, so one machine can open its own link without any network.

`publish` needs a passphrase for the local drive identity: set
`SKIPTA_PASSPHRASE` or let it prompt (echo off; twice when setting one up).
`passwd` changes that passphrase. `list`, `get` and `verify` need only the link.

```sh
export SKIPTA_PASSPHRASE='…'                                  # or let publish prompt
./build/skipta publish ~/club-photos --store ./skipta-store   # prints the link
./build/skipta publish ~/club-photos --store ./skipta-store   # same link, seq 2
./build/skipta passwd  ~/club-photos --store ./skipta-store   # new passphrase, same link
./build/skipta list  "skipta://v1/..." --store ./skipta-store
./build/skipta list  "skipta://v1/..." 2024/trip --store ./skipta-store
./build/skipta list  "skipta://v1/..." . --store ./skipta-store   # whole root
./build/skipta get   "skipta://v1/..." 2024/trip/best.jpg --store ./skipta-store --out best.jpg
./build/skipta get   "skipta://v1/..." video.mp4 --store ./skipta-store --out head.mp4 --range 0:1048576
./build/skipta get   "skipta://v1/..." video.mp4 --store ./skipta-store --out video.mp4 --resume
./build/skipta get   "skipta://v1/..." 2024/trip --store ./skipta-store --out trip --resume
./build/skipta verify "skipta://v1/..." --store ./skipta-store
./build/skipta gc   --store ./skipta-store                  # report reclaimable objects
./build/skipta gc   --delete --store ./skipta-store          # remove them

# share a store read-only with another machine on the LAN
./build/skipta serve --store ./skipta-store --listen 0.0.0.0:8787
# on the reader: fetch through the origin, cache locally, then read offline
./build/skipta list "skipta://v1/..." --store http://publisher:8787 --cache ./skipta-cache
./build/skipta get  "skipta://v1/..." 2024/trip/best.jpg --store http://publisher:8787 \
                    --cache ./skipta-cache --out best.jpg
```

- `publish` prints only the link on stdout; counts, warnings and the bearer-secret
  reminder go to stderr. Symlinks and other non-regular files are skipped and
  reported (spec §8: never follow symlinks out of a share).
- `list` prints `file`/`dir` entries with sizes in sorted order; the optional
  path may be `.` for the share root, matching `get` and `verify`.
- `get` streams block by block, so only the blocks of that file are read from
  the store; `--out -` writes to stdout, `--force` allows overwriting.
- `--range START:END` (half-open, END optional) reads only the 64 KiB blocks that
  overlap the range and writes exactly that slice (clipped at EOF) to the
  target; it is verified by tests that delete the other blocks first. Blocks are
  the smallest decryptable unit, so up to one block of extra bytes is read at
  each end, but only the requested bytes are written. A range cannot be combined
  with `--resume`; an existing target needs `--force`.
- `--in-flight N` (default 4) fetches that many blocks at the same time; the
  reader keeps the pipeline full, so it doubles as prefetch depth. Output is
  always written in ascending block order, and at most N blocks are held in
  memory. `--in-flight 1` is strictly serial and creates no threads.
- The store also holds `<store>/.lock`, an empty advisory lock file; `gc` and
  `publish` take it, readers ignore it.
- Each block is retried up to 3 times on a transient store or transport error
  (`NotFound`, `StoreIo`), waiting 25 ms and doubling after that. A bad tag or
  malformed data is never retried. Retries run inside the block's own pipeline
  slot, so output order and resume checkpoints are untouched; a block that never
  arrives still fails, leaving its partial file resumable.
- `--resume` continues an interrupted download. Progress is kept in
  `<out>.skipta-resume` (bytes written plus a SHA-256 of exactly those bytes); a
  resume re-hashes the partial file, refuses to continue if it does not match,
  and only then fetches the rest. A file that is already complete — right size
  with no state, or state that already covers every byte — is a no-op that
  reports it as such and removes any state. `--force` discards the partial and
  starts over.
  The state file is deleted when the file is complete.
- A directory path is downloaded recursively, depth-first in published order
  (the order entries appear in the manifests), recreating empty directories.
  Every file goes through the same block pipeline and keeps its own resume
  state, so `--resume` continues an interrupted directory download file by file
  and leaves the earlier ones alone. Files that already have the manifest size
  and no resume state are skipped; that check is by size, not content.
  `--range` and `--out -` need a file, not a directory. `get <link> . --out dir`
  downloads the whole share (the root has no name, so `--out` is required).
- Paths go through the §8 validator first, so `../` never reaches a manifest lookup.
  A published name may begin with `-`; put `--` after the options to pass it as
  a positional, for example `get <link> --store <dir> --out f -- -name`.
- `publish` keeps a drive identity per folder in `<store>/identities`, so
  publishing the same folder again is an update: the link is unchanged (it names
  the drive, not a version) and the signed pointer's `seq` goes up. `list`/`get`
  remember the highest `seq` they accepted for a drive in `<store>/accepted` and
  refuse an older pointer as `StalePointer`, so a rolled-back store cannot
  silently serve stale content. A folder published for the first time still gets
  a fresh drive and link.
- The identity file holds the publisher's secrets (drive key and signing seed)
  and is encrypted with the passphrase: `{"v":2,"wrap":…}` wraps
  `drive_key || signing_seed || seq` with Argon2id (3 passes, 256 MiB) and
  XChaCha20-Poly1305, written mode 0600. A copied store alone yields neither
  secret, so it cannot decrypt the share or sign new versions. `publish` refuses
  a store that sits inside the folder being published, because sealing the
  identity file into the share would hand every reader the signing seed; pass
  `--store` somewhere outside the folder.
- A pre-upgrade plaintext identity is still read, so existing stores keep
  working. The next `publish` rewrites that same path in the wrapped v2 form
  (temp file + rename), so no plaintext seed is left behind; the drive, its link
  and everything already published under it are unchanged. `list`, `get` and
  `verify` never touch the identity and need no passphrase, before or after
  migration.
- `passwd <dir>` re-wraps the identity under a new passphrase. The current
  passphrase comes from `SKIPTA_PASSPHRASE` or one prompt, the new one from
  `SKIPTA_NEW_PASSPHRASE` or two prompts; neither is ever taken from a command
  line argument. Only the identity file is rewritten (fresh salt and nonce,
  temp file + rename, 0600): the drive key, signing seed, `seq`, link, signed
  pointer and published blocks stay exactly as they were, so a passphrase change
  is invisible to readers and does not need a republish. A wrong current
  passphrase or an empty replacement is rejected before anything is written, so
  the old file stays usable. A folder with no identity is an error, and a legacy
  plaintext identity must be migrated by publishing once first.
- `gc` removes store objects that no current root pointer reaches: superseded
  manifests and blocks, and the ciphertext of files removed from a folder. That
  old ciphertext is still decryptable with the same link, so leaving it is a
  privacy leak as well as unbounded growth. It reports first and deletes only
  with `--delete`. It needs one passphrase that opens every identity in the
  store and refuses with `UnsafeStore`, deleting nothing, if any drive has a
  pointer without an identity or an identity without a pointer: what it cannot
  account for it keeps. Only names that look exactly like store objects are
  considered; symlinks and unknown entries are reported and left alone. Run it
  when no download is in progress, because a reader still on a superseded
  pointer keeps only what it already fetched. `publish` and `gc` take an
  exclusive lock on the store (`StoreBusy` if another one is running), so
  collection cannot see a publish's not-yet-referenced blocks as garbage.
- `serve` exposes a store read-only over HTTP. It answers only `GET` for
  exactly `/pointers/<64 hex>.ptr`, `/manifests/<32 hex>.mf` and
  `/blocks/<32 hex>/<index>.blk`; there is no directory listing and no write
  path. It never follows a symlink in any component below the store root,
  refuses non-regular or oversized objects, and answers everything else with
  400/404/405 (408 for a slow header, 500 for an object it refuses to serve).
  `--listen` defaults to `127.0.0.1:8787`; pass
  `--listen 0.0.0.0:8787` to share on a LAN. The pointer name is the drive
  public key from the link and manifest/block ids need authenticated metadata,
  so network reachability alone does not grant access; the link still does.
- A read store may be an `http://` origin. `list`, `get` and `verify` then fetch
  only the objects they need, cache them under `--cache` (`$SKIPTA_CACHE`, else
  `./skipta-cache`) and keep the accepted-seq rollback state there, so the same
  share opens again from the cache with the server gone. Cached objects are
  never trusted just because they are cached: every read authenticates them.
  `publish`, `passwd`, `gc` and `serve` require a local store; writing to a
  remote origin is refused. This build has no TLS client, so `https://` is
  rejected with an explanation rather than silently treated as a path.
- Exit codes: `0` ok, `1` error, `2` usage (including a passphrase mismatch at
  the prompt), `3` wrong passphrase or a wrapped identity that fails
  authentication, `4` missing passphrase with no terminal, `5` identity file
  that is neither wrapped v2 nor legacy plaintext (including a truncated or
  malformed one). A wrong passphrase is rejected before anything is written.
- `verify` decrypts and authenticates every manifest and every block below the
  given path (the whole share by default) and checks each file against its
  published size. It writes nothing and exits non-zero on the first missing,
  oversized, undecryptable or wrong-sized object. Use it on a store you copied
  from another machine, or after a crash.
- The store is written atomically: blobs go to a temp file and are renamed into
  place, so an interrupted publish cannot leave a torn blob under a name a reader
  trusts. Reads are capped at the format's object sizes (4 KiB pointer, 1 MiB +
  tag manifest, 64 KiB + tag block) and only accept regular files, so a corrupt
  or hostile store cannot exhaust memory. A hard power cut can still lose blocks
  the pointer already names; republish in that case (see ADR-0011).
- Downloads never write through a link: a symlink or device at the destination is
  refused (`UnsafeTarget`), and `--force` replaces the link itself instead of
  following it. A manifest name that collides with a symlinked directory is
  refused too, so extraction stays inside `--out`.
- **A manifest is untrusted metadata.** Every name is validated when the sealed
  manifest is opened, before it can become a path: separators and absolute names
  (`../x`, `/tmp/x`, `a/../../b`), `.`/`..`, empty names, NUL and other control
  characters, invisible/bidi characters, duplicates and case collisions are all
  refused (`PathSeparator`, `DotName`, `EmptyName`, `NulByte`, `ControlChar`,
  `UnsafeChar`, `DuplicateName`/`CaseCollision`). A hostile name in a child
  manifest is rejected when that child is opened; extraction creates at most the
  already-validated parent directory and never a file outside `--out`. A file
  entry never replaces a directory, a directory entry never replaces a file
  (even with `--force`), and files whose names are not in the manifest are not
  touched. A rejected block or pointer leaves no empty output file behind: a
  fresh target is removed when nothing authenticated reached it.
- **A source folder is untrusted input.** Symlinks (including loops), FIFOs,
  sockets and device nodes are skipped and reported, never followed or opened;
  nothing outside the chosen folder is encrypted or named in the archive. An
  unreadable file aborts the publish with `StoreIo` before the pointer is
  written, so no identity or root manifest is committed. A tree deeper than 32
  levels is refused (`TooDeep`), and a failed publish leaves no temp key file.
- **Every stored object is untrusted.** Blocks and manifests are AEAD-sealed and
  bound to their drive, file id, block index and size; a flipped, truncated or
  swapped block (`AuthFailed`/`SizeMismatch`), a corrupted manifest
  (`AuthFailed`), a pointer with a wrong signature (`BadSignature`) and a
  manifest sealed under another drive key (`AuthFailed`) all fail closed. No
  unauthenticated byte is ever written as content. The same distrust applies to
  the store layout on writes: reads use `openat` with `O_NOFOLLOW`, and
  publish/gc refuse a symlinked `blocks/`, `manifests/`, `pointers/`,
  `identities/`, `accepted/` or `.lock` (a FIFO or device there is refused too),
  so a hostile store copy cannot redirect a write or chmod outside itself.
- **On-disk modes do not depend on umask.** The store root and its
  `pointers/`, `manifests/`, `blocks/`, `blocks/<id>/`, `identities/` and
  `accepted/` directories are 0700; pointers, manifests, blocks, identities, the
  accepted-seq file and the `.lock` file are created 0600 (the file is opened
  0600 and `fchmod`ed, so even `umask 0777` cannot hide it from its owner or
  expose it to anyone else). Temp files are created 0600, renamed into place on
  success and removed on failure, so no partial key, plaintext or manifest
  outlives an operation.

Default store is `$SKIPTA_STORE`, else `./skipta-store`.

## Layout

```
include/skipta/   public headers: bytes, error, crypto, format, manifest,
                  pointer, link, keywrap, drive, identity, store, share, download,
                  gc, private_file, http
                  (share also has verify_path, the whole-share integrity check)
src/              implementation; format.cpp is the only place that builds
                  nonces and AADs; http.cpp is the read-only store transport
tests/            doctest suites, incl. vectors, the nonce-reuse guard, the
                  publish/list/get path over a local store and over HTTP, and
                  regressions for every parser the fuzzer attacks
fuzz/             sanitizer mutation harness (not linked into the library/CLI)
scripts/          fetch-deps.sh, fuzz.sh
cli/              skipta: publish, passwd, gc, list, get, verify, serve
                  (phase 3; read-only HTTP transport, no swarm)
tools/            gen_vectors (deterministic test-vector generator)
testvectors/      checked-in, verified by tests/test_vectors.cpp
docs/format-v1.md normative byte layout
docs/adr/         decision log
docs/platforms.md platform support matrix and real-hardware checklist
spike/            transport spike skeleton and results template
```

## What the format gives you

- Listing a directory costs one small encrypted blob, never file content.
- Fetching byte range `X..Y` of a file decrypts at most two 64 KiB blocks.
- Names, sizes and the tree are encrypted; only opaque random ids appear on the
  wire.
- One Ed25519 identity per drive; a signed root pointer is the only mutable
  item, with rollback protection.
- Share links are bearer secrets. Key material stays in the link; only
  secret-derived swarm names may go to a tracker or DHT.

Details: [`docs/format-v1.md`](docs/format-v1.md). The read path is an ordered,
bounded block pipeline ([ADR-0006](docs/adr/0006-ordered-block-pipeline.md)):
parallel reads, sequential output.

## Security warnings that belong in the UI

- **A link is a key.** Anyone who receives it can read the share. Forwarding it
  is publishing it. "Revoking" means publishing a new version under a new key;
  it cannot take back what was already downloaded.
- **No anonymity.** Peers see each other's IP addresses.
- **The passphrase protects the store, not the link.** The identity file is
  encrypted, so a copied `<store>` alone cannot reveal the drive key or signing
  seed. But a share link already carries the drive key: anyone with the link
  reads the share whether or not they have the store or the passphrase. Store
  plus passphrase is full control of the drive; the passphrase is not a second
  factor and does not revoke a link. Keep the store private anyway.
- **Losing the passphrase is permanent.** The signing seed exists only inside
  the wrapped identity: without the passphrase the drive can never be updated
  again by anyone (the existing link still downloads). There is no recovery and
  no project-held escrow.
- **`SKIPTA_PASSPHRASE` is visible to your own processes.** It is an automation
  convenience; a terminal prompt avoids leaving the passphrase in a process
  environment.
- **A store you did not write is untrusted.** Even with a valid link, the store
  can withhold or corrupt blobs; `skipta verify` tells you whether the copy you
  have is intact, but it cannot tell you it is the publisher's latest version
  (the signed `seq` guard only catches a rollback below what this store already
  accepted). A remote `http://` origin has exactly the same power: it can
  withhold or replay objects and observes object names, sizes and timing, but
  it never sees a key or plaintext and cannot forge content.
- **The HTTP transport is not confidential on the wire.** It carries only
  sealed objects, but plain HTTP reveals which opaque names are fetched and
  when. Put it on a trusted LAN, a VPN or behind a TLS-terminating proxy; do not
  bind `0.0.0.0` on an untrusted network. The server is read-only and handles
  one connection at a time, so a slow or malicious client can delay others for
  the socket timeout; use a real proxy for a busy or hostile network. The
  reader's cache grows with what it fetched and is not collected automatically.
- **Once ciphertext or plaintext leaves the store, the tool cannot recall it.**
  `gc` deletes unreachable objects from *this* store, so a deleted file's old
  blocks are not kept here forever; a copy of the store or of individual objects
  made before collection remains decryptable with the link, and a reader that
  already fetched content keeps it. An aborted publish can leave unreachable
  ciphertext objects written before the failure (never a pointer or identity, so
  nothing is published); only a store whose drives are fully accounted for can
  have that cleaned by `gc`.
- **Local modes protect against other users, not root.** 0700/0600 files stop
  other accounts and accidental sharing through backups or sync clients that
  preserve modes; they do not stop root, a compromised kernel, or a backup taken
  while the store was readable.
- **Not reviewed.** The format needs an external cryptographic review before any
  1.0 release. The untrusted-input parsers are mutation-fuzzed under ASan/UBSan
  (ADR-0018), but fuzzing does not replace that review.

## Not implemented yet

The measured swarm transport (both spikes), writable or remote publishing, a
TLS client, DHT/BEP 44 root publication, rotating the drive key
itself (a passphrase change re-wraps the same key, because a new key would
change the link), a passphrase prompt on Windows (use the environment variable
there), standalone browser, groups/rosters/epoch keys, public mode, Listi
`skipta://`, long-running coverage-guided fuzzing, packaging for
Haiku/BSD/Windows/macOS. Garbage collection
is manual and store-wide; there is no background or per-drive compaction, a
store whose identities use different passphrases cannot be collected in one run,
and a remote reader's object cache is cleared by deleting it rather than by `gc`.

## Licence

AGPL-3.0-or-later. Skipta is a separate component that Listi may use; it is
never a dependency of Listi.
