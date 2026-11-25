# 0018 — Sanitizer mutation fuzzing of every untrusted-input parser

Status: accepted

## Context

The format and the store/HTTP boundary are built on the rule that every byte
from a peer, a store or a link is untrusted. Unit and attack tests cover known
shapes, but they cannot cover the space of malformed lengths, truncated
encodings, nested JSON, bad UTF-8 or pathological header layouts. A parser bug
in this code is either a crash/UB in the user's process or a hang while opening
a share; both are security defects for a tool whose job is to survive hostile
input.

Sanitizers turn most memory and integer mistakes into a deterministic failure,
and mutation fuzzing reaches combinations a hand-written test will not. The
fuzzer must be reproducible, must treat hangs and memory growth as failures, and
must not slow down the normal build.

## Decision

Add `fuzz/fuzz_main.cpp`, built by `make fuzz-build` with:

```
-fsanitize=address,undefined -fno-sanitize-recover=all -D_GLIBCXX_ASSERTIONS
-O1 -g -fno-omit-frame-pointer
```

It is not part of `all` or `test`; `make clean` removes `build-fuzz/`. A wrapper,
`scripts/fuzz.sh`, sets `ASAN_OPTIONS` (leak detection on, abort on error) and
`UBSAN_OPTIONS` (halt on error), builds and runs it. `--seed`, `--iterations`,
`--only`, `--max-input`, `--corpus` and `--artifacts` make runs reproducible and
targetable.

The seed corpus is generated at startup by publishing a real folder through the
normal `publish_directory` path into a temporary store, then reading back the
signed pointer, sealed manifests, sealed blocks, link, legacy plaintext
identity and a passphrase-wrapped envelope. Optional `--corpus DIR` files are
fed to the selected parser and used for splicing. Mutation combines bit flips,
byte replacement, inserts, deletes, truncations, duplications, splices, JSON/
HTTP dictionary tokens, pathological repetition and raw random bytes.

The harness drives 17 parser entry points:

- pointer JSON and the signed-pointer envelope;
- manifest JSON (including names and relative paths);
- sealed manifest and sealed block framing/AEAD;
- links, base64url and hex;
- store object filename classification;
- HTTP request line, object target routing and response status/header parsing;
- store URL parsing;
- legacy identity and the keywrap envelope (parsed without running Argon2).

Every input runs under a 5 s `SIGALRM` deadline. The handler writes the exact
input and metadata to the artifact directory and exits 124, so a hang is a
failure rather than a stuck job. ASan's death callback and UBSan's
`__ubsan_on_report` hook save the triggering input as well. Any exception other
than the library's own `Error` is a failure. Resident set size is sampled; the
run fails on more than 1 GiB RSS or 512 MiB above baseline, treating unbounded
growth like a crash. `--selftest-timeout` exercises the timeout path itself.

## Results and fixes

The recorded runs total **6.4 million inputs** (1.8M seed 1, 1.5M seed 2, 0.5M
seed 11, 2.0M seed 5 with all 17 parsers, 600k targeted across HTTP, keywrap,
block and sealed-manifest parsers, and 3,000 deep-JSON manifests with 1 MiB
inputs). All completed with zero crashes, zero ASan/UBSan reports, zero
timeouts, and peak RSS under 375 MiB.

One correctness defect surfaced while designing the block-size corpus:
`format::block_count` computed `(file_size + kBlockPlaintextSize - 1) /
kBlockPlaintextSize`, which wraps for sizes near `UINT64_MAX` and under-counts
blocks. Manifest limits cap file size at 1 TiB, so published stores were never
affected, but the public framing helper was wrong. The fix divides first and
adds one for a non-zero remainder; a regression in `tests/test_crypto.cpp` pins
`block_count(UINT64_MAX)` and the last block length. The change does not alter
any valid block framing or serialized byte, and `make vectors` remains byte
identical.

## Consequences

- Known parser failures now have a cheap, reproducible regression path: a seed
  plus `--only <parser>`, or a normal test case when the shape is specific.
- Sanitizer runs are slow (about 8k inputs/s). The default budget is millions of
  inputs; a single `make fuzz` invocation is documented in the README and can be
  split by parser or seed.
- `-O1` and sanitizer instrumentation mean the fuzz binary is not a performance
  benchmark; it is a correctness oracle.
- Not covered: Argon2id execution per input (64–256 MiB is far too expensive;
  the envelope around it is fuzzed), filesystem races and GC directory walks,
  libsodium's primitives, full socket send/receive behavior beyond its pure wire
  parsers, and `format::decrypt_file` (a convenience that allocates the whole
  file by design). These remain covered by unit/e2e tests or are documented
  limits, and none replaces the external cryptographic review.
