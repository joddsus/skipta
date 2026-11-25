# 0016. The untrusted-input boundary of the CLI, end to end

## Context

Three different things reach the tool from outside its own trust domain:

1. a sealed manifest is written by a publisher (or an attacker with the link),
   so every name in it is hostile input until proven otherwise;
2. the folder handed to `publish` is a filesystem an attacker may have prepared
   with links, special files, unreadable entries or absurd depth;
3. every stored object (pointer, manifest, block) can be modified or replaced by
   whoever holds the store, and `get`/`verify` must never turn that into bytes
   the user believes are content.

A bug in any of those paths can write outside the chosen destination, read
something outside the chosen source, or hand back garbage. On-disk modes are a
fourth boundary: the store is ciphertext plus key material, and another local
user must not be able to read it.

The guarantees were partly implemented (name validation, AEAD, non-blocking
store reads, atomic writes) but not exercised end to end with real hostile
artifacts, and file creation still depended on the process umask: an identity's
temp file was created with the default mode and tightened afterwards, and store
objects were left at `0644`.

## Decision

- **Extraction never trusts a name.** `Manifest::parse` validates every entry
  name before the manifest is returned, and the same parser runs for the root
  and for each child manifest. A separator or absolute name, `.`/`..`, an empty
  name, NUL or control characters, invisible/bidi characters, duplicates, case
  collisions and invalid UTF-8 are refused with a named error. Extraction is
  therefore never handed a name that could become `../x`; a hostile child
  manifest fails after at most its already-validated parent directory was
  created. Destination collisions fail closed: a file never replaces a
  directory, a directory never replaces a file (even with `--force`), and
  symlinks/devices are refused rather than followed. Files whose names are not
  in the manifest are untouched.
- **Rejected content leaves no empty file.** `download_file` removes a target it
  created itself when the failure happened before any authenticated byte reached
  it (for example a flipped first block), together with its resume sidecar. If
  bytes did reach the disk, the partial file and its state stay resumable, as
  before.
- **`publish` never follows links out of the source.** Entries are examined with
  `symlink_status`: symlinks (so also loops), FIFOs, sockets and devices are
  reported as skipped and never opened or traversed. An unreadable regular file
  fails the publish (`StoreIo`) before the signed pointer is written. The depth
  limit and name validation apply to real paths, and `write_private_file`
  removes its temp file on every failure.
- **Store layout is untrusted on writes too.** Reads already use `openat` with
  `O_NOFOLLOW`; writes now refuse a symlink or non-directory in any component
  below the store root (`ensure_writable_directory`), so a hostile store copy
  cannot redirect `publish` blocks/manifests/pointers, identity saves, accepted
  seq state or HTTP-cache objects outside itself. `StoreLock` opens `.lock`
  with `O_NOFOLLOW | O_NONBLOCK` and requires a regular file after `fstat`, so a
  symlink, FIFO or device cannot make it chmod or block on something else.
- **Store objects fail closed.** A block is bound by AEAD and AAD to drive key,
  file id, index and file size, so flipping, truncating or swapping blocks is
  `AuthFailed`/`SizeMismatch`; a corrupted or truncated manifest is `AuthFailed`;
  a pointer whose signature does not verify is `BadSignature`; a manifest sealed
  under another drive key is `AuthFailed` for this link. The caller receives no
  plaintext for a rejected object.
- **Owner-only modes at creation.** `private_file.hpp` adds
  `make_private_directory` (0700) and `write_private_file` (POSIX `open` with
  0600, `fchmod` to 0600, write, optional fsync, rename). Store root and its
  `pointers/`, `manifests/`, `blocks/`, `blocks/<id>/`, `identities/` and
  `accepted/` directories are 0700; every file is 0600, including the `.lock`
  file, whose mode is repaired if an earlier extreme umask made it unreadable.
  The identity save uses the same helper, so the plaintext seed is never in a
  temp file that is group- or world-readable, and a failed save leaves no temp
  file.
- **Residual, documented:** an interrupted or failed publish can leave
  unreachable ciphertext objects from before the failure (never a pointer or an
  identity, so nothing is published and no key leaks); `gc` can remove them only
  when the store's drives are fully accounted for. Modes do not protect against
  root or a compromised kernel, and no collection can recall copies made before
  it.

## Consequences

A hostile manifest is rejected before it can name a destination, a prepared
source folder contributes only regular files, a corrupted store cannot produce
content, and a local user without the account cannot read the store or identity
even if the process runs with a permissive or restrictive umask. The cost is
stricter behaviour on odd inputs: special files are skipped rather than
archived, a same-named destination with a different size is replaced only for
the entry being extracted, and a fresh download that fails authentication leaves
no file to resume (it would have had no verified bytes).

## Tests

`tests/test_store.cpp` plants symlinked `blocks/`, `manifests/`, `pointers/`
and `.lock`, plus a FIFO lock, and checks there is no write outside the store and
no block; `tests/test_attacks.cpp` seals hostile manifests with real keys
(`../escape`, `../../etc/evil`, `/tmp/evil`, `a/../../b`, empty, `.`, `..`, NUL,
newline, duplicates, case collision, hostile child) and checks the refusal codes;
verifies destination collisions and untouched unrelated files; publishes a tree
with a link outside the folder, a symlink loop, a FIFO, an optional device node
and then decrypts everything to prove the outside content is absent; makes a
source file unreadable and checks no pointer or temp file is left; builds a
41-level tree and expects `TooDeep`; flips, truncates and swaps blocks, corrupts
and truncates a manifest, corrupts a pointer signature and seals a root under a
wrong drive; checks a fresh failed download has no target or sidecar; and sets
`umask(0)` to verify 0700 directories and 0600 files. `skipta get` on those real
artifacts is exercised separately against the CLI, including exit codes and the
absence of output files.
