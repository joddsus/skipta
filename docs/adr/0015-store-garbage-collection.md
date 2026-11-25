# 0015. Conservative, manual garbage collection of store objects

## Context

A publish writes a fresh tree and a new root pointer, and a file removed from the
folder disappears from the new manifest. The previous manifests and blocks stay
in the store: the local store, like the future swarm, is content-addressed and
never overwrote them. That has two costs.

- **Growth.** Every republish adds a full copy of the changed content, so a
  frequently updated folder grows without bound.
- **Privacy.** The old blocks are encrypted under the drive key, which the link
  already carries. Anyone who holds the link *and* the store (or a copy of it)
  can still decrypt a file that was deleted locally and republished. Deleting a
  file from the folder does not delete its ciphertext.

Collection cannot be done from object reachability alone in a store that may be
shared by several drives: blocks are not labelled with an owning drive, so a
drive that is simply not walked looks exactly like garbage. Deleting on that
basis would destroy another share.

## Decision

- Add `skipta gc [--delete] [--store <dir>]`, backed by
  `collect_garbage(store, drives, apply)` in `gc.hpp`.
- **Current pointers only.** The walk starts at each drive's signed root pointer,
  verifies its signature against the drive public key, decrypts and parses every
  manifest, and marks every manifest id and file id it reaches. A missing or
  unauthenticated current object aborts the run before any deletion.
- **Every drive must be accounted for.** The caller supplies one `DriveIdentity`
  per identity file in `<store>/identities`; the function compares that drive set
  with the `.ptr` files and refuses with `UnsafeStore` if either side has an
  extra entry. A pointer without an identity (store copied without identities)
  and an identity without a pointer (interrupted first publish) both refuse.
  This is why gc needs one passphrase that opens every identity: a store with
  per-drive passphrases cannot be collected in one command.
- **Only object-shaped names.** Sweeping considers regular files named
  `<32 hex>.mf` and regular blocks named `<16 hex>.blk` inside `<32 hex>`
  directories. Symlinks, directories and unknown names are counted as `ignored`
  and never opened or removed; a symlink named like a block directory is not
  followed. `pointers/`, `identities/`, `accepted/` and `.lock` are never swept.
- **Dry run by default.** Without `--delete` the command reports what it would
  remove and changes nothing. This is a destructive, hard-to-undo operation on
  the only copy of the data, so it is explicit.
- **Exclusive store lock.** `publish` and `gc` take a non-blocking `flock` on
  `<store>/.lock` (`StoreBusy` on contention). gc must not run between a publish
  writing objects and the pointer that names them, or it would collect fresh
  blocks. Platforms without `flock` build but do not lock; the CLI is currently
  POSIX-first (no Windows prompt either).
- Reads continue without a lock. A reader that opened a superseded pointer
  before a republish keeps only what it already fetched once gc runs; the README
  says to collect when nothing is downloading.

## Consequences

**What this fixes.** Reclaiming space after republishes, and removing previously
published ciphertext of deleted files from the local store, so a deleted file is
not indefinitely decryptable with the link by anyone who also holds the store.

**What it does not fix.**

- A copy of the store or of individual blocks made before collection is beyond
  the tool's reach; gc cannot revoke ciphertext that already left.
- Readers who copied an old manifest can still decrypt any old blocks they
  already fetched; gc only removes what is still in this store.
- It does not rewrite the current version, rotate keys, or compact a block's
  bytes; it only deletes whole unreachable objects.
- A store whose drives have different passphrases cannot be collected, and a
  reader-only store (pointers and blobs but no identities) is deliberately
  refused rather than guessed at.
- It is manual and store-wide: no background collection, no per-drive or
  per-version retention policy, and no protection against a reader racing a
  collection in another process.

## Tests

`tests/test_gc.cpp` republishes after deleting a file and checks the dry run's
counts and that it changes nothing; that applying removes exactly the reported
objects while the pointer, identity and current share still verify and read;
that a second run is a no-op; that a store with two drives refuses with one
drive's identity and keeps both when given both; that a missing identity, an
identity without a pointer, and a corrupt current manifest all refuse without
deleting; that symlinks and unknown names survive and are reported; and that an
empty store reports zeros.
