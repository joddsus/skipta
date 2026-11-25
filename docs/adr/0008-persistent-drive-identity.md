# ADR-0008: Persistent drive identity and reader-side rollback memory

Status: accepted

## Context

A share link contains the drive public key and the drive key — nothing else. It
therefore already names a *drive*, not a version of it: the mutable part of a
share is the signed root pointer, which has a `seq`. Earlier, every `publish`
minted a fresh drive, so the link changed and the pointer started over at
`seq = 1`. That made an update indistinguishable from a brand-new share, and it
left `seq` decorative: nothing on the read path compared it with what the reader
had accepted before.

## Decision

### Publisher: one identity per folder, saved between runs

`DriveIdentity` is the drive key plus the Ed25519 signing pair plus the last
published `seq`. It is stored as JSON:

```json
{"v":1,"drive":"<b64 32>","drive_key":"<b64 32>","signing_seed":"<b64 32>","seq":2}
```

in `<store>/identities/<sha256(canonical source path)>.id`.

- `publish_directory` takes an optional identity (`PublishOptions::identity`) and
  an explicit `seq`; without one it mints a new drive. The CLI loads the identity
  for the folder, publishes with `seq = last + 1`, then saves it back.
- Because the identity is keyed by the folder's canonical path, re-running
  `publish ~/photos` updates that share: same link, `seq` incremented.
- The file name is a hash, so the store does not reveal which folders are
  published in it. The path is canonicalised, so `./photos` and `photos/` agree.
- The file contains publisher secrets and is written atomically with `0600`
  permissions. The store is therefore a private publisher directory; readers
  only need the link.
- Losing the identity file means the next publish mints a new drive and a new
  link — links cannot be re-derived without the drive key, by design.
- Decoding refuses a public key that does not match the seed (`DriveMismatch`),
  so a corrupted file cannot quietly become a different drive.

### Reader: remember the highest seq accepted per drive

`open_share(store, link, min_seq)` passes `min_seq` to `verify_pointer`, which
already rejected `seq < min_seq` as `StalePointer`. The CLI feeds it
`accepted_pointer_seq(store, drive)` and then records the accepted `seq` with
`remember_pointer_seq` in `<store>/accepted/<drive hex>.seq` (monotonic; never
lowered).

## Consequences

- A republished share keeps its link, and a reader that has seen `seq = 2` will
  not open a replayed `seq = 1` pointer.
- The guard is local (trust-on-first-use), not global: a fresh reader has no
  memory and accepts whatever pointer the store currently holds, and two readers
  can disagree about which seq is current. Real consistency needs the transport
  phase; this only stops a store or replica from walking a reader backwards.
- A publisher whose identity `seq` is behind the store's pointer (identity file
  restored from a backup) produces a pointer that readers with memory refuse.
  That fails loudly rather than silently rolling back, which is the right
  trade-off.
- `seq` is not used to order manifests or to garbage-collect old ones; the drive
  keeps only the newest root, and superseded manifests and blocks stay in the
  store.
- `publish` without a stored identity (a new folder, or a different store) still
  behaves exactly as before: a new drive, `seq = 1`.
- The identity file is now passphrase-wrapped rather than plaintext; that is a
  change to the local file only and is recorded in
  [ADR-0013](0013-passphrase-wrapped-identity.md). Stable links, rising `seq`
  and reader rollback memory are unchanged.

## Tests

`tests/test_identity.cpp` round-trips both identity file formats, rejects a
mismatched public key and an unknown field, checks that the wrapped file hides
the drive key and seed, migrates a legacy plaintext identity, and drives the
CLI's sequence: publish, save, reload, publish again. It checks that the link and drive are unchanged, `seq` becomes 2
and then 3, and the root actually changed. It then replays the old signed
pointer into the store and checks that `open_share` with the remembered `seq`
refuses it as `StalePointer` while an unguarded open still returns `seq = 1`;
that the memory never decreases; and that two folders in one store get separate
identities.
