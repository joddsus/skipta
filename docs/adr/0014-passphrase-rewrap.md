# 0014. Change a wrapped identity's passphrase in place

## Context

ADR-0013 encrypts the publisher identity with a passphrase and treats a lost
passphrase as permanent. That left no way to replace a passphrase the owner
believes is weak or disclosed: republishing cannot re-wrap it, and deleting the
identity would create a new drive with a new link and orphan everything already
published.

A passphrase change needs the current passphrase, so it protects against a
later leak of the old one, not against an attacker who already has it. It must
also not disturb readers: the link and the signed pointer are the reader's
entire state.

## Decision

- Add `skipta passwd <dir>`, backed by `IdentityStore::rewrap(source, old, new)`.
- `rewrap` reads the identity bytes once, unwraps them with the old passphrase
  and saves the same `DriveIdentity` under the new passphrase. The drive key,
  signing seed and `seq` are unchanged, so the link, pointer, `seq` and every
  published block stay exactly as they were. Only the identity file is written
  (temp file + rename, mode 0600), with a fresh Argon2id salt and XChaCha20
  nonce, both at the same parameters as ADR-0013.
- A wrong or empty old passphrase is `BadPassphrase` and nothing is written; the
  unwrap happens before any write. An empty or over-long new passphrase is also
  `BadPassphrase`, caught while encoding before the temp file is created, so the
  previous file remains usable. A missing identity is `NotFound`. A legacy
  plaintext identity is `UnsupportedIdentity` here: only `publish` migrates it,
  which keeps migration in the command that also owns the pointer.
- Passphrase supply mirrors `publish`: the current passphrase comes from
  `SKIPTA_PASSPHRASE` or one echo-off prompt; the replacement comes from
  `SKIPTA_NEW_PASSPHRASE` or two echo-off prompts. No passphrase is accepted as
  an argument, where it would appear in the process list. Missing input without
  a terminal is `MissingPassphrase` (exit 4), the same as `publish`.
- Exit codes are unchanged: 0 ok, 2 usage (including a prompt mismatch),
  3 wrong passphrase, 4 missing passphrase, 5 unusable identity; a folder with
  no identity exits 1.

## Consequences

**What this protects.** A passphrase that is suspected to be disclosed can be
replaced without breaking the link or republishing, and the old passphrase no
longer opens the identity file. A user can also move from a short passphrase to
a long one while keeping the same share.

**What it does not protect.**

- An old copy of the identity file, or the old passphrase together with the
  current store, still opens the drive: re-wrapping cannot revoke a file that
  was copied before the change, and it cannot un-know a leaked passphrase.
- It does not rotate the drive key or signing seed, by design. Doing so would
  change the link and invalidate every reader's ability to fetch the next
  pointer. Anyone who extracted those secrets before the change keeps them;
  the passphrase change only limits future access to the identity file.
- It does not change the KDF parameters of the drive or the format version.
- A reader of a share is unaffected and cannot tell that the passphrase
  changed, which is intentional; there is no notification channel.
- Losing both the old and the new passphrase remains unrecoverable, and there is
  still no external audit, `mlock`, or Windows prompt.

## Tests

`tests/test_identity.cpp` publishes a drive, re-wraps it, and checks that a
wrong old passphrase and an empty replacement are refused with the file
byte-for-byte unchanged; that the old passphrase stops working while the new one
returns the same drive key, seed, public key and `seq`; that the pointer bytes,
link and downloaded content are unchanged; that the new envelope differs and
still hides both secrets with owner-only permissions; that publishing with the
new passphrase keeps the link and advances `seq`; and that a missing identity is
`NotFound` while a legacy plaintext file is left untouched as
`UnsupportedIdentity`.
