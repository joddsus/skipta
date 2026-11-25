# ADR-0013: The publisher identity is wrapped with a passphrase

Status: accepted

## Context

`<store>/identities/<sha256(canonical source)>.id` holds the drive key (which
decrypts the whole share) and the Ed25519 signing seed (which signs root
pointers, so it alone can publish new versions of a drive). It was stored as
plaintext JSON with mode 0600. Mode only helps against other users on the same
machine: a copied or stolen store directory carried both secrets, and with them
full read and write control of every share published from it. The keywrap
construction (Argon2id + XChaCha20-Poly1305, format §7) already existed and was
tested, but nothing used it.

## Decision

1. **One wrapped envelope.** The identity file is now
   `{"v":2,"wrap":<keywrap blob>}`. The keywrap plaintext is
   `drive_key[32] || signing_seed[32] || u64be(seq)` (72 bytes), so the file
   leaks neither the drive key, the seed, nor the published sequence. A fresh
   16-byte salt and 24-byte nonce are generated for every save; the default KDF
   is Argon2id with 3 passes and 256 MiB, so a copied file is expensive to
   attack offline. The share format, link format and test vectors are untouched:
   this is a local file only.
2. **Passphrase supply.** `publish` reads `SKIPTA_PASSPHRASE` when it is set and
   non-empty, otherwise it prompts on stderr with terminal echo disabled. A
   prompt when *setting up* protection (new drive, or migrating a legacy file)
   asks twice and refuses a mismatch; unlocking an existing wrapped identity
   asks once. With neither the variable nor a terminal, `publish` refuses with
   `MissingPassphrase` rather than guessing or writing an unprotected identity.
   The variable exists for automation; a prompt is preferable because process
   environments are visible to same-user processes.
3. **Exit codes.** `0` success, `1` any other error, `2` usage (including a
   passphrase mismatch at the prompt), `3` wrong passphrase or damaged envelope,
   `4` missing passphrase with no terminal, `5` identity file that is neither a
   wrapped v2 nor a readable legacy v1. A wrong passphrase is detected before
   the publish writes anything, so the store is left byte-identical.
4. **Migration, without a plaintext remnant.** v1 plaintext identities remain
   readable so an existing store keeps working. The only command that writes an
   identity is `publish`; on its next run it loads the legacy file, publishes,
   and saves the wrapped v2 form to the same path via a temp file plus rename.
   The old plaintext inode is unlinked and no plaintext copy is left in the
   identities directory. The drive and therefore the share link are unchanged,
   and previously published content still downloads. `list`, `get` and `verify`
   never read the identity and need no passphrase, before or after migration.
5. **Bounds and hygiene.** Identity reads accept only a small regular file (no
   symlinks, no devices), the passphrase is wiped on the way out, and the
   plaintext identity buffer is wiped after wrapping.

## Consequences

**What this protects.** A stolen or copied store on its own no longer yields the
drive key or the signing seed. Without them the content cannot be decrypted and
new pointers cannot be signed, so an attacker cannot read the share or
impersonate the publisher by rewriting it.

**What it does not protect.**

- A share link already contains the drive key. Anyone who has the link can read
  the share with or without this store; the passphrase does not revoke a link.
- Someone with both a store copy and the passphrase has full control of the
  drive. The passphrase raises the cost of a store-only compromise; it is not a
  second factor.
- Losing the passphrase means the drive can never be updated again by anyone,
  because the signing seed exists only inside this envelope. The existing link
  keeps downloading. There is no recovery. A reader who still knows the current
  passphrase can rotate it in place with ADR-0014.
- A plaintext identity file copied out of the store before migration is beyond
  the tool's reach; only the file in `<store>/identities` is rewritten.
- The wrapped file still reveals that an identity exists, its rough size, and
  the SHA-256 of the folder's canonical path (the file name). The drive id and
  the sequence number are inside the ciphertext.
- Passphrases and unwrapped secrets are wiped best-effort in normal memory; the
  process is not hardened with `mlock` or similar.
- No external cryptographic review has happened yet (ADR-0002).
