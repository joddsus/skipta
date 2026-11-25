# Architecture decision log

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-language-dependencies-and-licence.md) | C++17 core, libsodium + nlohmann/json + doctest, AGPL-3.0-or-later | accepted |
| [0002](0002-container-format-v1.md) | Container format v1: key hierarchy, nonces, AAD, blocks, manifests | accepted, needs external review |
| [0003](0003-metadata-encoding-and-parsing.md) | Strict JSON parsing, typed accessors, byte-exact signatures | accepted |
| [0004](0004-transport-spike-plan.md) | Transport spike gates and protocol | proposed, **not measured** |
| [0005](0005-local-blob-store-for-phase-3.md) | Local blob store as the phase 3 stand-in for the swarm | accepted |
| [0006](0006-ordered-block-pipeline.md) | Ordered block pipeline: bounded parallel reads, sequential output | accepted |
| [0007](0007-resumable-downloads.md) | Resumable downloads with a verified prefix sidecar | accepted |
| [0008](0008-persistent-drive-identity.md) | Persistent drive identity: stable links, rising seq, reader rollback memory | accepted |
| [0009](0009-recursive-directory-download.md) | Recursive directory download in published order, per-file resume | accepted |
| [0010](0010-bounded-block-retry.md) | Bounded per-block retry with exponential backoff | accepted |
| [0011](0011-store-and-extraction-hardening.md) | Atomic store writes, bounded reads, no writing through links, `verify` | accepted |
| [0012](0012-name-visibility.md) | Reject invisible, bidi and line-breaking characters in names | accepted |
| [0013](0013-passphrase-wrapped-identity.md) | Passphrase-wrapped local identity, exit codes and plaintext migration | accepted |
| [0014](0014-passphrase-rewrap.md) | Change a wrapped identity's passphrase in place, keeping the link | accepted |
| [0015](0015-store-garbage-collection.md) | Conservative manual gc of unreachable store objects, with a store lock | accepted |
| [0016](0016-untrusted-input-boundary.md) | Enforced untrusted-input boundary: extraction names, source tree, stored objects, 0700/0600 modes | accepted |
| [0017](0017-read-only-http-transport.md) | Read-only HTTP store transport with a validated local cache; writes stay local | accepted |
| [0018](0018-sanitizer-mutation-fuzzing.md) | ASan/UBSan mutation fuzzing of all untrusted-input parsers; block_count overflow fixed | accepted |

Format: context, decision, consequences. Security-relevant choices are flagged
inside the ADR that makes them; open questions for the owner are marked
"flagged decisions the owner has not explicitly approved".
