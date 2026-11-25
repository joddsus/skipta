# ADR-0007: Resumable downloads with a verified prefix

Status: accepted

## Context

A download of a large file can be interrupted by a dropped connection, a
crashed client, or a peer that stops serving. Restarting from zero is wasteful,
and the format makes resuming cheap: blocks are fixed-size, independently
authenticated items written in order, so the file on disk is always a prefix.
There is no need for a per-block bitmap.

## Decision

`download_file()` writes progress beside the target:

```json
{"v":1,"file_id":"<b64 16>","size":700000,"written":327680,"sha256":"<b64 32>"}
```

stored as `<target>.skipta-resume`.

1. **Resume point is a byte count, not a block list.** The block pipeline writes
   ascending blocks and the sink appends, so whatever is on disk is a prefix. The
   writer only records block boundaries, so the prefix is always a whole number
   of blocks (or the whole file).
2. **The prefix is verified, not trusted.** `sha256` covers exactly the first
   `written` bytes. On resume the local file is hashed and compared before any
   request is made; bytes beyond `written` are truncated (they were never
   verified), and a mismatch refuses the resume with `BadResumeState` rather
   than silently appending authenticated blocks to possibly wrong data.
3. **The state is bound to the file.** `file_id` and `size` must match the entry.
   A re-publish mints new file ids, so resuming into a changed share is refused
   by construction; a foreign or stale sidecar is detected instead of misused.
4. **Checkpointing is interval-based.** After each block, if at least
   `checkpoint_bytes` (default 1 MiB) were written since the last checkpoint, the
   state is written atomically (temp file + rename). On a failed fetch the sink
   flushes and checkpoints before the error propagates, so completed blocks are
   kept.
5. **Completion deletes the state**, so a finished file has no sidecar, and only
   after the final flush succeeded: a short write (full disk) is reported as
   `StoreIo` and keeps the state, never as a finished download. A file that is
   already complete but still has state (a crash after the last checkpoint) is
   verified, has that state removed, and is reported as done (`skipped`,
   `reused` = size) without fetching anything. A target that already has the
   entry's size and no state at all is treated the same way instead of failing
   with `BadResumeState`; the wrong size, or a state that cannot be read, is
   still refused.
6. **Overwrite wins over resume.** `--force` removes the target and its state and
   starts over; an existing target without `resume` or `overwrite` fails with
   `FileExists` instead of clobbering.
7. **CLI rules:** `--resume` needs a real output file (not stdout) and cannot be
   combined with `--range`, since a range would resume with different offsets.

## Consequences

- A crash repeats at most `checkpoint_bytes` of work (1 MiB by default), and a
  resume re-reads only the local prefix, not the network.
- The sidecar reveals that a download is in progress and its expected size. It
  sits next to the output file, in the same trust domain.
- **Residual risk, stated plainly:** SHA-256 is a checksum, not a MAC. An
  attacker who can write the sidecar can also write the target, so a forged
  sidecar can make the client accept a prefix it did not download. This protects
  against truncation, partial writes and corruption, not against local write
  access. Files are still per-block authenticated from the sidecar's end onward.
- No partial-block resume, no retries, no resume across a re-published share,
  and no background downloads.

## Tests

`tests/test_resume.cpp` interrupts a real download by removing a block from the
store, checks that the partial file and sidecar exist, restores the block,
resumes, and compares the result byte-for-byte with both the original file and a
fresh download. It also checks that a modified prefix, a truncated file, a
missing sidecar and a sidecar belonging to another file are all refused with
`BadResumeState`; that an existing target is refused with `FileExists` unless
resume or overwrite is requested; that resuming a complete target is a no-op that
needs no blocks and leaves the file alone, both without state and when the state
already covers every byte (which is then removed), while the same target with
the wrong size is still refused; that overwrite repairs a damaged partial file;
and that empty files finish with no state left behind.
