# ADR-0009: Recursive directory download in published order

Status: accepted

## Context

`get` could fetch one file, and resumable downloads (ADR-0007) made a single
interrupted file cheap to continue. Fetching a whole folder still meant one
command per file, in whatever order the caller chose, and an interruption
anywhere left the caller to work out what was already there.

The manifests already define an order: entries are stored sorted by name, and a
directory is one entry among them. Depth-first traversal of that order is the
natural, deterministic shape of a folder download, and it makes progress
reporting and tests comparable across runs.

## Decision

`download_directory()` walks the share depth-first, consuming each directory's
entries in manifest order, and creates the target tree as it goes (empty
directories included). Files are handled through `download_file()`, so each one
gets the ordered, bounded block pipeline and its own `*.skipta-resume` state.

Rules per file, evaluated in this order:

1. `overwrite` → delete the target and fetch everything again.
2. Target exists, has the manifest size and has no resume state → **skip**.
   Nothing is fetched and `reused` counts the whole file.
3. Target exists with resume state and `resume` is on → verify the prefix and
   continue from there (ADR-0007). This is what makes an interrupted directory
   download continue where it stopped: finished files are skipped in step 2,
   the file that was in flight resumes, and the rest are fetched normally.
4. Target exists without resume state but with the wrong size → replace it
   rather than appending to unknown bytes.
5. Otherwise → normal download.

`on_file` reports once per file, in walk order, so a caller can print progress
in the same order the data is fetched. The CLI uses it for its per-file lines
and a final summary (`files`, `directories`, bytes written, bytes kept, skipped).

## Consequences

- An interrupted folder download leaves a deterministic prefix of the published
  order, and re-running it with `--resume` does no redundant network work for
  completed files.
- **The skip check is by size, not by content.** A file of the right size with
  no resume state is assumed to be the published one; verifying it would mean
  fetching it again, which is exactly what resume is meant to avoid. For the
  same reason, a file that was modified locally but kept its length is left
  alone — use `--force` when in doubt.
- A partially downloaded file whose state file was deleted is re-downloaded from
  the start; it is never appended to.
- Order is depth-first over manifest order, which is stable for a given publish.
  A republish reorders only if names change, and it changes file ids anyway.
- Only entries below the given path are fetched. Names are already validated by
  the format (no separators, no dot names, no control characters), so a
  manifest entry cannot name a path outside the target directory. Pre-existing
  symlinks inside the target directory are followed, as with any local file
  write; that is local state, outside the threat model.
- Downloads are sequential at the file level. Parallel files would multiply the
  block pipeline's memory bound without changing correctness.

## Tests

`tests/test_directory.cpp` publishes a tree with nested and empty directories
and checks the exact walk order (`a.txt`, `cdir/d.txt`, `cdir/sub/e.txt`,
`f.txt`), that a subdirectory download only walks its subtree, and that content
and empty directories match. It interrupts a folder download by removing a block
of the second file, checks the first file is complete and the second is a
partial with state, restores the block, resumes, and compares the result with a
fresh download. Finally it covers the skip/restart rules: a second run fetches
nothing, a truncated file is replaced, `overwrite` re-fetches everything, and a
non-directory target is refused with `FileExists`.
