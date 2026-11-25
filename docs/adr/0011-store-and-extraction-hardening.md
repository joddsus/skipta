# ADR-0011: Treat the store and the destination as untrusted

Status: accepted

## Context

The local blob store (ADR-0005) is the first place Skipta handles bytes it did
not produce in this process. A store can be a copy from another machine, can be
left half-written by an interrupted publish or a full disk, or can be edited by
anyone who can write to the directory. Two concrete failures followed from that:

1. `put_*` opened the final path with `trunc`, so a crash mid-write left a torn
   blob under a name a reader would trust, and two concurrent publishes of one
   drive could interleave inside the shared temp name.
2. `get_*` read whole files into memory with no size check, and extraction built
   paths from manifest names without looking at what was already on disk. A
   planted multi-gigabyte blob is a memory exhaustion; a symlink at the
   destination is a write outside the directory the user named.

Neither is an attack on the cryptography. Both are ordinary "the input is not
what you assumed" bugs at the boundary, and both are cheap to close.

## Decision

1. **Atomic blob writes.** Every `FileStore` write goes to a sibling
   `<name>.tmp-<random>` and is renamed into place. A random suffix keeps two
   publishers from sharing a temp file; a failed write removes its temp. The root
   pointer is additionally flushed (`fsync`) before its rename, because it is the
   commit point of a publish. Blocks and manifests are not fsynced: that would
   put one disk flush on every 64 KiB and is not what this local stand-in is for.
2. **Bounded reads.** The store reads back at most 4 KiB for a pointer,
   1 MiB + 16 bytes for a sealed manifest and 65 552 bytes for a sealed block,
   checked from the file size before allocating. A read of anything that is not a
   regular file is refused as `UnsupportedFileType` rather than attempted, so a
   FIFO or device in the store cannot hang or flood the reader. Oversized blobs
   are `TooLarge`.
3. **No writing through links.** A download destination is inspected with
   `symlink_status`. A symlink or special file at the target is refused as
   `UnsafeTarget`; `--force` unlinks the entry and writes a fresh regular file
   there instead of following it. A directory entry that is a symlink is refused
   even during recursion, so a manifest cannot steer extraction outside the
   chosen folder. A file entry may never replace a directory, with or without
   `--force`. The resume sidecar is only read when it is a small regular file.
4. **An explicit integrity check.** `verify_path()` (CLI: `skipta verify <link>
   [path]`) walks the share, decrypts every manifest and every block, and checks
   each file against the size its manifest promises. It is the supported way to
   decide whether a copied or long-lived store is still intact.
5. **No publishing the store into itself.** `publish_directory` refuses a store
   root that is inside the published folder. `<store>/identities` holds this
   drive's key and its Ed25519 signing seed; sealing that file into the share
   would hand every reader the seed and let them sign later versions of the
   drive. The identity file is read through the same small-regular-file check as
   the store, and the reader's `accepted` seq file is bounded the same way.

## Consequences

- An interrupted publish can no longer produce a silently corrupt blob; at worst
  it leaves an unreferenced `.tmp-*` file, which readers ignore and which can be
  deleted. A crash during a block write costs at most that block, and the signed
  pointer still names a root manifest that was written before it.
- Power loss remains a possibility the format does not solve: blocks and
  manifests are renamed but not fsynced, so a pointer can be durable while the
  blobs it names are not. The pointer is only published after its manifests and
  blocks are written, so an ordinary process crash is safe; a hard power cut can
  require a republish. This is documented rather than hidden.
- Memory use for store reads is bounded by the format itself, independent of what
  is on disk. A hostile store can still make a read fail, but not make the reader
  allocate without bound.
- Writing through a symlink (for example a dotfile link chosen as `--out`) now
  needs `--force` or the real path. That is the deliberate cost of never writing
  somewhere the user did not name; the error says so.
- `verify` reads the whole share, so it costs one full pass. It is not run
  automatically on every open; it is pointed at a store whose provenance is in
  question.
- A folder that contains the store can no longer be published with that store.
  The default store is `./skipta-store`, so `skipta publish .` in a folder that
  already has one now fails with an instruction to pass `--store` elsewhere.
  This is the intended behaviour: the alternative is publishing a signing seed.
- This is not a format change and needs no new test vectors. The store remains a
  local stand-in for the swarm; when transport arrives, the same caps belong in
  the peer client.
