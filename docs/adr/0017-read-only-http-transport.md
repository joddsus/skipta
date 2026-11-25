# 0017 — Read-only HTTP store transport

Status: accepted (minimal transport, not the swarm)

## Context

Through ADR-0005 and ADR-0016 the app is complete over a local blob directory:
publish writes sealed blocks, sealed manifests and a signed pointer, and a link
can be browsed, fetched, resumed, verified and collected. The missing piece for
actually sharing a folder is a way for a reader on another machine to reach
those objects. The spec's real transport (ADR-0004) is a libtorrent/Iroh swarm
that has not been measured. Shipping that now would mean choosing an engine
without the numbers the spec asks for, and linking a large dependency that does
not build in this environment.

At the same time, the object layer is already a complete, authenticated
end-to-end format: everything a peer exchanges is opaque ciphertext plus a
signed pointer. A transport does not need to be trusted, only to move bytes.

## Decision

Add a deliberately small read-only HTTP transport:

- `skipta serve --store DIR [--listen [host:]port]` runs a single-threaded
  HTTP/1.x server that answers `GET` for exactly three object name shapes:
  `/pointers/<64 hex>.ptr`, `/manifests/<32 hex>.mf` and
  `/blocks/<32 hex>/<digits>.blk`. It never lists directories, never writes,
  never follows a symlink in any component below the store root, refuses
  non-regular files, refuses objects above the format's caps, and answers
  everything else with 400/404/405 (408 for a slow header, 500 for a local
  object it refuses to serve). A request header must arrive within 10 s and is
  capped at 8 KiB. `--listen` defaults to `127.0.0.1`.
- `FileStore(root, "http://host:port[/prefix]")` is a read-through cache: a
  missing local object is fetched over HTTP, written atomically into the local
  store/cache, and returned. Cached objects are used without the network. The
  cache also holds `<cache>/accepted/<drive>.seq`, so the rollback guard works
  across runs. `list`, `get` and `verify` accept such a store through `--store`
  and a cache directory through `--cache` (`$SKIPTA_CACHE`, else
  `./skipta-cache`).
- The client speaks HTTP/1.0 and HTTP/1.1 over a bounded connection, rejects
  chunked transfer encoding, redirects, conflicting or oversized
  `Content-Length`,   malformed status lines and bodies over the format caps, and
  applies connect and read timeouts plus an absolute 60 s deadline per object.
  `https://` is refused with an explanation instead of silently treating it as
  a path.
- Writes are local-only. `publish`, `passwd`, `gc` and `serve` reject an
  `http://` store, and `FileStore::put_*` refuses a remote store. Publishing
  over the network would give a remote party write access to a drive's object
  set, which is not needed for sharing and is not part of this decision.

Object bytes remain end-to-end authenticated: the origin is untrusted exactly
like a copied local store (ADR-0016). It can withhold or replay objects and
observe object names, sizes and timing; it cannot forge, alter or decrypt
content, and it never receives a key or plaintext. A cached object is never
trusted because it is cached; it is decrypted and authenticated on every read.

## Consequences

- Two machines on a trusted network can share a folder for real: the publisher
  runs `serve`, the reader uses the link and the origin. The reader can later
  open the share from its cache without the publisher.
- The transport is not confidential at the network layer. Anyone on the path
  sees which opaque object names are requested, their sizes and timing. An
  active attacker can cause a download to fail or serve stale objects; the
  accepted-seq guard catches a rollback below what this cache already accepted,
  but first contact has no pinned seq (documented in ADR-0008).
- Reachability is not access. Without the link, a peer cannot decrypt content;
  the pointer object name is the drive public key, which is already in the link,
  and manifest/block ids require opening authenticated manifests. There is no
  directory listing and no name oracle beyond "this opaque id exists".
- The server handles one connection at a time. A slow client can delay others
  for the socket timeout, and parallel block fetches queue. That is acceptable
  for a personal LAN share behind a VPN; a busy or hostile network needs a
  real reverse proxy, which also terminates TLS. Do not bind `0.0.0.0` on an
  untrusted network.
- The cache grows with what was fetched and is not garbage-collected; delete
  the cache directory (or point `--cache` at a fresh one) to reclaim it.
- This does not replace the swarm spike. It is a working, reviewable transport
  that uses the same `BlockFetcher`/`FileStore` seam the swarm will use, with no
  new dependency, so the format and safety work stays valid when a swarm engine
  is chosen from measured results.
