# Spike A: libtorrent-rasterbar

**This harness has not been compiled or run.** The development environment has
no libtorrent and is not a representative machine (no Haiku, no home NAT). Treat
`main.cpp` as a skeleton: expect to adjust it to the installed libtorrent minor
version, then measure and fill `../RESULTS.md`.

## What it measures

Two sessions in one process, loopback only:

1. Build a torrent from a generated directory (one 64 KiB manifest-like file and
   one large payload file).
2. Seed it in session 1 (private torrent: no DHT, no public tracker).
3. Add a **magnet link** in session 2 and time:
   - `metadata_ms` — magnet to torrent metadata (the "cold link" start),
   - `first_bytes_ms` — magnet to the first payload bytes,
   - `throughput_kib_s` — bytes over a short window after the first block,
   - `session_start_ms` — process start to session ready.
4. Print one JSON object per run so results can be pasted into `../RESULTS.md`.

Loopback numbers are an upper bound on goodness: they exclude NAT, loss and
real peers. G5 must be measured between two machines on home networks.

## Build and run

```sh
# Debian/Ubuntu: apt install libtorrent-rasterbar-dev
make                       # needs pkg-config libtorrent-rasterbar
./spike_a data/testdir 256 # seed dir, payload size in MiB
```

On Haiku, build libtorrent from source first, then point `PKG_CONFIG_PATH` at it.

## What this spike still cannot answer

- NAT traversal (needs two machines, G5).
- Whether a private tracker is acceptable for the first group (owner question).
- Interaction with our encrypted layer: this measures the engine, not the
  Skipta metadata path. Once the format is wired to a real engine, re-measure
  G2/G3 through sealed manifests.
