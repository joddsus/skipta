# ADR-0004: Transport spike plan (decision pending measurements)

Status: **proposed, not measured.** No numbers exist yet; nothing was run.

## Context

Spec §7 prefers reusing a mature transfer engine:

- **Option A:** libtorrent-rasterbar (or a Rust equivalent) with our encrypted
  layer and optionally a private tracker. Strong for many strangers, public
  swarms, and it is the C++ choice that matches this codebase.
- **Option B:** authenticated peer connections between known devices (Iroh or
  similar). Better fit for closed groups; unclear with many unknown peers.

Gates from the spec, all to be measured on real machines including Haiku:
builds on Haiku; time from link to first directory listing (cold and cached);
streaming a large file; NAT behaviour on typical home networks.

## Why this ADR has no result yet

The spike cannot be run honestly in the development environment this code was
written in: there is no libtorrent build, no Haiku machine, and no representative
home NAT. Claiming numbers from a container would be fiction. The harness and the
protocol are in `spike/`, and `spike/RESULTS.md` is the table to fill.

## Decision (to be recorded here after the spike)

To be filled with: chosen engine, version, the measured numbers, and the
reasoning. Until then the core stays transport-agnostic: `libskipta` exposes
blocks, sealed manifests and signed pointers, and knows nothing about swarms.

## Gate definitions

| Gate | Pass condition |
|---|---|
| G1 Builds on Haiku | Library builds; client starts; a share is listed. Record compiler and libtorrent version. |
| G2 Cold link → listing | < 5 s on a home connection for a 100-entry root manifest, single seed. |
| G3 Cached listing | < 100 ms with the manifest cached on disk. |
| G4 Large-file streaming | 1 GiB file, first bytes playable < 3 s; > 5 MiB/s sustained between two home peers. |
| G5 NAT | Works behind a typical home router without manual port forwarding, or documents that UPnP/NAT-PMP/relay is required. |
| G6 Private swarm only | No DHT or public tracker contact for a private share (optionally verified by packet capture). |

## Constraints carried into the spike

- Only `swarm_salt`/`swarm_id` from a link may be published to a tracker or DHT;
  the drive key never leaves the link.
- Seeding is opt-in, with rate and disk limits (spec T8).
- The engine must not be exposed in the public API of `libskipta`; transport is a
  `skiptad` concern.
