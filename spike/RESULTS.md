# Transport spike results

Status: **empty on purpose.** No measurement has been taken. Do not record
numbers you did not measure on real hardware; the ADR decision depends on them.

Copy this table into `docs/adr/0004-transport-spike-plan.md` once filled, then
change its status.

## Machine and network under test

| Field | Value |
|---|---|
| OS / version | |
| CPU / RAM | |
| Compiler | |
| libtorrent / Iroh version | |
| Network (link speed, router, NAT type) | |

## Option A — libtorrent-rasterbar

| Gate | Target | A: result | Notes |
|---|---|---|---|
| G1 builds on Haiku | builds and starts | | |
| G2 cold link → listing | < 5 s | | |
| G3 cached listing | < 100 ms | | |
| G4 1 GiB streaming | first bytes < 3 s, > 5 MiB/s | | |
| G5 NAT without port forwarding | works or documented | | |
| G6 private swarm: no DHT/public tracker | verified | | |

## Option B — Iroh (authenticated peers)

| Gate | Target | B: result | Notes |
|---|---|---|---|
| G1 builds on Haiku | builds and starts | | |
| G2 cold link → listing | < 5 s | | |
| G3 cached listing | < 100 ms | | |
| G4 1 GiB streaming | first bytes < 3 s, > 5 MiB/s | | |
| G5 NAT without port forwarding | works or documented | | |
| G6 closed group: only invited peers | verified | | |

## Decision

Chosen option: _(none yet — see ADR-0004)_
