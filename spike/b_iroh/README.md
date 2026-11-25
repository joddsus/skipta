# Spike B: Iroh (authenticated peers)

Status: **protocol only, no code.** Iroh is Rust, and the measured harness has to
run on the real machines (including Haiku). Writing unreviewed Rust here would
add a second toolchain to the repo for throwaway code; if the owner prefers that,
it can be a `spike/b_iroh/` cargo project instead.

## What to build on the measurement machine

A two-node harness with `iroh` + `iroh-blobs` (pin the versions you test):

1. Node A imports the same generated tree as spike A (`manifest/root.bin` ~4 KiB,
   `payload/large.bin` N MiB) as a blob collection and prints its ticket/link.
2. Node B opens the ticket and records the same three timestamps as spike A:
   ticket → first metadata, ticket → first payload byte, then throughput over 5 s.
3. Repeat with the nodes on different networks (home NAT on both sides) for G5.
4. Repeat on Haiku: confirm the daemon builds and a ticket is readable there.

## Why B is still a candidate

- Closed groups (Agder EDB) with known devices get authenticated connections
  without a tracker, which is closer to the spec's group model.
- No swarm exposure at all: nothing is announced anywhere.
- Weak for public mode, which the spec says matters ("leaning towards A").
  That asymmetry is exactly what the spike should quantify.

## Extra gate specific to B

| Gate | Pass condition |
|---|---|
| G7 many unknown peers | one publisher, 20+ readers on mixed OSes, each gets a listing in < 5 s; record whether relay is needed |

Record everything in `../RESULTS.md`, then fill ADR-0004.
