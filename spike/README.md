# Transport spikes

Spec §7 asks for a spike comparing two engines before the swarm transport is
written. (A small read-only HTTP store transport now exists under ADR-0017; it
is not the swarm and does not replace this decision.)

- **A: libtorrent-rasterbar** — mature swarm transport, C++, works with the
  private-tracker model. Harness: [`a_libtorrent/`](a_libtorrent/README.md).
- **B: Iroh** — authenticated peer connections between known devices. Protocol:
  [`b_iroh/`](b_iroh/README.md).

**Nothing has been measured.** The environment this code was written in has no
libtorrent, no Haiku and no representative home network, so producing numbers
would be dishonest. The harness (A) and the measurement protocol (B) are here,
and [`RESULTS.md`](RESULTS.md) is the blank table to fill on real machines.

## Rules while spiking

- Throwaway code. Nothing in `spike/` may be linked into `libskipta` or
  `skiptad`; the transport must stay behind `skiptad`'s API.
- Only `swarm_salt`/`swarm_id` derived from a link may be announced; the drive
  key never is (see `docs/format-v1.md` §6).
- Measure the same gates on every OS you intend to support, including Haiku.
- Record machine, versions and network alongside every number.

Fill `RESULTS.md`, paste the table into `docs/adr/0004-transport-spike-plan.md`,
and only then recommend an engine.
