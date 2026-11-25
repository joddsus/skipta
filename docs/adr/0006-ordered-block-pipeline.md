# ADR-0006: Ordered, bounded block fetching

Status: accepted (simplified after review; supersedes the first version of this ADR)

## Context

Phase 4 wants ranged and streaming fetch with piece prioritisation. Reading
block by block is fine against a local store but is one round trip per 64 KiB
over a real transport. Concurrency and output order pull against each other: the
fastest way to fetch is unordered, the only correct way to write is ordered.
Memory must stay bounded no matter how large the file is.

## Decision

`fetch_blocks()` — and therefore `fetch_file_range`, `fetch_file` and the CLI —
uses an ordered ring of futures:

```cpp
std::deque<std::future<Bytes>> in_flight;        // at most `window` entries
// launch first_block .. first_block+window-1, then:
plain = in_flight.front().get();                 // oldest submission first
in_flight.pop_front();
emit(plain, index);                              // write, in byte order
if (next <= last_block) in_flight.push_back(launch(next));
```

- **Order is structural.** Futures are created in ascending block order and
  consumed in that order, so a fast later block waits in its future while an
  earlier slow one finishes. No completion-order buffering, no whole file in
  memory.
- **One knob.** `FetchOptions::max_in_flight` (default 4, valid 1..32) is both the
  concurrency and the prefetch depth, because the ring is kept full. It is also
  the hard memory bound: at most `window` plaintext blocks exist at once
  (≤ `max_in_flight` × 64 KiB). The earlier design had separate `workers` and
  `readahead_blocks`, but the two could not be observed independently — prefetch
  beyond concurrency was only extra memory.
- **No threads when one block is in flight.** If `window == 1` (serial mode, or a
  range inside a single block) the task is launched with `std::launch::deferred`
  and runs inline on `get()`. One code path, zero threads for the common
  header-read case.
- **Only overlapping blocks are submitted.** A range starting in block 2 never
  fetches block 0 (regression-tested).
- **Errors abort the fetch.** `future::get()` rethrows the original exception, so
  the error code survives; already-written blocks stay written, nothing is
  emitted out of order or from a failed block.
- **`BlockFetcher` is the seam.** `fetch_blocks` takes
  `std::function<Bytes(uint64_t)>`, so the transport phase can plug in network
  reads without touching this logic, and tests can supply synthetic blocks with
  artificial delays.

This replaced a hand-rolled pool (mutex, two condition variables, index deque,
ready map, `exception_ptr`, stop flag, `request`/`take` protocol): ~80 lines of
concurrency machinery whose ordering guarantee was the same but harder to see,
and which had already produced one real bug (submission started at block 0
instead of the first block of the range).

Whole-block decryption is unavoidable: AEAD authenticates a block as a unit, so
a 1-byte read still decrypts its 64 KiB block. `FileStore` reads are stateless,
so they are safe from multiple threads.

## Consequences

- Large files are no longer fetched serially, memory stays bounded regardless of
  file size, and streaming to stdout stays ordered.
- `std::async(launch::async)` starts one thread per in-flight block instead of
  reusing a pool. At the default of 4 and with blocks of 64 KiB this is noise
  next to I/O; a pool can return if thread churn ever shows up in a profile.
- Thread creation can fail (`std::system_error`) under severe resource
  exhaustion; that propagates to the caller rather than being masked. Not
  specially handled.
- Not implemented: retries/hedged requests, adaptive concurrency, cancellation
  on consumer abort, per-peer scheduling. Cancellation today means "throw and
  tear down": remaining async futures are joined as the ring is destroyed.

## Tests

`tests/test_pipeline.cpp` covers: parallel reads stay ordered (block content
encodes its index), reverse completion order still yields ascending output, a
range across blocks stays ordered, a window of 2 never exceeds two blocks in
flight, `max_in_flight == 1` never overlaps, a failing block aborts with its own
error code, a wrong-length block is refused, and invalid option values are
rejected. The suite is run repeatedly to catch timing flakes. The store-level
test that deletes a non-overlapping block still proves that ranges read only
what they overlap.
