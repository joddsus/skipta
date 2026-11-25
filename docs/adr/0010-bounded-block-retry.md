# ADR-0010: Bounded per-block retry with backoff

Status: accepted

## Context

The block pipeline treated any error from one block as fatal for the whole
download. In the local store that is acceptable, but a real transport will have
peers that time out, drop connections or briefly lack a block, and failing a
multi-gigabyte download because one request lost a race would be poor behaviour.
Retrying is also the cheap option here: blocks are independently authenticated,
so a retry cannot corrupt anything, and the pipeline already has a natural place
to hide the wait — the failing block's own slot.

## Decision

`FetchOptions` gains two fields:

- `max_attempts` (default 3, valid 1–10): attempts per block, including the
  first. `1` disables retrying.
- `backoff` (default 25 ms, valid 0–60 s): wait before the first retry, doubled
  for each further attempt, capped at 60 s.

The retry loop lives inside the task that produces a block's bytes, in
`fetch_blocks`:

- Only `NotFound` and `StoreIo` are retried. They mean "this attempt did not get
  the bytes". `AuthFailed`, `SizeMismatch` and format errors are permanent: the
  same request will return the same bad data, so they surface immediately.
- Retries do not wrap the pipeline, only the single fetch call, so futures still
  resolve in launch order and output remains in ascending block order.
- Because a retry stays inside its own future, the resume sink sees either the
  block's bytes or the final error, exactly as before. A block that exhausts its
  attempts raises the last error, `download_file` checkpoints, and the partial
  file stays resumable.
- Non-`Error` exceptions are not retried.

## Consequences

- A transient failure on one block costs `backoff + 2·backoff + …` of latency but
  does not fail the download, and no other block is re-fetched.
- A slot is held while its block backs off, so with `max_in_flight = N` a flaky
  store can temporarily reduce throughput to N-1. That is the intended bound:
  retries never add concurrency or memory.
- Worst case latency for one block is bounded by the sum of the capped waits
  (25 + 50 + 100 … ms for the default three attempts), never an unbounded loop.
- Retrying `NotFound` costs two extra attempts before a genuinely missing block
  is reported (about 75 ms with the defaults). Tests that simulate a missing
  block therefore take slightly longer but observe the same error code.
- **No jitter.** Many readers retrying in lockstep after a shared outage will
  synchronise their retries. That is acceptable for a local store and cheap to
  add once a real transport exists; it is recorded here rather than guessed at.
- There is no total retry budget across a download and no per-peer circuit
  breaker; those belong to the transport phase.
- No CLI flag yet: the defaults apply to `get` and to every file of a directory
  download, and the per-file resume state makes even a fully failed block
  recoverable on the next run.

## Tests

`tests/test_retry.cpp` fetches a three-block file whose middle block throws
`StoreIo` twice and then succeeds: the output is byte-identical to the source, in
block order, and the attempts per block are `1, 3, 1`. It also checks that a
block failing every time stops after `max_attempts` with `NotFound`, that
`AuthFailed` is attempted once even with `max_attempts = 5`, that
`max_attempts = 1` fetches once, that a 2 ms backoff actually waits at least
2 + 4 ms, and that out-of-range options are rejected with `BadOptions`.
