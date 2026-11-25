# ADR-0003: Strict JSON for metadata, and what "untrusted" means here

Status: accepted

## Context

Spec §8: all metadata from the network is hostile; sanitise paths, hard limits,
fuzz the parsers. JSON parsers in particular disagree about duplicate keys and
nesting depth, which is a classic parser-difference vulnerability.

## Decision

1. All metadata (manifests, pointers, links, key-wrap blobs) is JSON, parsed
   through `skipta::jsonx::parse_strict`, which:
   - enforces a byte limit before parsing,
   - rejects duplicate object keys (`DuplicateKey`) instead of keeping the last,
   - rejects nesting deeper than 64 (`TooDeep`),
   - rejects unknown fields per structure (`UnknownField`), so a v1 reader can
     never silently ignore a field that changes meaning,
   - returns typed values only (`req_string`/`req_uint`/`req_b64`), refusing
     negative or fractional numbers for sizes and offsets.
2. Byte strings are URL-safe base64 without padding, decoded strictly (no
   padding, no whitespace, no trailing data) with libsodium's decoder.
3. Names/paths go through `validate_name` / `validate_relative_path`
   independently of JSON, so the same rules apply to a browser path, a link, or a
   filesystem write later.
4. Signatures cover raw bytes, not a canonical form, so JSON canonicalisation is
   never security-relevant. Ordering inside our own serializer is stable, which
   is why test vectors can pin it.

## Consequences

- Forward compatibility is intentionally absent: a v1 client rejects a future
  field instead of guessing. New fields therefore require a version bump, which
  is the intended cost of strictness.
- Signing raw bytes means a signed blob must be transported as opaque bytes
  (`SignedPointer::pointer`); re-encoding it would break verification. The wire
  form (`encode_signed_pointer`) preserves them as base64.
- Deeply nested hostile JSON is bounded by the nesting cap and the byte cap,
  not by the parser's own stack behaviour.
