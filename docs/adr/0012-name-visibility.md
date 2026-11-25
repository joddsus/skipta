# ADR-0012: Names may not contain invisible or text-reordering characters

Status: accepted

## Context

Entry names come from the publisher and are printed by `skipta list`, `get` and
`verify`. The existing validator rejected empty names, `.`/`..`, separators, C0
controls, DEL, trailing dots/spaces, Windows device names and invalid UTF-8. It
still allowed:

- C1 controls (U+0080..U+009F), which some terminals interpret as commands;
- bidi embeddings, overrides and isolates (U+202A..U+202E, U+2066..U+206F) and
  directional marks (U+200E/U+200F, U+061C), which reorder the text around them,
  so `pay<U+202E>fdp.exe` is displayed as `payexe.pdf`;
- zero-width and invisible characters (U+200B..U+200D, U+2060..U+2064, U+FEFF,
  U+FFF9..U+FFFB), so two different entries can look identical;
- line and paragraph separators (U+2028/U+2029), which break the line structure
  of a listing.

The publisher is the party whose names a reader must interpret, so this is a
phishing and confusion vector, not a rendering nicety.

## Decision

`validate_name()` decodes each UTF-8 code point and rejects the ranges above with
`UnsafeChar`. The rule is enforced on write (`add_file`, `add_directory`) and on
parse (`Manifest::parse`), like every other name rule, so a hostile manifest
cannot smuggle them in either.

Everything else stays accepted: non-ASCII letters, CJK, emoji, combining marks
and ordinary punctuation are legitimate file names. The format version does not
change; no byte layout, tag or KDF input is touched.

## Consequences

- A listing can be read as it is written: no name can hide, reorder or overwrite
  terminal text.
- Legitimate names containing those code points are now refused when a folder is
  published, with an error naming the character. Such names are vanishingly rare
  and cannot be typed by accident; renaming is the fix.
- A share published before this rule with such a name will not parse. There are
  no released shares, and the strictness matches the format's existing
  "unknown fields are rejected" stance.
- Fuzzy matching of names ("the file that looks like report.pdf") becomes
  dependable, and case-fold collisions remain the only near-duplicate rule.
