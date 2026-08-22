# 0080 - A finding carries typed evidence, not a free-form blob

Date: 2026-08-21
Status: Accepted

Sits under [0023](0023-a-finding-has-a-stable-identity.md), which decides what identifies a
finding. This decides what it carries beyond that.

## Context

The predecessor's finding record ended in `ContextJson`, a schemaless string with an informally
reserved key namespace. Three separate components read keys out of it that no type declared:
enrichment put display names there, the action report recovered edge identity from it, and the
provenance of a privileged principal travelled in it.

The failure was not theoretical. The helper that recovered edge identity parsed the blob and
swallowed every exception, so a malformed value silently downgraded an edge action to a principal
action with no diagnostic at all. The predecessor's own review named typing this field as a change
it would make, on the grounds that it "would remove an entire class of silent failure".

## Decision

**A finding carries a typed evidence record, and its shape is determined by the kind of finding.**

**There is no free-form context field.** A producer that has a value names it; a reader that needs
one takes it from a declared member. Nothing reads a key that no type declares.

## Consequences

**A new kind of finding costs a type.** That is the price of the decision and it is paid up front,
where it is visible, rather than at the third reader of an undeclared key.

**A malformed evidence record fails where it is built**, not three components downstream. The
failure mode this replaces was silent and produced a wrong answer rather than an error.

**Display, export and comparison read declared members**, so a rename is a compile error rather
than a value that quietly stops appearing on a screen.

**It forbids** putting a value on a finding without deciding where it belongs. That is the whole
point: the blob was convenient precisely because it deferred that decision indefinitely.
