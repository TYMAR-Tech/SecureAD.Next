# 0021 - Re-analysis produces a new bundle and never alters the one it read

Date: 2026-08-12
Status: Accepted

## Context

Re-analysis runs the derived analysis and the rules against a capture already on disk, without
reconnecting to Active Directory. It is how an improved rule catalogue reaches a forest that has
already been read.

It was removed on 2026-08-12 on the grounds that it re-sealed the bundle, so a re-analysed bundle
could no longer prove what it was at capture. That was wrong. It came from a summary rather than from
the implementation, which copies the source into a **new** run bundle and analyses the copy. The
original and its seal are never touched.

Removing it would have meant that improving a rule required reading a customer's forest again -
hours of LDAP against production to answer a question the evidence already contains, and the one
stage of this product that cannot be redone cheaply.

## Decision

**Re-analysis stays, and produces a new bundle.** It reads the source, copies it, analyses the copy,
and seals the copy. The source is opened read-only and is never written.

The new bundle records where it came from: the source it read, when that source was captured, and
that it reused a capture rather than performing one.

**A re-analysis declares nothing and discovers nothing.** It inherited its domain set rather than
choosing one, so it makes no coverage claim. Taking the source's own captured domains as a declared
set would manufacture a coverage claim out of the evidence being re-read, which is the circularity
[`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md) exists to prevent. Its coverage identity
is therefore absent, and two absent coverage identities are not a match.

**The source's seal is verified before it is read, and a failure warns rather than refuses.** Per
[`0020`](0020-the-seal-detects-corruption-not-tampering.md) the seal detects corruption, and
re-analysing a corrupted capture is a decision an operator is entitled to make knowingly. The source
must still demonstrate a completed capture, which `0003` already requires and which is not relaxed.

## Consequences

A re-analysed bundle costs a second copy on disk, which is what it always cost.

Two artefacts exist where there was one, and each can say what it is. That is the point: a bundle
that has been re-analysed and a bundle straight from capture are different kinds of evidence, and
the customer holding one can tell which they have.

Adding a metric or a rule later does not leave a permanent gap in a customer's history. Old sealed
captures can be re-analysed to produce the new output, computed from the original evidence.

Verification of a source moves to the single place a bundle is opened, rather than being the
responsibility of whatever happens to be reading. In the implementation being replaced, verification
was called from exactly one place - a view model - so the guarantee depended on a screen being
shown.
