# 0003 - Re-analysis refuses any source that does not demonstrate a complete capture

Date: 2026-08-07
Status: Accepted. The refusal below stands and was re-derived on the seal by
[0021](0021-re-analysis-produces-a-new-bundle.md). This record originally reasoned from an integrity
signature; there is none, per [0020](0020-the-seal-detects-corruption-not-tampering.md) and
[0030](0030-the-product-produces-sealed-evidence-never-signed.md). The Context below is left as
written because that reasoning is how the error entered.

## Context

Re-analysis copies an existing capture and derives fresh analysis over it, without contacting
the directory. The question was what to do when the source capture is torn — cancelled partway,
failed, or carrying no readable run record at all.

The deciding fact is what re-analysis ends with: the new bundle is signed by the integrity
service. Accepting a torn source therefore made the product issue a fresh integrity signature
over evidence that no build ever vouched for. That signature is the strongest claim SecureAD
makes, and it would have been made about a capture that is incomplete by its own record.
**— None of that is so. There is no integrity service, no signature and no key; the bundle carries
a seal that detects corruption, per `0020` and `0030`. The refusal was re-derived on the seal by
`0021` and survives. This paragraph is kept because it is how the error entered.**

An earlier assessment concluded that gating on the source's completeness "would still guard
nothing". That reasoned about the run state in isolation from the signing that consumes it, and
is wrong for this reason. **— The reason given is wrong too; nothing signs. The conclusion the gate
is worth having survives on `0021`'s grounds.**

Coverage does not substitute for the check. Coverage describes the new run, not the source's
integrity, and deriving a denominator from the evidence being re-read would be circular.

## Decision

Re-analysis inspects the source before copying anything and proceeds only for a source whose own
run record demonstrates a completed capture. Everything else is refused, with a message naming
what was observed.

The gate is stated positively — it accepts a demonstrated completion rather than rejecting a
list of known-bad states.

## Consequences

A bundle's seal is only ever written over evidence some build already vouched for.

A user with a torn capture cannot re-analyse it and must recapture. This is intended: the
alternative is a sealed artefact that misrepresents its own provenance.

Stating the gate positively matters because "old" and "unreadable" are indistinguishable to the
inspector — a blanket failure to read the source yields the same answer as a source with no run
table. A negative gate would have admitted the unreadable case by omission. The refusal message
therefore says the state could not be confirmed rather than asserting which it was.
