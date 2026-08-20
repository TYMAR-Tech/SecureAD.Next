# 0030 - The product produces sealed evidence, never signed

Date: 2026-08-12
Status: Accepted

Withdraws the word *signed* from [`0003`](0003-refuse-to-reanalyse-an-incomplete-capture.md),
[`0004`](0004-unknown-counts-name-the-failed-phase.md),
[`0009`](0009-greenfield-in-place-with-the-bundle-as-seam.md),
[`0015`](0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) and
[`0017`](0017-capture-reads-the-whole-forest.md). Every decision in those records stands; only the
word changes.

## Context

[`0020`](0020-the-seal-detects-corruption-not-tampering.md) established what the seal is. It adds up
the bytes of the evidence file into one number and writes that number beside it, so a file that
changed no longer matches. There is no key anywhere in this product, so it proves the bytes have not
changed and proves nothing about who produced them. [`0019`](0019-the-bundle-carries-a-seal.md) said
the same in one sentence - *"It is called a seal and not a signature, because it is not one"* - and
`0019` carries a supersession marker, so a reader is told to move past it.

The word did not move with the mechanism. Five accepted records still call the bundle signed, and
one of them is the product's own identity sentence: `0009` describes SecureAD as *"a forest-wide
security audit producing signed, point-in-time evidence."* `0003` rests its entire refusal on *"an
integrity signature"* which it calls *"the strongest claim SecureAD makes."* `0017` forbids *"a
scoped signature."*

Two slice documents put the claim in front of a customer. `S-7` and `S-8` both read *"A bundle is
signed, exportable, and forwarded by customers to auditors and insurers."* An auditor or an insurer
reading *signed* understands cryptographic provenance - proof the artefact came from this product
and from nobody else. The product cannot offer that, and per `0020` will not unless a customer asks.

This was found by reading every decision record against every other on 2026-08-12. Nothing caught it
before: each record was coherent, and the contradiction lived between them.

## Decision

**The product produces sealed evidence. It never describes evidence, a bundle or an artefact as
signed.**

The identity sentence is *a forest-wide security audit producing sealed, point-in-time evidence*.

*Signed* and *signature* are reserved for what they mean. They may be used about LDAP connection
security, where a signed bind is a real cryptographic property established by the SASL layer per
[`0018`](0018-connection-security-is-an-ordered-ladder.md), and they may be used about the
certificate-based signing `0020` leaves open. They may not be used about a bundle.

**The five records are corrected in place**, per
[`0032`](0032-a-decision-record-is-corrected-in-place.md): the word is fixed where it appears in
each `## Decision` section, and each `## Context` section keeps its reasoning with the superseded
claim marked inline. When this record was first written the treatment was a note on each status
line, which `0032` replaced the same day - a correction at the top of a file is invisible to a
reader arriving by `git grep`, which is how these records are most often read.

## Consequences

Every decision in the five records survives. `0003` refuses a torn source for the same reason it
always did - [`0021`](0021-re-analysis-produces-a-new-bundle.md) already re-derived that refusal on
the seal rather than on a signature - and `0017` still forbids a scoped bundle, because a scoped
artefact carrying this product's name and clean by omission is the failure whether it is sealed or
signed.

The strongest claim the product makes about an artefact is weaker than the documentation said, and
it is the claim an insurer is most likely to ask about. That is the cost, and it is paid because the
alternative is a claim the product cannot honour.

Certificate-based signing remains open on `0020`'s terms. Adopting it later requires a new record
and changes what may be claimed; it does not require renaming anything, because *seal* and
*signature* would then name two different things that both exist.

A word that survives the mechanism it described is the failure mode worth noticing here. The
mechanism was corrected in one record and the vocabulary travelled on, unremarked, through four
others and into two customer-facing documents.
