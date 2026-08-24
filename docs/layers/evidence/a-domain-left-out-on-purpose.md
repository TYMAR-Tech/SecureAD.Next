# A domain left out on purpose

**Code:** `next/src/SecureAD.Evidence/AttestedExclusion.cs`
**Layer:** Evidence — why a domain is not in a run, written into the evidence rather than onto a screen.

[`run-identity-and-coverage.md`](run-identity-and-coverage.md) says what a run covered and counts a
domain left out apart from one the run fell short on. This page is the other half of that: **the
statement a person made when the domain was taken out**, and the reason the product refuses to let
those two look alike.

Bound by `AttestedExclusionDocumentationTests`. The `TYPES` table and the `KINDS` table are both
bound in both directions against the code — a kind the enum declares and this page does not name
fails the build, and so does a row naming one that does not exist.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `AttestedExclusion` | One domain left out of a run, and everything stated about its leaving |
| `ExclusionKind` | Whether the operator took the domain out, or the forest named no controller for it |

<!-- TYPES:END -->

This table is the page's claim of ownership, bound in both directions against the public types
`AttestedExclusion.cs` declares.

---

## Two kinds, never merged

`AttestedExclusion.Kind` is which of the two this exclusion is, and it is a closed set of exactly
two because there are exactly two ways a domain leaves a run.

<!-- KINDS:BEGIN -->

| Kind | What it means |
|---|---|
| `ByChoice` | The operator took the domain out of the run |
| `ForWantOfCandidates` | The forest named no writable controller for it, so nothing could read it |

<!-- KINDS:END -->

[`0063`](../../decisions/0063-excluded-never-looks-like-unreachable.md) requires these to be told
apart **wherever they appear**, and this is the place where losing the difference costs most: a
bundle read months later, with no screen and no operator to ask.

They mean opposite things to a reader. *The operator excluded this domain* is a decision somebody
takes responsibility for. *The forest named no controller* is a fact about the directory — an
orphaned cross-reference, a failed demotion — and it is something the customer probably wants to
know about regardless of this audit. A viewer that showed both as "excluded" would hide a broken
domain behind a deliberate choice.

---

## The whole attestation is carried, not a flag

[`0062`](../../decisions/0062-what-an-exclusion-attestation-asks-for.md) settles what is asked for,
and all of it is stored: the reason, the note, the account the run was made under, the person who
authorised it, and when the statement was made.

**An exclusion that governed a run but was not stored with it is a fact about the audit that the
audit does not carry.** The first person to need it is an auditor reading the run months later, with
the operator unavailable and the screen long gone. A bundle that says *eight of nine domains* and
cannot say why is not evidence of anything.

`AttestedExclusion.AttestedUtc` is when the statement was made rather than when the run started,
because [`0059`](../../decisions/0059-an-exclusion-is-attested-once-per-run.md) re-asks every run and
never carries an attestation forward. Two runs a week apart excluding the same domain are two
separate statements by a person, and dating both from the same moment would merge them.

---

## `Reason` is a stable identifier, not a sentence

The wording an operator read on screen may be improved. **What the value means may not change**,
because runs already recorded carry it — the same footing as a rule identifier under
[`0024`](../../decisions/0024-a-rule-identifier-is-permanent.md).

A reason stored as the sentence displayed would make every wording change a silent rewrite of what
past runs claimed, and there is no way to tell afterwards which text a given run actually showed.

`AttestedExclusion.Note` is the opposite and is meant to be: the operator's own words, free text,
carried verbatim and never interpreted.

---

## `AuthorisedBy` is not validated and cannot be

It is a typed string and **a statement of accountability, not an identity**. Nothing that reads it
back may present it as though it had been checked. There is no directory lookup behind it and there
is not meant to be — the person who authorised leaving a domain out of an audit may not be a
principal in the forest being audited, and often is not.

`AttestedExclusion.RunBy` is the opposite: the signed-in account the run was made under, **captured
rather than typed**. One of these two the product knows; the other it has only been told.

---

## The domain name is carried, never derived

`AttestedExclusion.DomainFqdn` is stored beside `AttestedExclusion.NamingContext` rather than
computed from it. Turning `DC=ph,DC=ad,DC=lab` into `ph.ad.lab` by string surgery **invents a name
nobody published**, and is wrong in exactly the forest that renamed a domain — which is the forest
most likely to be audited over a change.

The DNS name is what run coverage is keyed by, so a name invented here would put the exclusion in a
different bucket from the coverage row it belongs to.

---

## What this document cannot tell you

It does not say how an operator is asked for an attestation, or what the wizard refuses to start
without — that belongs to the screen, and the screen has no layer document yet.

It also does not say how an excluded domain is counted. That is
[`run-identity-and-coverage.md`](run-identity-and-coverage.md), which keeps `ExcludedCount` apart
from `ShortfallCount` for the same reason `0063` keeps the two kinds apart here.
