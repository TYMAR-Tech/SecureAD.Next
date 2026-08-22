# Who is who

**Area.** How the product turns an identifier into a principal a person recognises, and how it keeps
track of who is who across domains and across time. Every permission names a trustee by identifier;
this is what stands between that and a readable answer.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Each line links the record that decided it. A record with `Status: Accepted` is the product's
position; nothing on this page overrides one, and where this page and a record disagree the record
wins and the disagreement is a finding.

| The product… | Decided by |
|---|---|
| keeps Tier 0 and expected-administrator as two separate sets, because they answer different questions | [`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) |
| captures the identity attributes needed to name a principal, including SID history | [`0065`](../decisions/0065-the-catalogue-recovers-what-the-rebuild-dropped.md) |
| reads the whole forest, so a principal from any domain in it can be resolved | `0017` |
| never enumerates a foreign forest, so a principal from one cannot be resolved | [`0051`](../decisions/0051-trusts-describe-a-boundary-and-never-widen-a-run.md) |
| stores an object under an identity that survives a rename or a move | [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) |

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for most rows and means unit-tested but not yet exercised against Active Directory -
a test with a synthetic descriptor proves the parser handles those bytes, not that a domain
controller sends them.

**Almost nothing in this area is built.** What exists is the naming machinery that a resolver would
sit on top of; resolution itself has not been written.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| see a readable name taken from a distinguished name | `DnHelperTests.WhenTheDnIsOrdinary_ThenTheFirstRdnValueIsReturnedWithoutItsType` |  |
| be certain a name containing an escaped comma is read correctly rather than split | `DnHelperTests.WhenTheValueContainsAnEscapedComma_ThenItIsUnescapedIntoTheName` |  |
| be certain the container of an object is derived without being fooled by escaping | `DnHelperTests.WhenTheFirstComponentContainsAnEscapedComma_ThenItIsNotTreatedAsASeparator` |  |
| be certain walking up a distinguished name reaches the root and stops | `DnHelperTests.WhenTheParentIsTakenRepeatedly_ThenTheWalkReachesTheRootAndStops` |  |
| read the same account of distinguished-name handling in the document and the code | `DistinguishedNameDocumentationTests` |  |

---

## What has not been discussed

**Nothing here is a plan.** These are questions nobody has answered. If work touches one of them,
stop and ask — do not infer an answer from the old application, from a ledger row, or from the
shape of the code.

**This area has barely been discussed at all.** The list below is the agent's, offered so there is
something to react to, and it is certainly incomplete. The owner has not written this section, and
the right move on reaching this area is to ask rather than to read the list as exhaustive.

- **How an identifier that resolves to nothing is presented.** A permission held by a principal that
  no longer exists is a real and common finding, and the product has no position on it.
- **How a principal from a trusted forest is named**, given that
  [`0051`](../decisions/0051-trusts-describe-a-boundary-and-never-widen-a-run.md) forbids
  enumerating one. The identifier is all there is.
- **What SID history means for identity** — whether a principal carrying another's former identifier
  is treated as one principal or two.
- **Whether a Tier-0 target can be something other than a principal.**
  [`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) names both sets by RID
  and, since 2026-08-22, gives the criterion Microsoft uses — control over the directory, direct or
  indirect. Every member of both sets is a principal. Whether the domain head, a domain
  controller's computer object, `AdminSDHolder` or a policy object linked to the Domain Controllers
  OU can also be a target is undecided, and it decides whether a chain has one kind of endpoint or
  two.
- **Whether well-known identifiers are named from a shipped table**, and what happens when one is
  not in it.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |

---

## Reference — the old application

**Reference only. Nothing here is owed, and a row existing here does not mean it is being built.**

The predecessor resolved principals live against a directory through `LiveSidResolutionService`,
which [`0008`](../decisions/0008-live-verification-is-removed.md) removed from this product. Whatever
resolution this product does must work from captured evidence alone.
