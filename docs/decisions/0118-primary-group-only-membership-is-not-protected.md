# 0118 - Primary-group-only membership does not carry AdminSDHolder protection, lab-verified

Date: 2026-09-11
Status: Accepted.

The owner accepted this on 2026-09-11, having read the observation and judged that the forest's other
two domains would answer the same way. It unblocks `AC-64` on the strength of a laboratory
observation rather than a Microsoft citation, which is the weaker of the two routes `AC-64` itself
permits. It changes what SecureAD asserts about domain-controller computer accounts. It does not
authorize live access, a capture change, a UI change, or any widening of the Tier-0 definition.

**Only `ba.ad.lab` was observed, and it holds one domain controller.** The record below recommended
running `ad.lab` and `ph.ad.lab` as well; the owner declined, judging the answer settled. That is his
call to make and it is recorded here rather than left implicit, because the evidence behind this
decision is one account in one domain and a reader a year from now must not mistake it for three.

## Why

`ProtectedPrincipalClosure.WalkPrimaryGroups` marks a principal `Unknown` when its only route to a
protected group runs through a `primaryGroupID` edge. The reasoning is recorded in
[`adminsdholder-catalogue-semantics.md`](../layers/derivation/adminsdholder-catalogue-semantics.md)
§ 6.3: Microsoft establishes that `primaryGroupID` **is** membership and that authorization honours
it, and establishes nothing at all about whether AdminSDHolder's protected-member enumeration follows
the same edge. Refusing to guess was correct.

**The refusal has a customer-visible cost, and it lands on the worst possible object.** A writable
domain controller's computer account normally carries `primaryGroupID` 516, and the `Domain
Controllers` group normally holds no explicit `member` entries for it — so the primary-group edge is
the only route. `SEC-031` and `SEC-032` both refuse an object whose protection status is unknown,
which means **the ownership question goes unanswered for every domain controller in the forest**: the
one class of machine account where a non-administrative owner would matter most. The laboratory run
`ad.lab-20260910-050319` produced exactly this, three unknown principals for three domains, and
`adminsdholder-catalogue-implementation.md` predicted it in advance.

`AC-64` names two ways out: a Microsoft protocol citation showing primary-group membership
participating in protected-group evaluation, or a lab observation recorded and labelled as
lab-verified rather than specified.

**The citation route was re-checked on 2026-09-11 and remains closed.** Appendix C, *Reducing the
Active Directory Attack Surface* and MS-ADA3 `primaryGroupID` were read again. Every one confirms
that `Domain Controllers` is a protected group; not one states which routes SDProp walks to find its
members. Those are different questions, and taking the first as an answer to the second is the
closed-loop-anchored-to-the-wrong-reference shape recorded as `F-S44-2`.

## The observation

Produced by [`tools/Observe-Ac64PrimaryGroupTraversal.ps1`](../../tools/Observe-Ac64PrimaryGroupTraversal.ps1)
against `ba.ad.lab` on 2026-09-10 07:15:35Z, PDC emulator `BADC.ba.ad.lab`, under PowerShell 7.6.5.
Read-only LDAP throughout.

SDProp leaves two fingerprints on what it stamps: `adminCount = 1`, and a DACL that refuses to
inherit. Both are read together, because `adminCount` alone persists after a principal leaves a
protected group and says nothing about the live state.

| Subject | `adminCount` | Refuses inheritance | Stamped |
|---|---|---|---|
| Domain Admins — *positive control* | 1 | yes | **yes** |
| Domain Users — *negative control* | not set | no | no |
| **Domain Controllers (the group)** | 1 | yes | **yes** |
| **BADC (the DC computer account)** | not set | no | **no** |
| BAMS1, BA2016, BAWK1 — ordinary computers | not set | no | no |

Supporting facts recorded in the same run: `Domain Controllers` holds **zero** explicit `member`
entries, so the primary-group edge is the only route into it; `dSHeuristics` is unset, so nothing is
excluded from protection; and the `BADC` account is 12,990 hours old, far beyond any SDProp cycle.

**The group is protected. SDProp is demonstrably running in this domain. The only route in is
`primaryGroupID`. The account has existed for eighteen months. It carries neither fingerprint, and is
indistinguishable from an unprotected workstation.**

### What makes this evidence rather than a green tick

The first two runs of this script, on 2026-09-10, reported a passing negative control that had never
executed: the call site piped into a function whose parameter lacked `ValueFromPipeline`, `$null`
bound silently, and `Stamped = False` was computed from no data. It printed a verdict anyway. That is
a check passing while measuring nothing — the failure `docs/next/README.md` puts first — and it
survived two runs because the line it printed looked exactly like a control that had passed.

The script now carries `DescriptorRead` beside `Stamped` rather than folding one into the other, and
**any unread descriptor voids the run and names the object**. It also checks that `Domain
Controllers` is itself stamped, and that at least one domain-controller account was found, because an
unstamped group and an empty result set both previously reached the same conclusion as a genuine
negative. The gates can fail, and two of them did.

## Decision

Primary-group-only membership does not carry AdminSDHolder protection. A principal whose sole route
to a protected root is a `primaryGroupID` edge is `NotProtected`, not `Unknown`.

**The answer is labelled lab-verified, and the label is load-bearing.** It is recorded in the
catalogue as an observation of one forest on one Windows version, distinguishable at any later date
from a claim Microsoft states. `CatalogueClaimStatus` gains no new member; the provenance
`CatalogueClaimProvenance.LaboratoryObservation` records where the answer came from, so a reader can
tell a measured answer from a cited one without reading this file.

## What this costs if it is wrong

**It understates.** If some forest does stamp its domain controllers through the primary-group edge,
SecureAD would report a protected object as unprotected — and `SEC-031` would report its ownership at
`Low` where `SEC-032` should have reported at `High`. That is the direction that matters most in an
audit tool, and it is the reason this is a decision for the owner rather than an implementation
detail.

Three things bound the risk. The observation is a *negative* with a working *positive* control beside
it, so it is not the absence of evidence. `Domain Controllers` cannot be excluded by `dSHeuristics`,
so the one documented way to change this behaviour is ruled out by measurement rather than by
assumption. And the label keeps the answer downgradeable: a single contradicting forest reverts it to
`Unknown` without disturbing anything else.

**One forest, one domain, one domain controller.** `ba.ad.lab` holds a single DC, so this is one
observation and not three. Running the same script against `ad.lab` and `ph.ad.lab` would strengthen
it at the cost of a few minutes. **The owner declined on 2026-09-11**, judging that the other two
domains would answer the same way, which is very likely true - they are domains of one forest at one
Windows version, so they are three readings of nearly the same thing rather than three independent
tests. The script remains in `tools/` and either domain can be run at any time.

## Consequences

- The primary-group walk is **removed** rather than inverted. A principal reachable only that way
  keeps the `NotProtected` it already carries, so a walk that observed the difference and recorded
  nothing would be a computation no caller reads. `Reachable` loses its `followPrimaryGroups`
  parameter with it: the only remaining caller passed `false`, and a parameter with one possible
  value is a branch nothing exercises. `SchemaOwners` still walks both edge kinds, because ownership
  acceptance is an authorization question and authorization does honour primary groups.
- The three unknown principals per lab run become answered. `SEC-031` and `SEC-032` judge domain
  controllers instead of refusing them, and `P-153` closes.
- **`SEC-030` changes what it reports, and this reaches a customer.** An account carrying
  `adminCount=1` with a DACL still refusing inheritance, reachable only through `primaryGroupID`,
  was previously hidden behind a doubt and is now a finding. That residue is exactly what the rule
  exists to report: AdminSDHolder left it behind and nothing protects the account now.
- `UnresolvedReason.PrimaryGroupRoute` and its wording stay, and so does
  `ProtectionUnknownReason.PrimaryGroupTraversalResearchBlocked`. The second is not optional:
  it is persisted as flag value 1 in every derivation written before schema 13, so removing it would
  make those stores unreadable. That it also happens to be what a reinstatement would need is a
  convenience rather than the reason.
- Catalogue version 2 → 3, recording the changed semantics with
  `CatalogueClaimProvenance.ControlledLabObservation`. Derived results are stamped with the version,
  so a closure records which rule it was judged under.
- Derivation schema 12 → 13. **The layout is byte-identical and that is the point**: this is the
  case `P-149` warns about, where a structural fingerprint cannot see the change. A version 12 store
  holds `Unknown` rows this version would have written as `NotProtected`, so it is refused rather
  than reinterpreted. Re-derive; no migration is offered, because those rows are honest records of
  what the product believed when they were written.
- `AC-64` and § 6.3 are updated to record the observation, its date, and the lab-verified label.
