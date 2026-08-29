# Review — shared AdminSDHolder catalogue semantics

**Reviewed:** 2026-08-28
**Subject:** `docs/layers/derivation/adminsdholder-catalogue-semantics.md`
**Status:** review findings; corrections accepted by decision
[`0089`](../decisions/0089-principal-protection-and-member-propagation-are-separate-claims.md).
**Recommendation after acceptance:** implement the canonical shared model before SEC-030; do not
implement the rule against the current flat Stage 2a model.

---

## Executive summary

The candidate specification is directionally correct and materially safer than the current implementation. Its central design decision — recording **principal protection** separately from **member propagation**, with evidence status per semantic — is required. The existing `ProtectedGroupCatalogue` cannot represent the Microsoft source conflicts or evidence gaps now known.

The review found:

- **3 release-blocking correctness defects** in current Stage 2a behavior or its persisted contract;
- **3 high-severity architecture/evidence gaps** that block canonicalization;
- **4 medium-severity documentation/test-contract defects** that can keep wrong behavior green;
- **several verified strengths** worth preserving.

The most serious current-code findings are:

1. `dwAdminSDExMask` removes operator **group objects themselves** from `IsProtected`, not only member propagation. The Microsoft evidence currently pinned establishes the mask's group assignments and describes protection of members, but does not yet justify changing principal protection and propagation together.
2. Every protected catalogue entry becomes a graph seed. The code therefore equates *this object is protected* with *membership beneath this object propagates protection*, which the candidate specification correctly rejects.
3. An invalid character at `dSHeuristics` position 16 is labeled `DefaultedByAbsence` and treated as complete. The character was present, and Microsoft documents only hexadecimal values as valid; the implementation converts an undocumented value into a clean zero-mask answer.

A further architectural blocker is that the derived protected-principal result is not persisted. `DerivationReader` reads input facts, phase status, size and global completeness, but no `ProtectedPrincipalClosure`. A future rule cannot consume the candidate semantics without a derivation schema and public read-model change.

---

## Architecture map

```text
CapturedAttributeCatalog
    captures dSHeuristics
            |
            v
MembershipNestingPass
    captures graph facts + forest heuristic string
            |
            v
DirectoryHeuristics.AdminSdExclusions
    resolves character 16 into four group names
            |
            v
ProtectedGroupCatalogue.NarrowedBy
    one flat set + edge provenance + mask
            |
            v
ProtectedPrincipalDeriver
    seeds graph traversal from every IsProtected SID
            |
            v
ProtectedPrincipalClosure (memory only)
            |
            x  not persisted / not readable by rules

DerivationWriter / DerivationReader
    persist SID dictionary, principals, direct edges,
    phase outcomes and global completeness only
```

The proposed model requires a different middle and lower half:

```text
CatalogueEntry
    PrincipalProtection: claim + status + provenance
    MemberPropagation:   claim + status + provenance
    Scope
            |
            v
EffectiveMemberPropagation
    catalogue semantics adjusted by forest mask
            |
            v
ProtectedPrincipalEvaluation
    Protected | NotProtected | Unknown
    decisive basis + per-principal unknown reasons
            |
            v
persisted protected-principal result
            |
            v
rule-facing read model
```

---

## Verified strengths

### S-01 — Principal protection and member propagation need separate semantics

**Status:** confirmed design requirement.

The candidate correctly identifies that one flat set cannot express:

- an account protected directly but incapable of propagating membership;
- a group object protected directly while member propagation is unverified;
- a group whose principal protection is established while member propagation remains disputed or unverified.

This is necessary for RIDs 498, 516, 521, 526 and 527 and is reusable beyond SEC-030.

### S-02 — Evidence states correctly distinguish conflict from absence

The candidate's five-state vocabulary is sound:

- `Established`
- `EstablishedNo`
- `Disputed`
- `Unverified`
- `DoesNotApply`

`Disputed` and `Unverified` must remain separate. An affirmative first-party conflict is not the same as no sufficient evidence.

### S-03 — Distribution-group traversal has direct Microsoft support

Microsoft's *Reducing the Active Directory Attack Surface* states:

> Any account that has direct or transitive membership in any protected group (regardless of whether
> the membership is derived from security or distribution groups) inherits this restricted security.

The page also gives the explicit user → distribution group → protected group example. Following distribution-group edges for an **established active membership root** is supported by current Microsoft product guidance.

### S-04 — Primary-group-only traversal remains appropriately unverified

The repository establishes `primaryGroupID` as real membership for authorization, but no reviewed Microsoft source establishes that AdminSDHolder protected-member enumeration follows a primary-group-only route. `Unknown` is the evidence-safe result when that route could change the answer.

### S-05 — SID scope requirements align with the implementation

The candidate requires independent scope for repeated `S-1-5-32-*` SIDs. `SidInterner` implements this by keying builtin SIDs by domain and SID text, while domain SIDs remain globally keyed by their self-contained domain authority. This matches decision 0087 and prevents cross-domain builtin groups from merging.

### S-06 — `SE_DACL_PROTECTED` is already preserved correctly in evidence

The capture path preserves both raw security-descriptor control flags and `IsDaclProtected`; it does not infer blocked inheritance from the ACE list. This supports SEC-030's corrected current-state predicate once a rule can access permissions and derived facts together.

---

## Findings

## F-ADH-001 — Flat graph seeding converts principal protection into member propagation

**Severity:** Critical
**Confidence:** High
**Release blocker:** Yes, for any rule or report relying on `ProtectedPrincipalClosure`.

### Affected files

- `next/src/SecureAD.Derivation/ProtectedGroupCatalogue.cs:103-127,220-227`
- `next/src/SecureAD.Derivation/ProtectedPrincipalClosure.cs:174-186`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedPrincipalDeriverTests.cs:40-81`

### Evidence

`ProtectedGroupCatalogue.IsProtected` answers one flat question. `ProtectedPrincipalDeriver` adds every SID for which it returns true to `seeds`, then walks downward through the membership graph from every seed.

This means every catalogue group object automatically becomes a membership-protection root. The model cannot express:

- principal protection established, member propagation unverified;
- principal protection disputed, member propagation unverified;
- established principal protection with `DoesNotApply` propagation.

The current tests verify only the ordinary Domain Admins route and the flat catalogue list. They do not verify that each listed group is a valid propagation root.

### Why it matters

A group object can be protected without current evidence establishing that its members are protected through that route. Flattening the two semantics can produce false `Protected` evaluations and suppress SEC-030 or later findings.

RIDs 516, 521, 526 and 527 cannot be represented safely by the current type.

### Recommended correction

Replace the flat catalogue with entries carrying independent principal-protection and member-propagation claims, statuses, provenance and scope. Build direct protected principals and traversal roots separately. Only `Established` active roots seed established member propagation. `Disputed` or `Unverified` possible roots contribute `Unknown`, not `Protected` or `NotProtected`.

### Validation needed

- catalogue test for every entry's two semantics;
- direct-principal tests independent of graph traversal;
- established/disputed/unverified root traversal tests;
- explicit RID 516/521/526/527 tests;
- one established route winning over uncertainty elsewhere.

---

## F-ADH-002 — `dwAdminSDExMask` currently changes principal protection and propagation together

**Severity:** Critical
**Confidence:** High
**Release blocker:** Yes, for protected-principal conclusions in forests using the mask.

### Affected files

- `next/src/SecureAD.Derivation/ProtectedGroupCatalogue.cs:70-90,191-192,202-227`
- `next/src/SecureAD.Derivation/ProtectedPrincipalClosure.cs:177-186`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedCatalogueExclusionTests.cs:34-43,87-102`
- `docs/layers/derivation/what-stage-2a-derives.md:333-338`

### Evidence

`NarrowedBy` stores mask exclusions on the catalogue. `IsProtected` returns false for an excluded operator SID. Because the deriver uses `IsProtected` to construct all seeds, the operator group object itself stops being directly protected and stops propagating protection in one operation.

The test `Stage2a_AnExcludedGroupIsNotProtected` explicitly pins this combined interpretation. The real-forest lab note confirms only that current code removed the four group objects; it does not independently verify that this interpretation matches server behavior.

Microsoft's pinned Support article establishes the four bit-to-group assignments and describes excluding users who are members of selected operator groups. The currently reviewed evidence does not establish that the selected group objects themselves lose principal protection.

### Why it matters

The product can report an operator group object as not protected when only member propagation has been established as disabled. This is the unsafe direction: a false `NotProtected` claim can drive incorrect remediation or suppress expectations about SDProp maintenance.

### Recommended correction

Apply the mask to **effective member propagation** only until normative algorithm evidence establishes an effect on principal protection. Keep the catalogue entry and principal-protection claim intact. Represent mask input, parse outcome, and disabled roots separately.

Narrow the existing lab documentation to: the value was captured, parsed, and current code behaved as recorded. Do not call the combined principal/propagation interpretation lab-verified.

### Validation needed

- mask bit disables only the named root's effective propagation;
- group object remains independently classifiable;
- exact combinations affect no other root;
- captured mask and resolved roots survive storage/read-back;
- controlled group-object lab check if principal impact is to be claimed.

---

## F-ADH-003 — Invalid mask character is mislabeled as absence and treated as complete

**Severity:** High
**Confidence:** High
**Release blocker:** Yes, for forests holding malformed character 16.

### Affected files

- `next/src/SecureAD.Kernel/Security/DirectoryHeuristics.cs:176-227`
- `next/tests/SecureAD.Next.Tests/Kernel/Security/DirectoryHeuristicsMicrosoftAnchorTests.cs:161-179`

### Evidence

MS-ADTS defines character 16 as a hexadecimal digit with valid values `0`-`9` and `a`-`f`. It defines absent characters as defaulting to zero. It does not define an invalid present character as absent.

When parsing fails, current code returns:

```text
Excluded = []
Outcome = DefaultedByAbsence
Character = invalid character
```

`AdminSdExclusionMask.IsComplete` is true for every outcome except `NotRead`. The test `AnUndocumentedCharacterExcludesNothing` pins only the empty exclusion list and does not assert that the result is incomplete or invalid.

### Why it matters

The product turns a present malformed value into a complete zero-mask answer. A consumer can conclude no roots are disabled even though server behavior for that value has not been established. The outcome also states something factually false: the character was not absent.

### Recommended correction

Add an explicit malformed/unsupported outcome. Preserve the raw character, set completeness false, and make every protection conclusion depending on an excludable root `Unknown`. Do not silently coerce it to zero or all bits.

### Validation needed

- invalid present character is distinct from absent/defaulted;
- `IsComplete` is false;
- dependent catalogue evaluations become `Unknown`;
- raw character remains available to the operator;
- valid upper/lower-case policy is explicitly sourced or normalized as a deliberate product decision.

---

## F-ADH-004 — Protected-principal results are not persisted or readable

**Severity:** High
**Confidence:** High
**Release blocker:** Yes, for SEC-030 and any judgement rule consuming protected-principal derivation.

### Affected files

- `next/src/SecureAD.Derivation/DerivationSchema.cs:150-260`
- `next/src/SecureAD.Derivation/DerivationWriter.cs:1-576`
- `next/src/SecureAD.Derivation/DerivationReader.cs:83-100`
- `docs/layers/derivation/adminsdholder-catalogue-semantics.md:356-393`

### Evidence

`ProtectedPrincipalClosure` is produced in memory by Stage 2a. The derivation schema stores SID dictionary, SID identities, principals, direct nesting edges, phase outcomes and global completeness. It has no protected-principal evaluation, decisive basis, unknown-reason, path, catalogue-claim or effective-root tables.

`DerivationReader` explicitly states that it reads no closures.

### Why it matters

Judgement runs after derivation and must operate from the sealed evidence plus persisted derivation. SEC-030 cannot safely consume an in-memory closure that no longer exists. Recomputing it inside judgement would create a second implementation and allow semantic drift.

### Recommended correction

Design a persisted protected-principal result shaped by the shared catalogue semantics and first consumer. Raise the derivation schema version. Persist at least:

- per-principal evaluation;
- decisive direct-principal or root basis;
- claim statuses/provenance used;
- per-principal unknown reasons;
- effective disabled roots and raw mask outcome;
- catalogue semantic version;
- completeness linkage.

Expose a narrow read-only API shaped by SEC-030 rather than a general graph-query abstraction.

### Validation needed

- write/read round trips for Protected, NotProtected and Unknown;
- schema mismatch refusal;
- deterministic result from same evidence and semantic versions;
- evidence-seal and derivation-generation binding;
- partial result cannot read as complete.

---

## F-ADH-005 — Global completeness cannot localize whether an unresolved edge affects one principal

**Severity:** High
**Confidence:** High
**Release blocker:** Yes, for clean `NotProtected` conclusions used by SEC-030.

### Affected files

- `next/src/SecureAD.Derivation/DerivationCompleteness.cs:22-59,84-110`
- `next/src/SecureAD.Derivation/ProtectedPrincipalClosure.cs:207-240`
- `docs/layers/derivation/adminsdholder-catalogue-semantics.md:343-379`

### Evidence

`DerivationCompleteness` records unresolved trustees and missing partitions globally. `ProtectedPrincipalDeriver` deliberately does not mark every principal Unknown when global membership evidence is partial; it leaves individual unconnected principals `NotProtected` and records only `PartialMembershipEvidence` in `StatedLimits`.

The candidate specification says `NotProtected` may be returned only where no unresolved trustee, FSP, missing domain or stopped expansion can hide a route for that principal. The current model cannot establish that locality. An unresolved member may name any principal, and the code comments acknowledge that the doubt is unbounded.

### Why it matters

A rule consuming per-principal `NotProtected` can interpret a global floor as a clean negative. SEC-030 would then emit a finding even though a missing membership route could prove the object protected.

### Recommended correction

Before allowing `NotProtected` to drive a positive rule finding, define one of:

1. a sound per-principal uncertainty region linking unresolved edges/partitions to affected principals; or
2. a conservative contract under which global partial membership prevents SEC-030 from treating any `NotProtected` as definitive.

Accepted decision 0086 supports surfacing qualified uncertainty, but does not license a clean negative under unbounded missing evidence.

### Validation needed

- unresolved member that could be the candidate prevents clean NotProtected;
- unresolved member demonstrably outside candidate's possible scope does not taint it, if locality is implemented;
- missing domain behavior is explicit;
- rule cannot emit positive SEC-030 from a floor.

---

## F-ADH-006 — Current rule contract cannot carry typed catalogue uncertainty to the customer

**Severity:** High
**Confidence:** High
**Release blocker:** Yes, for implementing SEC-030 under accepted decision 0086.

### Affected files

- `next/src/SecureAD.Evidence/Findings/RuleDefinition.cs:85-123,125-151`
- `next/src/SecureAD.Judgement/JudgingRun.cs:227-314`
- `next/src/SecureAD.Judgement/RuleExecution.cs:5-57`
- `docs/decisions/0086-a-qualified-statement-beats-silence.md:39-70`

### Evidence

`RuleVerdict` can return findings or a list of missing LDAP attribute names. `JudgingRun` aggregates incomplete verdicts into `ObjectsNotJudged` and `MissingInput(Attribute, Count)`. It cannot represent typed reasons such as:

- RID 498 principal protection disputed;
- RID 526/527 propagation unverified;
- primary-group traversal unverified;
- malformed forest mask;
- derivation phase incomplete.

Accepted decision 0086 requires uncertainty to be named and customer-visible. It explicitly says rules must be able to emit an `Indeterminate` finding with a stated reason rather than staying silent.

### Why it matters

Implementing SEC-030 with the current contract forces one of three wrong outcomes:

- flatten uncertainty into a fake missing attribute;
- emit no finding and expose only an aggregate not-judged count;
- guess a protected/not-protected answer.

### Recommended correction

Design the first derived-fact rule contract around typed rule inputs and typed uncertainty reasons. Preserve object-level uncertainty in stored findings or an equivalent customer-visible result, and keep missing LDAP attributes as one kind of unavailable input rather than the only kind.

This is a decision-record-level architecture change because `IRule` lives in Evidence while derived facts live in Derivation, and Derivation already depends on Evidence.

### Validation needed

- disputed catalogue route appears to the operator by name;
- malformed mask appears by name;
- missing LDAP attribute remains distinct;
- aggregate rule outcome remains Indeterminate;
- no uncertainty is converted into an empty findings list.

---

## F-ADH-007 — Existing tests are anchored to the flat model and can keep wrong semantics green

**Severity:** Medium
**Confidence:** High
**Release blocker:** No by itself; blocker when tests are used as proof of correctness.

### Affected files

- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedGroupCatalogueMicrosoftAnchorTests.cs:30-85`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedCatalogueExclusionTests.cs:34-102`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedPrincipalDeriverTests.cs:40-81`
- `docs/MICROSOFT-VERIFICATION.md:30-38,66-87`

### Evidence

The anchor test correctly pins Appendix C's fifteen object names, but the implementation and prose call that a catalogue of protected principals and then use the same set as traversal roots. The test does not verify member propagation.

`Stage2a_AnExcludedGroupIsNotProtected` pins the unresolved interpretation that the mask removes the group object's own principal protection.

`Stage2a_AMemberOfAProtectedGroupIsProtected` tests Domain Admins only and cannot justify propagation from every catalogue group.

The verification register says the catalogue question was settled, while current review shows only the flat object list and distribution-edge kind were pinned.

### Why it matters

The suite passes while measuring a weaker claim than the production code makes. This is the repository's documented false-green pattern: internally consistent tests anchored to an incomplete external reference.

### Recommended correction

Split anchor tests by semantic:

- object principal-protection claims;
- member-propagation claims;
- per-semantic disputes/unverified states;
- mask effect on propagation versus principal protection.

Revise `MICROSOFT-VERIFICATION.md` so each verified row says exactly what was checked and what remains unverified.

### Validation needed

Introduce negative controls that deliberately swap principal protection and propagation and prove the tests fail.

---

## F-ADH-008 — Accepted decision 0006 overstates RID 498 protection

**Severity:** Medium
**Confidence:** High
**Release blocker:** No for the candidate spec; yes before relying on the decision as authority.

### Affected files

- `docs/decisions/0006-tier-0-and-expected-admin-are-separate-sets.md:38-50`
- `docs/PUNCH-LIST.md:377`
- `docs/layers/specs/JUDGEMENT-HALF.md:998-1001`

### Evidence

Decision 0006 has `Status: Accepted` and states RID 498 belongs to expected-admin because Microsoft protects it with AdminSDHolder. The judgement specification and P-88 correctly record a first-party conflict: Appendix C omits RID 498 while the group-specific Microsoft page marks it protected.

Repository instructions say only accepted decisions and explicit finding decisions are authoritative. Therefore the accepted decision currently wins over the later non-authoritative caveat, even though its claim is disputed.

### Why it matters

Future implementation may treat RID 498 protection as settled by reading the accepted decision, bypassing the candidate's `Disputed` status.

### Recommended correction

Amend or supersede decision 0006 narrowly: its central separation of Tier 0 and expected-admin remains accepted, but the RID 498 expected-admin membership is disputed pending resolution. Do not rewrite history; add a dated correction as the record already does for operator groups.

### Validation needed

Documentation gate or test asserting that disputed catalogue entries cannot appear as unconditional facts in accepted decisions.

---

## F-ADH-009 — Distribution traversal status is contradictory across governing documents

**Severity:** Medium
**Confidence:** High
**Release blocker:** No for code already following distribution edges; yes before calling documentation canonical.

### Affected files

- `docs/layers/specs/JUDGEMENT-HALF.md:160-164,194-241`
- `docs/layers/specs/JUDGEMENT-HALF-ACCEPTANCE.md:38-41,74-76`
- `docs/decisions/0086-a-qualified-statement-beats-silence.md:16-18,65-70`
- `docs/MICROSOFT-VERIFICATION.md:66-87`

### Evidence

The main specification's summary table says distribution-group traversal is research-gated, while a later section says it was resolved and implemented. Acceptance criterion AC-26 remains marked blocked. Accepted decision 0086 still says AC-26 blocks distribution traversal. `MICROSOFT-VERIFICATION.md` and current code say distribution traversal is documented and followed.

### Why it matters

A reader cannot tell whether distribution traversal is accepted product behavior or an implementation ahead of authority. The code wins over ordinary docs under repository instructions, but an accepted decision remains authoritative and currently says the opposite.

### Recommended correction

Create a narrow accepted decision superseding only the distribution-traversal clause of 0086/AC-26, citing the exact Microsoft passage. Then update the summary table and acceptance criterion status. Keep primary-group traversal gated.

### Validation needed

A documentation test binding the accepted decision, spec table, acceptance criterion, catalogue provenance and implementation flag.

---

## F-ADH-010 — Candidate uses silence where accepted decision 0086 requires named uncertainty

**Severity:** Medium
**Confidence:** High
**Release blocker:** Yes before canonicalizing rule-consumer behavior.

### Affected files

- `docs/layers/derivation/adminsdholder-catalogue-semantics.md:329-379`
- `docs/layers/judgement/rules/SEC-030-admincount-without-protection.reviewed.md:344-367`
- `docs/decisions/0086-a-qualified-statement-beats-silence.md:39-70`

### Evidence

The candidate correctly returns `Unknown` for disputed/unverified protection semantics. SEC-030 currently describes these as “not judged” and forbids a positive finding. Decision 0086 goes further: uncertainty itself must be customer-visible, and rules must be able to emit an `Indeterminate` finding with the reason named.

### Why it matters

An aggregate “objects not judged” count does not tell an operator which account may be protected or why. Silence loses the actionable uncertainty the accepted decision requires.

### Recommended correction

The shared catalogue may continue to return typed `Unknown`. The rule specification should require a customer-visible indeterminate result for affected objects, separate from the positive SEC-030 condition. This must not be worded as the object being stale; it says the product could not settle protection and names the reason.

### Validation needed

- object-level indeterminate result stored and shown;
- unknown reason named;
- no positive stale-marker finding emitted;
- aggregate counts remain available without replacing object-level explanation.

---

## F-ADH-011 — The real-forest lab claim verifies code execution, not the disputed semantics

**Severity:** Medium
**Confidence:** High
**Release blocker:** No, but the current wording overstates evidence.

### Affected files

- `docs/layers/derivation/what-stage-2a-derives.md:333-338`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedCatalogueExclusionTests.cs:34-102`

### Evidence

The lab established that:

- `dSHeuristics` was captured;
- character 16 parsed as `f`;
- current code removed four operator groups from `IsProtected`;
- other catalogue entries remained.

It did not independently observe whether SDProp stopped protecting the operator group objects, whether only their members changed, or whether the current flat model matches server behavior.

### Why it matters

“Confirmed against a real forest” can be read as verification of the semantics when it only verifies the product path and output.

### Recommended correction

Rewrite the lab note to distinguish:

- confirmed capture and parsing;
- observed product output;
- unverified AD server behavior requiring a controlled before/after SDProp test.

---

## Source conflicts and unresolved questions

| Subject | Current evidence | Review status |
|---|---|---|
| RID 498 principal protection | Group-specific Learn page says Yes; Appendix C omits it | `Disputed` |
| RID 498 member propagation | No affirmative propagation evidence reviewed | `Unverified` |
| RID 516/521 principal protection | Appendix C and group-specific pages say protected | `Established` |
| RID 516/521 member propagation | Normative algorithm not pinned | `Unverified` |
| RID 526/527 principal protection | Appendix C and group-specific pages say protected | `Established` |
| RID 526/527 member propagation | Normative algorithm not pinned | `Unverified` |
| Distribution-group traversal | Exact Microsoft product-guidance passage affirmatively supports it | `Established` with product-documentation provenance; accepted-decision drift remains |
| Primary-group-only traversal | Real membership established; AdminSDHolder traversal not established | `Unverified` |
| Mask bit assignments | Exact Microsoft Support passage is pinned in anchor-test prose | `Established`, but verification register should quote it |
| Mask effect on group object | Not established by reviewed evidence | `Unverified` |
| Invalid mask character | Valid set documented; fallback not documented | malformed/unsupported, dependent answer `Unknown` |
| Supported Windows range | Candidate does not yet name it | unresolved |

---

## Recommended implementation order

1. **Do not implement SEC-030 yet.** Preserve both candidate rule specs for review.
2. **Write an accepted correction decision** covering:
   - separate principal protection and member propagation;
   - distribution traversal established by exact Microsoft passage;
   - primary-group traversal still unverified;
   - RID 498 dispute;
   - 526/527 established principal protection with unverified propagation.
3. **Correct malformed-mask semantics** in `DirectoryHeuristics` and tests.
4. **Redesign `ProtectedGroupCatalogue`** as per-semantic entries with provenance and scope.
5. **Redesign `ProtectedPrincipalDeriver`** with separate direct principals, established roots and possible roots.
6. **Resolve completeness policy**:
   - per-principal uncertainty regions, or
   - conservative global Unknown for consumers requiring clean negatives.
7. **Persist protected-principal results**, raise derivation schema version, and add reader APIs shaped by SEC-030.
8. **Design typed rule uncertainty** across the Evidence/Derivation/Judgement boundary, satisfying decision 0086.
9. **Update stale specs, acceptance criteria, decision 0006, verification register and lab wording.**
10. **Canonicalize the shared catalogue specification only after gates and source pins are complete.**
11. **Then canonicalize and implement SEC-030.**

---

## Files fully read

- `.github/copilot-instructions.md`
- `docs/WHAT-THE-PRODUCT-IS.md`
- `docs/layers/derivation/adminsdholder-catalogue-semantics.md`
- `docs/layers/judgement/rules/SEC-030-admincount-without-protection.reviewed.md`
- `docs/decisions/0006-tier-0-and-expected-admin-are-separate-sets.md`
- `docs/decisions/0086-a-qualified-statement-beats-silence.md`
- `docs/MICROSOFT-VERIFICATION.md`
- relevant complete sections of `docs/layers/specs/JUDGEMENT-HALF.md`
- relevant complete sections of `docs/layers/specs/JUDGEMENT-HALF-ACCEPTANCE.md`
- `next/src/SecureAD.Derivation/ProtectedGroupCatalogue.cs`
- `next/src/SecureAD.Derivation/ProtectedPrincipalClosure.cs`
- `next/src/SecureAD.Derivation/MembershipNestingPass.cs`
- `next/src/SecureAD.Derivation/DerivationCompleteness.cs`
- `next/src/SecureAD.Derivation/DerivationSchema.cs`
- `next/src/SecureAD.Derivation/DerivationWriter.cs`
- `next/src/SecureAD.Derivation/DerivationReader.cs`
- `next/src/SecureAD.Derivation/SidInterner.cs`
- `next/src/SecureAD.Kernel/Security/DirectoryHeuristics.cs`
- `next/src/SecureAD.Evidence/Findings/DomainControllerSignals.cs`
- `next/src/SecureAD.Evidence/Findings/RuleDefinition.cs`
- `next/src/SecureAD.Judgement/JudgingRun.cs`
- `next/src/SecureAD.Judgement/RuleExecution.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedGroupCatalogueMicrosoftAnchorTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedCatalogueExclusionTests.cs`
- `next/tests/SecureAD.Next.Tests/Derivation/ProtectedPrincipalDeriverTests.cs`
- `next/tests/SecureAD.Next.Tests/Kernel/Security/DirectoryHeuristicsMicrosoftAnchorTests.cs`

## Microsoft sources consulted

- [Appendix C: Protected Accounts and Groups in Active Directory](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
- [Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface)
- [Active Directory security groups](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups)
- [Admin-Count attribute](https://learn.microsoft.com/windows/win32/adschema/a-admincount)
- [DS-Heuristics attribute](https://learn.microsoft.com/windows/win32/adschema/a-dsheuristics)
- [MS-ADTS 6.1.1.2.4.1.2 dSHeuristics](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e5899be4-862e-496f-9a38-33950617d2c5)
- [MS-ADTS 3.1.1.6.1 AdminSDHolder](https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/dd3d29f3-8e1e-4e8c-a210-9eaef3abd628)
- [Protecting Objects from the Effects of Inherited Rights](https://learn.microsoft.com/windows/win32/ad/protecting-objects-from-the-effects-of-inherited-rights)
- [Microsoft Support: delegated permissions and AdminSDHolder exclusions](https://support.microsoft.com/topic/delegated-permissions-are-not-available-and-inheritance-is-automatically-disabled-56a70fa8-6d17-35ac-0f2c-87ec14b61980)
- [Troubleshoot insufficient access rights error](https://learn.microsoft.com/entra/identity/app-provisioning/insufficient-access-rights-error-troubleshooting)

---

## Validation performed

The review itself changed no production code. Its corrections were subsequently accepted by decision
`0089`, and the candidate specifications were aligned in the same change set.

- Workspace build: **succeeded**.
- Full test suite: **2,643 passed, 0 failed**.
- The review document is listed in Solution Explorer.

The green suite does not weaken findings F-ADH-001 through F-ADH-011. Several findings specifically
identify tests that pass while proving a narrower claim than production code makes.
