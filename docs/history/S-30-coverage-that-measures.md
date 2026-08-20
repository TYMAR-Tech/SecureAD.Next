# S-30 — Coverage that measures, and the group that is too big

> **This records session S-30 as of 2026-08-10. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

The slice document for [`S-30`](../next/sessions/S-30-coverage-that-measures.md). It records an
investigation session: **no product code was changed.** What it produced is an answer to
`F-S29-6`, four new findings, and a built design for `F-S29-3` that the next session implements.

The session stopped short of building for a stated reason, recorded here so it is not read as
drift: the five decision records that govern coverage — `0002`, `0003`, `0017`, `0027`, `0035` —
were read only through the brief's summaries of them, and [`README.md`](../next/README.md) is explicit that
a document summarising a decision is discussion rather than authority. Redefining what completeness
means in the evidence on a second-hand reading of the records that govern it is the mistake that
instruction exists to prevent. **The building session reads those five records first.**

## What was established, and how

Everything below came from reading the code and the bundle produced on 2026-08-10, which was still
sitting at `next/ad.lab-20260815-010309/`. Nothing here is inferred from a document.

The bundle's own answers, for reference:

| partition | kind | referrals suppressed | `is_complete` |
|---|---|---|---|
| `CN=Configuration,DC=ad,DC=lab` | Configuration | 0 | 1 |
| `CN=Schema,CN=Configuration,DC=ad,DC=lab` | Schema | 0 | 1 |
| `DC=ad,DC=lab` | Domain | 1 | 0 |
| `DC=ba,DC=ad,DC=lab` | Domain | 1 | 0 |
| `DC=ph,DC=ad,DC=lab` | Domain | 1 | 0 |

`domain_coverage` reports all three domains `Read`, and `bundle.coverage_is_complete` is 1. That is
`F-S29-3` reproduced exactly.

## F-S29-6, answered

**The question:** the real capture produced exactly one `unresolved_reference` with reason
`DomainNotCaptured`, in a forest where all three declared domains were read in full. Either
something legitimately references a principal outside the forest, or the reason is being attributed
wrongly. The brief said not to guess.

**The answer, by query rather than by guess:**

```
object_id=3388 | kind=ParentContainer | reference=DC=lab | reason=DomainNotCaptured
distinguished_name=DC=ad,DC=lab | domain_fqdn=ad.lab
```

The object is the forest root domain's own naming context root. `DC=lab` is not a domain, is not in
this forest, and does not exist. It is the string left over when everything before the first comma
is removed from `DC=ad,DC=lab`.

It is the second branch: **the reason is attributed wrongly, and a row that should not exist at all
is being reported as a coverage gap.** Recorded in full as `F-S30-1`.

## Findings

### F-S30-1 — the parent-container query splits a DN on the first comma

- **Severity:** correctness — the product states something false about the customer's forest, and
  separately detaches objects from the containment graph
- **Confidence:** verified against the 2026-08-10 bundle and by reading both implementations
- **Evidence:** `BundleWriter.ResolveParentGuids` derives an object's parent with
  `SUBSTR(distinguished_name, INSTR(distinguished_name, ',') + 1)`. That is a raw split on the first
  comma, with no awareness of RFC 2253 §2.4 escaping. Two separate defects follow.
  - **The forest root.** The query excludes naming context roots by requiring the object to have a
    comma at all — its own comment says this is done "rather than by naming the roots, so a
    partition this product has never heard of behaves correctly." That reasoning holds only for a
    single-label root. `DC=ad,DC=lab` contains a comma, so the exclusion does not fire, the root is
    treated as an object whose parent went missing, and one false row is produced. It fires on the
    forest root domain of **any** forest whose root DN has two or more components, which is
    substantially all of them. Child domains are unaffected: `DC=ba,DC=ad,DC=lab`'s parent was
    captured, so it never reaches the query.
  - **Escaped commas, which is the larger half.** `CN=Smith\, John,OU=Users,DC=corp,DC=local` yields
    a computed parent of `John,OU=Users,DC=corp,DC=local`, which matches nothing. `parent_guid`
    stays null and a false `DomainNotCaptured` row is written. "Lastname, Firstname" is a normal
    naming convention, so this is not a corner case in a real directory. The lab contains **zero**
    objects with a comma in the name, which is why five partitions and 6,359 objects produced no
    sign of it.
- **What happens to a user:** a coverage summary names domains that do not exist and reports them
  as uncaptured. Worse, an object with a null `parent_guid` is outside the containment tree.
  Inherited entries are stored specifically so that control over a container produces edges to
  everything beneath it — that was `F-S20-14`, and storing them was a deliberate reversal. An object
  detached from its parent does not receive those edges, so a principal holding control over its
  container does not appear to reach it.
- **Why it is this way:** the predecessor had this right. `src/SecureAD.Core/Discovery/DnHelper.cs`
  scans for an *unescaped* comma, and the rebuild **kept that helper**, correct, at
  `next/src/SecureAD.Kernel/Naming/DnHelper.cs` with `GetParentDn` already written and already
  handling the escaped form. `ResolveParentGuids` does not call it. The parent split was
  re-implemented in SQL because the work moved into the database, and the helper three projects away
  was not consulted.
- **How it will be acted on:** use `DnHelper.GetParentDn`, and exclude partition roots against
  `partition_coverage.naming_context_dn` rather than against the presence of a comma. That is still
  data-driven rather than a hardcoded list, so the property the original comment was reaching for
  survives.
- **Status:** **OPEN** — diagnosed, not built.

### F-S30-2 — `unresolved_reference.reason` has one producer and no classifier

- **Severity:** correctness — a closed vocabulary of four reasons, of which only one is reachable
- **Confidence:** verified — `git grep DomainNotCaptured -- next/src` returns the schema, the enum,
  and one SQL literal
- **Evidence:** the column accepts `DomainNotCaptured`, `AnotherForest`, `OrphanedIdentifier` and
  `Unreadable`. The only code that writes a row types `'DomainNotCaptured'` directly into the
  `INSERT`. Nothing classifies, and the other three values cannot occur.
- **What happens to a user:** every unresolved reference, whatever its cause, is reported as a
  domain the run failed to capture. A genuine foreign security principal, a trust to another forest
  and an orphaned SID all render as a coverage failure the operator is invited to fix by capturing
  more — which will not help, because there is nothing more to capture.
- **Why it is this way:** the schema comment records that the predecessor's equivalent column was
  reachable by omission and defaulted to `Undetermined`, and that the rebuild removed the default so
  that "there is no member to fall back to." The default was removed; the classifier was never
  written. The hardcoded literal is the default in a new place.
- **How it will be acted on:** not in `S-30`. It is a real gap and it is contained, so it is
  recorded rather than fixed. Note that `F-S30-1` removes the only rows currently produced, which
  makes the whole vocabulary unreachable until a classifier exists — the next session should say so
  plainly rather than leave a table that can never have a row.
- **Status:** **OPEN**.

### F-S30-3 — the end-to-end test asserts the opposite of what the product does

- **Severity:** a check that passes while measuring the wrong world — the `S-29` pattern
- **Confidence:** verified by reading the model against the real bundle
- **Evidence:** `CaptureRunEndToEndTests` asserts `DC=example,DC=com is_complete=1` for a **domain**
  partition. Every domain partition in the real capture is `is_complete=0`. Both are correct for the
  world each ran in: `ControllerModel.SupportedControls` is `["1.2.840.113556.1.4.319"]` — paged
  results only. `CaptureSearchRequestFactory.ShouldSendDomainScopeControl` requires the controller
  to advertise `1.2.840.113556.1.4.1339`, which the model does not, so the model never suppresses
  referrals and a real controller always does.
- **What happens to a user:** nothing directly. The damage is that the end-to-end test has been
  certifying the branch the product never takes, which is how `F-S29-3` survived to a live forest.
- **Why it is this way:** the model publishes the controls the tests needed, and nobody asked what a
  real controller publishes. Same shape as `F-S29-1` and `F-S29-2`.
- **How it will be acted on:** the model advertises the domain-scope control. Expect the end-to-end
  assertion to change value, and treat that change as the finding being confirmed rather than as a
  test to be repaired.
- **Bearing on `F-S29-4`:** this is the model that range retrieval has been tested against.
- **Status:** **OPEN**.

### F-S30-4 — `PartitionCoverage.IsComplete` is the sole thing vouching its own type for gate 4

- **Severity:** a constraint on the fix, recorded because the obvious fix breaks the build
- **Confidence:** verified by reading `UnvouchedResultGateTests`
- **Evidence:** gate 4 fires on a public type handing back a collection when the type cannot say
  whether it managed to look. `PartitionCoverage` hands back `ContinuationReferences`, an
  `IReadOnlyList<string>`. `IsVouched` uses `BindingFlags.DeclaredOnly`, so only members declared on
  the type itself count, and `PartitionCoverage` is not in `ExemptTypes`. It passes gate 4 solely
  because it declares a member whose *name* matches `IsComplete`.
- **What happens to a user:** nothing. This is a note to whoever builds `F-S29-3`.
- **Why it matters:** "delete the flag that means nothing" was the natural reading of the decision
  and it fails the build. The flag has to be replaced rather than removed.
- **Status:** **RECORDED** — acted on by decision `D1` below.

### F-S30-5 — incomplete coverage does not propagate to anything that consumes it

- **Severity:** capability gap against the predecessor, not a defect in what exists
- **Confidence:** verified by reading both trees
- **Evidence:** the predecessor carried `CoverageTaint`, `CoverageDependency` and
  `CoverageDependencyGraph`: a module whose coverage was not `Complete` tainted every module
  declared to depend on it, and `RunCoverageState.BuildReasonForDomain` produced a string naming
  which module was incomplete in which domain, which findings carried. The rebuild records coverage
  per partition and stops. Nothing propagates and no result can yet say "this is degraded because X
  was not fully read."
- **What happens to a user:** not yet anything, because the read side does not exist. It becomes a
  `0002` problem the moment it does: a finding computed from partial evidence renders identically to
  one computed from complete evidence.
- **How it will be acted on:** not in `S-30`, and not as a port — the predecessor's module×domain
  matrix does not match this tree's partition-level model. Recorded so it is a ledger row rather
  than a rediscovery.
- **Status:** **OPEN** — owed a ledger row on the read side.

### F-S30-6 — per-object completeness cannot see under-privilege

- **Severity:** a stated limit of decision `D2` below, recorded so it is not mistaken for coverage
- **Confidence:** reasoned from how confidential attributes work, not measured
- **Evidence:** `D2` derives an object's completeness from the connection rung, because a controller
  serving an unsealed search may omit confidential attributes without error. That is one of two ways
  a confidential attribute goes missing. The other is the audit account lacking `CONTROL_ACCESS`,
  which withholds values on any rung including a sealed one.
- **What happens to a user:** an object read over a sealed connection by an under-privileged account
  reports `Complete` while missing values.
- **How it will be acted on:** not in `S-30`. `D2`'s enum member is deliberately named for the
  transport risk it actually measures rather than for completeness in general, so the flag does not
  claim what it cannot support. Detecting under-privilege is separate work.
- **Status:** **OPEN**.

## What the predecessor's coverage stack contributes

Read in full during this session, because `F-S29-3` is a question the old product had already
answered and the rebuild had not looked.

**It was three states, not a boolean.** `src/SecureAD.Core/Assessment/RunCoverage.cs`:

- `Full` — covered equals discovered, every module completed, discovery itself was clean
- `Partial` — covered is a strict subset of discovered, *and the missing set is known*
- `Unknown` — "discovery did not cleanly enumerate the forest, so completeness cannot be
  determined." It "gates identically to `Partial`; named differently because the remedy differs —
  fix discovery, rather than select more domains."

**And it refused to compute before it had a denominator.** `RunCoverageResolver`:

> Completeness is measured against discovery, so an unvalidated discovery has no denominator to
> measure against and cannot support any completeness claim.

> With nothing discovered the three sets can only match by all being empty. **Full is earned by
> measurement, never acquired by the absence of anything to measure.**

That last sentence is the trap the `S-30` brief warns about, written down in the predecessor and
solved there.

**It checked three conditions where the rebuild checks two.**

```
declared.SetEquals(discovered) && covered.SetEquals(declared) && allModulesComplete
```

with the comment: "Covered == declared alone would let a deliberate subset claim the whole forest,
and **matching domain sets say nothing about whether their contents captured**." `RunCoverage.Of`
enforces the first two. The third is exactly what `CaptureRun` currently asserts from control flow,
and the predecessor names it as separately necessary.

**One thing it got wrong, which the rebuild inherited.** `CoverageReasonCode` includes
`ReferralDisabled`. The predecessor also treated referral suppression as a coverage reason, so
`IsComplete => !ReferralsSuppressed` is inherited confusion rather than a rebuild invention. The
owner's decision to separate the two is a genuine departure from the old design, and the old code
supports it: that product could not distinguish "we asked not to be told" from "we failed" either.

## Design for `F-S29-3`

**The owner's decision on `F-S29-3`, taken 2026-08-10, is the authority** and is recorded on the
finding in [`S-29`](S-29-finishing-the-entry-point.md). It has two parts: referral suppression is
not a completeness question, and the run-level record is derived rather than asserted. What follows
are this session's engineering proposals for *how*, built on that decision.

`D3` extends it rather than implementing it, and is flagged accordingly.

### D1 — `PartitionCoverage.IsComplete` becomes `ContinuationReferencesAreComplete`

- **Status: ACCEPTED — an engineering decision, taken in `S-30` rather than referred to the owner.**
  The stored value does not change and no statement the bundle makes to a customer changes with it;
  what changes is which of two meanings the word carries. That is naming and code shape, which
  [`copilot-instructions.md`](../../.github/copilot-instructions.md) puts on this side of the line.
- The value does not change. `!ReferralsSuppressed` is a correct statement about whether
  `ContinuationReferences` is a complete list of what lies below the partition; it is not a
  statement about whether the partition was read. Two meanings of one word is what gate 2 exists to
  prevent, and the finding says one of them stops existing. **The name is the thing that was wrong,
  not the value.**
- The bundle column `is_complete` is renamed to match.
- It keeps a reachable false state, and both states are observed in the real bundle — true on
  Configuration and Schema, false on all three domains.
- **Cost:** gate 4 gains one vouch shape, `*AreComplete`, carrying its own scanner self-test per
  [`README.md`](../next/README.md) § Gates. Widening a gate deserves the objection: the justification is
  that the vouching member and the collection it vouches for are the same subject —
  `ContinuationReferences` and `ContinuationReferencesAreComplete` — which is the pattern working
  rather than being evaded. The alternative was a fifth entry in the exemption list, whose own
  comment says a third entry not justified by "a compiled table that cannot fail" does not belong.

### D2 — `EvidenceObject.IsComplete` becomes `EvidenceObject.Completeness`

- **Status: ACCEPTED**, recommended to the owner on 2026-08-12 alongside `D1` and `D3` and not
  objected to. **Recorded here as the weakest of the three, because it is the one that changes what
  the evidence says to a customer** — 2,972 of 6,359 objects in the lab capture change their answer.
  A later reader is entitled to challenge it on that basis; what should not be re-litigated is the
  half that is not in doubt, which is that the present behaviour is wrong.
- **The defect being fixed:** it forwards to `Coverage.IsComplete`, so today **every domain object
  in the bundle reports that we cannot say whether we looked properly** — 2,972 of 6,359 objects in
  the lab capture — while configuration and schema objects report that we can. It is the wrong
  answer on nearly half the bundle, and it exists because the two meanings of the word were wired
  together.
- **What it should mean instead.** The brief's trap is that "was this partition read to the end" is
  true of every object in every sealed bundle, because an incomplete run never seals. The question
  that *is* reachable is the one `PartitionCoverage.ConnectionSecurity` already records and nothing
  consults: a controller serving an unsealed search may strip confidential attributes and return no
  error (`F-S24-1`). `ConnectionSecurityLadder` makes `Signed` — signed but not encrypted —
  `RequiresDeclaredAllowance: false`, so **any run can land there with no declaration and no
  operator action**, which is what makes this reachable rather than theoretical.
- **The shape:** an enum, not a boolean. `Complete` for LDAPS and `SignedAndSealed`;
  `MayBeMissingConfidentialValues` for `Signed` and `Unprotected`. A boolean named `IsComplete`
  would have to mean "everything about this object is here", which is not supportable — see
  `F-S30-6`. The enum says only what is observable: *the connection this object came over could have
  withheld values without saying so.*
- `Completeness` is already an accepted gate 4 vouch shape, so this costs no gate change.

### D3 — `RunCoverage` is derived, and three-state

- **Status: SUPERSEDED IN PART, 2026-08-13.** The derivation half was ratified, built in `S-31` and
  stands. **The three-state half is withdrawn**: `Unknown` is unreachable in any bundle this product
  can produce, because `0003` makes capture fail-fast and a bundle exists only when the denominator
  was established. The reasoning below was imported from the predecessor, which sealed incomplete
  runs deliberately and re-analysed saved captures — neither of which is true here. See
  [`S-31`](S-31-the-group-that-is-too-big.md) § `D3`, review addendum, which also records that
  `Partial` is equally unreachable and reframes the open question.
- **Decision:** taken by the owner on 2026-08-12. `RunCoverage` is derived from what capture
  recorded, and it resolves to three states — `Full`, `Partial`, `Unknown` — following the
  predecessor's `RunCoverageResolver`. The derivation half implements the owner's accepted decision
  of 2026-08-10 on `F-S29-3`; the three states extend it, and this line is that extension being
  ratified rather than assumed. *(The extension was ratified on the strength of the argument below,
  which was not checked for reachability. See the status line above.)*
- **Derived:** `CaptureRun` builds `RunCoverage` from the partition rows capture actually recorded,
  not from `plan.DeclaredDomains.Select(DomainCoverage.Read)`. `RunCoverage.Of`'s existing guard —
  which refuses a declared domain with no outcome — then becomes able to fire. No new check is added;
  `S-29` records a third check as deliberately not done, and that still holds.
- **Three-state:** a boolean cannot express "we could not establish a denominator", which is the
  state `0002` exists to protect and which `0040` (failover) and `0041` (parallel capture) both make
  reachable once built. `Unknown` gates identically to `Partial` and is named separately because the
  operator's remedy differs — fix discovery, rather than capture more.
- **The payoff, and it is concrete:** `RunComparability` consults `RunCoverage.IsComplete` in three
  places to refuse a comparison. All three are currently unable to fire.

## Observations owed against `B20`

- **`F-S7-39` — whether a controller tolerates a base-scope search between two pages.** Not settled,
  but evidence exists that the brief did not account for: the predecessor's
  `DirectCaptureModule.GetAllMembersAsync` issues its range requests as `SearchScope.Base` against
  the entry DN *while the outer paged enumeration is in flight*, and that product ran against real
  forests. Evidence, not proof — it is a product whose correctness this rebuild is re-verifying —
  but it is a stronger prior than the documentation alone.
- **`F-S7-37`, `F-S7-40`, `F-S7-26` and a controller declining a rung** remain owed. They need the
  oversized group, which needs the lab script below.

## What the predecessor's range retrieval says about `F-S29-4`

`DirectCaptureModule.GetAllMembersAsync` is a catalogue of how this fails silently, and it shipped:

- **Four `break` statements** — an empty response, no ranged attribute in the reply, a block with
  zero values, and an iteration cap — each returning **a prefix of the membership to a caller with
  no way to tell**.
- **`nextStart += vals.Count`** rather than reading the bound the controller actually served, so a
  short block silently skips values.
- **`DetermineCoverage`** immediately below marks the domain `Complete`, because a truncated group
  never changes `attempted` or `succeeded`.

The rebuild's `LdapEntryReader.Continue` is structurally better — it ends on the wildcard mark
rather than on counts, returns an `AuditError` where the old one broke out of the loop, and refuses
a round that advanced by nothing. **That is a reason to expect it to be right, and not a reason to
believe it, because it has never run.**

It is also the empirical case for the brief's insistence that the check compare membership rather
than counts: every one of the failures above leaves `attempted` and `succeeded` consistent.

## What the next session does

1. **Read decisions `0002`, `0003`, `0017`, `0027` and `0035` before touching coverage.**
2. `D1`, `D2` and `D3` are all settled — `D3`'s three-state extension was ratified on 2026-08-12.
3. Build `D1`, `D2`, `D3`, then `F-S30-1`, then `F-S30-3`.
4. Mutation-test each changed guard in both directions and record which were observed.
5. Run the lab script, capture, and compare membership against the directory's own.

## Housekeeping

The capture bundle at `next/ad.lab-20260815-010309/` is still in the working tree and is still not
committed. It was read during this session and should now be moved, deleted or ignored.
