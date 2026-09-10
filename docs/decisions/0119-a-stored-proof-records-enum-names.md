# 0119 - A stored proof records enum names, never positions

Date: 2026-09-11
Status: Accepted.

The owner approved this on 2026-09-11, together with the wider scope once the exposure turned out to
reach further than the case that prompted it, and stated that obsolete bundles do not matter because
the product has not shipped. It changes how every stored proof is written. It does not change what
any proof means, what is assessed, or what a customer is told.

## Why

`System.Text.Json` writes an enum as its numeric value unless told otherwise. Every stored proof in
this product used the default, so a value hashed into a fingerprint or rehydrated from a store meant
what it meant only because of the order somebody typed the members in.

**Found by trying to delete something.** `Tier0Basis.DirectControl` was left over from the design
where every object was assessed and a controller could be classified Tier 0 in its own right;
discovery-first admission replaced that, and nothing ever emitted the value. Removing it would have
renumbered `PartitionRoot` from 3 to 2 - a member added the previous day under
[`0117`](0117-naming-context-roots-are-tier-0-assets.md) - and silently changed the value of every
`ownership_seed.classification_fingerprint` written for a partition-root seed.

**The blast radius was smaller than first thought, and the hazard larger.** `OwnershipAuditValidation`
recomputes the classification and re-hashes it, so both sides of that comparison come from the same
build: the fingerprint proves the database was not edited rather than carrying a value across
versions. The first assessment of this - that removal would silently corrupt stored evidence - was
overstated and is recorded here rather than quietly dropped. But searching the rest of the tree found
the same coupling at ten more sites, including one that is worse than a changed fingerprint.

**A `[Flags]` enum is the sharp case.** `MembershipRouteIncompleteReason` is stored in
`ownership_seed.routes`. Inserting a member does not shift later values by one; it renumbers their
bits. A stored route recording *membership evidence was incomplete* would read back as a different
limitation entirely - parsing cleanly, reporting confidently, and being wrong. That is the failure
`docs/next/README.md` puts first: a check that passes while measuring something other than what it
claims.

**Two stores were already half-right, which is how this hides.** `SelfMembershipStorage` and
`SelfMembershipCoverageStorage` each kept a private `ReadOptions` used on the way in and nothing on
the way out. That works while the two defaults agree and stops working the moment they do not, with
no error at the point the mistake is made.

## Decision

Anything written as a proof - hashed into a fingerprint, or stored and later rehydrated - is
serialised through one shared `JsonSerializerOptions` carrying `JsonStringEnumConverter`. Enum
declaration order is no longer a stored value.

`SecureAD.Evidence.ProofSerialization.Options` is that instance, used by both directions at every
site. It is deliberately not a general-purpose serialiser: display, settings files and log output
have no such requirement and must not reach for it.

Thirteen call sites across eleven files were moved onto it: the ownership audit header, target
identity, seed classification and routes, the validator's recomputed fingerprint and the
owner-rights context hash; full-control source entries, the stored proof node, its read side and the
evaluator's replay comparison; member-attribution root, context and configuration proofs with their
three reads; self-membership assessment issues, evidence, edge identifiers and coverage; the
derivation membership input; the Tier-0 classifier's support de-duplication key; and the bundle seal
with both of its reads.

With order no longer meaningful, `Tier0Basis.DirectControl` and `Tier0RelevanceKind.DependencyCandidate`
were removed. Neither was ever emitted.

## What this cost, and what it did not

**Every stored proof changes value once.** A judgement written before this refuses to validate
afterwards. That is acceptable only because it rides with a schema bump - judgement 29 to 30 - which
already means *re-judge, do not reinterpret*, and because nothing has shipped. No migration is
offered and none should be: the old rows are honest records of what the product believed when they
were written.

**No proof changes meaning.** A fingerprint still proves the same thing about the same evidence; only
its encoding changed. Nothing is now asserted that was not asserted before.

## Consequences

- Judgement schema 29 → 30. The layout is byte-identical, which is the `P-149` case a structural
  fingerprint cannot see, so `ProofSerializationGateTests` carries the behavioural check instead.
- A gate enforces both halves: that the options really pin names, and that every stored-proof site
  uses them. Options that exist and are not reached protect nothing, which is exactly what the two
  half-right stores demonstrated.
- **The gate found a site the manual sweep missed.** `OwnershipAuditRun` reads `BundleSealContents`
  against a writer in `BundleSealing`, in a different assembly, with no shared options between them.
  Two strings today, so no enum exposure - but it is the pairing that drifts, and it was not found by
  reading.
- Removing `ControlEdgeDeriver.Derive`'s unused `includeOwnerTransitions` parameter exposed two tests
  asserting a compound takeover edge no run produces, one of them down to a precise count of fifteen
  preconditions. The parameter defaulted to `true`, every production caller passed `false`, and the
  test fixture was the only thing reaching the branch. Both were rewritten to assert what the deriver
  does; the transition itself remains covered by `OwnershipAuditIntegrationTests` on the scoped path
  and by `OwnershipWorkflowTests` asserting its absence off it.
- **That removal broke eleven more tests, and this record said it had not.** Only the two the
  compiler forced were rewritten; the rest failed at runtime and were not found because the full
  suite was not run before pushing. Eight had depended on the fixture producing the compound edge -
  storage counts, paging totals, presentation rows. The fix is
  `ControlEdgeDeriverTests.DeriveWithTransitions`, which derives the edges and then the transitions
  the way `OwnershipAuditRun` does, so a test about that edge reaches it by the path a run takes
  rather than through a deriver flag. Three tests whose own run performs no ownership audit -
  `JudgingRun.Judge` and `JudgeWithMemberAttribution` - were rewritten to assert the edge's absence,
  which is what those runs actually produce.
- **Four of them were absorbed into a "known failures" list rather than investigated.** The baseline
  carried ten names; four were this defect. A remembered failure list is not a baseline, and a
  regression that lands on one is invisible for exactly as long as the list is trusted. The true
  baseline is six.
- `AC-61` is restated: its requirement is unchanged but all three names it gave had moved.
