# 0106 - A membership is reported under the nearest privileged root

Date: 2026-09-05
Status: Accepted; reporting choice revised by [0108](0108-a-finding-summarizes-independent-membership-routes.md).

Settles `P-105`. Gates stage 6, because `0097` counts a control edge at the group.

## Context

When an account can reach several privileged groups, the derivation stores one of them as the
*basis* for its protection - the group the finding names as the reason. Until now the walk let each
later root overwrite an earlier one, so the **last** root processed was reported, ordered by
catalogue entry id.

**This was observable and it sent operators to the wrong place.** On `ad.lab` on 2026-08-31, three
accounts that are direct members of **Enterprise Admins** (catalogue entry 11) were each reported
with a decisive root of **BUILTIN\Administrators** (entry 13), because Enterprise Admins is itself
nested under Administrators and is therefore walked first.

**Nothing about that was false.** The accounts really are under both, and the stored path always
showed the whole chain. But the two answers differ in what they tell an administrator to *do*: the
remediation is to remove the account from Enterprise Admins, and removing it from
`BUILTIN\Administrators` would not have taken its privilege away - the account is not directly in
that group at all.

**Deciding this before stage 6 rather than inside it.** `0098` tags every control edge expected or
unexpected and `0097` counts a group-held permission at the group, so an edge naming the wrong group
is a remediation instruction pointing at the wrong object. Building the control-edge graph on top of
an arbitrary attribution would have spread the wrong answer across a second screen before anybody
noticed it on the first.

## Decision

**A membership is reported under the nearest root: the shortest membership chain from the principal
to a privileged group. Where two roots are the same distance away, the lower catalogue entry id
holds it.**

Three things follow from this and are part of the decision:

1. **A direct catalogue claim is never displaced by a membership.** A principal Microsoft names in
   the protected set is protected because of what it is. Nesting Domain Admins inside another
   protected group does not replace its direct catalogue status as the reason for protection.
2. **The whole chain must remain available behind the reported reason.** The earlier wording
   incorrectly claimed every outer-root path was already stored and shown. Source inspection on
   2026-09-05 found one selected basis and path per principal in `ProtectedPrincipalClosure`,
   persisted by `DerivationWriter`. P-146 has since added independent supporting routes and their
   presentation under `0108`, separately from that selected basis; it is not an all-paths enumeration.
   This corrects the implementation claim, not the requirement to retain supporting evidence.
3. **The choice must not move between runs over the same forest.** Roots are walked in catalogue
   order and an equal-length path never displaces one already held, which makes the tie-break a
   consequence of the walk order rather than a second comparison that could disagree with it.

## Why not the alternatives

**Report every root reached.** This is more complete and it was the owner's instinct, which is worth
recording because the reasoning against it is not obvious. The outer roots are *consequences* of the
nearest one rather than separate facts: remove the one membership an operator can act on and every
outer row vanishes by itself. So the extra rows are rows nobody can act on that resolve themselves,
which is precisely what trains an operator to scroll past a screen. Under `0097` the counted edge
would also multiply by nesting depth rather than by risk - the shape of the predecessor's 111,627
control edges and 0 escalation paths.

**Report the first root by catalogue entry id.** Deterministic, and still arbitrary. It would have
produced the same wrong answer on `ad.lab` about half the time, for no better reason.

**Keep the last root and document it.** The cheapest option and the only one that is actually
wrong: it is not a rule about the directory at all, only a record of the order a loop happened to
run in.

## Consequences

- `ProtectedPrincipalClosure.Walk` displaces an existing membership attribution only for a strictly
  shorter path. Covered by `Stage2a_AMembershipIsReportedUnderTheNearestRoot`,
  `Stage2a_TwoRootsAtTheSameDistanceAreBrokenDeterministically` and
  `Stage2a_ADirectCatalogueClaimIsNotDisplacedByAnyMembership`, the first two of which were seen
  failing `Expected: 512, Actual: 519` before the change.
- The stored nearest-root attribution is deterministic. It does not implement the independent-route
  explanation subsequently accepted in `0108`; P-146 has now implemented that separate summary.

## What this does not settle

**Two direct memberships in equally near roots require two removals, and naming one hides the
other.** Equally near roots reached through nesting can share an initial membership; an independent
route can also be longer. The tie-break makes the choice stable; it does not make it complete.
That is a real gap in *nearest* as a reporting model, not a presentation of all available routes.
Settled by `0108` and implemented by `P-146`, rather than left to be discovered by an operator who
removed one membership and found the account still privileged.
