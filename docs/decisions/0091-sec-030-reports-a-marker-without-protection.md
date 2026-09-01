# 0091 - SEC-030 reports a marker without protection, and names a deleted object as deleted

Date: 2026-08-31
Status: Accepted.

Accepts
[`SEC-030-admincount-without-protection.reviewed.md`](../layers/judgement/rules/SEC-030-admincount-without-protection.reviewed.md)
as the specification SEC-030 is built from, and settles the two questions that specification left open
to the owner. Sits under
[0089](0089-principal-protection-and-member-propagation-are-separate-claims.md) and
[0090](0090-adminsdholder-facts-are-a-persisted-derivation-product.md), and changes no catalogue
classification.

## Context

`SEC-030` reports an object that carries `adminCount=1` and a non-inheriting DACL while nothing
establishes that AdminSDHolder currently protects it. Microsoft describes the state in
[Reducing the Active Directory Attack Surface](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface#privileged-accounts-and-groups-in-active-directory):

> When an account is removed from a protected group, it is no longer considered a protected account,
> but its adminCount attribute remains set to 1 if it is not manually changed. The result of this
> configuration is that the object's ACLs are no longer updated by SDProp, but the object still does
> not inherit permissions from its parent object.

The consequence is real and operator-visible: the object sits somewhere permissions have been
delegated, and does not receive those delegated permissions.

The specification was reviewed twice against Microsoft Learn and MS-ADTS and reached a revised
candidate. It left three items to the owner. Two are settled here. The third - whether Microsoft's
general propagation sentence settles the four `Unverified` member-propagation claims - is deliberately
**not** settled, and is recorded as `P-107`.

Wave 5 made the facts SEC-030 needs available: per-principal `Protected`, `NotProtected` or `Unknown`
evaluations with typed reasons, persisted in Derivation and readable through a narrow model, verified
against a real forest on 2026-08-31.

## Decision

**SEC-030 is built from the reviewed specification, and reports a deleted object separately rather
than alongside live ones.**

### The specification is accepted as written

Its unresolved Microsoft questions do not block implementation, because it already routes every
unresolved case to `Unknown` rather than to a finding. Cases `U1`-`U9` are the mechanism: missing SID,
unreadable security descriptor, incomplete membership closure, an unread forest mask, a primary-group
route, and the disputed or unverified catalogue entries each produce *not judged*, never a positive
finding. **No positive finding may be emitted under `U1`-`U9`**, because a caveated positive still
accuses an object of being unprotected when the missing evidence might have proved otherwise.

The consequence is accepted deliberately: SEC-030 may report very little on a forest whose evidence
is incomplete. Reporting little and saying why is the intended behaviour, not a defect to be tuned
away.

### A deleted object is reported, and named as deleted

Microsoft states in
[Creating and Deleting Objects in Active Directory Domain Services](https://learn.microsoft.com/windows/win32/ad/creating-and-deleting-objects-in-active-directory-domain-services#deleting-an-object):

> The security descriptor of the deleted object is retained and inheritable access control entries are
> not propagated. The security descriptor is retained as-is at the time the object is deleted.

**Every tombstone therefore has a non-inheriting DACL.** That is what deletion does, not a
misconfiguration, so a deleted object satisfies SEC-030's DACL condition automatically. Mixing them
into the ordinary population would produce a body of positives that mean nothing and bury the ones
that do. The same page lists the attributes deletion retains - `objectSid`, `objectClass`,
`userAccountControl` among them - and `adminCount` is **not** among them, so most deleted objects will
not meet the first condition either.

They are still worth reporting, for a different reason than a live object. Microsoft warns in
[Restoring Deleted Objects](https://learn.microsoft.com/windows/win32/ad/restoring-deleted-objects#permissions-required-to-restore-a-deleted-object)
that reanimation lets the restorer set the initial password and thereby gain control of the account.
A deleted object that was privileged is a restore away from being a privileged account somebody else
owns.

So: a deleted object matching the condition is reported and **marked as deleted**, never counted with
the live findings. `isDeleted` is the discriminator.

### Judging refuses rather than reporting nothing

A rule that declares it reads derived facts is not offered a bundle whose derivation is absent, or
whose derivation does not belong to that evidence and generation. Judging refuses and names what is
missing.

The alternative - letting SEC-030 return *could not judge* for every object - is honest and useless:
an operator sees a wall of nothing and must work out why. Refusing wholesale is worse still, because
it would block rules that need no derived facts at all. `JudgementWriter.Create` already accepts a
`derivationGenerationId` that `JudgingRun` passes as `null`; that seam becomes load-bearing.

**Judging with a derivation belonging to different evidence would produce confidently wrong findings**,
which is the one thing this product must not do. The binding is the point, not the presence check.

## Consequences

Rules gain a declared derived-input package, the way they already declare `RequiredAttributes`. A rule
declaring none is unaffected, so the two delegation rules and `judge-bundle.ps1` keep working against
evidence alone.

An unresolved derived fact is recorded distinctly from an uncaptured attribute. Today
`RuleVerdict.CouldNotJudge` takes attribute names and `MissingInput` counts them; reporting `U1`-`U9`
that way would tell an operator an attribute was not captured when it was.

`SEC-030` is Medium. The condition is an inconsistent, non-inheriting ACL state - not proof of a
dangerous ACE or an active compromise.

Two follow-ups are explicitly outside this rule and remain undecided: `adminCount=1` with inheritance
**enabled**, and inheritance disabled **without** `adminCount`. Each may deserve its own rule.

`P-107` is untouched by this record. Should the four `Unverified` propagation claims later become
`Established`, SEC-030 needs no change - it reads the catalogue rather than restating it, which is why
`0089` separated the claims in the first place.
