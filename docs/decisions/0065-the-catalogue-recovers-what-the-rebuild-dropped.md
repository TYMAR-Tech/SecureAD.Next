# 0065 - The catalogue recovers what the rebuild dropped

Date: 2026-08-16
Status: Accepted

Rests on [0064](0064-an-attribute-is-justified-by-a-rule-or-the-object-view.md), which admits the
object view as a justification. Completes
[0051](0051-trusts-describe-a-boundary-and-never-widen-a-run.md), whose trust attributes were
decided and never captured. Answers `B1` of the [S-44 agenda](../next/sessions/S-44-agenda.md) and
closes finding `F-S44-1`.

## Context

The rebuild's catalogue was assembled from the rules that exist. Compared against the predecessor's,
which ran against real forests for fourteen months, it had lost a substantial set - and the loss was
not a decision. Nothing records a judgement that `lastLogonTimestamp` or the domain password policy
had failed to earn their place; they were simply not carried across.

The predecessor's object view is the clearest evidence. Every field on it maps to something the
rebuild still captures - owner, state, password age, LAPS, shadow credentials, admin marker, token
size - **except one**. `lastLogonTimestamp` is not captured, so that screen cannot be rebuilt.

## Decision

**The catalogue recovers the predecessor's attributes, and adds the trust attributes `0051`
already decided on.** The catalogue version increments.

**Every object gains**: `name`, `description`, `whenCreated`, `whenChanged`, `isDeleted`.

`description` was carried on every class in the predecessor and is restored on every class. It is
free text an administrator types, and administrators have been typing passwords into it for thirty
years. It is also, more mundanely, how an object explains itself on the view.

**Accounts gain**: `userPrincipalName`, `lastLogonTimestamp`, `accountExpires`.

These make the difference between an account with dangerous rights and an *abandoned* account with
dangerous rights. That distinction is a permissions judgement with a time qualifier, not account
hygiene, and it cannot be made at all without them.

**Computers gain**: `operatingSystemVersion`, `dNSHostName`.

**Groups gain**: `managedBy` - the product's only means of answering who owns a thing, which every
remediation report needs.

**Managed service accounts gain**: `msDS-ManagedPasswordInterval`, `msDS-ManagedPasswordId`,
`msDS-HostServiceAccountBL`.

**The domain object is read for its policy**, a class the catalogue did not previously carry:
`minPwdLength`, `maxPwdAge`, `minPwdAge`, `pwdHistoryLength`, `pwdProperties`, `lockoutThreshold`,
`lockOutObservationWindow`, `lockoutDuration`.

**Password settings objects are read whole**: the `msDS-Password*` set, the `msDS-Lockout*` set, and
`msDS-PSOAppliesTo`. A fine-grained policy that exempts a privileged group from the domain's rules is
invisible without them, and it is exactly where an exemption gets hidden.

**`trustedDomain` objects gain their attributes**: `trustAttributes`, `trustDirection`,
`trustPartner`, `trustType`. This is not new - `0051` decided it, naming *SID filtering absent on an
external trust* as a severe finding, and nothing was built. Until now the product could see that a
trust existed and who could modify it, and could not say what the trust permitted.

**Nothing here is speculative.** Every attribute above was captured by the predecessor or decided by
an accepted record, and each is justified under `0064` by a rule or by a field of the object view.

## Consequences

**Storage grows by a small fraction, not a multiple.** The security descriptor dominates a captured
object - variable-length binary, commonly kilobytes, already paid for every object. The additions
are timestamps and short strings, most empty on most objects. This is an estimate from relative
sizes and should be measured against a real forest rather than asserted.

**`msDS-ManagedPasswordId` must be checked against the credential guard before it is added.** It
identifies the key used rather than being key material, but `msDS-ManagedPassword` is banned outright
and the two are neighbours. If the guard refuses it, the guard is right and this record yields.

**`msDS-PSOAppliesTo` and `member` are multi-valued and can exceed the server's limit**, so the new
multi-valued entries are checked against the range-retrieval list rather than assumed small.

**Two attributes were offered and not taken**, and are recorded so their absence is not read as a
judgement: `ms-DS-MachineAccountQuota`, the number of computers any ordinary user may join to the
domain, and `dSHeuristics`, which governs anonymous LDAP access. Neither was in the predecessor.
Both are standard audit findings and both sit on objects now being read. Still open.

**Certificate services stays out**, deliberately, per `0064`. The first run after that decision
reverses will be the first run able to answer it.

**This record is a decision and not an implementation.** The catalogue, its version, the bound
document `S-8` and the derivation test all still have to be changed, and none of it happened here.
