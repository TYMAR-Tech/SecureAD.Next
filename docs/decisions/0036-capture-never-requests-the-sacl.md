# 0036 - Capture never requests the SACL, and the product reports nothing about audit configuration

Date: 2026-08-13
Status: Accepted

## Context

A Windows security descriptor has two access control lists. The **DACL** decides who may do what.
The **SACL** decides what gets audited. This product has always read the first and never the
second: `CaptureSearchRequestFactory.SecurityDescriptorFlags()` sends
`SecurityMasks.Owner | Group | Dacl` through `LDAP_SERVER_SD_FLAGS_OID`, and has done since branch B
was built.

The reasoning was written into the code at the time and it is good:

> The SACL - the audit half of a descriptor - is privileged: retrieving it is one of the operations
> Microsoft lists as failing with insufficient access rights for a caller without the privilege
> behind it. A capture runs as an ordinary authenticated user. Nobody has to grant an audit tool a
> privilege on their domain controllers before it will read anything, and the product never holds
> the audit configuration of a forest it was asked only to inspect permissions on.

What was missing is authority. Per [`docs/next/README.md`](../next/README.md) nothing outside this
folder settles the product's position, so a comment - however well argued - is a description of what
the code does rather than a decision it is held to. `S-21`
found the gap while reading the parser against `[MS-DTYP]`, and found the one place where the
absence actually misleads: `ParsedAce`'s own summary said it described *"a single ACE parsed from a
binary security descriptor DACL or SACL"*, promising a capability the product does not have.

There is also nothing to stop the mask quietly gaining `SecurityMasks.Sacl` later. It is one flag in
one expression, it would compile, and on a domain controller where the caller happens to hold the
privilege it would silently start collecting audit configuration - changing what the product holds
about a customer's forest without anybody deciding to.

## Decision

**Capture requests the owner, the group and the DACL. It never requests the SACL**, and the product
reports nothing about audit configuration.

**A capture runs as an ordinary authenticated user.** No privilege is required on a domain
controller to run this tool, and none is asked for. This is a property of the product, not an
incidental consequence of the mask.

**Adding the SACL requires a new record**, which must answer two things: what forest-scale question
it settles that the DACL does not, and what it costs a customer to grant `SeSecurityPrivilege` to
whatever account runs the audit.

**Nothing may promise otherwise.** `ParsedAce` is corrected to say it parses a DACL entry.

## Consequences

**A real class of finding is out of scope, and it should be named rather than discovered.** Audit
misconfiguration is a genuine security weakness - no auditing on `AdminSDHolder`, or on the domain
object, means the changes an attacker makes there leave no record. This product will not report it.
A customer who needs that answer needs a different tool or a different mode, and this record is
where that conversation starts.

**The privilege boundary is the thing being bought.** An audit tool that demands
`SeSecurityPrivilege` is an audit tool that has to be argued through a change board before it can
read anything. Running as an ordinary authenticated user is why this one can be pointed at a forest
on the day it is asked for.

**The product holds less than it could, deliberately.** Evidence not collected cannot leak, cannot
be subpoenaed, and cannot be wrong. For a tool whose output is sealed and travels, that is worth
something on its own.

**The parser's vocabulary narrows.** `ParsedSecurityDescriptor` has no SACL member and
`SecurityDescriptorParser` never reads header offset 12. That is now a decision rather than an
omission, and a reader who notices the missing constant has this record to find.

**— This record did not sweep what it invalidated, and should have.** Added 2026-08-13, the same
day, on re-reading. `AceType` still names `SystemAudit` (`0x02`) and `SystemAuditObject` (`0x07`),
and `DangerousPermissionClassifier` still has a branch returning *not dangerous* for them. After
this record there are no SACLs, so an audit-typed entry can only arrive inside a **DACL**, where it
is malformed.

**The verdict is right; its reason was not.** `[MS-DTYP]` §2.5.3.2 evaluates a DACL over allow, deny
and their object and callback forms — audit types take no part in it — and every Microsoft
description of `SYSTEM_AUDIT_ACE` places it in a SACL. Such an entry grants nothing wherever it
sits, so *not dangerous* is accurate. What was stale was the sentence beside it, *"an audit entry
records access; it grants none"*, which justified the answer by appeal to a structure this record
removed. Corrected in place.

**The vocabulary stays.** `IsObjectAceType` needs `0x07` to read the object-ACE body layout, and
removing it would have the trustee SID read from the object-flags field and a garbage value produced
in silence. Naming both types is also what lets the anomaly be found: `ace.ace_type` stores the type
by name.

**What is left is a finding, not a permission.** An audit entry inside a DACL means something wrote
a descriptor that should not exist. That is a fact about the customer's forest, and it is owed to
ledger row `E1` as `F-S21-7` in `S-21`.
