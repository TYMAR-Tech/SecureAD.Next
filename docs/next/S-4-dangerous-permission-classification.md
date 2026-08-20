# S-4 — Dangerous-permission classification

**Type:** slice
**Reviewed at commit:** working tree, session S-4
**Size:** 2 files, 2 test files
**Date:** 2026-08-10

## What it does

Says whether a permission somebody holds in Active Directory hands them control.

Active Directory records a permission as a number and, sometimes, a GUID. Neither is readable, and
between them they are the difference between "may read this person's telephone number" and "may
reset the domain administrator's password". Every screen and every report in this product that
uses the word *dangerous* is making a claim, and a customer removes a delegation on the strength of
it. This component is the one place that claim is made.

`DangerousPermissionClassifier` is the classifier. `PermissionAssessment` is what it returns.
`PermissionVerdict` is the four things it is prepared to say. All three are in
`SecureAD.Kernel.Security`.

## Why this row is a Rebuild, and what it answers

The map's K16 entry is unusually blunt. The question was *do the three implementations agree*, and
the answer it records is **"the three do not agree, and there are not three of them but five"** —
with a sixth list in the rule SQL.

| # | Where | How it decided | What it missed |
|---|---|---|---|
| 1 | `PermissionClassifier.IsDangerous` | Bitmask only | Declared the extended-rights constant and never used it, so a DCSync grant was not dangerous. No `GenericWrite`, no `CreateChild` |
| 2 | `GuidCatalog.IsDangerous` | A flag per GUID | Never saw an access mask, so it could not tell reading an attribute from writing it |
| 3 | `AceAnalysisService.AggregateByTrustee` | Unioned 1 and 2 | The right answer, computed inside a user-interface aggregation service |
| 4 | `EffectiveAccessViewModel` (live) | Matched on rendered display strings | Its own list, its own reason strings |
| 5 | `StoredEffectiveAccessViewModel` (stored) | The same idea, a shorter list | Dropped `gPLink`, `userAccountControl` and `scriptPath`, and both unscoped cases |
| 6 | `AdvancedRuleEvaluator` SQL | A seventh set of names | Not reconciled with any of the five |

**4 and 5 are the live and stored effective-access panels, which exist to be compared against each
other.** A customer opening both to check whether a permission changed since the capture was
reading two different definitions of the word. That is worse than the disagreement between 1 and 2,
because the comparison is the feature.

There is now one classifier, it is in the kernel rather than in a view model, and it reads both the
mask and the GUID because neither answers the question alone.

## Shape

| Member | Answers | When it does not know |
|---|---|---|
| `DangerousPermissionClassifier` | Constructed with the catalogue it will read | — |
| `Classify` | The verdict for one entry, and why | `CannotClassify`, with the reason |
| `PermissionAssessment` | `Verdict`, `Reason`, `RightName` | `RightName` is `null` when the entry is scoped to the object rather than to a right |
| `PermissionAssessment.Dangerous` | Builds a takeover verdict | — |
| `PermissionAssessment.DangerousInCombination` | Builds a component-of-a-pair verdict | — |
| `PermissionAssessment.NotDangerous` | Builds an examined-and-safe verdict | — |
| `PermissionAssessment.CannotClassify` | Builds a not-assessed verdict | — |
| `EntryReach` | Whether an entry governs the object it is attached to, or only the objects beneath it | — |
| `EntryReachReader` | Reads `EntryReach` off the stored propagation flags | — |
| `EntryReachReader.FromPropagationFlags` / `FromPropagationFlags` | `DescendantsOnly` when `INHERIT_ONLY_ACE` is set, `ThisObject` otherwise | — |

### An entry does not govern every object it sits in the DACL of

`INHERIT_ONLY_ACE` means the entry **does not control access to the object it is attached to**
(MS-DTYP 2.4.4.1). It is there to be copied downward.

`Classify` therefore takes an `EntryReach`. It does **not** change the verdict — an inherit-only
grant of Modify Permissions hands over every descendant and is exactly as dangerous — but it
changes what the reason may claim, which is `S-56` R13. A `Dangerous` or `DangerousInCombination`
reason for a `DescendantsOnly` entry is prefixed to say the grant lands beneath rather than here;
`NotDangerous` and `CannotClassify` are left alone, because neither makes a claim about a local
grant that `INHERIT_ONLY_ACE` falsifies.

The three-argument overload asserts `ThisObject`, which is what an entry means unless the flag says
otherwise.

This was `F-S58-6`: the flags were read for the Scope column and never passed on, so a row could
show *All descendant objects* beside a mark asserting a grant on the object being looked at.

`PermissionVerdict` has four values and deliberately not two:

| Verdict | Means |
|---|---|
| `Dangerous` | This entry hands over the object, the account, the policy or the credential |
| `DangerousInCombination` | Not a takeover alone; a component of one. One entry can see neither the set of rights the principal holds nor the container it is written on |
| `NotDangerous` | Examined, understood, and not a takeover |
| `CannotClassify` | **Not assessed.** Never rendered as safe |

### Why a `bool` was forbidden

The map's complaint about the previous classifier is that an entry carrying a GUID the product did
not recognise "is currently not assessed and found safe, never examined". A boolean return has one
slot for both, so a permission nobody looked at and a permission somebody checked come back
identical, and the screen prints the same thing for each.

That is the same separation
[`0002`](../decisions/0002-absent-view-means-degraded-run.md) and
[`0004`](../decisions/0004-unknown-counts-name-the-failed-phase.md) already require everywhere else
in this product: *found nothing* and *could not compute* are never rendered alike. An unrecognised
GUID and an unexpanded mask are the second kind, so they get the second kind of answer, and the
verdict carries the reason so a reader can act on it.

## How it decides

Three stages, in order.

1. **The entry type.** A deny entry grants nothing. An audit entry grants nothing. An entry type
   Windows does not define is `CannotClassify`, because a type this code does not model may grant
   in a way it does not model either. A *conditional* allow entry is classified on its mask, because
   the condition can only narrow who the grant reaches and not crediting the narrowing over-reports
   rather than under-reports — but the reason **says** the applicability was never evaluated, which
   is what `S-56` v4 R1 requires and what `S-57` finding `#6` found missing. The verdict is
   qualified, not withdrawn; the grounds are recorded under `S-58` order 8.
2. **Object-independent bits.** Modify Permissions and Modify Owner mean the same thing whether or
   not the entry also names an attribute, so they are read first. Create Child and Delete Child were
   read here too until `S-57` finding `#8` — for those two the GUID names the class of child being
   created, so it narrows the grant and they moved to the scoped and unscoped arms.
3. **Scoped or unscoped.** With no object type, a write bit is a grant over *everything* — all
   properties, all validated writes, or all extended rights. With an object type, the mask bit says
   which kind of thing the GUID is being used as, and the catalogue is asked by GUID.

Generic rights are expanded before any of this, so `GENERIC_ALL` and the specific mask it stands for
reach the same verdict. That is what brings `GenericWrite`, absent from the previous bitmask
classifier, into the unscoped write case.

### One GUID, two meanings

`Self-Membership` and `member` are the same GUID. Which one an entry means is decided by its mask
bit — `ADS_RIGHT_DS_SELF` for the validated write, `ADS_RIGHT_DS_WRITE_PROP` for the attribute — and
the catalogue returns both meanings so the classifier can pick. This is why `SchemaGuidKind` is a
property of an entry rather than of a GUID, and it is the first consumer to need that.

### The nine names handed over by F-S3-2

None was dropped. Every one is asserted in a test.

| Name | Kind | Verdict | Where the assertion comes from |
|---|---|---|---|
| `User-Force-Change-Password` | extended right | Dangerous | [`SEC-003`](../rules/SEC-003.md) |
| `DS-Replication-Get-Changes` | extended right | DangerousInCombination | [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md), F-S3-7 |
| `DS-Replication-Get-Changes-All` | extended right | DangerousInCombination | as above |
| `Self-Membership` | validated write | Dangerous | [`SEC-006`](../rules/SEC-006.md) |
| `Validated-SPN` | validated write | Dangerous | [`SEC-024`](../rules/SEC-024.md), [`SEC-020`](../rules/SEC-020.md) |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | attribute write | Dangerous | [`SEC-014`](../rules/SEC-014.md), [`SEC-122`](../rules/SEC-122.md) |
| `msDS-KeyCredentialLink` | attribute write | Dangerous | [`SEC-025`](../rules/SEC-025.md) |
| `userAccountControl` | attribute write | Dangerous | [`SEC-022`](../rules/SEC-022.md), [`SEC-023`](../rules/SEC-023.md), [`SEC-067`](../rules/_NEXT.md) |
| `unicodePwd` | attribute write | Dangerous | Microsoft: *the password of the user*, update privilege *Domain administrator or account owner* |

Three names were added that the old flag did not carry, each because a rule specification names it:
`member` (SEC-006), `servicePrincipalName` (SEC-024) and `sIDHistory` (SEC-123). Two more —
`ms-Mcs-AdmPwd` and `msLAPS-Password` — are dangerous **to read**, per SEC-090, which is a case no
per-GUID flag could express at all.

**Four more reads were added 2026-08-18** —
`msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`, `msLAPS-EncryptedDSRMPassword` and
`msLAPS-EncryptedDSRMPasswordHistory` — at the same weight as the clear-text pair. Windows LAPS only
encrypts above a 2016 domain functional level with encryption enabled, and Microsoft states that
below it passwords can be stored **only** in clear text. The schema is extended either way, so these
attribute names prove nothing about what they hold. They reach an access control entry through the
`ms-LAPS-Encrypted-Password-Attributes` property set, which Microsoft publishes with
`Valid accesses: 48` — a property set, not an extended right. `msLAPS-Password` by contrast has no
`attributeSecurityGUID` and is only ever reachable directly.

**Property sets are no longer answered by a blanket rule.** Until 2026-08-18 every property-set write
was `Dangerous`, which put the product's loudest mark on the `SELF` grant of `Personal-Information`
that Active Directory creates on every user and computer. A set is now dangerous exactly when it
contains an attribute already on one of the lists above, with membership read from the forest's own
schema through `attributeSecurityGUID` rather than shipped. Reading a property set is judged for the
first time. See [`0075`](../decisions/0075-a-property-set-is-judged-by-what-a-forest-puts-in-it.md).

The rule SQL's sixth list contributed `CreateChild` and `DeleteChild`, taken from
[`SEC-060`](../rules/SEC-060.md), which names them takeover-class write access in its own words. The
classifier is therefore no longer narrower than the rules that run beside it.

## Dependencies

- **Depends on:** `SchemaGuidCatalog`, `SchemaGuidEntry`, `SchemaGuidKind` (K13/K14);
  `GenericRightsExpander` and `AceType` (K15). Nothing outside the kernel.
- **Depended on by:** nothing yet. Forecast J33, the row that decodes ACEs and aggregates them by
  trustee, per the surface register.
- **Layering violations:** none. The union of mask and GUID that the previous product computed
  inside a user-interface aggregation service is now computed in the kernel, which is the layering
  defect K16 names.

## Microsoft Learn verification

Everything below was checked against Microsoft's own documentation. Rows 1 to 7 were verified in the
preceding session and are carried with their sources; rows 8 to 12 were verified for this one.

| # | Claim | Verdict | Source |
|---|---|---|---|
| 1 | `searchFlags` `fCONFIDENTIAL` is 128 (0x80) | Confirmed | [adschema `searchFlags`](https://learn.microsoft.com/windows/win32/adschema/a-searchflags) |
| 1b | The RODC filtered bit is 512 (0x200) | **Derived, not cited.** The value is arithmetic from `904 = 8 + 128 + 256 + 512`; it is not in the `searchFlags` table | [LAPS technical reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference) |
| 2 | `msLAPS-Password` is confidential and in the RODC filtered set | Confirmed, stated outright as `SearchFlags 904` | [LAPS technical reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference) |
| 2b | `ms-Mcs-AdmPwd` has a published `searchFlags` value | **Refuted.** Microsoft calls it confidential but publishes no `searchFlags` and no filtered-set statement. No value for it may be presented as cited | [WS2025 confidential attributes](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc) |
| 3 | `DS-Replication-Get-Changes` = *"Extended right needed to replicate changes from a given NC"*; `-All` = *"allows the replication of secret domain data"*; `-In-Filtered-Set` carries **no description at all** | Confirmed | adschema extended-rights pages |
| 4 | `validAccesses` separates the kinds: extended right 256, property set 0x30 (16 \| 32), validated write 8 | Confirmed | [Control Access Rights (AD DS)](https://learn.microsoft.com/windows/win32/ad/control-access-rights) |
| 5 | Labels come from `Display-Name` on control access rights and from display specifiers for attributes | Confirmed, and **incomplete on localization** — display specifiers are stored per locale (409, 407, 411) | adschema / display specifiers |
| 6 | `schemaIDGUID` is System-Only, set by the system, cannot be changed | Confirmed | adschema `schemaIDGUID` |
| 7 | `gPLink` is *"a sorted list of Group Policy options"* on OU, Sam-Domain, Site and Configuration; linking needs modify permission on the container, held by default only by Domain and Enterprise Admins. `scriptPath` is *"the path for the user's logon script"*, update privilege *"Domain administrator or account owner"* | Confirmed | adschema `gPLink`, `scriptPath`; GPMC documentation |
| 8 | `ADS_RIGHT_WRITE_DAC` = 0x40000, `ADS_RIGHT_WRITE_OWNER` = 0x80000, `ADS_RIGHT_DS_CONTROL_ACCESS` = 0x100, `ADS_RIGHT_DS_SELF` = 8, `ADS_RIGHT_DS_READ_PROP` = 16, `ADS_RIGHT_DS_WRITE_PROP` = 32, `CreateChild` = 1, `DeleteChild` = 2 | Confirmed | [`ADS_RIGHTS_ENUM`](https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum), [Exchange permissions reference](https://learn.microsoft.com/exchange/exchange-2013-deployment-permissions-reference-exchange-2013-help) |
| 9 | An entry with no `ObjectType` GUID controls **all** operations of that kind, not one | Confirmed, stated for `CONTROL_ACCESS`, `SELF`, `READ_PROP` and `WRITE_PROP` individually | [`ADS_RIGHTS_ENUM`](https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_rights_enum) |
| 10 | The owner of an object has the implicit right to modify its DACL | Confirmed — which is why Modify Owner is classified alongside Modify Permissions | [Security Descriptor Components](https://learn.microsoft.com/windows/win32/ad/security-descriptor-components) |
| 11 | `unicodePwd` is the user's password; update privilege *"Domain administrator or account owner"*; can be replaced outright by a caller with sufficient rights *"regardless of what the old password was"* | Confirmed | [Unicode-Pwd attribute](https://learn.microsoft.com/windows/win32/adschema/a-unicodepwd), [changing a password through LDAP](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password) |
| 12 | `msDS-AllowedToActOnBehalfOfOtherIdentity` is *"used for access checks to determine if a requestor has permission to act on the behalf of other identities to services running as this account"*, and the KDC always allows protocol transition for resource-based constrained delegation | Confirmed | [adschema attribute](https://learn.microsoft.com/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity), [Kerberos constrained delegation overview](https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview) |

**Sources deliberately not cited.** No Microsoft source states that
`DS-Replication-Get-Changes` plus `DS-Replication-Get-Changes-In-Filtered-Set` reads LAPS passwords.
Learn is silent on it, not contradictory. Nothing in this component cites Microsoft for it, per
[`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md).

## Verified-safe

Checked and found correct, so they are not re-investigated.

- **The verdict cannot collapse safe into unknown** — `PermissionVerdict` has four members and the
  classifier's scanner self-test asserts that the four cases it runs produce all four of them, so a
  classifier that answered `CannotClassify` to everything would fail.
- **No GUID literal escaped into production** — `SchemaGuidSingleSourceGateTests` scans
  `next/src/`, and the classifier asks the catalogue by LDAP name only.
- **The shared GUID is read correctly under both masks** —
  `TheSharedGuidIsReadAsTheValidatedWriteUnderSelfAndAsTheAttributeUnderWriteProperty`.
- **`GENERIC_ALL` and the expanded mask agree** — expansion happens before any bit is read, so the
  same permission written two ways reaches one verdict.
- **`WRITE_DAC` inside an object-scoped entry is still dangerous** —
  `WriteDaclIsStillDangerousInsideAnObjectScopedAce`. Naming an attribute alongside it does not
  narrow it, and reading the scoped path first would have hidden it.

### Mutation testing

Every new guard was broken on purpose and watched to fail, then repaired and watched to pass. Both
directions were observed for each; a guard only seen passing has not been shown to measure
anything.

| Guard | Broken by | Observed |
|---|---|---|
| `EveryFindingCarriesAnIdentifier` | Renaming `### F-S4-5` to `### Note:` | Failed on the mutation, passed on repair |
| `WritingADangerousAttributeIsDangerous` and `EveryNameHandedOverByTheCatalogueIsWrittenDownAndReachesAVerdict` | Removing `userAccountControl` from the dangerous set | **Both** failed on the mutation, so the document check is an assertion about behaviour and not only about prose. Passed on repair |
| `WhenTheObjectTypeGuidIsNotInTheCatalogueThenItCannotClassify` and `TheCheckExercisesEveryVerdictAndTheCatalogueKnowsTheNames` | Making an unrecognised GUID return `NotDangerous` — the exact defect K16 exists to remove | Both failed on the mutation, passed on repair |
| `TheCheckedListIsTheWholePublicSurface` | Dropping `PermissionVerdict` from the covered lists | Failed on the mutation, passed on repair |

A first attempt at the first mutation appeared to pass, and the edit had silently not applied. That
is recorded because it is the failure mode the repository has met twice: a check reporting success
while measuring nothing. The mutation was confirmed present in the file before the result was
believed.

## Findings

### F-S4-1 — `SEC-002` and `SEC-076` disagree about what DCSync is

- **Severity:** major
- **Status:** OPEN, owned by inventory row E18, which carries it as a prerequisite. Not resolved here,
  and nothing in this component assumes either has won. Checked 2026-08-10

[`SEC-002`](../rules/SEC-002.md) fires on any pair from `{GetChanges} x {GetChangesAll,
GetChangesInFilteredSet}` and surfaces `has_get_changes_in_filtered_set` in its context.
[`SEC-076`](../rules/SEC-076.md) requires the `GetChangesAll` pair, explicitly declines the
filtered-set case, and records the divergence as `[IMP-DCSYNC-FILTERED-SET]`, noting it "requires a
product-level decision".

Each is source of truth for its own rule, so the product currently holds two definitions of DCSync
and will report differently depending on which rule fires.

**What Microsoft says, gathered while writing this row.** It leans towards `SEC-076`, and it is
evidence rather than proof:

- Microsoft names the DCSync pair in two places and names the same two rights both times. The
  Secure Score assessment *Remove non-admin accounts with DCSync permissions* instructs the reader
  to uncheck **Replicating Directory Changes** and **Replicating Directory Changes All**; the
  *Suspected DCSync attack* alert lists the same two under prevention. The filtered-set right is
  mentioned in neither.
- A read-only-domain-controller troubleshooting article gives the mechanism behind that pair without
  discussing attacks at all: an RODC granted **Replicating Directory Changes All** replicates *"all
  user attributes, including passwords"*, and the documented fix is to downgrade the grant to plain
  **Replicating Directory Changes**. So `Get-Changes` alone is the safe half and `Get-Changes-All`
  is the secret-bearing half, which matches the schema page's *"allows the replication of secret
  domain data"*.
- **Against `SEC-002` specifically:** a replication-error article lists the DACL present on every
  directory partition **by default** in Windows Server 2008 and later, and
  `Replicating Changes in Filter Set` is in that list. `SEC-002`'s extra pair therefore fires on a
  permission Microsoft ships, granted so that read-only domain controllers work.

**What is still true about the other side.** `msLAPS-Password` is documented as being in the RODC
filtered attribute set, and a right named for replicating the filtered set plausibly replicates it.
The theory is coherent. It is simply not written down by Microsoft anywhere, which is why
[`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) withdrew
the word "documented" from it.

**How it gets settled, and when.** Granting a test principal exactly
`Get-Changes` + `Get-Changes-In-Filtered-Set` in a lab forest and attempting the read. It does not
block anything today and it must happen before the DCSync rule is rebuilt, so it is written into
E18's inventory row as a prerequisite rather than left in a finding — a caveat that lived only in a
finding has already been stripped off once in this repository, which is what `0016` exists to
record.

K16 is written so that it does not have to take a side. All three replication rights return
`DangerousInCombination`, which says *this is a component of something and the set decides* without
naming which sets qualify.

### F-S4-2 — The per-principal half of the question has no owner

- **Severity:** major
- **Status:** OPEN, owned by inventory row D7 since 2026-08-10. Checked 2026-08-10

This component classifies one entry. `DangerousInCombination` is a promise that something else
looks at the set a principal holds, and nothing does yet.

Until that lands, three replication rights are correctly *not* called safe and are also not called
dangerous, which is the honest answer but not a complete product.

**The obligation now has a home.** It is written into inventory row **D7**, control-edge derivation,
which is where ACEs first become per-principal facts, and `OwedFindingHomeTests` fails the build if
that row stops naming it. This follows the DCSync lab check, which was written into E18's row for
the same reason: a caveat that lives only in a finding has already been stripped off once in this
repository.

This is F-S3-7's reasoning carried forward: the danger is a property of the combination, and the
old table had one tick box per GUID and no way to express a pair. Moving the classification into
code fixed the shape. It did not by itself supply the second half.

### F-S4-3 — Decision 0014 is incomplete on localization

- **Severity:** minor
- **Status:** OPEN, owner question. Checked 2026-08-10

[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) says capture reads the friendly
labels from the directory, and speaks of display specifiers as one set. They are not one set:
Active Directory stores them per locale, under containers named for the locale identifier — `409`
for English (United States), `407` for German, `411` for Japanese — and a forest can hold several.
Shipped control access rights additionally carry `localizationDisplayId`, which points into
`Dssec.dll` rather than into the directory.

So "capture reads the display specifiers" does not yet say *which*. This affects what a report
prints, not what this classifier decides, which is why it is minor and why the classifier keys on
LDAP names rather than on labels.

### F-S4-4 — A conditional entry's condition is not evaluated

- **Severity:** minor
- **Status:** OPEN, accepted for now. Checked 2026-08-10

A callback ACE grants what its mask says only when a condition expression evaluates true. This
product does not parse those expressions, so a conditional allow entry is classified on its mask
alone.

The consequence is over-reporting: a permission that in practice reaches nobody may be reported as
dangerous. That is the safe direction, and it is recorded so the next reader knows it is a decision
rather than an oversight. The unsafe direction — treating a conditional entry as unclassifiable, so
a conditional Full Control renders as "could not compute" — was rejected.

### F-S4-5 — The surface register cannot say "consumed by something that does not run"

- **Severity:** minor
- **Status:** OPEN, recorded rather than repaired. Checked 2026-08-10

Three register entries — `SchemaGuidCatalog`, `SchemaGuidEntry`, `SchemaGuidKind` — named K16 as the
row that would consume them. K16 has now consumed them, and the register had no way to say so.

Gate 5a holds two checks that pull against each other at exactly this moment. One requires every
public type to have an entry. The other fails an entry whose awaited row is Done, on the reasoning
that the promise has come due and the entry should go. Together they mean the first type in the
rebuild ever to acquire a consumer cannot satisfy both.

The resolution taken is to move the forecast from K16 to J33 rather than to delete the entries,
because it is the truer statement: gate 5's real question, as `README.md` records at length, is
**what a running consumer can reach**, and a library reading a library does not answer it. That is
the precise wording failure that made the original single gate pass against a tree in which nothing
was used at all. Nothing in `next/` runs yet, so nothing here is reachable yet, and the register
should go on saying so.

What remains unresolved is that the gate will meet this again on every component, and each time a
session will decide it by hand. The wording that would fix it — an entry naming the row that
consumes it, and a separate mark for reached-from-a-root — belongs with gate 5b, which is blocked
on there being a root at all.

## Open questions for the owner

### Settled 2026-08-10 — `gPLink` and `scriptPath` are dangerous to write

**The owner confirmed both.** This was the one judgement in this row that was not mine: the live
effective-access panel called both dangerous, the stored panel did not, so the two screens a
customer opens to compare each other gave different answers about the same permission. The
classifier settles it in favour of the wider reading, and that is now a decision rather than a
placeholder.

The reasoning, kept because a settled question with no reasoning behind it is a question that gets
reopened:

- `scriptPath` is, in Microsoft's words, *"the path of the user's logon script, .cmd, .exe, or .bat
  file"*. Whoever can write it chooses what program runs, as that user, at their next logon. Its
  update privilege is documented as *"Domain administrator or account owner"* — Microsoft's own
  expectation of who edits it.
- `gPLink` is *"a sorted list of Group Policy options"*, and it exists on organizational units, the
  domain itself, sites and the Configuration container. Microsoft's Group Policy documentation
  states that linking a policy requires modify permission on the container, that by default only
  Domain and Enterprise Admins hold it, and that whoever does can link policies, change link order
  and set block inheritance.
- The vector everyone overlooks is **unlinking**. Removing a link needs no right to create a policy,
  no right to edit one, and leaves nothing obviously wrong behind. A hardening policy that is no
  longer linked simply stops applying, and the next audit sees machines that were compliant last
  month and are not now, with no misconfiguration to point at.

The cost accepted is noise: delegated organizational-unit administration legitimately involves both,
so environments that delegate properly will see these permissions reported. The cost rejected is the
thing an audit tool must not do — a real code-execution path reported as safe. Dropping live LDAP
would otherwise have left the *narrower* of the two old definitions as the only one, silently
shrinking what the product calls dangerous, which is the trap the map warns about in this exact
entry.

If these should later rank below a password reset rather than beside it, that is a shape this
component can carry and it needs a severity concept it does not have yet. Recorded under *Not
reviewed*.

### Open — nothing in this component

No question in K16 is waiting on the owner. The DCSync question is real and is not this component's:
it is a prerequisite on inventory row E18, where the rule is rebuilt.

## Not reviewed

- **Whether a principal is dangerous.** Only entries are classified here. The per-principal
  question is F-S4-2.
- **Severity.** Every dangerous verdict is equally dangerous to this component. Ranking a
  password reset against a logon-script write belongs with the rules, which already have severity.
- **The target.** Whether the object an entry sits on is Tier-0 changes what the permission is
  worth, and the classifier is not given it. That is deliberate: it keeps this component a pure
  function of the entry, which is what makes it testable, and tiering is E's.
- **Ownership.** An object's owner has the implicit right to modify its DACL, which the rule SQL
  models as an `Owns` control edge. Ownership is not in an ACE, so it is not visible here.
- **Deny that cancels an allow.** A deny entry grants nothing and is classified as such. Whether a
  deny elsewhere in the DACL cancels an allow is a property of the list, not the entry, and the
  rules already model it as `deny_cancelled`.
