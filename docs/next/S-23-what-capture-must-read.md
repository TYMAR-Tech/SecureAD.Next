# S-23 — What capture must read, derived from the rules

**Type:** slice
**Reviewed at commit:** `HEAD` of `explore/design-challenges`
**Size:** 62 rule cards, plus the predecessor's writers that turn an attribute into a stored column
**Date:** 2026-08-13

## What it does

This session re-derives the **captured attribute catalogue** against the product rather than against
the rebuild's progress. Capture is the one thing that cannot be redone: an attribute not requested
is not in the bundle, is in no report, and nobody can go back and re-read last quarter. Until now
the catalogue was bounded by what a rebuild component could name as a consumer, and almost no
component is built — so the question *what does the product need?* had never actually been asked of
the sixty-two rules that define it.

Two of those rules turned out to be unanswerable. That is the finding this session exists for.

## Shape

- `CapturedAttributeCatalog` — the ceiling on everything the product can ever say. Version 2 as of
  this session.
- `CapturedAttributeCatalogDocumentationTests` — the gate binding it to
  [`S-8`](S-8-captured-attribute-catalogue.md). What counts as a consumer changed here.
- `CredentialAttributeGuardTests` — the guard that keeps a password out of a bundle. Strengthened
  here, because the catalogue now legitimately mentions LAPS.
- `S23CapturedAttributeDerivationTests` — new. Binds the two tables below to the catalogue in both
  directions.

## Dependencies

- **Depends on:** the sixty-two cards in `docs/rules/`; the predecessor's `DirectObjectWriter` and
  `DerivedAnalysisPipeline`, which are the only place the mapping from an attribute to a stored
  column is written down.
- **Depended on by:** C1, which cannot store what capture does not read; every rule at branch E.
- **Layering violations:** none. Nothing in `src/` was touched; it is frozen.

## How this was derived, and where the method is weak

**The cards do not name attributes.** The brief expected §4 *Data dependencies* to name the LDAP
attributes a rule reads. It does not. It names **columns in the predecessor's database** —
`dim_object.user_account_control`, `dim_delegation.delegation_type`, `fact_control_edge.source_sid`.
So a second step was needed: tracing each column back to the attribute it was written from.

That trace is a **reading**, not a search:

- `DirectObjectWriter.WriteEntry` (`src/SecureAD.Infrastructure/Storage/DirectObjectWriter.cs`
  117–173) and `ExtractAccountHygiene` (262–276) write the `dim_object` columns.
- `WriteDelegations` (299–361) is the whole of the `delegation_type` vocabulary. Each branch names
  its own source attribute in the `source_attribute` column, so the mapping is stated by the code
  rather than inferred: `Unconstrained`, `ProtocolTransition`, `NotDelegated`, `ASREPRoastable`,
  `Disabled` and `DontExpirePassword` all come from `userAccountControl`; `Constrained` from
  `msDS-AllowedToDelegateTo`; `RBCD` from `msDS-AllowedToActOnBehalfOfOtherIdentity`;
  `ShadowCredential` from `msDS-KeyCredentialLink`; `SPN` from `servicePrincipalName`; `AdminCount`
  from `adminCount`; `LapsEnabled` from the two LAPS expiration timestamps; `GmsaPasswordReader`
  from `msDS-GroupMSAMembership`.
- `DerivedAnalysisPipeline.cs:309` fills `dim_principal.display_name` from
  `ExtractNameFromDn(distinguished_name)`.

**Which rule filters on which `delegation_type`** was extracted from the cards' own SQL:

```
foreach($f in (git ls-files "docs/rules/SEC-*.md")){ $t=(Get-Content $f -Raw);
  $m=[regex]::Matches($t,"delegation_type\s*(?:=|IN)\s*\(?\s*'([A-Za-z]+)'(?:\s*,\s*'([A-Za-z]+)')?")
    | ForEach-Object { $_.Groups[1].Value; if($_.Groups[2].Success){$_.Groups[2].Value} }
    | Sort-Object -Unique;
  if($m){ "{0}: {1}" -f [IO.Path]::GetFileNameWithoutExtension($f), ($m -join ", ") } }
```

**Where the method is weak, stated rather than hidden.** The evaluator source for each of the
sixty-two rules was **not** read; the cards were. A card that misdescribes its own evaluator would
carry that error into this table. The cards are verification documents written against the code, so
this is a reasonable basis, but it is second-hand and the next session should know that. What was
read first-hand is the writer, which is the half where a silent mismatch would be invisible.

## The union — every attribute, and every rule that consumes it

`—` means no rule among the sixty-two consumes it; the *Consumed by* column then names what does.
*In catalogue* is the state **after** this session: three rows read `yes (added here)`, and those
three are the whole of what was missing.

<!-- DERIVATION:BEGIN -->

| Attribute | In catalogue | Rules that consume it | Consumed by, if no rule |
|---|---|---|---|
| distinguishedName | yes | every rule that joins `dim_object`, which is all sixty-two | — |
| objectGUID | yes | all sixty-two, as the join key | — |
| objectClass | yes | SEC-010, SEC-011, SEC-012, SEC-020, SEC-021, SEC-026, SEC-032, SEC-051, SEC-052, SEC-063, SEC-076, SEC-077, SEC-080, SEC-090, SEC-091, SEC-092, SEC-100, SEC-101, SEC-102, SEC-122, SEC-126, SEC-131, SEC-201, SEC-204 | — |
| objectCategory | yes | none directly; it is the single-valued answer `objectClass` cannot give | B20 |
| objectSid | yes | every rule that names a trustee or a member | B12 |
| nTSecurityDescriptor | yes | SEC-001, SEC-002, SEC-003, SEC-004, SEC-005, SEC-006, SEC-014, SEC-024, SEC-025, SEC-031, SEC-040, SEC-060, SEC-063, SEC-080, SEC-081, SEC-090, SEC-120, SEC-121, SEC-123, SEC-124, SEC-201, SEC-204 | — |
| sAMAccountName | yes | none read its value; thirty-three cards print it | B12, E19 |
| userAccountControl | yes | SEC-010, SEC-011, SEC-012, SEC-022, SEC-023, SEC-032, SEC-067, SEC-077, SEC-101, SEC-126, SEC-131 | — |
| adminCount | yes | SEC-030 | — |
| primaryGroupID | yes | none directly; it is an edge of the membership graph every membership rule reads | B11 |
| memberOf | yes | none directly; the reverse edge, carried so a cross-domain gap is seen rather than inferred | B11 |
| member | yes | none directly; the forward edge under SEC-003, SEC-004, SEC-005, SEC-006, SEC-013, SEC-021, SEC-023, SEC-030, SEC-050, SEC-051, SEC-052, SEC-061, SEC-062, SEC-063, SEC-100 | B11 |
| sIDHistory | yes | — | B12, E19 |
| servicePrincipalName | yes | SEC-020, SEC-021, SEC-026, SEC-126 | — |
| msDS-AllowedToDelegateTo | yes | SEC-010, SEC-011, SEC-012 | — |
| msDS-AllowedToActOnBehalfOfOtherIdentity | yes | SEC-010, SEC-011, SEC-013, SEC-122 | — |
| msDS-KeyCredentialLink | yes | — | E19 |
| msDS-SupportedEncryptionTypes | yes | — | E19 |
| pwdLastSet | yes | — | E19 |
| whenCreated | yes (added at S-51) | — | the object view, which asks when anything unexpected came into existence |
| description | yes (added at S-51) | — | the object view; the only field in the directory that says why an object exists |
| userPrincipalName | yes (added at S-51) | — | the object view, which has to name a principal the way an administrator will be given it |
| accountExpires | yes (added at S-51) | — | the object view, for whether the account has a lifetime at all |
| lastLogonTimestamp | yes (added at S-51) | — | the object view, for whether anybody still uses the account. `lastLogon` is refused: it is not replicated |
| msDS-GroupMSAMembership | yes | SEC-102 | — |
| groupType | yes | — | B11, E20 |
| operatingSystem | yes (added here) | SEC-091 | — |
| ms-Mcs-AdmPwdExpirationTime | yes (added here) | SEC-091, SEC-092 | — |
| msLAPS-PasswordExpirationTime | yes (added here) | SEC-091, SEC-092 | — |
| gPLink | yes | — | E21 |
| gPOptions | yes | — | E21 |
| displayName | yes | — | D3, E21 |
| gPCFileSysPath | yes | — | B14 |
| flags | yes | — | E21 |
| versionNumber | yes | — | E21 |
| gPCMachineExtensionNames | yes | — | B14 |
| lDAPDisplayName | yes | — | D3 |
| cn | yes | — | D3 |
| schemaIDGUID | yes | none directly; every rule matching an `object_type_guid` resolves through it | D3, J33 |
| attributeSecurityGUID | yes | none directly; SEC-090, SEC-123 and SEC-124 cannot expand a property set without it | D3 |
| isSingleValued | yes | — | D3 |
| searchFlags | yes | — | D3 |
| systemFlags | yes | — | D3 |
| rightsGuid | yes | none directly; SEC-002 and SEC-040 match extended rights through it | D3, J33 |
| validAccesses | yes | — | D3 |
| appliesTo | yes | — | D3 |

<!-- DERIVATION:END -->

The three rows marked `yes (added here)` were added to the catalogue this session, on the owner's
decision of 2026-08-13. Nothing else was added, and nothing was removed. Every other row was already
requested, which is the reassuring half of this table: the catalogue was three attributes short of
the product, not thirty.

## What each rule needs, by shape

`DESIGN-what-makes-a-finding.md` predicted three shapes of rule. The derivation agrees with it, with
one correction.

| Shape | Rules | What capture must have read |
|---|---|---|
| Permission rules | SEC-001 to SEC-006, SEC-014, SEC-024, SEC-025, SEC-031, SEC-040, SEC-060, SEC-063, SEC-080, SEC-081, SEC-090, SEC-120, SEC-121, SEC-123, SEC-124, SEC-201, SEC-204 | `nTSecurityDescriptor` and identity. Nothing else |
| Attribute rules | SEC-010 to SEC-013, SEC-020 to SEC-023, SEC-026, SEC-030, SEC-032, SEC-067, SEC-077, SEC-091, SEC-092, SEC-101, SEC-102, SEC-122, SEC-126, SEC-131 | One or two named attributes, listed above |
| Membership rules | SEC-050, SEC-051, SEC-052, SEC-061, SEC-062, SEC-070 to SEC-076, SEC-100 | `member`, `memberOf`, `primaryGroupID` and identity. **No security descriptor at all** |
| Group Policy rules | SEC-064, SEC-065, SEC-066, SEC-082, SEC-083, SEC-093 | Files in SYSVOL. Nothing in the directory answers them |
| Disabled | SEC-041 | Nothing; `enabled: false` in `rules.yaml` |

**The correction.** `DESIGN-what-makes-a-finding.md` says about a third of the rules need no graph.
That is right in outcome and wrong in composition: the group it describes as *capability rules* is
in fact the twelve membership rules plus the six Group Policy ones, and the Group Policy six need no
graph because they need no directory data at all. The document should be corrected rather than the
derivation.

## Verified-safe

Things checked and found correct, so they are not re-investigated.

- **Certificate templates are already served.** This was asserted once in conversation from a search
  and the brief asked for it to be read. `CaptureSearchRequestFactory.Build`
  (`next/src/SecureAD.Audit/Capture/CaptureSearchRequestFactory.cs` 142–176) bases every search at a
  naming context root with `SearchScope.Subtree`, and `CapturePlan` (`CapturePlan.cs:99`) makes the
  configuration partition a capture unit. `nTSecurityDescriptor` is in `Universal`. So a
  `pKICertificateTemplate` object is captured with its permissions, and SEC-040 has its data.
- **`name` is genuinely redundant.** `DerivedAnalysisPipeline.cs:309` fills
  `dim_principal.display_name` from `ExtractNameFromDn(distinguished_name)`. The predecessor never
  used the captured `name` for it. S-8's claim was correct.
- **The whole catalogue is requested on every object.** `CaptureSearchRequestFactory.Build` 155–158
  adds `CapturedAttributeCatalog.All`, not the class-specific subset. The class split in the
  catalogue is documentation of *why* an attribute is carried, not a request-time filter. This is
  what makes the cost of an addition predictable: an attribute an object does not have is simply not
  returned.
- **`lastLogonTimestamp`, `accountExpires`, `description`, `managedBy`, `userPrincipalName`,
  `whenCreated`, `whenChanged`, `dNSHostName`, `operatingSystemVersion`, the `msDS-ManagedPassword*`
  pair, `msDS-HostServiceAccountBL` and the password-policy sets are correctly dropped.** No card
  among the sixty-two reads any of them. S-8's reasons were right even where its evidence base was
  narrower than it looked.
- **The predecessor's `isDeleted` filter is a no-op, not a gap.** Twenty-one cards filter
  `is_deleted = 0`. Deleted objects live in a container that needs the Show Deleted Objects control,
  which capture does not send, so the column would be present and always false. Leaving `isDeleted`
  out changes no rule's verdict.

## Findings

### F-S23-1 — Two shipped rules could not be answered at all

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `SEC-091.md` §4 reads `dim_object.operating_system` and joins `dim_delegation` on
  `delegation_type = 'LapsEnabled'`; `SEC-092.md` §4 reads `laps.details` and compares it to
  `o.captured_utc`. `DirectObjectWriter.cs:345–351` shows `LapsEnabled` and its `details` come from
  `ms-Mcs-AdmPwdExpirationTime` and `msLAPS-PasswordExpirationTime`, and `operating_system` from
  `operatingSystem` at `:151`. None of the three was in `CapturedAttributeCatalog`. Both rules are
  enabled — only `SEC-041` carries `enabled: false` in `rules.yaml`.
- **What happens to a user:** a customer with no LAPS anywhere in the estate, or with LAPS installed
  and silently not rotating for a year, gets a report that says nothing about it. Not *unknown* —
  nothing. The rules run, join no rows, and produce no findings, which is indistinguishable from a
  clean result. This is the failure mode an audit tool must not have.
- **Why it is this way:** `F-S20-13` recorded the absence and explained it as *"an attribute with no
  rule yet written was correctly left out."* The premise is false. The rules are written; they are
  unported. The gate that produced the catalogue accepted only an inventory row as a consumer, and
  almost no inventory row is built, so the catalogue was bounded by the port's progress.
- **Options:** add the three attributes; or drop the two rules and say so. The owner chose to add
  them on 2026-08-13.
- **Test cover:** none before. `TheCatalogueTakesTheLapsTimestampAndNotTheLapsPassword` now pins the
  three in, and the password attributes beside them out.
- **Status:** REPAIRED — 2026-08-13. Catalogue version 2.

### F-S23-2 — The consumer gate measured the plan, not the product

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `EveryReaderNamedIsARealLedgerRow` checked a `Read by` cell against
  `OldAppInventory.LedgerStatuses().Keys` and nothing else. Of the inventory rows named across S-8's
  catalogue table, the great majority are `Not started`.
- **What happens to a user:** indirectly, `F-S23-1`. A gate that asks *can you name a rebuild
  component that will read this?* cannot admit an attribute the product needs and the rebuild has
  not reached, so every such attribute is silently correct to omit. The gate was doing its job and
  its job was the wrong one.
- **Why it is this way:** written when the rebuild had no rules, on the reasoning recorded in S-8 §3
  and in the test's own remarks: walking an empty set of rules would pass forever while measuring
  nothing. That reasoning is sound about *rule code* and was wrongly extended to *rules*, which
  exist as sixty-two cards.
- **Options:** none worth listing. A card is a real, checkable artefact.
- **Test cover:** `EveryReaderNamedIsARealLedgerRowOrRuleCard`, with the scanner self-test widened
  so that a document naming only inventory rows, or a pattern matching no rule identifier, fails rather
  than passing quietly.
- **Status:** REPAIRED — 2026-08-13.

### F-S23-3 — `F-S20-13`'s reasoning was wrong, and the finding understated the damage

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `S-20-what-a-bundle-stores.md` §`F-S20-13`, *"an attribute with no rule yet written
  was correctly left out"* and *"LAPS state and stale-account detection are the visible ones."*
- **What happens to a user:** nothing directly; it is a record that would have stopped the next
  reader from looking. It also graded itself `maintainability` when its LAPS half is
  `breaks-for-user`, and it treated LAPS and stale-account detection as one kind of problem when
  they are not: two shipped rules depend on the first, and none on the second.
- **Why it is this way:** the session that wrote it read the schema rather than the rule catalogue,
  which it says.
- **Options:** none. Recorded and referred.
- **Test cover:** not applicable.
- **Status:** REPAIRED — 2026-08-13. `F-S20-13` amended in place and its LAPS half closed here.

### F-S23-4 — Six captured attributes have no consumer in the product

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** no card among the sixty-two reads `sIDHistory`, `msDS-KeyCredentialLink`,
  `msDS-SupportedEncryptionTypes`, `pwdLastSet`, `groupType` or the `dim_delegation` type
  `ShadowCredential`. Checked with `git grep -l -- <column> "docs/rules/SEC-*.md"` per column and by
  the `delegation_type` extraction above, which returns no card for `ShadowCredential`.
- **What happens to a user:** nothing today, and that is the point. Three of these are named attack
  surfaces the product carries the data for and says nothing about — a shadow credential written to
  `msDS-KeyCredentialLink` is authentication as the account without touching its password, and the
  predecessor already projected it into `dim_delegation` for a rule that was never written. This is
  a **gap in the rule catalogue, not in capture.** The attributes should stay.
- **Why it is this way:** the predecessor's catalogue grew alongside its rules and outran them.
- **Options:** write rules for the three that matter, at branch E; or drop the attributes and accept
  a recapture if a rule is ever wanted. Dropping is the worse trade: they cost little and a bundle
  cannot gain them.
- **Test cover:** none possible until the rules exist. This is the other half of B2b.
- **Status:** OPEN — referred to E16 and E19, 2026-08-13.

### F-S23-5 — Six rules need SYSVOL, and nothing in the directory can answer them

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** SEC-064 and SEC-065 read `dim_gpo_setting` where `source_file = 'GptTmpl.inf'`,
  sections `Privilege Rights` and `Group Membership`; SEC-066 the `Registry Values` section; SEC-093
  a Registry.pol value; SEC-082 `fact_sysvol_ace`; SEC-083 `dim_gpo_setting`. All six declare a
  `Sysvol` coverage module. Inventory rows **B14** and **B15** are `Not started` and `(undecided)`.
- **What happens to a user:** a customer whose Group Policy grants `SeDebugPrivilege` to Domain
  Users gets no finding. Ten per cent of the rule catalogue is inert, and today nothing in the
  product says so.
- **Why it is this way:** deliberate. SYSVOL capture is a different mechanism — file access rather
  than LDAP — and is tracked separately.
- **Options:** the owner's answer on 2026-08-13 was that B14/B15 will get to them, and that saying
  something in a report now would be acceptable if it helps. **There is nothing to add to a report
  today**, because the rebuild has no reporting; so this is recorded here and against B14 as the
  wording that will be owed when there is somewhere to put it: *Group Policy settings were not
  assessed*, naming the six rules, rather than a silent absence of findings.
- **Test cover:** none. Nothing to bind yet.
- **Status:** OPEN — referred to B14, 2026-08-13.

## The five questions the brief asked

1. **Which rules need an attribute capture does not request?** Two: SEC-091 and SEC-092. Three
   attributes. Named per rule in `F-S23-1`, with the card as evidence. Every other rule's data is
   either captured or is SYSVOL.
2. **Which rules need no attribute beyond the universal set?** Twenty-two, the permission rules in
   the table above — a third of the catalogue, which matches `DESIGN-what-makes-a-finding.md` in
   outcome. Its composition claim is wrong and is corrected above.
3. **Which captured attributes does no rule consume?** Six with no consumer at all (`F-S23-4`), and
   a further group consumed by presentation or by derivation rather than by a rule — the schema and
   extended-rights sets belong to D3, the Group Policy container set to B14 and E21, the membership
   edges to B11. The two are told apart in the table's last column.
4. **Does any rule need something that is not an attribute?** Yes, and both known cases resolved.
   SYSVOL file contents: six rules, `F-S23-5`, B14/B15. Certificate template objects: **already
   served**, and verified by reading rather than assumed — see *Verified-safe*.
5. **What does the product refuse to read?** A LAPS password value. Capture now takes the LAPS
   expiration timestamps, which sit one suffix away from `msLAPS-Password` and `ms-Mcs-AdmPwd`. The
   owner's decision of 2026-08-13 is **never**, and it is a guard rather than a sentence:
   `CredentialAttributeGuardTests` forbids six LAPS names and asserts that the computer class takes
   the timestamps and none of the passwords.

## What the union costs

**Nothing measurable, and the reason is worth stating** because it is not what the brief expected.

The union is three attributes. All three exist on computer objects only, all three are short strings
— an operating-system name, and two FILETIME values of about twenty characters. An LDAP search does
not return an attribute an object does not have, so they cost nothing on the users, groups,
containers and vendor objects that make up most of a forest.

Against `S-20`'s measurement — a production domain, 100,000 objects, where parsed access-control
entries cost **4.81 GB** and deduplicated raw descriptors **0.63 GB** — a forest with, say, fifteen
thousand computers carrying all three attributes adds well under a megabyte. That is four orders of
magnitude below the smallest storage choice on the table.

**The general lesson, which outlives these three attributes.** The expensive thing a bundle holds is
`nTSecurityDescriptor`, and it is already captured on every object. An ordinary attribute is
therefore close to free, and the argument against adding one is not storage. It is the two real
costs S-8 already names: absence has to be told apart from withholding per
[`0002`](../decisions/0002-absent-view-means-degraded-run.md), and an attribute nobody removes sits
in every bundle forever. Both are reasons to require a consumer. Neither is a reason to refuse an
attribute two shipped rules cannot work without.

## The guards were mutation-tested in both directions

A guard is not shown to work by passing. Each check below was made to fail deliberately, the
mutation was confirmed to have reached the file before the result was believed, and every mutation
was reverted. All on 2026-08-13.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | `adminCount` pointed at `SEC-999`, which has no card | The rule half of the widened consumer check fires | `EveryReaderNamedIsARealLedgerRowOrRuleCard` fired |
| 2 | `adminCount` pointed at `Z99`, which is no inventory row | The ledger half still fires \u2014 the widening did not weaken it | `EveryReaderNamedIsARealLedgerRowOrRuleCard` fired |
| 3 | `adminCount` pointed at `B2`, which is `Done` | The decay guard still fires on an inventory row, and is not confused by the rule beside it | `NoAttributeStillWaitsForALedgerRowThatIsFinished` fired |
| 4 | The rule pattern changed to `^ZZZ-[0-9]{3}$`, so no identifier matches | The self-test fires rather than every check passing while the widening measures nothing | `TheCheckReadsBothTheCatalogueAndTheDocument` fired |
| 5 | `operatingSystem` relabelled `absent` in the derivation table | The absent-versus-present direction fires | `EveryAttributeTheDerivationCallsAbsentIsAbsentFromTheCatalogue` fired |
| 6 | A `notAnAttribute` row added, marked captured | The other direction fires | `EveryAttributeTheDerivationCallsCapturedIsInTheCatalogue` fired |
| 7 | The `member` row renamed, so the table stops accounting for it | Exhaustiveness fires | `TheDerivationAccountsForEveryAttributeTheCatalogueRequests` fired, and the captured-direction check fired with it |
| 8 | `adminCount` in the derivation pointed at `SEC-999` | The card check fires | `EveryRuleTheDerivationNamesIsARealCard` fired |
| 9 | The `DERIVATION:BEGIN` marker renamed | The parse refuses rather than silently reading nothing | **All eight** checks fired |
| 10 | `msLAPS-Password` added beside the timestamp in `ComputerAttributes` | The credential guard fires, and so does the new LAPS-specific check | `TheCatalogueNeverRequestsACredential` and `TheCatalogueTakesTheLapsTimestampAndNotTheLapsPassword` both fired |
| 11 | `operatingSystem` renamed in the catalogue | The pinning of F-S23-1's three attributes fires | Five checks fired, `TheAttributesThatUnblockTheLapsRulesAreCapturedAndAttributed` among them |

Mutation 9 is the one that matters most, and it is why the markers exist. S-23 holds four other
tables \u2014 the rule shapes, this one, and the findings \u2014 and a parser reading every table in the file
would have treated the rule-shape rows as attributes. A parser that lost its markers and read
nothing would have been worse: every check would have passed against an empty set.

**Two things went wrong doing this, and both are worth recording** because both are failures this
repository has had before and neither was caught by a test.

- **A revert threw away real work.** Mutation 1 was reverted with
  `git checkout -- docs/next/S-8-captured-attribute-catalogue.md`, which discarded not only the
  mutation but every uncommitted edit this session had made to that file. A mutation must be
  reverted by putting the original substring back, never by restoring the file from git, whenever
  the file also carries work that is not committed.
- **`Set-Content -Encoding utf8` corrupted a document.** Windows PowerShell 5.1 writes a BOM and
  re-encodes, and the file came back with every em dash mangled. `git diff --numstat` caught it
  \u2014 42 changed lines became 85 \u2014 which is exactly why the workspace rule says to check it after a
  scripted edit. Scripted edits to these documents now read and write bytes through
  `[IO.File]::ReadAllBytes` / `WriteAllBytes`.
- **A cancelled run left mutation 4 applied.** It was found by reading the file back rather than by
  any check, which is the same way S-8 records this happening once before. Mutations are now run one
  per command so a cancellation cannot strand one mid-script.

## Open questions for the owner

None outstanding. Four were put and answered on 2026-08-13: add the three attributes; never request
a LAPS password value and guard it; leave `whenCreated`/`whenChanged` out; and the Group Policy
wording, which is recorded in `F-S23-5` as owed to B14 because there is nowhere to put it yet.

## Not reviewed

- **The evaluator source of the sixty-two rules.** The cards were read; the code behind them was
  not. Stated above under *where the method is weak*.
- **Whether the rule catalogue is the right catalogue.** Out of scope by the brief; it is a product
  question.
- **The evidence schema at C1.** This session exists to give it a stable input, not to design it.
- **SYSVOL and Group Policy capture.** B14 and B15, deliberately untouched.
