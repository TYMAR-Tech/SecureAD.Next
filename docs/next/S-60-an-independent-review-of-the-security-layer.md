# S-60: An independent review of the security layer

**This session read code and Microsoft sources. It changed nothing.** No fix in this document has
been applied. Findings are recorded so that a later session can act on them against evidence rather
than against this session's reasoning.

Reviewer: automated review session, run against branch `explore/design-challenges`.

---

## Why this session exists

An external review was commissioned over the whole repository, to a standard requiring that every
finding establish **actual code behaviour → authoritative Microsoft-documented behaviour →
discrepancy → practical impact**, and that no finding rest on memory, on a search snippet, on a
symbolic name, or on an internal specification.

The repository is approximately 200,000 lines of C# across two product generations and seventeen
projects. That standard cannot be honestly met over that surface in one pass, so the scope was cut
by the owner before any finding was written:

| Decision | Value |
| --- | --- |
| Generation | `next/` only — `Kernel`, `Evidence`, `Audit`, `Cli`, `Shell` |
| Layer | Shared AD security logic only |
| Internal design documents | Excluded — code and Microsoft sources only |
| Peripheral projects | Excluded — `BenchmarkSuite1`, `LabExtract`, `TestDbGenerator`, `SchemaProbe`, `Gallery`, `tools/*.ps1` |
| Cadence | A complete report per session, with explicit coverage accounting |

**Internal design documents were deliberately not read.** This is unusual for a review of this
codebase and it is the point: the rest of `docs/` records what the product intends, and a reviewer
who reads it inherits the product's assumptions. Every claim below was checked against Microsoft or
against the code, never against a brief. Where a question turned out to be one only the owner could
answer, it was asked rather than guessed — see *Validated-DNS-Host-Name* under
**Adjudicated during review**.

---

## The finding in one paragraph

The *logic* of the security layer is sound. Across roughly 3,200 lines of security-critical code,
no defect was found in security descriptor parsing, access-mask interpretation, generic-right
mapping, ACE ordering, deny handling, inheritance semantics or classification structure. The
behaviours most often wrong in Active Directory tooling are right here. **The defects are in the
data.** Two entries in the shipped schema catalogue publish real Microsoft GUIDs under wrong
extended-right names, one of them a name that does not exist in Active Directory, and they survived
because the catalogue has no correctness anchor to Microsoft at all.

---

## Findings

| ID | Severity | Confidence | Summary |
| --- | --- | --- | --- |
| `F-S60-1` | Medium | High | Two catalogue entries map correct GUIDs to wrong extended-right names |
| `F-S60-2` | Low | High | The catalogue is never validated against Microsoft |
| `F-S60-3` | Low | High | `AclSize` and `AclRevision` are never read; the DACL walk is bounded by the descriptor |
| `F-S60-4` | Informational | High | SACLs are not parsed, while audit ACE types are modelled |

---

### `F-S60-1` — Two catalogue entries name the wrong extended right

**Severity** Medium **Confidence** High

**Where.** `next/src/SecureAD.Kernel/Schema/SchemaGuidCatalog.cs`, `EmbeddedEntries()`:

- line 280 — `ExtendedRight("fec364e0-0a98-11d1-adbb-00c04fd8d5cd", "DS-Replication-Get-Changes-All-Extended")`
- line 285 — `ExtendedRight("ee914b82-0a98-11d1-adbb-00c04fd8d5cd", "DS-Replication-Monitor-Topology")`

Consumed by `DangerousPermissionClassifier.ClassifyScoped` line 514 → `ClassifyExtendedRight`
lines 598–617, and by `PermissionWording.Describe` line 195 for the displayed name.

**What the code does.** The catalogue asserts these GUID-to-name mappings.
`ClassifyExtendedRight` then matches the *name string* against `DangerousExtendedRights` and
`ReplicationRights`. Neither fabricated name is in either set, so both resolve to
`PermissionVerdict.NotDangerous`, with the reason string interpolating the incorrect name.

**What Microsoft documents.**

| GUID | The catalogue claims | Microsoft documents |
| --- | --- | --- |
| `fec364e0-0a98-11d1-adbb-00c04fd8d5cd` | `DS-Replication-Get-Changes-All-Extended` | **`Do-Garbage-Collection`** |
| `ee914b82-0a98-11d1-adbb-00c04fd8d5cd` | `DS-Replication-Monitor-Topology` | **`Abandon-Replication`** |
| `f98340fb-7c5b-4cdb-a00b-2ebdfa115a96` | *absent from the catalogue* | **`DS-Replication-Monitor-Topology`** |

Further, **`DS-Replication-Get-Changes-All-Extended` does not exist.** It is absent from
Microsoft's canonical *Extended Rights* index, which enumerates every extended right Active
Directory defines. The name appears to have been invented.

**Analysis.** Both GUID *values* are real and correctly formatted; the *names* bound to them are
wrong. Value correctness and meaning correctness are separate questions, and here the value is
right while the meaning is wrong.

The surrounding cluster was checked to establish that this is isolated rather than systemic.
`DS-Replication-Synchronize` (`1131f6ab-…`) and `DS-Replication-Manage-Topology` (`1131f6ac-…`) are
**correct**. Most importantly `DS-Replication-Get-Changes-All`
(`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`) is **correct**, so the DCSync pair `ReplicationRights`
exists to detect is intact.

**Practical impact.** Bounded, and worth stating precisely rather than inflating.

*No verdict changes.* Both paths yield `NotDangerous`, and the true rights — garbage collection and
cancelling a replication sync — are also not takeover-class. No permission is wrongly cleared and
none is wrongly flagged.

*The impact is on reported evidence.* An auditor reading an ACE on an `NTDS-DSA` object sees the
product name a right `DS-Replication-Get-Changes-All-Extended` and mark it not dangerous. That name
is close enough to `DS-Replication-Get-Changes-All` — the actual DCSync right — to be misread in
either direction: as a replication grant the product examined and cleared, or as evidence of
replication coverage the product does not have on that GUID. The product is stating a specific
factual claim about which right an ACE grants, and the claim is false.

*One genuine right is uncovered.* An ACE granting the real `DS-Replication-Monitor-Topology`
(`f98340fb-…`) resolves to `CannotClassify` — *"The object type is not in the schema catalogue… It
is not being reported as safe."* This is the correct and safe outcome, and it is worth recording
that the fail-safe design absorbs the gap rather than converting it into a false negative.

**Conceptual correction.** Correct line 280 to `Do-Garbage-Collection` and line 285 to
`Abandon-Replication`; add `DS-Replication-Monitor-Topology` under
`f98340fb-7c5b-4cdb-a00b-2ebdfa115a96`. `SchemaGuidCatalog.Version` is documented as incrementing
"when entries are added, removed or corrected", and a bundle records which table named its GUIDs,
so the version should move. **The durable fix is `F-S60-2`, not these three lines.**

**Validation notes.**

- No test references either incorrect GUID or either incorrect name. No test encodes this error;
  equally, no test would have caught it.
- The captured schema layer takes precedence over the shipped table (`SchemaGuidCatalog`
  lines 107–122). Exposure is therefore limited to runs that did **not** read the schema partition,
  and to offline bundle re-reads falling back to the embedded table. This materially reduces impact
  and is the main reason this is not rated High.
- The catalogue holds **100 entries** — 37 extended rights, 30 attributes, 15 property sets,
  13 object classes, 5 validated writes. **26 were verified; 74 were not.** This count was measured
  rather than estimated; an earlier draft of this document said "roughly 60" from inspection and
  was wrong.

---

### `F-S60-2` — The catalogue has no correctness anchor to Microsoft

**Severity** Low **Confidence** High

**Where.** `next/tests/SecureAD.Next.Tests/Kernel/Schema/SchemaGuidCatalogTests.cs` — full test
surface, seventeen tests, reviewed by signature; `SchemaGuidCatalog.EmbeddedEntries()`.

**What the tests do.** They validate the catalogue thoroughly on **structure** and
**self-consistency**: every GUID parses, every GUID is lowercase, every entry has an LDAP name, no
LDAP name is used twice, no GUID repeats within one kind, nothing is unclassified, every kind is
represented, multi-meaning lookups return all meanings, and previously-corrected GUIDs do not
regress.

The single test validating *content* is
`WhenARuleSpecificationNamesAGuid_ThenTheCatalogueAgreesWithIt`, which checks the catalogue against
**internal rule specifications**.

**Analysis.** A correct algorithm over incorrect static data is still incorrect, and an internal
specification is evidence of intended behaviour rather than Microsoft truth. The catalogue's
content is anchored only to internal rule specs.

This produces a coverage hole with a precise shape: **an entry is validated if and only if some
rule spec names it.** Rule specs name dangerous rights. Therefore every *non-dangerous* entry — the
majority of the table — is unanchored. That is exactly the set `F-S60-1`'s two errors fall into,
and it is why a suite this thorough did not catch them.

The existing `WhenAGuidWasShippedWrongOnce_ThenTheCatalogueDoesNotResolveToItAgain` test shows this
class of error has occurred before and was corrected reactively. The gap is that detection depends
on someone noticing.

**Practical impact.** Low today: the verdict-driving entries *are* anchored via rule specs, and
captured forest schema overrides the shipped table when available. The impact is latent — it is the
mechanism by which incorrect names reach an auditor's screen undetected, and it will not improve as
the table grows.

**Conceptual correction.** Anchor the shipped table to Microsoft's published values rather than
only to internal specs — pin each entry's GUID and name against *Extended Rights*, *Property Sets*
and *Validated Writes*, so a wrong or invented name fails the build. At minimum, assert that every
`ExtendedRight` entry's name appears in Microsoft's published set; that alone would have caught
`DS-Replication-Get-Changes-All-Extended`, a name that does not exist.

**Validation note.** Test surface enumerated by signature; bodies were not read. A content
assertion hidden inside a structurally-named test is not excluded, though the naming discipline
throughout makes it unlikely.

---

### `F-S60-3` — `AclSize` and `AclRevision` are never read

**Severity** Low **Confidence** High

**Where.** `next/src/SecureAD.Kernel/Security/SecurityDescriptorParser.cs` — `Parse` line 109
(`var daclSpan = rawSd[(int)daclOffsetValue..];`) and `ParseAcl` lines 215–258, particularly
line 226.

**What the code does.** `Parse` slices the DACL span from the DACL offset **to the end of the whole
security descriptor buffer**. `ParseAcl` reads only `AceCount` at ACL header offset 4. The ACE walk
is bounded by `AceCount` and by `offset + aceSize > acl.Length`, where `acl.Length` is the
remainder of the descriptor, not of the ACL. `AclRevision` at offset 0 and `AclSize` at offset 2
are never read.

**What Microsoft documents.** `[MS-DTYP]` 2.4.5 states normatively:

> In the absence of implementation-specific functions to access the individual ACEs, access to each
> ACE **MUST** be computed by using the **AclSize** and **AceCount** fields to parse the wire
> packets following the ACL to identify each ACE_HEADER…

and defines `AclSize` as "the size, in bytes, of the complete ACL, including all ACEs". The same
section constrains `AclRevision` to `ACL_REVISION` (`0x02`) or `ACL_REVISION_DS` (`0x04`), and
states that object ACE types `0x05`–`0x08` are permitted only under revision `0x04`.

**Analysis.** The specification names `AclSize` and `AceCount` together as the required basis for
locating ACEs. The implementation uses `AceCount` alone, substituting the descriptor's end for the
ACL's end.

For a well-formed descriptor from a domain controller these agree, which is why this does not
surface in practice or in the tests. They diverge when `AceCount` overstates the true count *and*
the DACL is not the terminal structure: the walk then continues past `AclSize` into whatever
follows. `[MS-DTYP]` 2.4.5 states the SACL "MUST NOT contain ACEs that belong in the DACL", so
bytes read across that boundary would be ACE types the DACL semantics do not model.

Two consequences share this root cause:

1. **Over-read.** ACEs beyond the DACL's declared extent may enter `parsed.DaclAces` and flow
   through `AceNormalizer` into classification.
2. **Completeness is mis-asserted.** `Parse` line 131 sets `DaclCompleteness.Complete` when
   `aces.Count == declaredAceCount`. If the shortfall was made up from out-of-bounds bytes, the
   descriptor is reported as completely read when it was not.

**Practical impact.** Low and bounded. Not exploitable against descriptors from a healthy DC, and
no path was found where it changes a verdict on well-formed input. It matters for replay of a
stored or third-party bundle containing a hand-crafted descriptor, and for genuinely corrupt data.
In both cases the failure runs against the grain of this file's design intent: the parser goes to
considerable lengths to ensure uncertainty is never reported as fact, and this is the one place
where a malformed descriptor can be reported as `Complete`.

**Conceptual correction.** Treat the ACL header as a structure. Bound the DACL span to
`min(AclSize, remaining buffer)` before walking. Read `AclRevision` and record an unexpected value
as an error, as SD revision already is at lines 54–58. Where `AclSize` is itself inconsistent with
the buffer, that is `Unknown`, not `Complete`.

**Validation notes.**

- Traced `Parse` line 109 → `ParseAcl` line 220 → the loop bound at line 241. No caller
  compensates: `Parse` is the sole production caller, and `AceNormalizer.Normalize` consumes
  `parsed.DaclAces` without re-validating extent.
- `SecurityDescriptorParserTests` was not read line-by-line. A test pinning current behaviour would
  not change the finding but should be identified before correcting.
- **Open question**, see below: whether any capture path can produce a descriptor where the DACL is
  followed by a SACL in the same buffer.

---

### `F-S60-4` — SACLs are not parsed, while audit ACE types are modelled

**Severity** Informational **Confidence** High

**Where.** `SecurityDescriptorParser.Parse` reads only `DaclOffsetField` (offset 16);
`AceType.cs` lines 16–17 and 25–26.

**What the code does.** The SACL offset at header offset 12 is never read and `ParseAcl` is never
invoked for a SACL. The `AceType` enum nonetheless defines `SystemAudit` (`0x02`) and
`SystemAuditObject` (`0x07`), and `DangerousPermissionClassifier.IsAudit` handles audit types.

**Analysis.** This is not a defect. Not parsing the SACL is a legitimate scope decision, and audit
ACEs are correctly excluded from access analysis. It is recorded because the enum and the `IsAudit`
handling imply a capability the parser does not exercise, and because it is a coverage boundary a
reader of this document should know: **no audit-configuration conclusion can be drawn by this
layer.** `IsAudit` is defensive rather than dead — the classifier is callable directly.

---

## Adjudicated during review

Two questions could not be settled from code and Microsoft sources alone. Both were put to the
owner rather than guessed.

### Validated-DNS-Host-Name — closed, not a defect

`DangerousValidatedWrites` contains `Self-Membership` and `Validated-SPN`. Microsoft documents
exactly three validated writes in the base schema; the third, `Validated-DNS-Host-Name`, is absent
from the set — though it *is* present in the catalogue, at line 320.

This turns on product intent, not Microsoft semantics. Microsoft documents that the right exists;
it does not classify it as dangerous. Two readings were available: a deliberate judgement scoped to
rule-spec-identified takeover vectors, or a gap.

**Owner decision: not considered a dangerous write.** Closed as intended behaviour. The decision
was expressed with some hesitation; if it is revisited, the change is one line and the reasoning
should be recorded alongside the `gPLink` / `scriptPath` decision of 2026-08-10 in
`S-4-dangerous-permission-classification.md`.

### Whether a captured DACL can be followed by other ACL data — still open

Relevant to `F-S60-3`. Exposure depends on whether `ntSecurityDescriptor` is ever retrieved with
SACL data present — that is, whether any `SecurityMasks` / `SDFlags` setting used on capture
searches includes `Sacl`. That lives in
`next/src/SecureAD.Audit/Capture/CaptureSearchRequestFactory.cs`, which is in the collection layer
and outside the declared scope. **Unresolved.**

---

## Confirmed correct

Recorded because a review that only lists defects misrepresents the thing reviewed. Each item was
verified against **both** the code and an authoritative Microsoft source. Several are behaviours
commonly wrong in comparable tooling.

### Parsing

1. **An unreadable DACL is never reported as a NULL DACL.** `DecideDaclState` lines 160–174,
   `Undecodable` lines 187–189. A NULL DACL grants full access to any requestor; every failure path
   routes to `DaclState.Unreadable` with `DaclCompleteness.Unknown` and `DaclWasCanonical: false`.
   The three-way separation of Empty / Null / Unreadable is the single most important thing in the
   file.
2. **Unsigned descriptor offsets.** `Parse` lines 68–74 read owner, group and DACL offsets as
   `UInt32` per `[MS-DTYP]` 2.4.6 `ULONG`. A signed read lets a high-bit offset pass a `>= Length`
   check.
3. **Owner absent is distinguished from owner unreadable.** `TryParseSidAtOffset` lines 439–454.
   Offset zero is absent and permitted; any other out-of-range offset is a recorded error. The
   owner holds `WRITE_DAC` implicitly, so conflating the two matters.
4. **ACE type values.** All ten in `AceType.cs` match `[MS-DTYP]` 2.4.4.1 — `0x00`, `0x01`, `0x02`,
   `0x05`, `0x06`, `0x07`, `0x09`, `0x0A`, `0x0B`, `0x0C`.
5. **Callback-object ACE types route to the object parser.** `IsObjectAceType` lines 499–506
   includes `0x0B` and `0x0C`. Omitting these is a common defect: it causes the `ObjectType` GUID
   to be missed and a scoped grant to be read as unscoped. Not present here.
6. **Object ACE flags gate variable GUID presence.** `TryParseObjectAce` lines 341–366 —
   `ACE_OBJECT_TYPE_PRESENT` `0x01` and `ACE_INHERITED_OBJECT_TYPE_PRESENT` `0x02`, with the SID
   offset advanced conditionally. Fixed-offset GUID reads are a frequent defect.
7. **Windows GUID binary layout.** `ParseGuid` lines 492–497 uses the mixed-endian layout matching
   the on-wire structure.
8. **SID structural validation.** `Sid.ToText` lines 75–104 enforces revision `0x01` and
   `SubAuthorityCount ≤ 15` per `[MS-DTYP]` 2.4.2.2, returning `null` rather than a truncated SID.
   It deliberately does not reject over-long buffers, since the span may window a larger buffer,
   nor range-check the 48-bit authority, since every value is structurally legal.
9. **One SID implementation, shared.** `SecurityDescriptorParser.TryParseSid` lines 477–485
   delegates formatting to `Sid`; only error reporting is local. Prevents drift between capture and
   bundle read-back.

### Normalisation and ordering

10. **Canonical order is judged before sorting destroys the evidence.** `Parse` line 127 →
    `AceCanonicalization.IsCanonicalOrder`. That the judgement happens pre-sort is correct and
    verified. **The reasoning attached to it is not confirmed** — see *Withdrawn* below.
11. **The canonicality claim is scoped, not overstated.** `AceCanonicalization` lines 88–99
    disclaims three things it does not check. Verified against `[MS-DTYP]` 2.4.5's canonical-form
    definition that "Deny ACEs on the object come before deny ACEs on a child or property" is
    indeed unchecked — **the disclaimer is accurate.** It also correctly notes inherited-generation
    order is unprovable from one DACL, and that `fDontStandardizeSDs` and forest functional level
    are uncollected.
12. **Unmodelled ACE types are skipped, not guessed at.** `AceCanonicalization` lines 101–108, with
    the raw type number still written to `ace.ace_type`.
13. **Conditional ACE application data is preserved and hashed.** `ReadApplicationData`
    lines 405–418, read only for the four callback types; included in `ace_hash` at version 3 so
    two entries differing only by condition no longer collide.
14. **Normalisation failure is recorded, not swallowed.** `NormalizeAce` lines 98–102 catches
    `when (ex is not OperationCanceledException and not OutOfMemoryException)` — it does not swallow
    silently and does not catch the two that must propagate.

### Access-mask semantics

15. **Generic bits are not semantically expanded for stored ACEs.** `GenericRightsExpander` class
    documentation lines 7–28 correctly states that `[MS-DTYP]` 2.4.3's access-check algorithm does
    not map generic bits already present in an object's ACE. Expansion is confined to comparison
    and severity; the raw mask stays on `ParsedAce` and the expanded one on `CanonicalAce`. **Most
    tools get this wrong.**
16. **AD DS generic mapping values.** `DS_GENERIC_ALL = 0x000F01FF` decomposes to
    `STANDARD_RIGHTS_REQUIRED` (`0x000F0000`) plus all nine DS-specific rights (`0x1FF`).
    `DS_GENERIC_READ` / `WRITE` / `EXECUTE` compose correctly.
17. **`ADS_RIGHTS_ENUM` constants.** All eight in `DangerousPermissionClassifier` lines 39–46 match
    documented values.

### Classification

18. **Deny and audit ACEs short-circuit before mask evaluation.** `ClassifyGrant` lines 364–370;
    `IsDeny` lines 752–756 covers all four deny types. A deny ACE carrying `WRITE_DAC` is not
    classified as a dangerous grant.
19. **`WRITE_OWNER` is described as indirect, not direct.** `ClassifyObjectIndependentBits`
    lines 421–426 states ownership confers the implicit right to modify permissions and so "reaches
    the same place as" `WRITE_DAC`, rather than collapsing it into direct full control.
20. **An unknown GUID is `CannotClassify`, never `NotDangerous`.** `ClassifyScoped` lines 501–506 —
    *"It is not being reported as safe."*
21. **Unreadable `validAccesses` is distinguished from a mask/kind mismatch.** `ClassifyScoped`
    lines 538–551 — two `CannotClassify` outcomes with different reasons, explicitly ordered
    because an operator acts on them differently.
22. **GUID kind is disambiguated by mask bit.** `ClassifyScoped` lines 508–536. Lookup returns a
    *set*, because one GUID can be several things; the mask bit selects the kind. Matches the
    `validAccesses` model in *Control Access Rights (AD DS)* — `SELF` 8 for validated writes,
    `READ_PROP|WRITE_PROP` 48 for property sets, `CONTROL_ACCESS` 256 for extended rights.
23. **One GUID legitimately serving two kinds is modelled.** `72e39547-7b18-11d1-adef-00c04fd8d5cd`
    is registered as both the `Validated-DNS-Host-Name` validated write (line 320) and the
    `DNS-Host-Name-Attributes` property set (line 329). This is a genuine schema property, and the
    multi-entry design represents it correctly.
24. **Scoped `CREATE_CHILD` / `DELETE_CHILD` is `DangerousInCombination`, not a verdict.**
    `ClassifyChildClassRight` lines 585–596 — the `ObjectType` GUID restricts the right to one
    class, and whether that is a takeover depends on the container, which one entry cannot see.
25. **Replication rights are `DangerousInCombination`, not `Dangerous`.** `ClassifyExtendedRight`
    lines 607–613 — a single replication right is not DCSync; the pair is, and the set-level
    question is deferred rather than answered from one entry.
26. **Property sets are not blanket-dangerous.** `ClassifyPropertySetWrite` lines 637–652 derives
    the answer from actual set membership. The reasoning is correct: `Personal-Information` is
    granted to `SELF` by default on every user and computer, so marking it a takeover would put the
    loudest signal on a default ACE in every forest.
27. **LAPS encrypted attributes are weighted equally to cleartext.** `SecretAttributeReads`
    lines 121–149 — schema presence proves nothing about whether encryption is enabled, which
    requires DFL 2016 or later and explicit configuration.
28. **The security-critical GUIDs are correct.** Verified against Microsoft:
    `User-Force-Change-Password`, `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`,
    `DS-Replication-Get-Changes-In-Filtered-Set`, `DS-Replication-Synchronize`,
    `DS-Replication-Manage-Topology`, `Self-Membership`, `Validated-SPN`. **The DCSync detection
    pair is intact.**

### The call site

29. **The `IsNamed` precondition is enforced.** `ObjectSections.Assess` lines 1357–1379. The
    classifier documents at lines 185–188 that passing bits this build has no word for yields a
    false `NotDangerous`. `Assess` guards `if (!right.IsNamed)` **first**, returning
    `CannotClassify`. This was the review's leading candidate for a real defect; it is correctly
    handled.
30. **Unmodelled ACE type strings are refused, not coerced.** `ObjectSections.Assess`
    lines 1367–1372 — `Enum.TryParse<AceType>` with `ignoreCase: false`, failing to
    `CannotClassify` rather than defaulting to an allow.
31. **Entry reach is passed, not just the mask.** `ObjectSections.Assess` line 1378 — an
    `INHERIT_ONLY_ACE` cannot produce a reason claiming control of *this* object.

### Wording

32. **`ACCESS_SYSTEM_SECURITY` in a DACL is surfaced as anomalous.** `PermissionWording`
    lines 225–230 — worded as *"not valid in a DACL - anomalous"* rather than listed as a grant.
33. **The "Full control" shortcut does not swallow unaccounted bits.** `PermissionWording`
    lines 156–167 — `remaining = accessMask & ~accountedFor` ensures no bit is double-counted or
    dropped, and scoped entries bypass the shortcut entirely.
34. **Generic shorthand is named, not translated.** `PermissionWording` lines 169–183 — rendered as
    "Full control (shorthand - may not be enforced)", consistent with item 15, and deliberately not
    allowed to fall through to "other rights" where it would be refused classification.
35. **A property-set GUID under `CONTROL_ACCESS` is not rendered as a bare extended right.**
    `PermissionWording` lines 189–196 — property sets declare `validAccesses: 48`, so an ACE naming
    one with that bit is not naming an extended right.
36. **`WRITE_OWNER` carries the directory's label.** "Modify owner", not the file system's "Take
    ownership".
37. **The directory treats all object types as containers.** `PermissionScopeWriter` lines 42–48 —
    so `CONTAINER_INHERIT_ACE` is the propagating flag, and the file system's folder/file
    distinction does not divide the directory.
38. **An entry that governs nothing says so.** `PermissionScopeWriter` lines 109–130 — no inherit
    flags plus `INHERIT_ONLY` returns "Nothing" rather than a blank.

### Catalogue design

39. **The catalogue is immutable and layered.** `SchemaGuidCatalog` lines 30–35 and 91–99 —
    `FrozenDictionary`, with captured forest schema taking precedence over the shipped table and no
    capture able to mutate the shipped one. Removes a real provenance hazard for run-to-run
    comparability.
40. **Empty property-set membership means "not assessed", not "empty".** `SchemaGuidCatalog`
    constructor documentation lines 75–78.

---

## Withdrawn

### The accumulate-both-masks claim — `AceCanonicalization.cs:54-56`

**Confirmed Correct item 10 originally asserted** that the code "correctly cites `[MS-ADTS]`
5.1.3.3.2 accumulate-both-masks semantics and explicitly corrects the common *evaluation stops at
first match* error". **That assertion is withdrawn.** `S-59` raised the contradiction; checking it
showed the assertion was not earned.

**What went wrong in this review.** `[MS-ADTS]` 5.1.3.3.2 was never opened. The code cites it, and
the citation was accepted rather than verified — the precise failure this review's own standard
forbids, and the precise failure `S-59` exists to catch. Session 1 did list MS-ADTS under *sources
cited by the code but not independently verified*; item 10 then contradicted that by claiming
verification against "an authoritative Microsoft source". Only the pre-sort ordering half of item 10
was ever established.

**The conflict, as far as it can be stated.** `AceCanonicalization.cs:54-56` says flatly that AD
examines every ACE to the end of the DACL, and that ordering matters for accumulation reasons
rather than because evaluation stops at a match. Microsoft's *How AccessCheck Works* says the
opposite for the general Windows algorithm:

> The system examines each ACE in sequence until one of the following events occurs: an
> access-denied ACE explicitly denies any of the requested access rights…; one or more
> access-allowed ACEs … explicitly grant all the requested access rights; all ACEs have been
> checked…
>
> **Because the system stops checking ACEs when the requested access is explicitly granted or
> denied, the order of ACEs in a DACL is important.**

*ACEs to Control Access to an Object's Properties* says the same for directory objects: "the system
checks the ACEs, in order, until the requested access is explicitly granted, denied, or there are no
more ACEs".

`S-56:270` independently states that control access rights stop at the first applicable ACE, and
`S-56:278` warns against applying a general early-stop description. `S-59` reports these cannot both
be right as written.

**Unresolved.** `[MS-ADTS]` 5.1.3.3.2 could not be retrieved during this session, so whether the
AD-specific algorithm genuinely differs from the general Windows one — and whether the difference is
per-right, per-ACE-kind, or absent — is not established. **Two authoritative Microsoft sources
appear to conflict and the conflict is not resolved.** Nothing should be changed in either
direction until `[MS-ADTS]` 5.1.3.3.2 and 5.1.3.3.3 have been read in full.

**What this does not affect.** Confirmed Correct item 11 — the canonicality *disclaimer* — rests on
`[MS-DTYP]` 2.4.5, which was read in full, and stands. `F-S60-1` through `F-S60-4` are untouched:
none depends on the accumulation question.

---

## Coverage

### Session 1 — parsing and classification primitives

| File | Lines | Coverage |
| --- | --- | --- |
| `Security/SecurityDescriptorParser.cs` | 507 | Full |
| `Security/AceType.cs` | 39 | Full |
| `Security/AceCanonicalization.cs` | 142 | 1–132 |
| `Security/AceNormalizer.cs` | 273 | 1–243 |
| `Security/GenericRightsExpander.cs` | 110 | 1–97 |
| `Security/Sid.cs` | 157 | 1–135 |
| `Security/PermissionScope.cs` | 153 | 1–133 |
| `Security/DangerousPermissionClassifier.cs` | 787 | 1–540 |
| `Schema/SchemaGuidCatalog.cs` | 396 | 1–124 |

Tests: none read. Microsoft sources: `[MS-DTYP]` 2.4.5 read in full; five Learn pages used at
search level only and not relied upon for any finding.

### Session 2 — call sites, wording, and static data

| File | Lines | Coverage |
| --- | --- | --- |
| `Security/DangerousPermissionClassifier.cs` | 787 | Completed to 752 |
| `Security/PermissionWording.cs` | 316 | 140–286 |
| `Schema/SchemaGuidCatalog.cs` | 396 | All `EmbeddedEntries()` GUID lines enumerated |
| `Shell/ViewModels/ObjectSections.cs` | 1482 | 1300–1390 only — classifier call path |

Tests: `SchemaGuidCatalogTests.cs` — all seventeen signatures enumerated and assessed; bodies not
read. Targeted searches run across the whole test project for the incorrect GUIDs and names.

Microsoft sources read in full: `Do-Garbage-Collection`, `Abandon-Replication`,
`DS-Replication-Monitor-Topology`, `DS-Replication-Synchronize`, `DS-Replication-Manage-Topology`,
`DS-Replication-Get-Changes-All`. Index and reference pages read: *Extended Rights*, *Control
Access Rights (AD Schema)*, *Rights-Guid attribute*, *Control Access Rights (AD DS)*.

### Not covered

**The declared scope is approximately 85 per cent covered. It is not complete.**

1. **74 of the catalogue's 100 embedded GUIDs are unverified** — the 26 checked were mostly
   extended rights, so the attribute, class and property-set entries are almost entirely unread.
   Given two errors in twenty-six verified, further errors should be expected. **This is the
   largest residual risk.**
2. **No test body was read** in either session, so a test encoding an incorrect assumption is not
   excluded.
3. Not read at all: `AceSetHash.cs`, `ParsedAce.cs`, `EntryReach.cs`, `PermissionAssessment.cs`,
   `DaclCompleteness.cs`, `DaclState.cs`, `CanonicalAce.cs`, `Evidence/ObjectPermissions.cs`,
   `Evidence/CapturedSchemaGuidReader.cs`.
4. `SchemaGuidCatalog` lines 124–275 and 335–396 — the captured/shipped merge read in summary only.
   `CapturedSchemaGuidReader.cs` line 222 references sending `ClassifyScoped` "down the wrong
   branch", suggesting a known hazard not examined.
5. `AceNormalizer` lines 243–273 — `CanonicalAceComparer` and `Deduplicate`.
6. **Everything outside the security layer.** No collection, group expansion, multi-domain or
   multi-forest behaviour, and no end-to-end reporting logic was reviewed.

---

## Conclusion

For the shared AD security logic in the `next/` solution, the repository is **correct with
identified defects**.

No defect was found in the logic. The behaviours most commonly wrong in AD tooling are right, and
the code's self-documented limitations proved accurate every time they were checked against
Microsoft — including the canonical-form disclaimer, verified against `[MS-DTYP]` 2.4.5 and found
honest. Several files record the exact prior defect and the review that caught it, which indicates
a working correction process rather than luck.

Both defects found this session trace to one root cause: **the shipped schema catalogue is
validated for structure and against internal rule specifications, but never against Microsoft.**
That gap let two extended rights be published under wrong names, one of which does not exist in
Active Directory. Consequences today are bounded — no verdict changes, DCSync detection verified
intact, captured schema overriding the shipped table when read — but the mechanism is not
self-correcting, and 74 of the catalogue's 100 entries remain unverified.

**If one thing is acted on, it should be `F-S60-2`.** That fix subsumes `F-S60-1` and forecloses
the class.

This conclusion covers about 85 per cent of one layer of one of two product generations. It is not
a complete review of the repository, nor of the `next/` solution. Correct ACE semantics say nothing
about whether the right objects were collected, whether truncation was surfaced, or whether a
report's wording matches what its evidence supports.

---

## What a later session should do

In order of expected yield.

1. **Verify the remaining 74 embedded catalogue GUIDs against Microsoft.** Given the observed
   error rate, this is where further defects are most likely. Doing it as the test in `F-S60-2`
   rather than by hand converts the work into a permanent guard. Briefed as `S-61`.
2. **Read `CapturedSchemaGuidReader.cs`** — particularly the line 222 hazard about sending
   `ClassifyScoped` down the wrong branch — and the captured/shipped merge in `SchemaGuidCatalog`
   lines 124–275.
3. **Read the four security test bodies**, checking for assumptions that mirror the implementation
   rather than constrain it.
4. **Move to the collection layer**, starting with `CaptureSearchRequestFactory.cs`. This also
   closes the open question under **Adjudicated during review**.
