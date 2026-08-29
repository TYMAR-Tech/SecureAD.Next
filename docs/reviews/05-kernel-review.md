# Review 05 — Kernel AD semantics and parsers

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Status:** Findings open; no production correction accepted by this document

## Executive summary

The Kernel is generally the strongest-reviewed layer. It centralizes DN, SID, security-descriptor,
ACE, schema-GUID, timestamp, dSHeuristics and Group Policy interpretations; avoids Windows-only parser
APIs; records malformed input rather than throwing in most parsers; and contains unusually thorough
Microsoft-anchor and malformed-input tests. Several historical semantic defects have already been
corrected and documented directly beside the code.

The review nevertheless found three high-impact contract issues. The security-descriptor parser ignores
the ACL's declared byte size, so bytes outside the ACL boundary can be parsed as ACEs. Generic-right
expansion, correctly documented as comparison/severity-only for stored ACEs, is also used in semantic
permission classification and persisted canonical masks, which can manufacture rights the directory
would not grant from a stored generic bit. Finally, malformed `dSHeuristics` character 16 is labeled as
an absent/defaulted value rather than malformed stated evidence.

Additional medium findings cover known incomplete DN parsing, unpersisted catalogue/provenance
versions, an unsupported `lastLogonTimestamp` sentinel, crossRef classification outside the Kernel,
`gPLink` absence flattening, security-parser version provenance, and a dead CSE parser whose comments
claim production use. These do not invalidate the Kernel approach; they show where narrow, explicit
value types have not yet been carried through storage and consumers.

## Semantic-family map

```text
DnHelper
  -> Evidence tree/listing/parent resolution
  -> Audit topology and domain-name derivation
  -> Judgement finding domain/name fields

Sid / WellKnownSidCatalog
  -> security descriptor trustees
  -> Evidence permission names
  -> Derivation SID identity/scoping

SecurityDescriptorParser
  -> BundleCaptureSink / SysvolCapture
  -> raw descriptor persistence + normalized ACE persistence
  -> ObjectPermissions reparse/display

AceNormalizer / GenericRightsExpander / SchemaGuidCatalog
  -> canonical comparison hashes
  -> persisted ACE projection
  -> dangerous-permission classification and Shell wording

CapturedAttributeCatalog
  -> LDAP requests, Evidence schema, rule input ceiling

DirectoryHeuristics
  -> AdminSDHolder catalogue narrowing

Group Policy parsers
  -> SysvolCapture -> Evidence settings/errors/coverage
```

## Verified strengths

### S-01 — Unknown and malformed security data usually remain distinct

The security-descriptor parser distinguishes null, empty, present and unreadable DACLs and separately
records complete/incomplete/unknown parsing. Unknown ACE types, parser errors, callback condition data
and noncanonical order remain visible rather than being silently dropped.

### S-02 — SID parsing is bounded and specification-based

SID revision, maximum sub-authority count, mixed endianness and bounds are validated against MS-DTYP.
Malformed bytes return no SID rather than a partial identity. BUILTIN scoping is centralized and
explicitly carried into Derivation.

### S-03 — Timestamp interpretation is attribute-specific

Directory times are not guessed from shape. `accountExpires`, `pwdLastSet`, `lastLogonTimestamp`, LAPS
expiration values and generalized `whenCreated` are mapped explicitly, with stale-logon caveats and
ages measured against capture time rather than the reader's clock.

### S-04 — Captured schema is preferred without mutating shipped knowledge

`SchemaGuidCatalog.CapturedOver` creates an immutable two-layer catalogue, preserves source provenance,
lets a classified shipped answer beat an unclassified captured row, and treats unknown property-set
membership as unknown rather than empty.

### S-05 — Group Policy parser errors survive into Evidence

Registry.pol, security-template and GPP parsers return partial values plus errors. `SysvolCapture`
persists both and degrades per-policy coverage. The GPP parser prohibits DTD/entity resolution and
never retains `cpassword` content.

## Findings

## K-01 — SecurityDescriptorParser ignores the ACL's declared byte size

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, before permission-derived rules  
**Status:** Confirmed

### Evidence

`ParseAcl` reads `AceCount` but not the ACL `AclSize` field and receives the entire descriptor tail
starting at `OffsetDacl` (`SecurityDescriptorParser.cs:109-139, 211-257`). It walks ACEs against that
larger span. A malformed ACL declaring a shorter boundary can therefore cause bytes belonging outside
the ACL to be accepted as entries; a declared size extending past available bytes is not identified as
that structural defect.

### Customer consequence

Permissions can be fabricated from trailing bytes or a malformed ACL can receive an inaccurate
completeness explanation. Downstream normalized ACEs and classifications then look structurally valid.

### Recommended correction

Validate ACL revision and `AclSize` (minimum header, within descriptor, sufficient for each declared
ACE). Slice parsing to exactly the declared ACL span and report trailing bytes separately. Completeness
must consider both declared count and declared size.

## K-02 — Generic-right expansion crosses from comparison into permission semantics

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, before access-path rules  
**Status:** Confirmed

### Evidence

`GenericRightsExpander` correctly documents that generic bits already stored in an ACE are not mapped by
the AD access-check algorithm and expansion is for comparison/severity only. `AceNormalizer` expands
the raw mask and persists only the expanded canonical mask (`AceNormalizer.cs:69-96`).
`DangerousPermissionClassifier` also expands its input before semantic classification
(`DangerousPermissionClassifier.cs:354-385`).

### Customer consequence

A malformed/unusual stored ACE containing a generic bit can be reported as granting mapped directory
rights the DC would not grant. Future graph/rule analysis reading canonical ACE rows can inherit this
manufactured access.

### Recommended correction

Keep raw and comparison masks distinct in type and storage. Semantic access classification must use raw
stored-mask rules; comparison/deduplication may use a separately named expanded mask. If severity uses
potential mapped impact, label it as potential rather than granted.

## K-03 — Malformed dSHeuristics is reported as default absence

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for AdminSDHolder derivation  
**Status:** Confirmed

### Evidence

For an invalid character 16, `AdminSdExclusions` returns an empty exclusion list with
`HeuristicReadOutcome.DefaultedByAbsence` and preserves the invalid character
(`DirectoryHeuristics.cs:200-227`). The character was present and malformed; it was not absent.
Consumers can therefore treat the published protected set as established under the documented zero
default.

### Recommended correction

Add a distinct malformed/disputed outcome carrying the raw character. It must make the protected
catalogue uncertain and survive Derivation persistence and rule input.

## K-04 — DN parsing has two known structural defects

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No for controller-returned escaped DNs; Yes for arbitrary/configured DNs  
**Status:** Confirmed and pinned

### Evidence

`DnHelper` supports escaped form but not quoted RDN values and determines separator escaping only from
the immediately preceding backslash (`DnHelper.cs:14-16, 183-205`). Tests deliberately pin incorrect
results for quoted values and values ending in an escaped backslash (`DnHelperTests.cs:282-323`).

### Customer consequence

Parent, displayed name and domain can be wrong for typed/configured DNs or any source using legal
quoted form/even backslash escaping. Parent resolution can then produce false unresolved-container gaps.

### Recommended correction

Implement one RFC4514-compatible component scanner handling quotes, escaped pairs and hexadecimal
escapes; use it for first RDN, parent and domain extraction. Replace defect-pinning tests with correct
behavior and Microsoft/RFC examples.

## K-05 — Catalogue and semantic provenance versions are not persisted

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

`CapturedAttributeCatalog.Version` says every bundle records it, and `SchemaGuidCatalog.Version` says a
bundle can identify the shipped table used. Repository search finds no production persistence or reader
check for either version. Bundle schema version changes when some catalogue changes, but it does not
state the exact attribute or GUID catalogue/provenance.

### Customer consequence

Two bundles produced under different interpretation tables can appear equivalent, and an older shipped
GUID name cannot be identified as coming from a corrected catalogue.

### Recommended correction

Persist captured-attribute catalogue version and shipped schema-GUID catalogue version in Evidence.
Persist/derive parser and permission-semantic versions for any interpretation that affects stored
projections. Readers should display/refuse according to the accepted compatibility policy.

## K-06 — lastLogonTimestamp maximum sentinel lacks first-party support

**Severity:** Medium  
**Confidence:** Medium  
**Release blocker:** No  
**Status:** Needs evidence

### Evidence

`DirectoryTime` maps both zero and `long.MaxValue` to “No logon has been recorded” for
`lastLogonTimestamp` (`DirectoryTime.cs:171-185`). Microsoft evidence and tests clearly establish both
sentinels for `accountExpires`; current repository evidence establishes zero for no recorded logon but
does not establish the maximum value for `lastLogonTimestamp`.

### Recommended correction

Pin an exact first-party source or remove the maximum-value special case and treat an out-of-range value
as unreadable. Do not transfer sentinels between attributes by analogy.

## K-07 — Non-NC crossRefs can be reported as skipped application partitions

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed (Audit consumer of Kernel metadata)

### Evidence

Microsoft states an application-partition crossRef has `ADS_SYSTEMFLAG_CR_NTDS_NC` set and
`ADS_SYSTEMFLAG_CR_NTDS_DOMAIN` clear. `ForestPartitions` adds every entry that is not a domain (and not
Configuration/Schema) to `PartitionsNotRead`, without first requiring the NC bit
(`ForestPartitions.cs:182-200`).

### Customer consequence

External or other crossRef records can be presented as partitions in the customer's forest that
SecureAD deliberately skipped, overstating an audit coverage gap.

### Recommended correction

Classify three states explicitly: domain NC, application NC, and not-a-local-NC/external reference.
Record external references separately if useful; do not count them as unread forest partitions.

## K-08 — gPLink absence is flattened to no linked policies

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed (Kernel API/consumer contract)

### Evidence

`PolicyLinkList.Of(null/blank)` returns no links and no errors, and tests assert that behavior.
`ObjectAttributes` documents that an empty value means either unset or withheld because LDAP does not
distinguish them. The parser receives no completeness/basis and therefore labels Unknown as None.

### Recommended correction

Accept a typed captured-attribute reading rather than nullable text, or return a result that carries
`AbsentOrUnread` separately from established empty. Consumers must qualify a no-links statement by
connection/schema evidence.

## K-09 — Security parser semantics can change without reader compatibility refusal

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

Evidence stores raw descriptor bytes, parsed metadata/errors and canonical ACEs. Bundle open gates on
`AceCanonicalization.Version`, but no independent security-descriptor-parser version exists.
`ObjectPermissions` re-parses raw bytes in the current build and appends fresh errors, so the same
sealed bundle can display a different DACL interpretation after parser changes while still opening as
compatible.

### Recommended correction

Version parser semantics separately from canonical hashes, or define readback explicitly as current-
build reinterpretation and expose stored-vs-current disagreement as a typed state. Rules must declare
which interpretation they consume.

## K-10 — GPO CSE parser documentation claims production behavior that is unused

**Severity:** Low  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Evidence

`GpoClientSideExtensions` says it smart-filters SYSVOL capture, but production reference search finds no
caller. `SysvolCapture` directly attempts known policy files and enumerates XML files. No current data is
lost; the tested helper is dead code and its documentation is stale.

### Recommended correction

Remove the unused helper/catalogue or integrate it only under a specification proving that filtering
cannot hide settings. Current correctness-first all-file behavior should not be weakened for I/O savings
without production tests and coverage evidence.

## Test-evidence assessment

- Microsoft anchor tests generally use independent literal values and are strong.
- Parser suites have extensive truncation/malformed-input cases and partial-result assertions.
- Golden ACE hashes prove deterministic compatibility, not Microsoft correctness.
- Three schema GUIDs explicitly described as unpublished are stability fixtures, not Microsoft anchors;
  they should be labeled separately in the verification register.
- Missing tests: ACL Size boundaries, non-NC crossRefs, malformed heuristic outcome, catalogue-version
  persistence, parser-version compatibility, and typed absent `gPLink`.

## Recommended correction order

1. K-01/K-02 before permission-derived rules or effective-access work.
2. K-03 together with Decision 0089/AdminSDHolder correction.
3. K-05/K-09 as the shared interpretation-provenance design.
4. K-07/K-08 before broad coverage/GPO claims.
5. K-04 before accepting arbitrary user/configuration DNs.
6. Resolve K-06 by source verification.
7. Remove or formally integrate K-10.

## Files read fully

- All production files in `next/src/SecureAD.Kernel`
- Relevant Evidence, Audit, Derivation, Judgement and Shell consumers
- Kernel parser, anchor, golden and malformed-input tests
- Relevant cross-layer tests and documentation

## Tools and external sources consulted

- Microsoft Open Specifications: MS-DTYP, MS-ADTS, MS-GPREG, MS-GPPREF
- Microsoft Learn AD schema, security identifier, RootDSE, crossRef/application partition,
  UserAccountControl, control-access-right and Group Policy documentation
- Microsoft security guidance cited by existing anchor tests

## Validation performed

- Kernel semantic-family production reachability mapped repository-wide.
- Full source/test reads by family, including malformed-input paths.
- Existing anchor claims compared with production behavior and source status.
- No production or test code changed.
- Build/tests: deferred to publication validation because this review adds documentation only.
