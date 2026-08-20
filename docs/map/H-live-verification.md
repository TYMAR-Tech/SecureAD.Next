# H — Live verification

Live access against a running directory, and what it is permitted to claim about stored evidence.

Branch A owns the connection, the bind and discovery. H owns what a live read *means* once a
connection exists, and what a discrepancy between live and stored is allowed to assert. C owns the
stored evidence H is verified against.

`docs/review/00a-product-identity.md` decision 4 holds that live verification has no meaning without
stored evidence to verify against. This branch tests that claim against the code. It is broadly
borne out — `VerifyLiveAclAsync` really does read `audit.db` — but the branch also contains three
separate implementations of "what access does this principal have", one live browsing destination
that survives a deletion decided seven months ago, and an error taxonomy nothing produces.

**Sequencing item 4 has not been executed.** `src/SecureAD.UI/Shell/ContentHost.xaml:58` still hosts
`<views:InspectView>`; `MainViewModel.cs:499` still constructs `DirectoryTreeViewModel`;
`ServiceFactory.cs:108` still exposes `CreateDirectoryTreeService`. This file maps what is there.

## The flow

There is no single flow. H is a set of on-demand tools invoked from the UI, not a pipeline. Four
distinct paths exist; the numbering below covers all four.

**Path 1 — live ACL verified against stored evidence (the audit case).**

1. The user selects an object or a finding in a grid. `PreviewActionService` (J) checks that a
   snapshot database is loaded; if not it sets status `Error` — "No snapshot database is loaded;
   cannot compare live ACL" — and stops.
2. `LiveCheckService.VerifyAclAsync` is called with the DN and the `audit.db` path, under a
   20-second `CancellationTokenSource`.
3. `LiveDiagnosticsService.VerifyLiveAclAsync` opens an LDAP connection routed by DN to the owning
   domain's DC via `DcTopologyManager`, falling back to the home-domain DC with a warning if routing
   fails.
4. It issues a base-scope `SearchRequest` for `ntSecurityDescriptor` and `objectGUID`, attaching a
   `SecurityDescriptorFlagControl` for `Dacl | Owner`.
5. The descriptor is parsed twice: once into `MaterializedDeltaAce` records covering **every** ACE
   including inherited ones, and once through `SecurityDescriptorParser` + `AceNormalizer` to yield
   only the **explicit** `CanonicalAce` set with capture-compatible hashes.
6. `audit.db` is opened read-only. The stored owner SID is read from `dim_object`.
7. `CompareStoredAcl` picks a mode. If `fact_object_acl_materialized` exists and holds a row for this
   GUID, it deserialises the stored applied DACL and compares it against the live materialized set by
   multiset key. Otherwise it falls back to comparing live *explicit* ACEs against `fact_ace` by
   `ace_hash`.
8. Deltas are emitted as `Added` or `Removed` only, capped at 200. There is no `Modified`; a changed
   access mask surfaces as one `Added` and one `Removed`.
9. `OwnerChanged` is set when the stored owner is present and differs.
10. `LiveCheckService` maps the result to `Drift` when there are deltas or an owner change, `Match`
    otherwise, and `Error` when `ErrorMessage` is set or an LDAP exception was thrown.
11. The preview overlay renders the status. If the user opens the deltas window,
    `AclDeltasWindowViewModel` wraps each delta in an `AclDeltaRowViewModel` and asynchronously
    back-fills trustee names via `PrincipalNameResolver`.

**Path 2 — live effective access for a trustee.**

12. `EffectiveAccessViewModel` calls `CheckEffectiveAccessAsync(targetDn, trusteeSid)`.
13. The trustee's token SID set is assembled: own SID, transitive groups via
    `LDAP_MATCHING_RULE_IN_CHAIN`, SIDHistory, primary group and well-known SIDs.
14. `S-1-5-10` (SELF) is added if the target object's own SID equals the trustee SID.
15. `EffectiveAccessEvaluator.Evaluate` walks the DACL in order, tracking granted and denied bits per
    `(bit, objectTypeGuid)` pair. A deny bit already granted by an earlier allow is skipped — DACL-order
    precedence, computed and then discarded.
16. `BuildOperationChecks` runs ten named `CheckAccess` probes — GenericAll, WriteDacl, WriteOwner,
    ResetPassword, AddMember, WriteSPN, WriteRBCD, WriteKeyCredentialLink, and a composite DCSync test
    requiring Get-Changes plus Get-Changes-All or In-Filtered-Set.

**Path 3 — object-to-object ACL comparison.** `AclCompareViewModel` reads two live DACLs via
`ReadLiveDaclAsync` and diffs them. `StoredAclCompareViewModel` does the same over two `audit.db`
objects via `ObjectQueryService.QueryAces`. Neither compares live against stored.

**Path 4 — live browsing.** `DirectoryTreeService.LoadTreeAsync` enumerates containers only; leaves
load on expand via `LoadChildrenAsync`. `InspectView` accepts a typed name or DN, or falls back to
the tree selection, and opens an inspector. `MainViewModel.FindAuditObjectByLiveIdentityAsync`
bridges the live object back to `dim_object` via `AuditObjectLocator` (C).

## Components

### H1 — Live directory tool contract

**Owns** The nine on-demand live LDAP operations the application may perform, as a Core-defined interface.
**Layer** Core
**Depends on** H3, H5, H6, H8, H9
**Implemented by** `src/SecureAD.Core/Services/ILiveDiagnosticsService.cs` (90)

**Non-obvious** The doc comment asserts results are "clearly separated from the audit pipeline", but
`VerifyLiveAclAsync` takes a `storedDbPath` and reads the audit database. The separation is
one-directional: live never writes to the pipeline, but it does read from it. This is the only
interface in the codebase that spans both.

### H2 — Live connection acquisition and DC routing

**Owns** Obtaining an `LdapConnection` for a live tool call, routed to the DC that owns the target DN, with one failover retry.
**Layer** Infrastructure
**Depends on** A (`ILdapConnectionFactory`, `DcTopologyManager`)
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.cs` (377)

**Non-obvious** Two acquisition strategies coexist and only one is used broadly.
`OpenConnectionAsync` creates and disposes a connection per call — used by seven of the nine tools.
`AcquirePooledConnectionAsync` maintains a single serialised connection with a 60-second idle
timeout, and is used by exactly one caller: `ResolvePrincipalAsync` in `PrincipalTools.cs:32`. The
pool exists because SID resolution is the only tool called in bursts. The asymmetry is undocumented
and looks like an oversight rather than the deliberate choice it is.

Failover is *routing* failover, not authentication failover: `OpenConnectionAsync` catches
`LdapException` and retries against `ReportFailure`'s next DC, but only when a cross-domain
`targetDc` was resolved. A home-domain connection failure has no retry.

### H3 — Live object and principal lookup

**Owns** Reading a live object's attributes, resolving a SID to a principal, searching by name, and enumerating transitive group membership.
**Layer** Infrastructure, with Core result records
**Depends on** H2, A
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.ObjectTools.cs` (152), `LiveDiagnosticsService.PrincipalTools.cs` (156), `src/SecureAD.Core/LiveAccess/LiveToolResults.cs` (111)

**Non-obvious** `SearchObjectsAsync` uses ANR (`anr=`) *plus* four substring filters as a
belt-and-braces fallback, because ANR matches on prefix only. Substring filters on `cn` and
`sAMAccountName` are unindexed and will table-scan on a large directory; the server-side `SizeLimit`
is what keeps this survivable.

`LivePrincipalResult` is cached for the session in a `ConcurrentDictionary` on the service instance.
The cache has no invalidation — a principal renamed during a session keeps its stale name until the
app restarts. For an audit tool whose selling point is freshness, a live read that returns a cached
answer is a contradiction worth naming.

### H4 — Live schema GUID overlay

**Owns** Loading extended rights, property sets, schema attributes and object classes from the Configuration and Schema partitions into the runtime `GuidCatalog`.
**Layer** Infrastructure
**Depends on** H2, K (`GuidCatalog`)
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.SchemaTools.cs` (244)

**Non-obvious** This is the one live operation that is not a diagnostic at all — it mutates a
process-wide catalog that D, E and J all read from. It is invoked once at startup from
`MainViewModel.cs:605`, and if it succeeds, every GUID rendered anywhere in the app for the rest of
the session came partly from a live read. Entries are tagged `GuidCatalogSource.Captured` to
distinguish them from the embedded catalog, which is the right call; but nothing surfaces to the user
that the schema overlay loaded, or that a name they are reading came from this forest rather than
from the shipped table.

`ClassifyControlAccessRight` derives category from `validAccesses`, paging the schema partition at
1,000 entries with `PageResultRequestControl`. This is the only paged live query.

### H5 — Live DACL read

**Owns** Reading a raw `ntSecurityDescriptor` and projecting it into ACE records, in two shapes.
**Layer** Infrastructure
**Depends on** H2
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.AclTools.cs` (672, `ReadLiveDaclAsync` and `ExtractMaterializedAces`), `src/SecureAD.Core/LiveAccess/LiveToolResults.cs` (`LiveDaclResult`, `LiveDaclAce`)

**Non-obvious** Two independent ACE projections exist over the same descriptor and neither is derived
from the other. `ExtractMaterializedAces` produces `MaterializedDeltaAce` for comparison;
`ReadLiveDaclAsync` produces `LiveDaclAce` for display. They differ in what they keep — `LiveDaclAce`
carries `AceFlags` as a string and an `IsAllow` bool, `MaterializedDeltaAce` carries the raw `AceType`
int — and in GUID casing: `ExtractMaterializedAces` emits `ToString("D")` while `LiveAceConverter`
(H9) emits `ToString("D").ToLowerInvariant()`. A third projection, `LiveAceConverter`, exists for
bundle matching. Three converters, one descriptor.

Neither projection preserves ACE ordinal position, so nothing downstream can reason about canonical
DACL ordering even though the evaluator (H7) depends on it.

### H6 — Live-versus-stored ACL verification

**Owns** Comparing an object's live DACL against the ACEs captured for it in `audit.db`, and reporting the differences.
**Layer** Infrastructure
**Depends on** H2, H5, C (`DatabaseConnectionFactory`, `dim_object`, `fact_ace`, `fact_object_acl_materialized`, `MaterializedAclPayloadCodec`)
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.AclTools.cs` (672, `VerifyLiveAclAsync`, `CompareStoredAcl`, `AddMaterializedDeltas`, `AddExplicitHashDeltas`), `src/SecureAD.Core/LiveAccess/LiveToolResults.cs` (`LiveAclVerificationResult`, `LiveAclDelta`)

**Non-obvious** This is the component the product-identity note keeps the branch for, and it does
what the note says: it compares live against stored evidence, not against another live read. That
claim, tested, holds.

But it answers **two different questions under one name, and does not say which.**
`CompareStoredAcl` returns an `AclStoredComparisonMode` — `MaterializedPayload` when the applied DACL
is available, `ExplicitOnly` when it falls back to `fact_ace`. `VerifyLiveAclAsync` reads
`StoredAceCount`, `LiveAceCount` and `Deltas` from that record and **never reads `Mode`**.
`LiveAclVerificationResult` has no field to carry it. `git grep` confirms `Mode` is read at exactly
two places, both in `LiveAclComparisonTests.cs` (:46 and :81). The distinction is fully implemented,
fully tested, and entirely invisible to the user. Those are not interchangeable answers: "the applied
ACL differs" and "the explicitly-set ACL differs" are different findings, and inheritance changes are
visible only to the first.

The fallback path compares by `ace_hash`, which requires the live normalizer to produce
byte-identical hashes to capture-time normalization. Any divergence in the hash scheme between
capture and this call site would render every ACE as both `Added` and `Removed`, and nothing detects
that.

A `SqliteException` during the stored comparison is caught, logged at warning, and **swallowed** with
the comment "Keep best-effort live-only result". The result then carries zero deltas,
`StoredAceCount = 0` and no `ErrorMessage` — which `LiveCheckService` maps to `Match` and summarises
as "Live ACL matches snapshot." A comparison that failed reports agreement. This is the same shape G
found in the drift card, arrived at by a different route: G's refused compare and unchanged pair were
the same object; here a *failed* compare and a matching pair are the same object.

**Nothing in this component reads `SealedUtc`.** `git grep SealedUtc -- src` returns seven files,
none of them in H. `LiveAclVerificationResult` carries `QueriedUtc` — when the live read happened —
and nothing at all about when the stored evidence was captured. A drift reported against a
six-month-old bundle and one reported against yesterday's are rendered identically. F owns
`SealedUtc` and it is available; H simply never asks.

`LiveAclDelta.TrusteeName` is declared on the record and set to `null` by both `ToDelta` overloads,
unconditionally. The field exists solely for H12 to back-fill later.

### H7 — Live DACL evaluation

**Owns** Deciding what access a token SID set has against a raw security descriptor, applying DACL-order precedence and object-type scoping.
**Layer** Core
**Depends on** nothing
**Implemented by** `src/SecureAD.Core/LiveAccess/EffectiveAccessEvaluator.cs` (251), `src/SecureAD.Core/LiveAccess/LiveAclEvaluationResult.cs` (71)

**Non-obvious** This is where H and D answer the same question with different machinery. D's
`ControlEdgeService` persists `fact_control_edge` rows with a `deny_cancelled` flag, and G9 filters on
`deny_cancelled = 0`. `EffectiveAccessEvaluator.Evaluate` computes the identical concept inline: a
deny bit is added to `denySet` only if `IsGranted(grantSet, ...)` is false, so a deny that arrives
after an allow for the same bit is *cancelled*. **The two agree on precedence.** They disagree on what
they can report — D persists the cancellation as an explicit column that rules and compare can filter
on, while H discards it, so a live check can tell you a right is granted but never that it is granted
because a deny was cancelled.

They disagree on inheritance too. `ParsedAce` captures `IsInherited` and `Evaluate` does not consult
it; the flag only reaches the display record. D reconstructs inheritance explicitly through
`InheritedAceResolver` (C). The live evaluator treats an inherited ACE and an explicit one
identically, which is correct for an access decision and lossy for an explanation.

The scoping fallback is asymmetric by design and undocumented: `IsDenied` and `IsGranted` let an
object-scoped lookup fall back to the unscoped entry, but an unscoped lookup never consults scoped
entries. That is the conservative direction, and it is right, but a reader has to derive it.

`Evaluate` and `CheckAccess` are two different algorithms over the same DACL. `Evaluate` walks
per-bit with two sets; `CheckAccess` walks a shrinking `requested` mask with first-match-wins. They
should agree and no test asserts that they do.

### H8 — Live effective-access orchestration

**Owns** Assembling a trustee's token SID set from the live directory and turning an evaluation into named operation verdicts.
**Layer** Infrastructure
**Depends on** H2, H3, H7, K (`WellKnownAdGuids`)
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.AclTools.cs` (672, `CheckEffectiveAccessAsync`, `BuildOperationChecks`, `FromCheck`)

**Non-obvious** The token set is the part that is hard to get right and the part that is least
visible: own SID, transitive groups via `1.2.840.113556.1.4.1941`, SIDHistory, primary group,
well-known SIDs, and `S-1-5-10` injected only when the trustee *is* the target. The SELF case is a
genuine Windows behaviour most tools miss.

`WriteDacl` is special-cased to `Granted` by ownership before the DACL is consulted, which is correct
and is the only place ownership overrides ACL evaluation. `DCSync` is the only composite check —
Get-Changes AND (Get-Changes-All OR In-Filtered-Set) — and it is expressed inline rather than as
data, so adding a second composite means editing this method.

The GUID constants are sourced from `WellKnownAdGuids` rather than duplicated, with an
`[IMP-WK-GUID]` comment recording the consolidation after findings F-1/F-2/F-3. This is the one place
in H where a past correction is legible in the code.

`LiveAclEvaluationResult` has both `ErrorMessage` and `WarningMessage`. The warning carries
incomplete-token-resolution — a check run against a partial group closure. It is populated and it is
the only signal in H that a live answer is qualified rather than wrong.

### H9 — Live delegation-bundle verification

**Owns** Matching an object's live DACL against the built-in delegation bundles and reporting which are fully or partially applied, per trustee.
**Layer** Infrastructure, with Core conversion and result types
**Depends on** H2, H5, K (`DelegationBundleMatcher`, `DelegationBundleMatchResult`)
**Implemented by** `src/SecureAD.Infrastructure/Ldap/LiveDiagnosticsService.AclTools.cs` (672, `VerifyBundlesAsync`), `src/SecureAD.Core/LiveAccess/LiveAceConverter.cs` (70), `src/SecureAD.Core/LiveAccess/BundleVerificationResult.cs` (23)

**Non-obvious** **`BundleVerificationResult` is reachable** — this is not the E/F dead-subsystem
pattern. It has exactly one production consumer, `DelegationReportViewModel.cs:79` (J), plus three
test stubs. Its 23 lines and expansive name are honest; the record is a thin envelope and the
substance is in `DelegationBundleMatcher`, which is not H's.

`LiveAceConverter` is the third ACE projection (see H5) and the only one that discards information
silently: `ConvertAce` returns `null` for any ACE that is neither `CommonAce` nor `ObjectAce`, and the
caller drops nulls without counting them. `BundleVerificationResult.TotalAceCount` therefore reports
converted ACEs, not ACEs present. A callback or conditional ACE would reduce the count with no
indication.

It also sets `ObjectTypeGuid: null` for every `CommonAce`, which is correct, and synthesises
`AceHash: $"live-{index}"` — a positional identifier that is not comparable to any stored hash. This
converter cannot be reused for H6 even though both compare ACEs, and the naming does not warn you.

### H10 — Stored effective-access service — dead

**Owns** Computing effective access for a principal on an object from the derived store, with group expansion and deny cancellation.
**Layer** Infrastructure
**Depends on** C, D (`fact_control_edge`, `deny_cancelled`), E (`IGroupExpansionService`)
**Implemented by** `src/SecureAD.Core/Services/IEffectiveAccessService.cs` (62), `src/SecureAD.Infrastructure/EffectiveAccess/EffectiveAccessService.cs` (321), `src/SecureAD.Core/EffectiveAccess/EffectiveAccessResult.cs` (68), `src/SecureAD.Core/EffectiveAccess/AccessCapability.cs` (65). Tests: `tests/SecureAD.Infrastructure.Tests/EffectiveAccess/EffectiveAccessServiceTests.cs` (433).

**Non-obvious** **This has no production caller.** `git grep "EffectiveAccessService\b" -- src`
returns three hits: the interface declaration, the class declaration, and its own constructor. It is
not registered in `ServiceFactory`, not constructed in any view model, and not reached from XAML. 383
production lines and 433 test lines with nothing invoking them — the third such subsystem after E's
~1,380 unreachable lines and F's untriggered `OutputEligibilityKind.Compare`.

This is the fourth dead subsystem the map has found and the pattern is now unmistakable: it is always
the *complete, well-designed* one that dies. `IEffectiveAccessService` is the best-specified access
API in the codebase — five methods covering both directions of the question
(`GetPrincipalsWithControl` and `GetObjectsWithControl`), a proper `AccessCapability` model, and deny
cancellation read from D's persisted flag rather than recomputed. What shipped instead is
`StoredEffectiveAccessViewModel` (H16), which re-implements a subset of the same thing in a view model
against `fact_ace`.

**What should survive a rebuild:** the interface, nearly verbatim. Its bidirectional shape — ask by
principal, ask by object — is what the live path (H8) lacks and what a triage workflow actually needs.
And it is the only effective-access implementation in the product that consumes D's `deny_cancelled`
rather than recomputing precedence, which means it is the only one that cannot silently disagree with
the findings engine. Rebuild this and delete both of its rivals, rather than the reverse.

### H11 — Live check façade and failure taxonomy

**Owns** Turning a live tool call into a `Match` / `Drift` / `Error` verdict with a human summary, and mapping every LDAP failure mode to one of them.
**Layer** UI
**Depends on** H1, H6
**Implemented by** `src/SecureAD.UI/Services/LiveCheckService.cs` (520)

**Non-obvious** This is the only place in H that takes failure seriously, and it does it well. Every
path — `OperationCanceledException`, `DirectoryOperationException`, `LdapException`,
`ObjectDisposedException`, `InvalidOperationException` — maps to a distinct `Error` result with a
specific summary, and `MapDirectoryOperationException` translates LDAP result codes into language an
operator can act on. **A live read that fails is distinguishable from one that found no
difference**, which is exactly the property G found missing from the drift card. On this axis the live
path is better built than the compare path.

The gap is upstream, not here. `VerifyAclAsync` derives `Match` from
`ErrorMessage is null && Deltas.Count == 0 && !OwnerChanged`, and H6 can satisfy all three after a
swallowed `SqliteException`. This component correctly reports what it was told; it was told the wrong
thing.

`LiveCheckService` declares its own `LiveCheckResult` and `AclVerifyResult` record structs,
duplicating most of `LiveAclVerificationResult`'s fields to add `Status` and `Summary`. The wrapping
exists because the Core records have no notion of a verdict — a reasonable layering call that costs a
full field-by-field re-projection at every call site.

It is `internal static`. Seven of its call sites are in `PreviewActionService` (J), which means the
boundary between H and J is a static method call and cannot be substituted for testing.

### H12 — ACL delta presentation

**Owns** Displaying the live-versus-stored ACE differences for one object, with trustee names resolved after the fact.
**Layer** UI
**Depends on** H6, H11, J (`PrincipalNameResolver`)
**Implemented by** `src/SecureAD.UI/ViewModels/AclDeltasWindowViewModel.cs` (89), `src/SecureAD.UI/ViewModels/AclDeltaRowViewModel.cs` (35), `src/SecureAD.UI/AclDeltasWindow.xaml` (96) + `.xaml.cs` (67)

**Non-obvious** `AclDeltasWindowViewModel` is constructed by `PreviewActionService` from **eleven
loose scalars scraped off the preview view model** — owner SIDs, both ACE counts, the delta list —
rather than from the `LiveAclVerificationResult` that produced them. The result object is destructured
in H11, flattened onto a preview VM in J, and reassembled here. Any field added to the verification
result must be threaded through three types to reach the window.

Consequently `OwnerChanged` is re-derived here rather than carried: the VM computes it from the two
SIDs with `!IsNullOrWhiteSpace(LiveOwnerSid) && !IsNullOrWhiteSpace(StoredOwnerSid) && !Equals(...)`,
while `VerifyLiveAclAsync` computes it as `!IsNullOrWhiteSpace(storedOwnerSid) && !Equals(...)`. The
two agree today only because a live read that succeeded always has an owner. Two definitions of one
predicate, in two layers, both authoritative.

`ResolveTrusteeNamesBestEffortAsync` is where `LiveAclDelta.TrusteeName` finally gets filled, via a
snapshot-first, live-fallback resolver. It is guarded against re-entry by `IsResolvingTrustees` but
not cancelled on window close.

### H13 — Object-to-object ACL comparison, live

**Owns** Reading two live DACLs and presenting their differences side-by-side or grouped by trustee.
**Layer** UI
**Depends on** H1, H5, K (`WellKnownSidCatalog`, `DnHelper`)
**Implemented by** `src/SecureAD.UI/ViewModels/AclCompareViewModel.cs` (513)

**Non-obvious** **This compares live against live.** `AclCompareViewModel.cs:303` calls
`ReadLiveDaclAsync(dn)` for each of two user-supplied objects. No stored evidence is consulted
anywhere in the file. The README boundary ruling describes the four `Acl*` view models as comparing
"live DACLs against live or against stored" — the "or against stored" belongs to H6, not to this
pair. Recorded as a correction below.

It maintains three parallel output collections — `SideBySideRows`, `TrusteeGroups` and `Differences`,
the last documented as "Legacy flat diff list (kept for backward compatibility)". A view model cannot
have backward compatibility; there is no consumer outside this application. It is a third rendering of
the same diff kept alive by a comment.

`ResolveSidDisplay` falls back to `WellKnownSidCatalog` and then to the raw SID, so an unresolvable
trustee is displayed as a SID with no indication that resolution was attempted and failed.

### H14 — Object-to-object ACL comparison, stored

**Owns** The same comparison as H13, over two objects in the audit database.
**Layer** UI
**Depends on** C (`ObjectQueryService.LookupByGuid`, `LookupByDn`, `QueryAces`), H13 (shares `AclSideBySideRow`, `AclTrusteeGroup`, `AclCompareDelta`)
**Implemented by** `src/SecureAD.UI/ViewModels/StoredAclCompareViewModel.cs` (264)

**Non-obvious** **H13 and H14 are two views of one capability, not two capabilities.** Both answer
"how do these two objects' ACLs differ", differing only in evidence source — live LDAP versus
`audit.db` — and they emit the *same* output types. That is the right pairing and the wrong
factoring: the diff algorithm is written twice, once against `LiveDaclAce` and once against
`ObjectQueryService`'s ACE rows, and only H14 supports `ShowSharedAces` filtering by re-projecting a
cached `_allSideBySideRows`.

G recorded `StoredAclCompareViewModel`'s private `CompareResult` record (:133) as a name collision
with G's `CompareResult`. **The collision is only a name.** This one is a five-field DTO — `Groups`,
`SideBySideRows`, `Summary`, `ResolvedNameB`, `Error` — private to the class, existing purely to
return five values from `CompareFromDb` across a `Task.Run` boundary. It shares nothing with the
run-versus-run compare result but the identifier.

Object B is resolved by trying `LookupByDn` then `LookupByGuid`, and the failure message tells the
user to "Enter a DN or object GUID" — which is accurate, and notably better than H13, which resolves
through live search with no such guidance.

### H15 — Live effective-access panel

**Owns** The user-facing surface for asking what a trustee can do to an object, against the live directory.
**Layer** UI
**Depends on** H1, H8
**Implemented by** `src/SecureAD.UI/ViewModels/EffectiveAccessViewModel.cs` (549)

**Non-obvious** The only caller of `CheckEffectiveAccessAsync` (:442). At 549 lines it is the largest
view model in H, and the bulk is presentation of `LiveAccessOperationResult` — the ten named operation
verdicts H8 builds — rather than access logic.

### H16 — Stored effective-access panel

**Owns** The same question as H15, answered from the audit database.
**Layer** UI
**Depends on** C (`fact_ace`, group closure), K (`GuidCatalog`)
**Implemented by** `src/SecureAD.UI/ViewModels/StoredEffectiveAccessViewModel.cs` (319)

**Non-obvious** **This is the third implementation of effective access in the product**, after H7
(live, Core) and H10 (stored, Infrastructure, dead). Its own summary describes it as evaluating "ACEs
from the audit database against the trustee's transitive group membership closure, applying
deny-before-allow" — which is precisely what H10 was built to do, better, one layer down.

The three do not agree about the same case. H10 reads D's persisted `deny_cancelled`. H7 recomputes
cancellation inline over the live DACL and discards it. H16 applies "deny-before-allow", which is
*not* the same rule as DACL-order precedence: deny-before-allow makes a late deny win, whereas Windows
and H7 let an earlier allow stand. **On an object with a non-canonical DACL — allow before deny for
the same right — H16 will report denied and H7 will report granted, for the same principal and the
same right.** Neither is labelled as an approximation in the UI, though H16's XML doc does say "not a
full Windows AccessCheck".

`DangerousRight` and `HasDangerousRights` are H16's alone; no other effective-access path classifies
rights by severity. That classification is the one thing here worth keeping if the panel goes.

### H17 — Directory tree contract

**Owns** The shape of a browsable directory hierarchy and the two operations that populate it.
**Layer** Core
**Depends on** nothing
**Implemented by** `src/SecureAD.Core/Services/IDirectoryTreeService.cs` (62), `src/SecureAD.Core/Discovery/DirectoryTreeNode.cs` (31)

**Non-obvious** Both files document a capability that **no longer exists**. `IDirectoryTreeService`:
"Retrieves the OU/container hierarchy from Active Directory for scope selection." `DirectoryTreeNode`:
"Used for scope selection in the UI — the user picks a node to define the capture scope." Scoped
capture was removed on 2026-08-02. The tree's original reason to exist is gone and the only remaining
consumer is live browsing — which is itself scheduled for removal. This is the clearest evidence in
the branch that sequencing item 4 is the right decision: the component is already an orphan and its
own documentation says so.

`LoadTreeAsync` carries an `includeLeafObjects` parameter that its implementation explicitly ignores
(H18). The interface also offers two default-implementation overloads that hard-code
`includeLeafObjects: false` — a default for a parameter one method does not read.

`DescendantCount` is a recursive `Sum` over `Children` with no memoisation, evaluated per property
access. On a bound tree this is O(n) per binding refresh.

### H18 — Directory tree LDAP enumeration

**Owns** Querying containers and leaves from a live DC and shaping them into a tree, with a curated exclusion policy.
**Layer** Infrastructure
**Depends on** A (`ILdapConnectionFactory`), H17
**Implemented by** `src/SecureAD.Infrastructure/Ldap/DirectoryTreeService.cs` (477)

**Non-obvious** Contains the branch's only piece of site-specific data: `ExcludedLeafClasses` includes
`enatelSSOAccountParameter`, `enatelUserManagedAuth` and `enatelSSOStorageV3` — object classes from a
single vendor's schema extension, hard-coded into a general-purpose product. Alongside them sit
legitimate general exclusions (`msFVE-RecoveryInformation`, `msTPM-InformationObject`,
`foreignSecurityPrincipal`). One customer's directory is embedded in a `HashSet` with no comment
saying so.

`LoadTreeAsync` ignores `includeLeafObjects` and always loads containers only; leaves arrive through
`LoadChildrenAsync` on expand. The remarks explain this honestly, which makes it a documented lie in
the signature rather than an undocumented one.

`LeafObjectFilter` restricts the tree to security principals on the stated grounds that "everything
else has its own grid" — a UI justification compiled into an Infrastructure LDAP filter.

### H19 — Directory tree presentation

**Owns** Lazy expansion, selection and refresh of the live tree.
**Layer** UI
**Depends on** H17, H18
**Implemented by** `src/SecureAD.UI/ViewModels/DirectoryTreeViewModel.cs` (194), `src/SecureAD.UI/ViewModels/DirectoryTreeNodeViewModel.cs` (151)

**Non-obvious** `DirectoryTreeViewModel` takes an explicit `Dispatcher` through an internal
constructor purely so its tests can run without a UI thread. It is the only H component with that
accommodation, and `DirectoryTreeViewModelTests` (88) is one of only three UI tests in the branch.

Selection is pushed *into* the view model by the view's `SelectedItemChanged` handler
(`InspectView.xaml.cs:29`) because `TreeView.SelectedItem` is read-only, and read back out by
`ObjectPickerHelper.cs:52` — so the tree's selection is a shared mutable field two unrelated features
write through.

### H20 — Inspect destination

**Owns** Live browsing as a place the user goes, and the bridge from a live object back to its match in the loaded audit database.
**Layer** UI
**Depends on** H1, H3, H19, C (`AuditObjectLocator`)
**Implemented by** `src/SecureAD.UI/Views/InspectView.xaml` (173) + `.xaml.cs` (149), `src/SecureAD.UI/ViewModels/MainViewModel.Inspect.cs` (32), `src/SecureAD.UI/ViewModels/InspectorDetailModel.cs` (38), `src/SecureAD.UI/InspectorDetailWindow.xaml` (177) + `.xaml.cs` (18), `src/SecureAD.UI/Themes/InspectorStyles.xaml` (431)

**Non-obvious** This is the component sequencing item 4 exists to delete, and it is still wired:
`ContentHost.xaml:58`.

`MainViewModel.Inspect.cs` is the part worth separating from the verdict. Thirty-two lines, and it is
the only bidirectional live-to-stored identity bridge in the product:
`FindAuditObjectByLiveIdentityAsync` reads the live object's `objectGUID`/SID and hands it to
`AuditObjectLocator` (C) to find the corresponding `dim_object` row. Every other H component goes
stored-to-live (here is a stored object, check it against the directory). This one goes
live-to-stored (here is a directory object, what did we capture about it). Deleting the Inspect view
deletes the only path in that direction.

Its doc comment is unusually good about layering — "this partial only supplies the connection and
live-diagnostics service the View is not allowed to touch directly" — and the discipline holds:
`InspectView.xaml.cs` reaches the directory only through `Vm.LiveDiagnostics`.

`InspectorDetailModel` is a template-keyed bag with six mutually exclusive shapes (`Items`, delegation
fields, info fields) selected by a string `templateKey` passed to `Show`. It is not live-specific and
would survive as a J concern.

`InspectorStyles.xaml` (431) is a resource dictionary read but not analysed in this pass.

### H21 — Live error taxonomy — dead

**Owns** A vocabulary for live failure modes.
**Layer** Core
**Depends on** nothing
**Implemented by** `src/SecureAD.Core/Errors/LiveErrorCode.cs` (13), plus one overload in `src/SecureAD.Core/Errors/AuditErrorCodes.cs:36`

**Non-obvious** Five well-chosen codes — `DcUnavailable`, `AccessDenied`, `Timeout`, `ObjectNotFound`,
`AttributeReadFailed` — that cover exactly the failure modes H11 handles. **Nothing produces one and
nothing consumes one.** `git grep LiveErrorCode -- src` returns two hits: the enum, and
`AuditErrorCodes.Format(LiveErrorCode)`. `git grep "AuditErrorCodes.Format" -- src` returns **zero**
hits, so even the formatter is unreachable.

Every live failure path instead returns a free-text `ErrorMessage` string:
`$"Object not found: {dn}"`, `"Could not read ntSecurityDescriptor"`, `ex.Message`. H11 then
re-derives structure from those strings by catching exception types it did not throw.

**What should survive:** the enum, used. This is a designed taxonomy that lost a race against
`string`. In a rebuild, `LiveAclVerificationResult.ErrorMessage` and its siblings should be
`LiveErrorCode? Code` plus a detail string, so that H11's classification becomes a lookup rather than
an exception-type inference, and so that `ObjectNotFound` — which today means "there is nothing to
verify" — stops being indistinguishable from "verification found nothing wrong".

### Cross-branch dependencies

**H depends on:** A (`ILdapConnectionFactory`, `DcTopologyManager`, `LdapToolsSettings` — H2, H18);
C (`DatabaseConnectionFactory`, `dim_object`, `fact_ace`, `fact_object_acl_materialized`,
`MaterializedAclPayloadCodec`, `ObjectQueryService`, `AuditObjectLocator` — H6, H14, H16, H20);
D (`fact_control_edge`, `deny_cancelled` — H10 only); E (`IGroupExpansionService` — H10 only);
K (`GuidCatalog`, `WellKnownAdGuids`, `WellKnownSidCatalog`, `DelegationBundleMatcher`, `DnHelper`).

**Depends on H:** J renders everything H produces — `PreviewActionService`, `InheritanceViewModel`,
`DelegationReportViewModel`, `GroupMembershipViewModel`, `ResolvePrincipalViewModel`,
`PrincipalNameResolver`, `ObjectDetailPanelViewModel.Live*`, `ObjectDetailWindow`, `LdapInputDialog`.
D, E and J all read the `GuidCatalog` that H4 mutates at startup, which is H's only write into
another branch's state. C's read half records `AuditObjectLocator` as taking a live identity from H.

**Not H's:** `LiveSidResolutionService` (398) is B's — its only consumer is
`SecurityModeCaptureService`, and it resolves SIDs during capture, not during verification. The name
is the only thing linking it to this branch.

## Naming & taxonomy

| Current | Proposed | Why it matters |
|---|---|---|
| `ILiveDiagnosticsService` | `ILiveDirectoryReader` | "Diagnostics" suggests troubleshooting the app. Eight of its nine methods read directory state and one loads a schema catalog. Nothing diagnoses anything. The name is why this interface accumulated `LoadSchemaGuidsAsync`, which is not a diagnostic by any reading. |
| `VerifyLiveAclAsync` | `CompareLiveAclToSnapshotAsync` | The current name says which side is live and hides which side is authoritative. This is the branch's one true audit operation and its name does not say it touches stored evidence at all — the `storedDbPath` parameter is optional and defaulted to `null`, which reads as though stored comparison is a bonus. |
| `LiveAclVerificationResult` | `AclDriftResult` | It is not the result of a verification; it is the difference between two states. And it should carry the comparison mode and the snapshot seal time, which the current name gives no reason to expect. |
| `AclStoredComparisonMode` | `AclComparisonBasis`, surfaced on the result | The type is right and its placement is wrong. Renaming it to a *basis* rather than a *mode* makes it obvious it belongs in the output, because a basis is something a claim rests on. |
| `EffectiveAccessEvaluator` (Core, live) vs `EffectiveAccessService` (Infra, stored) vs `StoredEffectiveAccessViewModel` (UI, stored) | `LiveAccessEvaluator` / `StoredAccessEvaluator` / (delete) | Three types whose names differ by suffix and layer, not by what they answer. Two of the three are stored-evidence evaluators and their names do not distinguish them; the dead one has the better name. |
| `LiveAclEvaluationResult` vs `EffectiveAccessResult` | `LiveAccessCheck` / `StoredAccessCheck` | The existing files already carry a comment explaining that these are "named distinctly" from each other — a comment that exists because the names are not distinct enough to work without one. |
| `AclCompareViewModel` | `LiveAclDiffViewModel` | It compares two live objects. Its unqualified name reads as the general ACL comparison, and its qualified sibling `StoredAclCompareViewModel` reinforces that reading. The live one should carry the qualifier too, because live is the special case. |
| `StoredAclCompareViewModel.CompareResult` | `AclDiffProjection` | Collides in name only with G's `CompareResult`, but that is enough: a reader grepping for compare results finds a private DTO in a view model and has to read it to rule it out. |
| `LiveCheckService` | `LiveCheckPresenter` or `LiveVerdictMapper` | It performs no checks. It calls a check and assigns a verdict — `Match`, `Drift`, `Error` — which is the one thing in H that is genuinely presentation policy. |
| `LiveCheckService.LiveCheckResult` / `AclVerifyResult` | `LiveVerdict` / `AclDriftVerdict` | Both are verdicts wrapping a result. Naming them `Result` invites the field-by-field re-projection that H12 then has to undo. |
| `DirectoryTreeNode.ObjectClass` free strings (`"domainDNS"`, `"organizationalUnit"`, `"container"`) | An enum | Three `string.Equals(..., OrdinalIgnoreCase)` predicates on the record and a `HashSet<string>` exclusion list in H18, all keyed on strings the LDAP layer produced. |
| `MaterializedDeltaAce` / `AclDeltaAce` / `CanonicalAceForMatching` / `LiveDaclAce` | one `LiveAce` with explicit projections | Four ACE shapes over one descriptor, two of which differ only in GUID casing. The names describe the consumer, not the data, so nothing signals that they are the same ACE four times. |

## Would-do-differently

**Consider not rebuilding this branch at all.** The strongest structural conclusion from mapping H is
that the branch may not have a reason to exist in a forest-wide audit product. LDAP is obviously
required for capture — that is B's, and it is not in question. But live *verification* is a
single-object operation bolted onto a whole-forest tool: `VerifyLiveAclAsync` takes one DN,
`CheckEffectiveAccessAsync` takes one DN and one trustee, `VerifyBundlesAsync` takes one DN. There is
no forest-wide live operation anywhere in H. A user who has just been told that 4,000 objects carry a
dangerous ACE cannot ask "which of these are still true"; they can only ask it one object at a time,
and only while connected to the directory the bundle came from.

The evidence in this file points the same way from several directions. The one genuinely live-versus-
stored component (H6) cannot say what it compared against (`Mode` discarded) or when the baseline was
taken (`SealedUtc` never read) — both of which a whole-forest freshness answer would have to carry.
H13 and H15, the two largest UI surfaces in the branch, do not compare against stored evidence at all.
H10 and H21 are dead. H17 through H20 exist to serve a capability (scoped capture) that was deleted.
Strip out what is dead, what does not verify anything, and what serves a removed feature, and what
remains is H6, H7, H8 and H11 — roughly 1,800 lines — answering a question the product cannot ask at
the scale it operates at.

If a rebuild wants a freshness story, the cheaper and more honest one is a **re-capture and compare**:
run the audit again and diff the two runs, which is G, already built, already forest-wide, and already
able to state both baselines. "Is this finding still true" is then answered for every finding at once
rather than for one object on demand. The remainder of this section assumes the branch *is* rebuilt,
and is written to be useful if that decision goes the other way.

**Say what a live answer is measured against, in the answer.** If anything survives, this is it, and
it has three parts, all traced above. A `LiveAclVerificationResult` should carry (a) the comparison
basis — materialized applied DACL or explicit-only hash — because those answer different questions and
the code already computes the distinction and throws it away; (b) the snapshot's `SealedUtc`, because
"drift since yesterday" and "drift since March" are different findings and F already stores the value;
and (c) a positive statement that stored evidence *was* consulted, so that a swallowed
`SqliteException` cannot surface as "Live ACL matches snapshot." Today the result records when the
live read happened and nothing about the other side of the comparison. An audit finding that cannot
state its baseline is not an audit finding.

**One effective-access evaluator, not three.** H7, H10 and H16 all answer "what can this principal do
to this object". They disagree in ways a user cannot see: H16 applies deny-before-allow while H7
applies DACL-order precedence, so on a non-canonical DACL they return opposite answers for the same
principal and right. H10 is the only one that reads D's `deny_cancelled` rather than recomputing it,
and H10 is the one that is dead. A rebuild should have exactly one evaluator with two evidence
adapters — live descriptor, stored `fact_control_edge` — and the shared precedence rule should live in
the evaluator, not in each adapter. The evaluator should also *return* the cancellation, not consume
it: D persists `deny_cancelled` as a column precisely because "granted, but only because a deny was
cancelled" is a fact worth showing, and H currently computes that fact and drops it.

This item survives even if the live branch does not. Two of the three implementations are stored-only,
and the duplication is between D and the UI, not between D and LDAP.

**Do not let the wrapper own the verdict.** `LiveCheckService` decides `Match` / `Drift` / `Error`
from three fields of a record produced two layers down, and the record cannot express "I did not
compare". Verdicts should be produced where the evidence is, by the component that knows whether the
comparison happened. The same shape appears in G — a refused compare rendering as "No changes" — and
the fix is the same in both branches: make the absence of a comparison a representable value, not the
same value as an empty comparison.

**Pass the result object, not eleven scalars.** `LiveAclVerificationResult` is destructured in H11,
flattened onto a preview view model in J, and reassembled into `AclDeltasWindowViewModel` from eleven
constructor arguments. That is why `OwnerChanged` is defined twice with two slightly different
predicates. This is also precisely why the first item is expensive today: adding `SealedUtc` to the
result means threading it through three types and a window constructor. The re-projection is the
reason the fix has not happened.

**Delete `DirectoryTree` and `InspectView`, but lift `MainViewModel.Inspect.cs` out first.** The
tree's own documentation says it exists "for scope selection… to define the capture scope", and scoped
capture was removed on 2026-08-02. It is an orphan by its own account and sequencing item 4 is right
about it. But those 32 lines are the only live-to-stored identity bridge in the product: every other H
component asks "is this stored object still true", and only this one asks "what did we capture about
this directory object". If live browsing goes, that question should survive as a lookup on the stored
object grid — paste a DN, find the captured row — rather than dying with its host view. This is the
G14 pattern exactly: a component that should not survive, containing one capability that should. Note
that the surviving form needs no LDAP at all, so it holds under the no-live-branch option too.

**Give `LiveErrorCode` a producer or delete it.** Five accurate codes, zero producers, zero consumers,
and an unreachable formatter. Meanwhile H11 recovers the same five categories by catching exception
types across a layer boundary, and H6 emits `$"Object not found: {dn}"` as free text. `ObjectNotFound`
in particular is not an error at all in an audit context — it means the object was deleted since
capture, which is a *finding*, and today it is a string that H11 maps to `Error` and the user reads as
a tool failure.

**Get the vendor schema out of the product.** `DirectoryTreeService.ExcludedLeafClasses` contains
three `enatel*` object classes — one customer's schema extension compiled into a shipped binary,
sitting unremarked among legitimate exclusions. Exclusion lists like this belong in configuration, and
if that is too much machinery, they at least belong behind a comment saying whose directory they came
from.

**Do not cache identity in a session-scoped dictionary without invalidation.** H3's `_sidCache` never
expires. The product's claim is freshness; a live read that silently returns a cached principal name
undermines the only thing live access is for. Either bound it by time as H2's connection pool already
is — the 60-second `PoolIdleTimeout` is the right instinct applied to the wrong resource — or drop it.

**This was right, keep it: the token-set construction in H8.** Assembling a trustee's effective token
from own SID, transitive membership via `LDAP_MATCHING_RULE_IN_CHAIN`, SIDHistory, primary group,
well-known SIDs, and `S-1-5-10` injected only when the trustee is the target object, is the hardest
thing in this branch to get right and it is got right. The SELF case in particular is a real Windows
behaviour that most tooling misses, and it is guarded correctly — the target's `objectSid` is read from
the same response as the descriptor and compared, rather than inferred from the DN.
`BuildOperationChecks`'s DCSync composite is right for the same reason: it encodes that Get-Changes
alone is not DCSync. And the `[IMP-WK-GUID]` comment consolidating GUID literals into
`WellKnownAdGuids` after findings F-1/F-2/F-3 is the only place in H where a past mistake is visible in
the code so it cannot be repeated. If the live branch is dropped, the operation-check *catalogue* —
the ten named rights and the DCSync composition rule — should still migrate to the stored evaluator,
because the question "what can this principal actually do" is the same question over either evidence
source.

**Second keep: H11's failure mapping.** Every LDAP failure mode maps to a distinct, actionable
summary, and a failed live read is genuinely distinguishable from a clean one — the property G found
missing in the compare branch. The problem in H is not that failures are mishandled here; it is that
H6 hands this component a success that was not one. The mapping itself is the standard the rest of the
branch should be held to.

## Corrections to existing documents

Recorded, not applied. No document listed here has been edited.

| Document | Claim | Correction |
|---|---|---|
| `docs/map/README.md`, boundary rulings table | "`AclCompareViewModel`, `StoredAclCompareViewModel`, `AclDeltasWindowViewModel` and `AclDeltaRowViewModel` … compare live DACLs against live or against stored" | Only partly so. `AclCompareViewModel` compares live against live (`AclCompareViewModel.cs:303`, `ReadLiveDaclAsync` twice). `StoredAclCompareViewModel` compares stored against stored (`ObjectQueryService.QueryAces` twice). Neither compares live against stored. The live-versus-stored comparison is `VerifyLiveAclAsync` (H6), reaching these types only via `AclDeltasWindowViewModel`. The ruling's placement of all four in H stands; its stated reason does not. |
| `docs/map/G-compare.md`, coverage gaps | `StoredAclCompareViewModel`'s private `CompareResult` (:133) recorded as a name collision | Confirmed as a name collision only. It is a private five-field DTO (`Groups`, `SideBySideRows`, `Summary`, `ResolvedNameB`, `Error`) returning values across a `Task.Run` boundary, sharing nothing with G's `CompareResult` but the identifier. |
| `docs/map/README.md`, note on branch H | "Live browsing as a destination in its own right — the Inspect view and `DirectoryTree` — is scheduled for removal by sequencing item 4 of that note, still outstanding at the time of writing." | Still outstanding as of this pass. `ContentHost.xaml:58` hosts `InspectView`; `MainViewModel.cs:499` constructs `DirectoryTreeViewModel`; `ServiceFactory.cs:108` exposes `CreateDirectoryTreeService`. The note should also record that `IDirectoryTreeService` and `DirectoryTreeNode` still document themselves as serving capture scope selection, removed 2026-08-02. |
| `docs/review/00a-product-identity.md`, decision 4 table | `VerifyLiveAclAsync` — "Keep — compares stored evidence against live. The audit case." | Upheld on the central claim: it does read `audit.db` and compare against it. Two qualifications: `storedDbPath` is optional and defaults to `null`, so the audit case is a caller opt-in rather than the method's contract; and a `SqliteException` during the stored comparison is swallowed, producing a result that presents as a clean match. |

## Coverage gaps in this pass

Line counts throughout are from `(Get-Content $f).Count`.

**Read in full:** `ILiveDiagnosticsService.cs` (90), `IDirectoryTreeService.cs` (62),
`IEffectiveAccessService.cs` (62), `LiveToolResults.cs` (111), `LiveAclEvaluationResult.cs` (71),
`BundleVerificationResult.cs` (23), `LiveAceConverter.cs` (70), `EffectiveAccessEvaluator.cs` (251),
`DirectoryTreeNode.cs` (31), `LiveErrorCode.cs` (13), `AclDeltaRowViewModel.cs` (35),
`AclDeltasWindowViewModel.cs` (89), `MainViewModel.Inspect.cs` (32), `InspectorDetailModel.cs` (38).

**Read in sections:** `LiveDiagnosticsService.AclTools.cs` (672) — lines 1–200, 155–200, 200–400,
400–560 read; 560–672 (`VerifyBundlesAsync` body, `FromCheck`) not read directly, characterised from
its three `BundleVerificationResult` construction sites and its one consumer.
`LiveDiagnosticsService.cs` (377) — lines 1–240 read; 240–377 (`ExploreObjectPropertiesAsync` tail,
`EscapeLdapFilter`, `GetDefaultNamingContextAsync`) not read. `LiveDiagnosticsService.SchemaTools.cs`
(244) — lines 1–80 read. `DirectoryTreeService.cs` (477) — lines 1–90 read; the LDAP paging and
node-shaping bodies not read. `AclCompareViewModel.cs` (513) — lines 1–140 read plus a targeted grep
for its `_liveDiagnostics` call sites. `StoredAclCompareViewModel.cs` (264) — lines 1–180 read.
`StoredEffectiveAccessViewModel.cs` (319) — lines 1–60 read; its deny-before-allow implementation
characterised from its own XML doc, not from the algorithm. `LiveCheckService.cs` (520) — lines 1–60
and 110–200 read; `MapDirectoryOperationException`, `CheckFindingAsync`, `EvaluateObject` and
`BuildAclDriftSummary` bodies not read. `PreviewActionService.cs` (556) — lines 1–50 and 78–100 read.
`InspectView.xaml.cs` (149) — lines 30–80 read.

**Not read:** `LiveDiagnosticsService.ObjectTools.cs` (152) and `.PrincipalTools.cs` (156) — H3 is
characterised from `ILiveDiagnosticsService`'s contract, `LiveToolResults`, and greps for the
pooled-connection call sites, not from the method bodies. `EffectiveAccessService.cs` (321),
`EffectiveAccessResult.cs` (68), `AccessCapability.cs` (65) — H10's deadness is proven by `git grep`,
and its shape taken from `IEffectiveAccessService`; the implementation's internals are unmapped by any
branch. `EffectiveAccessViewModel.cs` (549) — H15 rests on its one `CheckEffectiveAccessAsync` call
site and its file size. `DirectoryTreeViewModel.cs` (194), `DirectoryTreeNodeViewModel.cs` (151).
All XAML: `InspectView.xaml` (173), `InspectorDetailWindow.xaml` (177), `AclDeltasWindow.xaml` (96),
`InspectorStyles.xaml` (431).

**Claims verified by `git grep` rather than by reading:** H10's and H21's deadness;
`AuditErrorCodes.Format` having zero callers; `AclStoredComparisonMode.Mode` being read only in tests;
no H file referencing `SealedUtc`; `LiveSidResolutionService`'s only consumer being
`SecurityModeCaptureService`; `BundleVerificationResult`'s single production consumer.

**Two claims that would benefit from a test rather than a read.** First, that H7's `Evaluate` and
`CheckAccess` agree — they are different algorithms over one DACL and no test asserts equivalence.
Second, that H7 and H16 disagree on a non-canonical DACL: this is derived from H16's stated
"deny-before-allow" against H7's traced order-precedence, not from executing both. Both are stated as
reasoned rather than observed.

**Deliberately excluded per the boundary agreed at the start of this session**, and referenced rather
than mapped: `PreviewActionService` (556), `InheritanceViewModel` (316), `DelegationReportViewModel`
(157), `GroupMembershipViewModel` (110), `ResolvePrincipalViewModel` (139), `PrincipalNameResolver`
(130), `LdapInputHelper` (65), `ObjectDetailWindow.xaml.cs` (329), `LdapInputDialog.xaml.cs` (154),
`ObjectDetailPanelViewModel.Live.cs` (368), `.LiveDetail.cs` (312), `LiveSidResolver` (93) — all J's.
`LiveSidResolutionService` (398) — B's. `DelegationBundleMatcher` and the bundle catalogue — K's.
`RunDatabaseInspector` (75) — matched the file-name search but is unrelated to live access.
