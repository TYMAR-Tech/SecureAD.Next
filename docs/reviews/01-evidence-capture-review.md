# Review 01 — Evidence and capture correctness

**Reviewed:** 2026-08-28  
**Reviewer/model:** GitHub Copilot  
**Baseline:** `review-baseline-2026-08-28` (`d36ddb4`)  
**Status:** Findings open; no production correction accepted by this document

## Executive summary

The persistence design has a strong central invariant: capture writes one SQLite transaction under a
partial name, commits it, builds deferred indexes, checkpoints WAL, seals the resulting bytes, and
only then promotes the database to the name readers accept. Coverage and absence are generally typed
and stored positively rather than inferred from empty results.

Five corrections are recommended. The most important is a false-green retry path: Microsoft requires
a failed paged search to restart at page one, and `PartitionCapture` attempts that, but the production
sink and writer cannot discard the abandoned attempt. A retry after the sink has opened or received a
partition therefore throws or retains overlapping rows instead of performing the documented restart.

The second high-impact gap is that the implemented continuation-reference reconciliation is never
called in production. The product persists references but does not perform the comparison that its
documentation says surfaces an unplanned partition. Three narrower robustness/identity findings cover
exclusion cross-validation, filesystem exceptions during seal verification, and the run-library
completion reader's departure from the immutable SQLite opening used everywhere else.

Feature work that relies on complete capture should wait until E-C01 and E-C02 are resolved. This
review does not accept a correction or change production code.

## Architecture / data-flow map

```text
CLI Program / Shell NewAuditViewModel
  -> CaptureLauncher (Shell only)
  -> CaptureSession.ValidateAsync / RunAsync
  -> CaptureRun.RunAsync
     -> BundleWriter.Create (evidence.db.partial, WAL, one transaction)
     -> PartitionCapture.ReadAsync per planned naming context
        -> LdapDirectoryChannel
        -> BundleCaptureSink.BeginPartition / Receive / CompletePartition
        -> BundleWriter persistence
     -> SysvolCapture
     -> RunCoverage.Of
     -> BundleWriter.Complete
        -> commit -> indexes -> derived rows -> WAL checkpoint
        -> seal partial bytes -> annotations sidecar -> rename evidence.db
  -> Stage2aRun.Derive only after sealed capture
```

## Verified strengths

### S-01 — Partial evidence is not exposed as a finished bundle

`BundleWriter.Create` writes `evidence.db.partial`; `Complete` commits, builds indexes, checkpoints,
closes, seals, and only then renames it to `evidence.db` (`BundleWriter.cs:112-167, 1086-1185`).
`BundleReader.Open` asks only for the promoted name and verifies its seal before opening
(`BundleReader.cs:127-204`). An interrupted run therefore does not become analysable merely because
some rows exist.

### S-02 — Coverage is explicit and has a declared denominator

`RunCoverage.Of` refuses undeclared outcomes, missing declared-domain outcomes, and missing or repeated
configuration/schema outcomes (`RunCoverage.cs:171-234`). The bundle stores domain, forest-partition,
per-read-partition, excluded-domain, unread-partition and SYSVOL coverage independently. This avoids
using an empty object/result set as evidence that nothing exists.

### S-03 — Paging and attribute-range completion are represented as states

A response without a paging control is distinct from a last page, and a repeated cookie is refused
(`DirectoryPage.cs:13-109`; `PartitionCapture.cs:179-241`). An absent attribute is distinct from an
empty returned value, and range retrieval requires progress before it can complete
(`LdapEntryReader.cs`). Microsoft confirms that no cookie means successful completion, while an LDAP
error means the search is unsuccessful and a retry starts at page one.

### S-04 — Referral-chasing risk is correctly recognized before the first request

Capture refuses a connection whose referral policy is not the required value and checks controller
capabilities before conditionally applying domain scope (`PartitionCapture.cs:106-153`). Microsoft
confirms that subordinate referral chasing can erase a valid primary paging cookie and end a query
after its first page, and recommends disabling chasing or applying domain scope.

### S-05 — Missing and unreadable descriptors remain visible

`BundleCaptureSink` stores the fact that `nTSecurityDescriptor` did not arrive separately from parser
errors in bytes that did arrive (`BundleCaptureSink.cs:174-225`). Partition coverage also records the
connection-security rung, so a reader can avoid interpreting silently withheld confidential values as
an affirmative directory fact.

## Findings

## E-C01 — A paged-search restart cannot discard the abandoned production attempt

**Severity:** Critical  
**Confidence:** High  
**Release blocker:** Yes  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Audit/Capture/PartitionCapture.cs:77-92, 145-154, 161-224`
- `next/src/SecureAD.Audit/Capture/BundleCaptureSink.cs:82-112, 115-171`
- `next/src/SecureAD.Evidence/BundleWriter.cs:202-295`
- `next/tests/SecureAD.Next.Tests/Capture/PartitionCaptureTests.cs:271-296`
- `next/tests/SecureAD.Next.Tests/Capture/ControllerModel.cs:615-633`

### Evidence

`PartitionCapture.ReadAsync` calls `ReadOnceAsync` again for restart-worthy failures. Each attempt calls
`_sink.BeginPartition` before its first request. `BundleCaptureSink` retains `_openPartition`, and
`BundleWriter` retains the reserved coverage row and every object already written. Neither exposes an
abort/rollback operation. The next attempt therefore reaches a sink that rejects a second open
partition; if that guard were relaxed, the writer would independently reject the duplicate pair and
the already-written objects would remain.

The green restart test fails the first request before any object is handed on and uses `RecordingSink`,
whose `BeginPartition` only appends to a list. It does not exercise `BundleCaptureSink` or
`BundleWriter`, and therefore proves the loop retries while missing the production state that makes
that retry impossible.

Microsoft's cookie guidance says an LDAP error makes the paged search unsuccessful and retrying starts
from the first page. Restarting is therefore necessary; retaining or merging the abandoned attempt is
not a valid alternative.

### Customer consequence

A transient connection-ending failure can turn a recoverable capture into an unhandled exception.
Where the failure happens after objects were persisted, any naive retry fix that merely permits the
second open risks duplicate or mixed-attempt evidence.

### Recommended correction

Give one capture-unit attempt an explicit storage boundary. A restart must atomically remove the
attempt's objects, descriptors, trustees/ACEs reachable only from them, continuation references,
coverage row and in-memory writer/sink state before opening a new connection. Alternatively, stage an
attempt outside the permanent writer and merge it only after `PartitionCoverage` is constructed.
Do not weaken duplicate guards without implementing rollback.

### Validation required

- Fail after at least one complete page has reached a real `BundleCaptureSink` and `BundleWriter`.
- Restart and seal; assert every object, descriptor and coverage row occurs exactly once.
- Fail both attempts; assert no finished evidence exists and the partial records no claim of a
  completed partition.
- Exercise failure during ranged-attribute retrieval after prior objects were persisted.

## E-C02 — Continuation-reference reconciliation is not reachable in production

**Severity:** High  
**Confidence:** High  
**Release blocker:** Yes, for claims that unplanned partitions are surfaced  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Audit/Capture/ContinuationReferenceReconciliation.cs:1-156`
- `next/src/SecureAD.Audit/Capture/PartitionCapture.cs:155-224`
- `next/src/SecureAD.Evidence/BundleWriter.cs:282-294`
- `next/tests/SecureAD.Next.Tests/Capture/PartitionCaptureTests.cs:188-202`

### Evidence

The reconciliation type promises to compare received referrals with planned naming contexts and
return unplanned or unreadable references. Repository-wide symbol/text search finds no production
caller of `ContinuationReferenceReconciliation.Reconcile`; its only occurrence is its declaration.
Capture carries references into `PartitionCoverage`, and the writer persists them, but no production
path performs the documented comparison.

The relevant test asserts only that a reference reaches a `PartitionCoverage` value. It does not pass
through reconciliation or prove that a newly mentioned partition becomes a visible coverage gap.

Microsoft documents that a subtree search with chasing disabled returns referrals to direct
subordinate domains. It also documents that domain-scope suppresses continuation referrals, matching
the type's incompleteness state. The evidence is useful, but the promised interpretation is absent.

### Customer consequence

A forest can mention a subordinate/unplanned naming context during capture without the product
surfacing the documented coverage gap. Operators may believe the run checked for newly introduced
partitions when it only stored raw references that no current workflow evaluates.

### Recommended correction

Run reconciliation after all partition reads and before sealing, using the exact plan, accumulated
references and units that sent domain-scope. Persist a typed result: unplanned naming contexts,
unreadable references, suppressed units, and whether the reconciliation was complete. Decide
explicitly whether an established unplanned partition fails capture or seals with a visible degraded
coverage state.

### Validation required

- End-to-end capture where a controller returns a reference absent from the plan.
- Malformed-reference and domain-scope-suppressed cases remain Unknown/incomplete, not clean.
- A production reachability test starts from `CaptureRun` or `CaptureSession` and reads the persisted
  result back from the bundle.

## E-C03 — Exclusion keys and exclusion identities are not cross-validated

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Audit/Connect/CaptureSession.cs:296-321, 377-389`
- `next/src/SecureAD.Audit/Capture/CaptureRun.cs:132-172, 252-275`
- `next/src/SecureAD.Audit/Capture/CapturePlan.cs:92-140`
- `next/src/SecureAD.Evidence/Run/CoverageId.cs:181-220`
- `next/src/SecureAD.Evidence/AttestedExclusion.cs:44-65`

### Evidence

Exclusions are keyed by naming context for `CapturePlan.Excluding`, while `CoverageId` and domain
coverage use `AttestedExclusion.DomainFqdn`. `CaptureSession` and `CaptureRun` initially validate only
counts. `CoverageId` correctly rejects an excluded DNS name outside the declared DNS set, but no
boundary proves that each dictionary key, `AttestedExclusion.NamingContext`, and `DomainFqdn` are the
same domain from the discovery plan.

`CapturePlan.Excluding` deliberately ignores keys it does not carry. A mismatched key/value pair can
therefore remove one unit while recording or hashing another declared domain, eventually producing a
late duplicate/missing coverage exception or a contradictory attestation identity instead of a
precise refusal before traffic starts.

Existing tests prove valid exclusions remove units and alter scope identity. They do not exercise a
valid declared FQDN paired with another plan unit's naming context.

### Customer consequence

A malformed caller/UI mapping can waste a full capture and fail only during sealing, or produce
conflicting statements about which domain was authorized for exclusion.

### Recommended correction

Validate exclusions against the discovered domain records as exact pairs before creating the run
directory. Require dictionary key = `AttestedExclusion.NamingContext`, require one planned/declared
domain match, reject duplicate DNS identities, and calculate unread domains by set difference rather
than count.

### Validation required

- Swap naming contexts between two valid declared FQDNs and require an early typed refusal.
- Supply an unknown dictionary key with a valid declared FQDN and require refusal.
- Assert no run directory or LDAP capture traffic exists after refusal.

## E-C04 — Seal verification can throw instead of returning `Unreadable`

**Severity:** Medium  
**Confidence:** High  
**Release blocker:** No  
**Status:** Confirmed

### Affected files

- `next/src/SecureAD.Evidence/BundleSealing.cs:221-279`
- `next/src/SecureAD.Evidence/Run/RunStateReader.cs:57-83`
- `next/src/SecureAD.Evidence/BundleReader.cs:136-204`
- `next/tests/SecureAD.Next.Tests/Evidence/RunStateReaderTests.cs`
- `next/tests/SecureAD.Next.Tests/Evidence/BundleReaderTests.cs`

### Evidence

`BundleSealing.Verify` maps absent files, malformed JSON, missing hashes, unknown algorithms and hash
mismatches to typed verdicts. It does not catch `IOException` or `UnauthorizedAccessException` from
reading the seal or hashing the evidence. Those exceptions escape before `RunStateReader` can classify
the run as damaged and before `BundleReader.Open` can return an `AuditError`.

Tests cover the four logical seal states but do not inject filesystem read failures.

### Customer consequence

A locked, denied or transiently unreadable seal/evidence file can abort library listing or bundle open
through an exception rather than producing the actionable `SealUnreadable`/damaged state promised by
the public API.

### Recommended correction

Convert expected filesystem access/read failures into `SealState.Unreadable` with the path and precise
exception message. Keep programmer errors and unsupported conditions fail-fast; do not catch base
`Exception`.

### Validation required

- Denied/locked seal read and denied/locked evidence hash cases.
- `RunStateReader.Observe` returns `Damaged`; `BundleReader.Open` returns a typed failure.
- Other runs remain listable when one bundle is inaccessible.

## E-C05 — The completion-time fast path does not use the immutable SQLite open

**Severity:** Low  
**Confidence:** Medium  
**Release blocker:** No  
**Status:** Needs evidence

### Affected files

- `next/src/SecureAD.Evidence/Run/RunCompletionReader.cs:27-70`
- `next/src/SecureAD.Evidence/BundleReader.cs:472-497`
- `next/tests/SecureAD.Next.Tests/Evidence/BundleReaderTests.cs:351-371`

### Evidence

`BundleReader` opens the sealed WAL-mode database through an escaped `file:` URI with `immutable=1`,
explicitly to prevent SQLite from creating `-wal`/`-shm` files during a read. `RunCompletionReader`
opens the same verified file using a plain path and `ReadOnly`. It states that listing must not alter
a byte, but it does not reuse the immutable URI or an equivalent shared helper.

Microsoft.Data.Sqlite documents support for read-only mode and URI filenames. Microsoft guidance also
notes that WAL mode creates `.wal` and `.shm` associated files. The exact behavior of this provider
for a clean checkpointed, read-only WAL database should be reproduced before this is promoted from a
risk to a confirmed defect.

### Customer consequence

Potentially, listing a library can create SQLite sidecars beside sealed evidence or fail on read-only
media, contrary to the stated read-only observation guarantee. The sealed database bytes remain
covered, but the bundle directory can be changed by inspection.

### Recommended correction

First add a behavior test around the actual provider/version. If the plain read creates or requires
sidecars, centralize the immutable URI construction and use it in both readers. If it does not,
document the demonstrated behavior and close this finding.

### Validation required

- List a sealed bundle after deleting all sidecars and assert directory contents are unchanged.
- Repeat on a read-only directory/media simulation.
- Verify paths containing `%`, `?`, `#`, spaces and non-ASCII characters.

## Source conflicts and unresolved questions

| Subject | Sources/evidence | Status |
|---|---|---|
| Paged retry starts at page one | Microsoft “How LDAP server cookies are handled”; production comments | Established |
| Referral chasing can truncate paged queries | Microsoft KB 2561166; production guard | Established |
| Domain-scope suppresses continuation referrals | Microsoft KB 2561166 and `DomainScopeControl` API documentation | Established |
| Plain read-only open of clean WAL database creates sidecars | Microsoft WAL guidance establishes associated files; repository uses immutable specifically to prevent them | Reproduction required |
| What to do with an established unplanned partition | Current reconciliation model identifies it but no production policy consumes it | Product decision required |

## Recommended correction order

1. E-C01 — make restart atomic and add production-sink failure tests.
2. E-C02 — make reconciliation reachable and persist its typed outcome.
3. E-C03 — validate exclusion identity pairs before capture traffic.
4. E-C04 — normalize expected seal filesystem failures.
5. E-C05 — reproduce provider behavior, then fix or close.

## Files read fully

- `next/src/SecureAD.Evidence/BundleWriter.cs`
- `next/src/SecureAD.Evidence/BundleReader.cs`
- `next/src/SecureAD.Evidence/BundleSealing.cs`
- `next/src/SecureAD.Evidence/EvidenceCompleteness.cs`
- `next/src/SecureAD.Evidence/PartitionCoverage.cs`
- `next/src/SecureAD.Evidence/BundleLayout.cs`
- `next/src/SecureAD.Evidence/Run/RunCoverage.cs`
- `next/src/SecureAD.Evidence/Run/RunCompletionReader.cs`
- `next/src/SecureAD.Evidence/Run/RunStateReader.cs`
- `next/src/SecureAD.Audit/Capture/PartitionCapture.cs`
- `next/src/SecureAD.Audit/Capture/LdapEntryReader.cs`
- `next/src/SecureAD.Audit/Capture/RetryPolicy.cs`
- `next/src/SecureAD.Audit/Capture/DirectoryPage.cs`
- `next/src/SecureAD.Audit/Capture/BundleCaptureSink.cs`
- `next/src/SecureAD.Audit/Capture/CaptureRun.cs`
- `next/src/SecureAD.Audit/Capture/CapturePlan.cs`
- `next/src/SecureAD.Audit/Capture/ContinuationReferenceReconciliation.cs`
- `next/src/SecureAD.Audit/Connect/CaptureSession.cs`
- Relevant test files named in each finding

## Tools and external sources consulted

- Microsoft Learn: https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-ldap-server-cookies-are-handled
- Microsoft Support: https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased
- Microsoft Learn: https://learn.microsoft.com/windows/win32/ad/referrals
- Microsoft Learn: https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols.domainscopecontrol
- Microsoft Learn: https://learn.microsoft.com/dotnet/standard/data/sqlite/connection-strings
- Microsoft Learn: https://learn.microsoft.com/dotnet/maui/data-cloud/database-sqlite#advanced-configuration

## Validation performed

- Production call graph traced from CLI/Shell through capture, persistence and derivation kickoff.
- Repository-wide reference searches performed for reconciliation and affected APIs.
- Relevant production and test files read; no production code changed.
- Build/tests: deferred to report-publication validation because this review adds documentation only.
