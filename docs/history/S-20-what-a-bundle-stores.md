# S-20 — What a bundle stores

**Type:** slice
**Reviewed at commit:** `58506270`
**Size:** 5 files read in full or near-full, ~2,400 lines; plus 12 documents and 6 decision records
**Date:** 2026-08-12

> **This session did not write the schema, and that is deliberate.** It did its reading, found that
> two of the design's stated justifications do not survive contact with the old code, and reached a
> question that cannot be answered by argument. The measurement that answers it needs a production
> forest, which takes time to arrange. What is recorded here is what was found and what is still
> undecided. **Ledger row C1 is unchanged and still reads `Decided, rebuilding after review`.**
>
> **Cross-referenced 2026-08-13 in `S-26`, as `F-S26-4`.** That last sentence was true on
> 2026-08-12 and is not true now. `C1` was taken to **Done** by
> [`S-25`](S-25-the-finished-schema.md), having been built by
> [`S-24`](S-24-the-audit-database-schema.md). The sentence is left as written because this is a
> historical record and its account of what was found is evidence; what is corrected is the
> reader's expectation, not the record. The undecided question it names is settled or reassigned in
> `S-24` and `S-25` \u2014 read those before acting on anything here.

## What it does

C1 is the evidence schema — the tables a run writes its findings about a forest into. Everything
the product ever says is read back out of them, so their shape decides what the product is able to
say, and what it is able to notice it cannot say. If this subsystem vanished, a run could read a
forest and would have nowhere correct to put it.

## Shape

Nothing new was built. What exists today is the superseded implementation at
[`next/src/SecureAD.Evidence/`](../../next/src/SecureAD.Evidence): `BundleSchema` with ten tables,
`EvidenceObject`, `BundleWriter`, `BundleSealing` and `BundleLayout`. Of those, `BundleLayout` and
the partial-file mechanism survive review; the name/value storage in `BundleSchema`,
`captured_attribute`, `attribute_value`, `StoredAttributeCompleteness` and `EvidenceValue` do not,
because [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) removed the distinction
they exist to preserve.

## Dependencies

- **Depends on:** `SecureAD.Kernel` only, per the layering rule in [ARCHITECTURE](../next/ARCHITECTURE.md).
- **Depended on by:** `SecureAD.Audit`. Nothing calls the writer, because the row that joins capture
  to the bundle is B20 and does not exist.
- **Layering violations:** none found. The bundle sits below capture and cannot see `CapturedObject`,
  which is `F-S15-6` and remains correct.

## What was read, and what was not

Recorded because the first pass of this session overstated its own coverage, and the correction
changed two conclusions.

**Read in full or near-full:** the S-20 brief; [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md),
[`0002`](../decisions/0002-absent-view-means-degraded-run.md),
[`0023`](../decisions/0023-a-finding-has-a-stable-identity.md),
[`0021`](../decisions/0021-re-analysis-produces-a-new-bundle.md); ledger row C1;
[`S-16`](../next/S-16-the-bundle.md); [README](README.md); [ARCHITECTURE](../next/ARCHITECTURE.md);
`CapturedAttributeCatalog`, `CapturedObject`, `PartitionCoverage`, `BundleSchema`; and in the old
tree `DerivedStoreSchema.cs` (667 lines), `DirectObjectWriter.cs` (520), `DirectAceWriter.cs` (304)
and `DerivedAnalysisPipeline.cs` (631).

**Not read:** `POINT-IN-TIME-REVIEW.md`, [`S-15`](S-15-storage-dispositions.md),
`CONCEPT-REGISTRY.md`, `SURFACE-REGISTER.md`, `docs/map/C-storage.md`, and in the old tree the
rules engine, `EscalationPathService` and the UI. Statements below about the derived stages are read
off the schema those stages write, not off their code.

## Verified-safe

Things checked and found correct. Recorded so they are not re-investigated.

- **The old product's re-analysis genuinely worked.** `DerivedAnalysisPipeline.ResetForReanalysis`
  deletes and rebuilds exactly `dim_guid_map`, `dim_asset_tier`, `fact_delegation_bundle_match`,
  `fact_group_membership_closure`, `fact_expansion_status`, `fact_control_edge`,
  `fact_escalation_path` and `fact_finding` — evidence at
  `src/SecureAD.Infrastructure/Storage/DerivedAnalysisPipeline.cs:200`. The captured/derived split
  this session proposed **already exists** in the old product as that string array. An earlier claim
  in this session that re-analysis "only half-works" was wrong and is retracted at `F-S20-9`.
- **`fact_ace` is a faithful representation of a standard or object ACE.** Type, trustee, access
  mask, both object-type GUIDs, inherited flag, inheritance flags and propagation flags are all
  stored; the two flag columns together reconstruct the original flags byte. Rule and graph
  improvement never needed the raw descriptor.
- **Neither implementation captures the SACL.** Old: `SecurityMasks.Owner | Group | Dacl` at
  `src/SecureAD.Infrastructure/Ldap/DirectCaptureModule.SecurityDescriptors.cs:38`. New: the same
  three masks at `next/src/SecureAD.Audit/Capture/CaptureSearchRequestFactory.cs:316`. Storing raw
  bytes would therefore **not** recover audit entries — that is a capture decision, not a storage
  one.
- **The rebuild's capture request matches the predecessor's.** Same masks, page size 1000
  (`next/src/SecureAD.Audit/Capture/ServerLimits.cs:63`), so a measurement taken against the old
  request shape is valid evidence for the new one.
- **The attribute catalogue holds 38 distinct attributes**, 29 single-valued and 9 multi-valued.
  Reproduce with:
  ```powershell
  $t = Get-Content next/src/SecureAD.Kernel/Capture/CapturedAttributeCatalog.cs -Raw
  [regex]::Matches($t, 'new\("([^"]+)",\s*AttributeCardinality\.(\w+)') |
    ForEach-Object { [pscustomobject]@{ Name=$_.Groups[1].Value; Card=$_.Groups[2].Value } } |
    Sort-Object Name -Unique | Group-Object Card | Select-Object Name, Count
  ```

## Findings

### F-S20-1 — Ledger row C1 instructs adopting a deleted flag that capture never reads

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** C1 in [WHAT-THE-OLD-APP-HAD](../next/WHAT-THE-OLD-APP-HAD.md) says "adopt from the predecessor … a deleted
  flag". `isDeleted` is absent from `CapturedAttributeCatalog`, and nothing under `next/src`
  references deleted objects or tombstones (`git grep -in "deleted\|tombstone" -- next/src`, which
  returns only prose in comments and `ComparabilityOutcome.EarlierRunDeleted`).
- **What happens to a user:** an `is_deleted` column would be `0` on every row of every bundle ever
  written. Any report or rule reading it would state that no objects are deleted, which is a claim
  the product has no evidence for. This is a field that looks like an answer and measures nothing.
- **Why it is this way:** the predecessor did populate it — `DirectObjectWriter.cs:129` reads
  `isDeleted` from the entry — because its own capture requested that attribute. The rebuild's
  catalogue, decided separately at B2, does not.
- **Options:** (a) drop the column from C1 and correct the ledger row; (b) add `isDeleted` to the
  catalogue at B2 and send the Show Deleted Objects control, which is a capture change and a
  product decision about whether deleted objects are in scope at all; (c) build the column and
  leave it always false — rejected, it is the failure the gates exist to prevent.
- **Test cover:** none. No test asserts that a stored column has a producer.
- **Status:** OPEN — blocking, raised to the owner 2026-08-12, not yet decided.

### F-S20-2 — `0022` credits the typed-column shape with a performance measurement it did not take

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) Consequences:
  "The shape is the one whose performance has been measured in production, which is the only
  performance evidence that exists." The predecessor's `dim_object`
  (`src/SecureAD.Infrastructure/Storage/DerivedStoreSchema.cs:13`) has 21 columns holding
  *interpreted* data; `0022`'s shape is 29 single-valued columns plus 9 multi-valued tables of
  *raw* values. They are not the same shape.
- **What happens to a user:** nothing directly. The risk is to the next design decision — a future
  session reads that sentence, believes the shape is proven at scale, and skips a measurement.
- **Why it is this way:** both designs are called "typed columns", and the phrase hid the difference.
- **Options:** correct the sentence in place per
  [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md). It is in Consequences, not
  Context, so it is correctable rather than preserved.
- **Test cover:** none.
- **Status:** OPEN — identified 2026-08-12, correction not yet written pending the owner's decision
  on the layering, which may change the sentence further.

### F-S20-3 — `0022`'s Context says 45 attributes; the catalogue holds 38

- **Severity:** cosmetic
- **Confidence:** verified
- **Evidence:** measured at 38 distinct, by the command in **Verified-safe** above.
- **What happens to a user:** nothing. It is the number sizing the argument for abandoning
  name/value storage, and the argument holds at 38.
- **Why it is this way:** likely counted before the catalogue was consolidated, or counted
  per-class occurrences rather than distinct names.
- **Options:** leave it. It sits in a `## Context` section, which
  [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md) preserves as written so the
  reasoning that produced an error survives.
- **Test cover:** none.
- **Status:** OPEN — recorded rather than corrected, deliberately, 2026-08-12.

### F-S20-4 — The predecessor silently discards any object whose `objectGUID` did not arrive

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `src/SecureAD.Infrastructure/Storage/DirectObjectWriter.cs:126` —
  `var objectGuid = LdapAttributeHelper.ExtractGuid(entry, "objectGUID"); if (objectGuid is null) return;`
- **What happens to a user:** the object is not stored, no error is raised, no counter moves, and
  the run reports success. The object's permissions leave with it, and the audit reports the forest
  as covered. This is the exact failure the rebuild exists to remove.
- **Why it is this way:** the writer runs over millions of objects and must not throw. Returning is
  the cheapest way not to crash.
- **Options:** for the rebuild — (a) refuse, ending the run, consistent with `S-16`'s rule that a
  value the product cannot represent ends the run; (b) store the object in a table that does not
  require a GUID, so it is visible as a hole. What is not available is the predecessor's answer.
- **Test cover:** none in the old tree.
- **Status:** OPEN — informs the rebuild's design, raised to the owner as open question 4.

### F-S20-5 — A failed materialised-ACL write is swallowed to `Debug.WriteLine`

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `src/SecureAD.Infrastructure/Storage/DirectAceWriter.cs:262-270` —
  `catch (Exception ex) when (ex is not OutOfMemoryException) { System.Diagnostics.Debug.WriteLine(...) }`
- **What happens to a user:** an object whose ACL payload failed to write is indistinguishable from
  an object with no ACL. In a release build the message is not even emitted.
- **Why it is this way:** the same pressure as `F-S20-4` — the ingest loop must survive.
- **Options:** old tree, not carried. The rebuild has no materialised payload column at all, per
  `S-16`, so the defect has no counterpart to inherit.
- **Test cover:** none.
- **Status:** DEAD — the mechanism is not carried into the rebuild. Recorded because it is the third
  instance of one habit and that pattern is the finding.

### F-S20-6 — The predecessor's upsert keeps an object's first distinguished name forever

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `src/SecureAD.Infrastructure/Storage/DirectObjectWriter.cs:48-68`. The
  `ON CONFLICT(object_guid) DO UPDATE SET` list omits `distinguished_name`, `domain_fqdn`,
  `object_class`, `parent_guid`, `sid` and `dn_reversed`.
- **What happens to a user:** an object seen a second time — across a merge, or a re-capture into an
  existing database — updates its timestamp and attributes while reporting its **old** location. A
  moved object appears never to have moved.
- **Why it is this way:** the merge model. One database could accumulate several captures.
- **Options:** not carried. The rebuild is one run to one bundle with no merge, which removes the
  whole class.
- **Test cover:** none.
- **Status:** DEAD — no counterpart in the rebuild's model.

### F-S20-7 — `fact_ace` discards entry order and collapses duplicate entries

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `src/SecureAD.Infrastructure/Storage/DerivedStoreSchema.cs:69` —
  `PRIMARY KEY (object_guid, ace_hash)`, with no ordinal column.
- **What happens to a user:** order within a DACL is semantically meaningful — deny entries are
  evaluated before allow entries — and two byte-identical entries in one list become one row.
- **Why it is this way:** the hash makes a natural key and deduplicates for free.
- **Options:** already answered. The superseded `next` schema added `ordinal` with
  `UNIQUE (object_id, ordinal)` at `next/src/SecureAD.Evidence/BundleSchema.cs`, and that fix is
  worth keeping whatever else changes.
- **Test cover:** the kernel's `AceNormalizer` tests cover canonical ordering; nothing covers its
  survival through storage.
- **Status:** OPEN — carried forward as a requirement on the rebuilt schema.

### F-S20-8 — The predecessor performs no delegation analysis on an unrecognised object class

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `src/SecureAD.Infrastructure/Storage/DirectObjectWriter.cs:163-169` — `WriteDelegations`
  is inside `if (classAttributes is not null)`, and `classAttributes` is null for any class not in
  the old catalogue.
- **What happens to a user:** an object of an unanticipated class with unconstrained delegation set
  is never assessed for it. No row, no error.
- **Why it is this way:** an inclusion list. The class had to be known in advance.
- **Options:** already fixed in principle. `CapturedAttributeCatalog.AttributesFor` in the rebuild
  always returns at least the universal set and documents that it "is never empty, so an empty
  answer is not a state a caller has to handle."
- **Test cover:** `CapturedAttributeCatalogTests` in the rebuild.
- **Status:** REPAIRED in the rebuild's catalogue, 2026-08-12. Recorded because it is the concrete
  damage the rebuild's one-filter rule prevents.

### F-S20-9 — Interpretation at capture time is unrecoverable where the source value was binary

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `DirectObjectWriter.WriteDelegations` at
  `src/SecureAD.Infrastructure/Storage/DirectObjectWriter.cs:299-360` writes labelled conclusions —
  `Unconstrained`, `RBCD`, `ShadowCredential` — at capture. `dim_delegation` is **not** in
  `ReanalysisTables`, so those labels are frozen. `DirectAceWriter.WriteMaterializedAcl`
  (`DirectAceWriter.cs:274`) re-serialises already-parsed `CanonicalAce` values, so the original
  `nTSecurityDescriptor` bytes are never stored anywhere.
- **What happens to a user:** where the source was text or an integer, the input survives in
  `dim_object` or in `dim_delegation.target`/`.details`, so a better classifier could be recomputed.
  Where the source was binary it cannot. The clearest case is resource-based constrained delegation:
  `InsertDelegation(guidStr, "RBCD", null, ...)` passes `null` for the target, so the bundle records
  **that** RBCD is configured and never **who** can use it — that trustee lives inside a binary
  descriptor that was not parsed and not kept.
- **Why it is this way:** capture is expensive and the data is in hand, so computing once is the
  natural instinct. It is the right instinct for a monitoring tool and the wrong one for an evidence
  tool.
- **Options:** the layered split under open question 1, which moves labelling to the derived side.
  Whether raw descriptor bytes are also kept is open question 2 and needs the measurement.
- **Retraction:** an earlier claim in this session that the predecessor's re-analysis "only
  half-works" was **wrong**, and is withdrawn. Everything the owner used re-analysis for — rules,
  the control graph, escalation paths, tiering — rebuilds correctly from `fact_ace` and `dim_object`.
  The limitation is narrower than stated and is confined to this finding.
- **Test cover:** none.
- **Status:** OPEN — the central input to open questions 1 and 2.

### F-S20-10 — `S-16` still says re-analysis does not come across, which `0021` reversed

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** [`S-16`](../next/S-16-the-bundle.md) § One way in: "There was a second — re-analysis of an
  existing bundle — and it does not come across". Ledger row C15 already records the reversal:
  "**Reversed 2026-08-12 per [`0021`]:** re-analysis comes back."
- **What happens to a user:** nothing directly. A reader of `S-16` alone concludes the product cannot
  re-analyse a saved capture, which is the opposite of what was decided.
- **Why it is this way:** `S-16` was written on 2026-08-12 and `0021` reversed it the following day.
  The ledger row was swept and the slice document was not.
- **Options:** correct `S-16` when it is next rewritten, which the S-20 brief already requires.
- **Test cover:** none. `BundleDocumentationTests` binds the table list, not the prose.
- **Status:** OPEN — found 2026-08-12, correction owed by whichever session finishes C1.

### F-S20-11 — `ARCHITECTURE.md` reports C1, C10, C11 and C15 as built; the ledger says they are being rebuilt

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** [ARCHITECTURE](../next/ARCHITECTURE.md) stage 3: "The write half is decided and built: C1,
  C3, C10, C11 and C15". Ledger rows C1, C10, C11 and C15 all read
  `Decided, rebuilding after review`, and [README](README.md) states the code in `SecureAD.Evidence`
  does not match the decisions.
- **What happens to a user:** nothing. A reader of `ARCHITECTURE.md` believes storage is finished.
- **Why it is this way:** the paragraph was written before the 2026-08-12 review superseded the code.
- **Options:** correct the stage 3 line to match the ledger.
- **Test cover:** `ArchitectureDocumentationTests` binds projects and dependencies, not stage status.
- **Status:** OPEN — found 2026-08-12, not corrected in this session because it is prose about work
  that is about to change again.

### F-S20-12 — `S-16` makes `object_guid` nullable while `0022` makes it the identity

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** [`S-16`](../next/S-16-the-bundle.md) § What identifies an object: "It is nullable, because an
  identity that did not arrive is not invented."
  [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md): "An object's identity is its
  `objectGUID`".
- **What happens to a user:** unresolved, this produces either a primary key that cannot be null and
  a silent drop (`F-S20-4`), or a nullable identity column that joins to nothing.
- **Why it is this way:** the two documents answer different halves and neither is wrong alone.
- **Options:** open question 4.
- **Test cover:** none.
- **Status:** OPEN — raised to the owner 2026-08-12.

### F-S20-13 — Attributes the predecessor used that the rebuild's catalogue does not request

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** absent from `CapturedAttributeCatalog` and present in the old `dim_object` or
  `WriteDelegations`: `isDeleted`, `lastLogonTimestamp`, `accountExpires`, `operatingSystem`,
  `operatingSystemVersion`, `ms-Mcs-AdmPwdExpirationTime` and `msLAPS-PasswordExpirationTime`.
- **What happens to a user:** any rule or report the old product built on those attributes has no
  data in the rebuild. LAPS state and stale-account detection are the visible ones.
- **Why it is this way:** the catalogue was rebuilt from scratch at B2 and each entry must name a
  consumer, so an attribute with no rule yet written was correctly left out.
  **This reasoning was challenged and does not hold — 2026-08-13,
  [`S-23`](../next/S-23-what-capture-must-read.md).** The rules were not unwritten; they are sixty-two cards
  in `docs/rules/`, unported. What made the attributes look unwanted is that the gate accepted only
  a **ledger row** as a consumer, and almost no ledger row is built — so the catalogue was bounded
  by the port's progress rather than by the product. The severity here was wrong too: the LAPS half
  is `breaks-for-user`, not `maintainability`. SEC-091 and SEC-092 are both enabled and both
  reported a clean forest whatever the forest looked like, which is not a missing feature but a
  false statement to a customer. And the two halves are not one problem: two shipped rules depend on
  the LAPS attributes; **no rule at all** depends on `lastLogonTimestamp` or `accountExpires`, so
  those two remain correctly dropped. Recorded as `F-S23-3`.
- **Options:** none here. This belongs to B2 and to the rule catalogue at branch E. It is recorded
  because C1 cannot store what capture does not read, and `F-S20-1` is the first instance of that
  colliding with an instruction.
- **Test cover:** `CapturedAttributeCatalogDocumentationTests` requires every catalogue entry to name
  a consumer; nothing requires a consumer to find its attribute present.
  Since S-23, a consumer may be a rule card, and
  `CapturedAttributeDerivationDocumentationTests` binds the per-attribute derivation to the
  catalogue in both directions.
- **Status:** PARTLY REPAIRED — 2026-08-13. **Closed:** `operatingSystem`,
  `ms-Mcs-AdmPwdExpirationTime` and `msLAPS-PasswordExpirationTime` are captured, catalogue version
  2, so SEC-091 and SEC-092 are answerable. **Closed as correct:** `isDeleted` (the container needs
  a control capture does not send, so the value would always be false), `lastLogonTimestamp`,
  `accountExpires` and `operatingSystemVersion` — no rule among the sixty-two reads any of them.
  Nothing of this finding remains live.

### F-S20-14 — The predecessor's escalation graph never modelled containment, so inherited permissions were invisible to it

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** the chain, each link read rather than inferred:
  - `fact_ace` holds explicit entries only — `DirectAceWriter.cs:158`, and commit `0093b571`
    (2026-03-16) *"Skip inherited ACEs during SD ingest to reduce DB size by ~80-90%"*
  - control edges are built from it — `ControlEdgeService.cs:107`,
    `SELECT ... FROM fact_ace WHERE ace_type IN (0, 5)`, one edge per entry with the target being
    the object the entry sits on — plus ownership edges at `ControlEdgeService.cs:212`
  - escalation paths are built from those — `EscalationPathService.DataAccess.cs:26, 110`, joined
    with `fact_group_membership_direct` at `:68`
  - findings read the same tables: 15 queries `FROM fact_control_edge`, 5 `FROM fact_escalation_path`,
    3 `FROM fact_ace` (`git grep -ho "FROM fact_[a-z_]*" -- src/SecureAD.Infrastructure/Findings/`)
  - **containment is modelled nowhere in derivation.** `parent_guid` is consumed only by
    `InheritedAceResolver` (the object-detail read path), the schema, the views and its own
    population pass (`git grep -n "parent_guid" -- src/`). `dn_reversed` is consumed only by UI
    grids. The only `LIKE` in derivation is relative-identifier matching and one
    `OU=Domain Controllers,%` check for controller detection.
- **What happens to a user:** a principal granted control on a container appears to control the
  container and nothing else. If Alice holds `GenericAll` on `OU=Finance` and it inherits to the
  5,000 accounts beneath it, `fact_ace` has one row, `fact_control_edge` has one edge, and there
  are **no edges from Alice to any of those accounts**. Asked *"who can take over the CFO's
  account"*, the product answers *"nobody"*. The grant itself is still reported, so the cause is
  visible and the consequence is not — which is why this was survivable long enough to reach path
  analysis before being noticed.
- **Why it is this way:** the commit that introduced the skip carries its own justification —
  *"Inherited ACEs are redundant: they originate as explicit ACEs on parent objects which are
  already captured. Control edges, findings, and escalation paths only need explicit ACEs to detect
  dangerous permissions."* The first sentence is true. The second is true **only if the graph
  expands containment**, and it never did. The saving was real and the justification was not
  re-checked against the code that was supposed to rely on it.
- **What it costs, specifically:** paths that route through a container into its contents do not
  exist; `fact_escalation_chokepoint.affected_path_count` is computed from those paths and therefore
  understates impact — the chokepoint feature is the one most damaged by this; and Tier 0
  reachability is understated wherever the route is inherited. Detection of the grant is intact
  throughout.
- **Magnitude:** narrower than the 80-90% of entries that were skipped, because most inherited
  entries are defaults inherited from the domain root — `SYSTEM`, `Domain Admins`,
  `Authenticated Users` read. The missing slice is **custom delegation at container level**, which
  is far smaller but is also the normal way delegation is performed in Active Directory. No number
  is put on it here because none was measured.
- **Options:** store inherited entries, so each object's stored permissions already include what it
  inherited and an edge falls out per object with no inheritance logic anywhere; or keep explicit
  entries and add containment edges plus correct inheritance semantics — inheritance and
  propagation flags, `INHERIT_ONLY`, `SE_DACL_PROTECTED` blocking the chain, and object-type-scoped
  inheritance. The second is `InheritedAceResolver`'s problem moved from the user interface into the
  graph, where being wrong matters more.
- **Test cover:** none. No test in the old tree asserts that an inherited permission produces a
  control edge.
- **Status:** OPEN against the predecessor, which is frozen and not being fixed. **Resolved by
  decision in the rebuild** — see *Decisions taken* below — with the condition recorded at
  `F-S20-15`. Verified 2026-08-12.

### F-S20-15 — Storing inherited entries requires derivation to suppress expected grants, and that obligation is owed to D7

- **Severity:** correctness-risk
- **Confidence:** verified by inspection of what the entries contain
- **Evidence:** every object inherits full control from `SYSTEM`, `Domain Admins` and
  `Enterprise Admins` from the domain root down. Storing inherited entries and deriving an edge per
  entry produces an edge from each of those to every object in the forest.
- **What happens to a user:** a graph in which `Domain Admins` controls all 100,000 objects is
  technically true, analytically worthless, and large enough to bury every finding that matters.
  Part of the 80-90% the predecessor saved by skipping inherited entries was accidental noise
  suppression, and that benefit is given up along with the defect.
- **Why it is this way:** it is a direct consequence of the decision at `F-S20-14`, not a
  pre-existing defect.
- **Options:** derivation classifies and suppresses expected grants. The machinery is already
  anticipated — [`0006`](../decisions/0006-tier-0-and-expected-admin-are-separate-sets.md) separates
  Tier 0 from expected administrators, K16 is the single answer to whether a right is dangerous, and
  the predecessor already had the shape of it for owners in `ControlEdgeService`'s
  `IsExpectedPrivilegedOwnerSid` and `expectedPrivilegedOwnerEdges`.
- **Test cover:** none yet; the row is not started.
- **Status:** OPEN, **owed to D7 (control edge derivation)**, recorded 2026-08-12 at the moment the
  decision that creates it was taken rather than when the graph is built.

### F-S20-16 — One object in five returned no security descriptor, and coverage has no state for it

- **Severity:** correctness-risk
- **Confidence:** verified against a production domain
- **Evidence:** a 100,000-object read returned 80,073 objects with a descriptor and 19,927 without.
  Re-querying 200 of the missing objects **individually** recovered 0, left 200 still empty and
  errored on none, so this is a permissions boundary and not a lossy bulk read. The objects are
  `ENATEOUserManagedAuth` and `enatelSSAAccount` — roughly two per user account, from a single
  sign-on product — and the run was made with an ordinary user account, not an administrator.
- **What happens to a user:** as the schema stood, those objects would be stored with no permissions
  and no explanation, indistinguishable from objects whose permissions were read and found to grant
  nothing. That is `F-S20-7`'s distinction failing on 20% of a domain.
- **Why it is this way:** an unprivileged account cannot read the access control list on a credential
  store, which is the vendor behaving correctly. The gap is in the model, not the directory.
- **The state that has no home:** [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md)
  describes coverage in terms of domains read fully or in part. This domain was **enumerated
  completely** while permissions were unreadable on a fifth of it. That is a third state, and the
  vocabulary has no word for it. Applying `0027` literally makes every unprivileged run a failure.
- **What cannot be solved inside one run:** LDAP returns the same thing for *this object is locked
  down* and *you lack privilege* — the attribute is simply absent, with no error. The product cannot
  derive which; it can only record the account, the privilege and the count, and let a reader judge.
- **Options:** record unreadable descriptors positively, per object and as a run total; probe the rate
  in preflight before committing to a multi-hour run; decide whether an under-privileged run may be a
  baseline.
- **Test cover:** none.
- **Status:** OPEN. Recording is decided below; **whether an under-privileged run may be a baseline is
  not**, and is the largest question left after this session.

### F-S20-17 — The rebuild's write connection sets two of the seven settings the predecessor tuned, and never sets the one that matters most here

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `BundleWriter.cs:109-110` sets `journal_mode = WAL` and `synchronous = NORMAL`, and
  nothing else. `DerivedStore.ApplyPragmas` (`DerivedStore.cs:216`) sets those two plus
  `foreign_keys`, `temp_store = MEMORY`, `cache_size` (512 MB), `mmap_size` (256 MB write, 1 GB on
  the read path) and `busy_timeout`. C3 is recorded as `Done`.
- **What happens to a user:** slower capture and slower index building than the predecessor achieved,
  for no reason anybody chose.
- **Neither app sets `page_size`.** The default is 4,096 bytes and production descriptors average
  **31,742 bytes**, so each one spills across eight or more overflow pages in a database that is now
  mostly large values. It must be set **before the first table is created** and cannot be changed
  afterwards without rebuilding the file, so it is a C1/C3 decision or an expensive one later.
- **Options:** carry `temp_store` and `mmap_size` unchanged; carry `cache_size` at a stated, lower
  default because capture also holds the descriptor hash map; turn `foreign_keys` **off during ingest**
  and run `PRAGMA foreign_key_check` before sealing, which converts a per-row cost into one pass at
  the moment the bundle is already being verified; measure 8 KB and 16 KB page sizes against a real
  bundle.
- **Test cover:** none.
- **Status:** OPEN — carried into C1/C3 as work, 2026-08-12.

### F-S20-18 — The measurement tool asked for an attribute that does not exist and reported zeroes

- **Severity:** correctness-risk
- **Confidence:** verified, reproduced locally without a directory
- **Evidence:** passing an inline `@('nTSecurityDescriptor','objectClass')` to the `SearchRequest`
  constructor marshals the array into the `params string[]` parameter as a **single space-joined
  name**. Reproduce:
  ```powershell
  [string[]]$typed = @('nTSecurityDescriptor','objectClass')
  (New-Object System.DirectoryServices.Protocols.SearchRequest("DC=x","(objectClass=*)",$scope,$typed)).Attributes.Count      # 2
  (New-Object System.DirectoryServices.Protocols.SearchRequest("DC=x","(objectClass=*)",$scope,@('nTSecurityDescriptor','objectClass'))).Attributes.Count  # 1
  ```
- **What happens to a user:** the tool reported `0` distinct descriptors and `0` bytes, which reads as
  a fact about the forest and was really a failed read — the exact conflation the product it serves
  exists to prevent, committed by the tool measuring for it. Two theories were pursued and published
  before the real cause was found: byte extraction, and page size. Both were wrong, and the page-size
  theory was escalated as a possible defect in the rebuild's capture before being withdrawn.
- **Why it is this way:** the working diagnostic passed a typed `[string[]]` variable and the failing
  scripts passed an inline array; the difference is invisible at the call site.
- **The product is unaffected.** `CaptureSearchRequestFactory` adds attributes one at a time
  (`foreach (var attribute in CapturedAttributeCatalog.All) request.Attributes.Add(...)`) and sets
  `SizeLimit = 0` explicitly, so no marshalling occurs.
- **Options:** already applied — the tool builds its request with `Attributes.Add`, and carries a
  guard that throws when entries come back with **zero** descriptors, printing the attribute list it
  actually requested. Every object in a directory has a security descriptor, so that total can only
  mean a broken read.
- **Test cover:** the guard is the test, and it was written from the failure rather than in advance.
- **Status:** REPAIRED 2026-08-12. Recorded because the tool is in the repository, the guard exists
  only because of this, and the same class of defect appeared twice more in this session's own
  diagnostics — a check that failed for a reason unrelated to what it measured.

## Decisions taken

Settled by the owner on 2026-08-12, after the measurements below. These replace the open questions
this document originally carried.

**1. The bundle is split into a captured layer and a derived layer, with an enforced boundary.** The
captured layer records what the directory said; the derived layer holds everything computed from it.
One testable rule: delete every derived table, recompute from the captured layer with no network
access, and the result is identical. The predecessor already had this boundary as
`DerivedAnalysisPipeline.ReanalysisTables` — eight table names in a string array, unnamed and
unenforced.

**2. Security descriptors are deduplicated.** One `security_descriptor` row per *distinct* descriptor,
keyed on SHA-256 of its bytes with the byte length stored beside it; objects reference it. The row
carries the raw bytes, owner, group, DACL state, the protected flag, the entry-set hash and any parse
errors. **Entry sets are stored once per descriptor, not once per object.** A cryptographic hash is
required rather than a fast one: the failure mode of a collision is silent misattribution of an
object's permissions.

**3. Raw descriptor bytes are stored.** Roughly 13% on top of the parsed entries, against a raw form
that is *smaller* than what parsing it produces. It makes a defect in the descriptor parser
recoverable by re-analysis rather than by re-reading a customer's forest, which is the one stage that
cannot be redone.

**4. Inherited entries are stored** — because of `F-S20-14`, not for completeness in the abstract. Each
object's stored permissions then already include what it inherited, and a control edge falls out per
object with no inheritance logic anywhere. **Conditional on `F-S20-15`**, owed to D7.

**5. What could not be read is recorded positively.** A descriptor that could not be read gets a row
saying so, per object, with a run-level count beside the object count. Absence never means *grants
nothing*.

**6. What was asked of each object is recorded positively.** The catalogue holds about eight distinct
attribute sets; they become a small table, and each object row carries an integer naming the set it
was asked for. Without it, an organizational unit's empty `sAMAccountName` and a user's empty
`sAMAccountName` are the same empty cell meaning opposite things — `0002`'s failure inside the shape
`0022` chose to prevent it.

**7. Coverage is recorded per naming context and controller**, which is what capture can vouch for,
with the domain verdict derived from it.

**8. The reason an unseen reference was never seen comes from the closed four in
[`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md)**, with no free text beside it. The
predecessor carried both a free-text `reason` and a `reason_category` **defaulting to
`'Undetermined'`** (`DerivedStoreSchema.cs:276`) — a constrained set that does not constrain.

**9. An object whose `objectGUID` did not arrive ends the run.** It is mandatory and system-generated
on every Active Directory object, so this should never fire; if it does, that is information rather
than a row to store unidentifiably. The predecessor's silent drop (`F-S20-4`) is not available.

**10. Privilege is probed and recorded.** Preflight samples objects and reports the readable-descriptor
rate before a multi-hour run is committed to; the run records the account and the rate. An
under-privileged run's blind spots are biased toward exactly the objects someone took the trouble to
protect, so the rate is not a footnote. **Whether such a run may serve as a baseline is not yet
decided** — see `F-S20-16`.

**11. The SQLite settings at `F-S20-17` are carried**, with `foreign_keys` off during ingest and
checked before sealing, and `page_size` chosen before the first table exists.

**12. No object classes are excluded beyond DNS.** With deduplication the single sign-on objects cost
single-digit megabytes rather than the gigabytes the per-object shape implied, so this stopped being a
cost question. Excluding a class holding user authentication data would be a judgement needing
defence; recording that its permissions were unreadable is honest and nearly free.

## Measurements

Taken 2026-08-12 with [`next/tools/Measure-DescriptorCost.ps1`](../../next/tools/Measure-DescriptorCost.ps1),
which reads a naming context using the request shape capture uses — `Owner | Group | Dacl`, page size
1000, domain-scoped.

**Production, one of the more complex domains, 100,000 objects, unprivileged account:**

| | |
|---|---|
| Objects read | 100,000 |
| With a descriptor | 80,073 |
| Without one | **19,927** — see `F-S20-16` |
| Parse failures | 0, over 20,383 distinct descriptors |
| Raw descriptor bytes | 2,541,643,828 (2.42 GB) |
| Descriptor size | 324 B min, **31,742 B mean**, 60,356 B max |
| Distinct descriptors | 20,383 |
| Deduplicated bytes | 657,210,780 (0.63 GB) |
| Dedup ratio | 3.9 : 1 |
| Entries in distinct descriptors | 11,317,860 — about 555 per descriptor |
| Elapsed | 7.9 minutes, 100 pages |

**What each storage choice costs per 100,000 objects**, entries per object extrapolated through the
byte ratio at ~110 bytes per row:

| Option | Cost |
|---|---|
| A — parsed entries, per object | ~4.81 GB |
| B — raw descriptors, per object | 2.42 GB |
| C — raw descriptors, deduplicated | **0.63 GB** |
| D — parsed entries, deduplicated | **1.24 GB** |

Deduplicating the entry sets saves ~3.57 GB per 100,000 objects — roughly six times what keeping the
raw bytes costs. The raw form (B) is half the size of its own parsed form (A).

**What these numbers are not.** The sample was truncated at 100,000 objects in tree order, which
over-represents siblings sharing an inherited descriptor and therefore **overstates** deduplication.
It was taken with an unprivileged account, so the 19,927 withheld objects — those with unusual access
control lists, which tend to be larger and more distinct — are missing, which **also** overstates it.
And the run predates the convergence check, so it is not known whether 3.9:1 had settled; a lab run of
2,461 objects was still finding ~72 new descriptors per thousand with no sign of flattening. The
comparison between A, B, C and D holds directionally. The absolute figures are not ones to design
against.

**Still estimates, not measurements:** 110 bytes per entry row; the explicit-versus-inherited split
(the script now measures it, and the predecessor's commit claimed 80-90% inherited); a converged dedup
ratio; and the inferred uniformity of the single sign-on objects' permissions, which cannot be
observed without the privilege to read them.

## What remains open

Everything else was settled on 2026-08-12. These are not.

1. **May an under-privileged run serve as a baseline, or be compared?** `F-S20-16` is the evidence:
   a domain can be enumerated completely while permissions are unreadable on a fifth of it, and
   [`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) has no
   word for that state. Read literally it makes every unprivileged run a failure. The blind spots are
   biased toward objects somebody deliberately protected, so treating such a run as an ordinary audit
   would be generous in the wrong direction.

2. **What privilege does the product require, and does it refuse, warn, or record?** Refusing is
   defensible for an audit tool; recording alone is defensible if the number is prominent; proceeding
   silently is not. Whatever is chosen becomes a documented requirement with a delegation procedure,
   or every customer discovers it the way this session did.

3. **`F-S20-13`** — the attributes the predecessor read and the rebuild's catalogue did not:
   `lastLogonTimestamp`, `accountExpires`, `operatingSystem`, `operatingSystemVersion` and the two
   LAPS expiration attributes. That belonged to B2 and to the rule catalogue at branch E, not here.
   **Settled 2026-08-13 at [`S-23`](../next/S-23-what-capture-must-read.md).** `operatingSystem` and the two
   LAPS attributes are captured; the other three are read by no rule and stay out. The reasoning
   this finding gave for the omission did not survive — see the finding.

## Reproducing the measurements

[`next/tools/Measure-DescriptorCost.ps1`](../../next/tools/Measure-DescriptorCost.ps1) reads a naming
context with the request shape capture uses and reports objects, raw bytes, **distinct** descriptors,
the deduplicated total, the explicit-versus-inherited split, and whether the ratio has converged.

```powershell
& .\next\tools\Measure-DescriptorCost.ps1 -Server dc01.example.com
```

**Run it unbounded against a complete naming context.** `-MaxObjects` truncates in tree order, which
samples clusters of siblings sharing an inherited descriptor and overstates deduplication; the script
now says so when it has been used. The convergence check compares the rate of newly-seen descriptors
in the first quarter of pages against the last, and reports `NOT CONVERGED` when a ratio should not be
designed against — a lab of 2,461 objects was still finding ~72 new descriptors per thousand with no
sign of flattening, which is what a synthetic forest looks like.

Two further diagnostics were written during this session and left outside the repository, in
`$env:TEMP`: one that opens up what a paged read actually returns per entry, and one that separates a
permissions boundary from a lossy bulk read by re-querying missing objects individually. Both are
throwaway; the parse-failure count and the individual re-query are the parts worth rebuilding if the
question returns.
