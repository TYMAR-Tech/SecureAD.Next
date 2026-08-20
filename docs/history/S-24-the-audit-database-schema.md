# S-24 — The audit database schema

**Type:** slice
**Reviewed at commit:** `HEAD` of `explore/design-challenges`
**Size:** the bundle schema and its writers, plus the four documents that govern them
**Date:** 2026-08-13

## What it does

This session builds the schema a bundle holds — the tables and indexes of `evidence.db`, and the
types that write them — as ledger row **C1** owes. Capture is finished and has nowhere to put what
it reads: nothing downstream of capture can begin until this exists, not the membership graph at
B11, not principal resolution at B12, and not a single rule at branch E.

It began by settling a contradiction between two governing documents, and that work turned up two
things nobody was looking for: a finding that had been open for a week on a misreading, and a
default change in Windows Server 2025 that can make this product report a clean forest it never
fully read.

**In progress.** The findings below are recorded as they are established rather than at the end,
because a session that defers recording is one interruption away from losing all of it.

> **The build is left failing on one check**, deliberately.
> `UnvouchedResultGateTests.NoPublicMemberReturnsACollectionThatCannotSayWhetherItLooked` fires on
> `EvidenceObject.Attributes`, for the reason and with the decision recorded at `F-S24-7`. The
> repair changes the capture-to-bundle seam and is owed as its own session; the alternative was to
> add a fifth entry to an allowlist whose own comment forbids it, which would have turned a visible
> debt into an invisible one.

## Shape

- `BundleSchema` — every table in a bundle, and the indexes built once writing is done. Its columns
  and its per-attribute value tables are **derived from `CapturedAttributeCatalog`** rather than
  listed, so the schema cannot store a different set of attributes from the one capture asks for.
- `BundleWriter`, `EvidenceObject` — the writer and the object type it takes.
- [`S-16`](../next/S-16-the-bundle.md) — the document this schema is bound to, in both directions, by
  `BundleDocumentationTests`.
- [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) — the decision that governs the
  storage shape.

## Dependencies

- **Depends on:** `CapturedAttributeCatalog` for the attributes a typed-column schema must name;
  `ConnectionSecurityLevel` for what a bundle can honestly claim about how its evidence arrived.
- **Depended on by:** every row downstream of capture — B11, B12, C2, D3 and all of branch E.
- **Layering violations:** none found.

## Verified-safe

Things checked and found correct. Recorded so they are not re-investigated.

- **An absent attribute really is indistinguishable from a withheld one, on the wire.** Not
  inferred — [Access Control and Read
  Operations](https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations)
  states it: *"The impact of security on read operations is not necessarily manifested as an error.
  For example, a search operation can succeed, but the search results don't include objects or
  properties to which the caller doesn't have access."* `LdapEntryReader.ValuesOf` at
  `LdapEntryReader.cs:164-167` is correct to collapse the two into `NotReturned`.
- **`NotReturned` is enforced, not merely intended.** `BundleWriter.cs:367-374` refuses an
  attribute that states it did not come back while offering values, so the two states cannot both
  be true of one row.
- **The unprotected rung really does require a declared allowance.**
  `ConnectionSecurityLadder.PermittedBy` filters it out unless `allowance.IsDeclared`, and
  `ConnectionSecurityLadder.Rungs` sets `RequiresDeclaredAllowance` on that rung alone. The concern
  in `F-S24-1` is the rung above it, not this one.
- **The catalogue requests no attribute that Microsoft ships as confidential.**
  `msLAPS-PasswordExpirationTime` ships `SearchFlags: 0` and `msLAPS-Password` ships `904`
  (`512 | 256 | 128 | 8`) per the [Windows LAPS schema extensions
  reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference); the
  catalogue takes the first and `CredentialAttributeGuardTests` forbids the second. The blast radius
  of `F-S24-1` is therefore small **today** and is not zero, because the flag is a customer setting.
- **The bidirectional document binding row C1 owes already exists** and carries a scanner self-test:
  `BundleDocumentationTests.TheCheckReadsBothTheDocumentAndARealDatabase` reads a real database
  through `sqlite_master` rather than comparing the code's own list to itself.

- **The bidirectional bindings caught a cross-project type move on the first run.** Moving
  `CapturedAttributeCatalog` out of `SecureAD.Audit` failed three documentation tests immediately,
  and mutating the assembly reference in `RebuildAssemblies` fails five checks including the three
  architecture gates. A register bound in both directions cannot quietly change its subject: the
  assembly drops out of the scan, the register still names types from it, and
  `SurfaceRegisterTests.TheRegisterNamesNoTypeThatDoesNotExist` fires. This is recorded because the
  first draft of `F-S24-4` claimed the opposite.

## Findings

### F-S24-4 — One assembly list, written out three times

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `ConceptRegistryTests.cs:54`, `SurfaceRegisterTests.cs:37` and
  `UnvouchedResultGateTests.cs:59` each held their own copy of the production-assembly list, and
  each named the audit assembly through
  `typeof(SecureAD.Audit.Capture.CapturedAttributeCatalog).Assembly` — a type that this session
  moved into the kernel. After the move that expression still compiles and returns the *kernel*
  assembly, so all three lists read kernel, evidence, kernel.
- **What happens to a user:** nothing. This is a test-suite concern.
- **What I got wrong, and how it was caught.** This finding was first written as *"three gates would
  silently stop covering `SecureAD.Audit`"*, and that is false. Mutating the reference fails five
  checks, three of them the gates themselves, because the registers are bound in both directions.
  The claim was disproved by the mutation test that was run to confirm it — which is the argument
  for running one even when the answer seems obvious. The overstatement had already reached four
  doc comments before it was corrected.
- **Why it is this way:** the list was written once and copied twice as gates were added, each
  reasonably naming a type it knew lived in the target assembly.
- **Options:** leave three copies and accept that each must be updated together; or hold the list
  once with a self-test. The second, taken here.
- **Test cover:** now `RebuildAssemblyTests.TheGatesCoverThreeDistinctAndCorrectlyNamedAssemblies`
  and `EveryCoveredAssemblyExportsSomething`, mutation-tested in one direction — replacing the
  audit type with the kernel catalogue fails the self-test plus four gate checks.
- **Status:** REPAIRED — 2026-08-13. The list is held once in `RebuildAssemblies`, each assembly
  named by a type that cannot leave it, and the three gates read from it.

### F-S24-1 — A signed but unencrypted connection loses confidential attributes in silence

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `ConnectionSecurityLadder.cs:66-72` defines rung `Signed` with `Seal: false` and
  `RequiresDeclaredAllowance: false` — an unencrypted session reached as an automatic fallback with
  no operator acceptance. A Windows Server 2025 domain controller *"allow[s] LDAP only to add,
  search, and modify operations that involve confidential attributes when the connection is
  encrypted"* ([What's new in Windows Server
  2025](https://learn.microsoft.com/windows-server/get-started/whats-new-windows-server-2025#advanced-multilayer-security)),
  and strips them from an unencrypted search while returning **no error to the client** — the event
  table for Event ID 3079 lists *"User error (returned to the client): None"*
  ([Unexpected results for operations on confidential attributes on Windows Server 2025
  DCs](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc)).
  The rung is unencrypted because encryption on a SASL bind is `LDAP_OPT_ENCRYPT`, which is what
  `LdapSessionOptions.Sealing` sets
  ([ldap_set_option](https://learn.microsoft.com/windows/win32/api/winldap/nf-winldap-ldap_set_option),
  [Sealing](https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols.ldapsessionoptions.sealing)),
  and that rung sets it false.
- **What happens to a user:** a capture that lands on `Signed` against a 2025 controller reads a
  forest in which every confidential attribute has silently vanished, is told nothing, and records
  the absence as a fact about the forest. `ConnectionSecurityLog.AnyUnprotected` and
  `RefusedIntegrity` both key off `Unprotected` only, so the run discloses nothing either. That is
  exactly what [`0002`](../decisions/0002-absent-view-means-degraded-run.md) exists to forbid,
  reached through the one rung that had been reasoned about and cleared.
- **Why it is this way:** deliberately, and for a reason that was sound when written.
  `ConnectionSecurityLog.cs:92` records it: *"Signing is the line, not encryption, because signing is
  what makes a session safe from alteration in transit and it is what Microsoft's hardening guidance
  and the Windows Server 2025 default are both about. A controller that accepted signing but not
  sealing is not a finding."* That reasoning addresses tampering, and it is correct about tampering.
  It was written before anyone had read what 2025 does to confidential attributes, which is a
  different threat that the same rung fails.
- **The dangerous rung is the middle one.** Rung `Unprotected` is gated behind a declared allowance
  and, on a 2025 controller requiring signing by default, will not complete a bind at all — it fails
  loudly. Rung `Signed` connects happily and is the only rung that both succeeds and misleads. The
  loud failure was gated and the quiet one was not.
- **Options:** **(A)** document only — the silent false negative stays reachable. **(B)** make
  sealing the automatic line, so `Signed` requires a declared allowance as `Unprotected` does; cheap,
  because sealing is Kerberos encryption available since Windows 2000 and required by default on
  2025, so refusal is a misconfiguration rather than a normal case. **(C)** record the connection
  security level per controller in the bundle and disclose it in the report, so a run that used a
  weak rung says so. **(D)** refuse at capture time when a catalogued attribute is effectively
  confidential and the session is unencrypted; the most correct and the least useful now, because it
  needs a pass-ordering guarantee that does not exist and would never fire against today's
  catalogue. **(E)** probe for stripping — rejected as fragile and unfalsifiable when it passes.
- **Decision:** **B and C, with D deferred to D3**, on the owner's decision of 2026-08-13. B is a
  change to the connection ladder rather than to the schema, so it belongs to ledger row **A2** and
  [`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md) and is handed there rather
  than absorbed here. C is C1's own work and lands in this schema.
- **Test cover:** none. `ConnectionSecurityLadderTests` asserts the rungs agree with the level
  enumeration; nothing asserts that an automatic rung is encrypted, which is the property that
  failed.
- **Status:** OPEN — 2026-08-13, raised and decided here, unbuilt. C is owed by this session; B is
  owed by A2.

### F-S24-2 — Two governing documents describe different schemas

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** [`S-16`](../next/S-16-the-bundle.md) §*The tables* lists `captured_attribute` and
  `attribute_value` — one row per object per attribute — while
  [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md), dated one day later, states
  that *"an object is one row with typed columns"* and explicitly replaced that mechanism.
  `BundleSchema.cs:60-70` implements S-16's shape. A session building to both builds neither.
- **What happens to a user:** nothing directly; the schema is unreachable because nothing runs. The
  exposure is to the next reader, who has a fifty-fifty chance of building the shape that was
  replaced — as the committed code already did.
- **Why it is this way:** the code and `S-16` were written on 2026-08-12 and `0022` superseded them
  on 2026-08-12. The document was never brought forward, and `docs/next/README.md` carries a warning
  box instead, which works until somebody skims past it.
- **Which is authoritative: `0022`, and not merely because it is newer.** `S-16` justifies its table
  pair with *"the completeness on the attribute row is stored separately, since withheld and unset
  are the same emptiness"* — conceding the two are one emptiness and then storing a column to
  separate them. The column separates nothing: `LdapEntryReader.cs:164-167` returns `NotReturned`
  whenever the name is absent from the entry, and `BundleWriter.cs:367-374` refuses `NotReturned`
  with any values, so `completeness = NotReturned` is exactly *has no rows in `attribute_value`*.
  Roughly forty rows per object, one of which is derivable from another.
- **Options:** correct `S-16` in place to `0022`'s shape; or supersede `0022`. The first, on the
  evidence above.
- **Test cover:** `BundleDocumentationTests` binds `S-16` to the schema in both directions, which is
  why the two agree with each other today — and neither agrees with `0022`. A binding between a
  document and the code cannot detect that both are describing a superseded design.
- **Status:** REPAIRED — 2026-08-13. `S-16` §*The tables* now describes the typed-column shape and
  the nine per-attribute value tables, and `BundleSchema` creates it. The contradiction warning in
  `docs/next/README.md` is corrected to say the schema is no longer among the mismatches.

### F-S24-3 — `0022`'s stated reason was withdrawn, and its conclusion is right for another reason

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** [`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md) §Context argues
  that the withheld-versus-unset distinction *"turned out not to exist in the data"* because *"per
  Microsoft's own account a base schema attribute cannot be marked confidential at all — which
  covers the attributes this product captures."* Both halves fail. The general claim was challenged
  on 2026-08-11 as `F-S7-27`; the coverage claim failed on 2026-08-13 when
  [`S-23`](../next/S-23-what-capture-must-read.md) added two LAPS attributes that are schema extensions
  rather than base schema.
- **What happens to a user:** nothing yet. The exposure is that a correct decision rests on a
  retracted argument, so the next reader who checks the argument may reasonably overturn the
  decision.
- **The conclusion survives on an argument `0022` did not make.** The distinction is not merely
  unrecorded — it is **unobservable at the point of capture**, because Active Directory omits an
  absent attribute without saying why (see *Verified-safe*, first entry). A per-attribute column
  recording which it was would be recording a guess. That is a stronger reason than the one
  withdrawn, and it does not depend on any claim about base-schema attributes.
- **The brief's LAPS example does not hold either.** `S-24`'s own brief states the two LAPS
  timestamps are *"exactly the kind that can be marked confidential and withheld without an error"*.
  As shipped they are not: `msLAPS-PasswordExpirationTime` carries `SearchFlags: 0`. A customer
  could mark it confidential, since it is an extension and the bit would take effect — but the
  concrete SEC-091 false finding the brief presents requires a deviation from the shipped schema.
  `ms-Mcs-AdmPwdExpirationTime` could **not** be checked: legacy LAPS is an out-of-band download and
  its schema is not published on Microsoft Learn. Recorded as unverified rather than assumed to
  match.
- **Options:** correct `0022` in place per
  [`0032`](../decisions/0032-a-decision-record-is-corrected-in-place.md), keeping its `## Context`
  as written so the reasoning that produced the error survives, and record the real reason beside
  it.
- **Test cover:** none, and none is possible — this is a claim about a decision record's reasoning.
- **Status:** REPAIRED — 2026-08-13. `0022` carries a `## Correction` section recording that its
  stated argument is withdrawn and that the conclusion stands on unobservability at capture. Its
  `## Context` is left exactly as written, per `0032`.

### F-S24-5 — WITHDRAWN. A null column does not have a third meaning

- **Severity:** none — the finding was wrong
- **Confidence:** verified withdrawn
- **What it claimed:** that `captured_object` carries a column for every single-valued attribute in
  the catalogue, so a `user` row holds `rightsguid` and `searchflags` columns that are null not
  because the value is absent but because *capture never asks a user for them* — a third meaning of
  null, entirely observable from the catalogue and recorded nowhere.
- **Why it is false:** capture does not scope its request by object class.
  `CaptureSearchRequestFactory.Build` at `CaptureSearchRequestFactory.cs:156` adds
  **`CapturedAttributeCatalog.All`** to every search request, and `PartitionCapture.ReadEntryAsync`
  at `PartitionCapture.cs:257` walks the same complete list for every entry. Every object is asked
  for every catalogued attribute whatever its class. A user object genuinely *is* asked for
  `rightsGuid`; the directory has nothing to return. So a null means *no value or withheld* — the
  two `0022` correctly says are indistinguishable — and there is no third case.
- **What this makes of the schema:** the union-of-all-classes column set is not a cost of the
  single-table shape, it is the **exact mirror of the one request capture sends**. That is a better
  outcome than the finding assumed, and no change is owed.
- **What I got wrong, and how it was caught.** The catalogue is written as a per-class table and
  exposes `AttributesFor(objectClass)`, so it reads as though it scopes what is requested. I assumed
  it governed capture without checking, and built a finding on the assumption. It was caught by
  reading the capture pipeline end to end on the owner's instruction to stop reading documents and
  read the code.
- **Worse: the evidence was already in hand.** `BundleSchema.cs` carried the sentence *"the whole
  catalogue is asked for on every object and most objects have no value for most of it"* in the very
  comment block this session deleted, and `CapturedObject.cs:90-94` still carries it. It was read,
  quoted in this document, and then contradicted an hour later.
- **What survives:** nothing of the finding. The real defect it stumbled over is `F-S24-8`.
- **Status:** WITHDRAWN — 2026-08-13. Kept rather than deleted, because a session that has been
  wrong three times should leave the record of how.

### F-S24-8 — The catalogue is written per class and used as a union

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `CapturedAttributeCatalog.ClassSpecific` maps eight object classes to their own
  attribute lists, and `AttributesFor(string ldapObjectClass)` returns `Universal` plus whatever
  that class adds. **No production code calls it.** Every caller is a test —
  `CapturedAttributeCatalogTests`, `CredentialAttributeGuardTests`,
  `CapturedAttributeDerivationDocumentationTests`. What capture actually uses is
  `CapturedAttributeCatalog.All`, the flattened union of every list, at
  `CaptureSearchRequestFactory.cs:156` and `PartitionCapture.cs:257`.
- **What happens to a user:** nothing directly. The exposure is to whoever edits the catalogue next.
- **The trap.** Adding an attribute to `ComputerAttributes` looks like scoping it to computers. It
  is not: `All` unions every class list, so the attribute is requested for **every object in the
  forest** — every user, every organisational unit, every group policy container. The structure that
  appears to limit scope only feeds a union, and nothing fails when the two are confused. This is
  not hypothetical: it is what produced `F-S24-5`.
- **It may be the documentation that is wrong rather than the code.** The catalogue's own remarks
  argue for exactly this behaviour — *"every object in every naming context capture reads is
  captured, with `Universal` requested for it whatever its class"* and *"nothing is invisible
  because nobody thought of its class"*. Requesting everything of everything is robust against an
  object class nobody anticipated, and an attribute a class cannot hold costs one absent value on
  the wire. On that reading the union is deliberate and `AttributesFor` is the fiction.
- **Options:** **(A)** make capture ask per class, which makes the class structure real and is
  impossible in one pass — an LDAP search names its attributes in the request and an object's class
  is not known until the response arrives, so scoping by class means one paged search per class over
  every partition, each with its own bookmark, retry handling and referral exposure, to save absent
  attributes that cost nothing on the wire; **(B)** keep the union and stop the per-class lookup
  claiming to govern the request; **(C)** keep both and document the relationship, which is the state
  that misled this session.
- **Test cover:** now `CapturedAttributeCatalogTests.CaptureAsksEveryObjectForTheWholeCatalogueWhateverItsClass`,
  which asserts against the request the factory actually builds rather than against the catalogue's
  own shape, and names `rightsGuid`, `searchFlags` and `gPCFileSysPath` so a request that had quietly
  become class-scoped fails rather than passing by comparing two short lists. Mutation-tested in one
  direction — pointing the factory at a single class's list fails it.
- **Status:** REPAIRED — 2026-08-13. **Option B**, on the owner's decision. `AttributesFor` is now
  `AttributesJustifiedBy`, and says in its own remarks that it does not decide the request and never
  has; `All` says that it *is* the request, and why a per-class one is not possible. A class-scoped
  request now requires deleting a test, which makes it a decision rather than an edit.

### F-S24-9 — `CapturedObject.Completeness` is a constant

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `CapturedObject.Completeness` at `CapturedObject.cs:96-99` reports
  `SomeAttributesDidNotArrive` when any attribute is `NotReturned`. Because the whole catalogue is
  requested for every object (`F-S24-8`), a user object is asked for `rightsGuid`, `searchFlags`,
  `schemaIDGUID` and `gPCFileSysPath` — attributes it cannot hold — and every one comes back
  `NotReturned`. The value is therefore `SomeAttributesDidNotArrive` for effectively **every object
  in every forest**, permanently. The code says so itself: *"Most objects will be
  `SomeAttributesDidNotArrive`."*
- **What happens to a user:** nothing yet. The exposure is a field that looks like a per-object
  quality signal and carries no information, which is the kind of thing a rule author reads as
  meaningful.
- **Why it is this way:** it was written when the request was imagined to be class-scoped, where the
  value would have discriminated.
- **This is the same defect that was removed from the bundle, at the other end.** This session
  removed `StoredObjectCompleteness` and `captured_object.completeness` for this reason and stopped
  there. The capture-side twin was not looked at, because the session was scoped to the schema.
- **Options:** remove it as its counterpart was removed; or keep it only if `F-S24-8` is decided in
  favour of per-class requests, which would make it discriminate again.
- **Test cover:** none asserts it is ever `Complete` for a real object.
- **Status:** OPEN — 2026-08-13. Blocked on `F-S24-8`: whether this field can carry information
  depends on whether the request is scoped.

### F-S24-6 — The range-retrieval refusal loses its second wall

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `captured_attribute.completeness` carried
  `CHECK (completeness IN ('Complete', 'NotReturned'))`, described in the schema as *"the second
  wall"* against an attribute still carrying `MoreToFetch`. The typed-column shape has no
  per-attribute completeness column, so the constraint has nowhere to live and is gone.
  [`S-16`](../next/S-16-the-bundle.md) §*What is refused, and what is recorded* still claims the refusal
  happens twice, and after this change it happens once.
- **What happens to a user:** nothing today — but the failure the two walls existed to prevent is
  the silent one, a ten-thousand-member group stored as five thousand with nothing downstream able
  to tell.
- **The remaining wall is the stronger of the two, which is why this is recorded rather than
  repaired.** `StoredAttributeCompleteness` has two members where the capture-side enum has three,
  so `MoreToFetch` has no spelling in the type an object is built from. A missing enum member
  cannot be forgotten in the way a check can. What is lost is the redundancy, not the guarantee.
- **What I got wrong, and how it was caught.** This session's plan said the enum would be deleted
  and its guard would survive as a write-path refusal. That is false: no converter exists from
  `CapturedObject` to `EvidenceObject`, so `MoreToFetch` never reaches the evidence layer and a
  write-path check would have nothing to inspect. Deleting the enum would have removed the only
  remaining wall while appearing to keep it. Caught by looking for consumers before deleting the
  member, which is the only reason the plan was wrong on paper rather than in the schema.
- **Options:** leave the single wall and correct `S-16`'s claim; or restore a second wall when the
  capture-to-evidence converter is written, which is the natural place for it.
- **Test cover:** none for the constraint, which no longer exists. The vocabulary wall is covered by
  the type system rather than by a test.
- **Status:** OPEN — 2026-08-13. `S-16` is corrected in this session; the second wall is owed to
  whichever row builds the capture-to-evidence conversion.

### F-S24-7 — Removing the object's completeness left `EvidenceObject` unable to vouch for itself

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `UnvouchedResultGateTests.NoPublicMemberReturnsACollectionThatCannotSayWhetherItLooked`
  fires on `EvidenceObject.Attributes`, and **is failing as this session ends**. `Completeness` was
  incidentally the member that made the type vouched under gate 4; with it gone, an empty attribute
  list reads the same whether capture found nothing or never ran.
- **What happens to a user:** nothing yet — but this is `0002` at the object level, which is the
  defect the gate exists to catch, and it was introduced by a change made in the name of `0002`.
- **Why the obvious repair is wrong.** `UnvouchedResultGateTests.ExemptTypes` holds four entries and
  its own comment says *"widening an allowlist is how a gate dies"* and *"a third entry whose reason
  is not 'a compiled table that cannot fail' does not belong here"*. `EvidenceObject` is not a
  compiled table. Adding it would be disabling a gate to let a change through, which is the failure
  the gate's author anticipated in writing.
- **Why the type genuinely can vouch, on `0022`'s own terms.** `0022` records coverage positively and
  per partition. An `EvidenceObject` carrying the coverage it was read under answers *did anyone look
  here* from the one place the answer is real, rather than from a per-attribute column where it is
  not. That satisfies the gate for a reason rather than an exception.
- **Options:** **(A)** give `EvidenceObject` a coverage reference, which changes `WriteObject`, since
  the coverage handle is currently a separate argument and the object and its partition can
  therefore disagree today; **(B)** a fifth exemption with widened terms; **(C)** restore
  `StoredObjectCompleteness` to satisfy the gate, storing a derivable guess to pass a check;
  **(D)** leave it failing.
- **Decision:** **A**, on the owner's decision of 2026-08-13, and **not built here** — it changes the
  capture-to-bundle seam rather than the schema, and this session had already revised its own design
  twice. It is owed as its own session.
- **Test cover:** the gate itself, which is currently red. That is deliberate: a failing gate is a
  visible debt and an exemption is an invisible one.
- **Status:** OPEN — 2026-08-13. Decided, unbuilt, and **the build is left failing on this one
  check**.

### F-S24-10 — The security-descriptor half of the schema was rebuilt around and left as it was

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `BundleSchema.cs` creates `security_descriptor` keyed
  `object_id INTEGER PRIMARY KEY REFERENCES captured_object(object_id)` and `ace` rows per object.
  Row **C1** instructs the opposite: *"Security descriptors are deduplicated: one row per distinct
  descriptor keyed on SHA-256 of its bytes with the length beside it, objects referencing it ... and
  entry sets stored once per descriptor rather than once per object, which measured 4.81 GB down to
  1.24 GB per 100k objects and removes three quarters of the parsing and inserting."* Two further C1
  instructions are also unbuilt: the **raw descriptor bytes** are not stored, so a parser defect is
  recoverable only by recapturing a forest rather than by re-analysis; and there is **no row for a
  descriptor that could not be read at all**, per object or as a run total, which C1 requires because
  a production domain returned 19,927 of 100,000 objects with no readable descriptor and nothing
  distinguished them from objects that grant nothing.
- **What happens to a user:** a bundle roughly four times larger than it needs to be, a capture
  paying four times the descriptor parsing and inserting, and — the part that is not merely cost —
  an object whose descriptor could not be read is indistinguishable from an object that grants
  nothing. That is `0002` at 20% of a real domain.
- **This was not introduced here, and this session made it harder to see.** The descriptor tables are
  the 2026-08-12 shape that review superseded. `S-24` rebuilt the object half of the same file and
  left the descriptor half untouched, so `BundleSchema.cs` now holds current and superseded work side
  by side with nothing marking the boundary. The `docs/next/README.md` warning box was also edited to
  say the schema was no longer among the superseded code, which was an overstatement and is
  corrected.
- **Why it happened:** the session worked from `S-16` and `0022` and did not open row **C1**, which
  is the row that owns the work and the only place the dedup instruction and its measurement are
  recorded.
- **Options:** build the three C1 instructions as the remainder of C1; or record them as owed and
  leave the descriptor tables as they are until the descriptor writer is rebuilt with them.
- **Test cover:** none. Nothing asserts that two objects sharing a descriptor produce one stored
  descriptor, and nothing asserts an unreadable descriptor is distinguishable from an absent one.
- **Status:** OPEN — 2026-08-13. Not started. `C1` remains *rebuilding after review* and is not done.

## Open questions for the owner

- **Which of options A to E for `F-S24-1`** — answered 2026-08-13: B and C, D deferred to D3.
- **Whether the withheld-versus-unset distinction should be stored at all** — answered 2026-08-13:
  **no, and it is not stored anywhere in the schema as built.** Not on the owner's preference but
  because the three findings above between them removed every reason to: the distinction cannot be
  observed at the point of capture (`F-S24-3`), the attributes at issue do not ship confidential
  (*Verified-safe*), and the real cause of a silent withholding turned out to be the connection
  rather than the schema (`F-S24-1`). A per-attribute column would have recorded a guess.
  <br>
  What replaces it is not one thing. Coverage is recorded per partition, what was never seen is
  recorded by reference per `0022`, and the connection security a run actually reached is owed by
  `F-S24-1` option C. `StoredAttributeCompleteness` survives in the write-side vocabulary, where it
  refuses an unfinished attribute, but it is no longer written down — the two jobs it was doing are
  now separated, and only the storage one was wrong.

## Not reviewed

- View definitions (**C2**), the bundle's layout and lifecycle on disk (**C10**), the seal
  (**C11**), the write-path entry points (**C15**) and the suppression sidecar (**C5**). These are
  the other `rebuilding after review` rows and they are separate sessions.
- The rule catalogue, and anything that reads a bundle.
- Whether a production domain controller behaves as the Windows Server 2025 documentation
  describes. No test in this repository can settle it; `F-S24-1` rests on the documentation and is
  owed a lab check alongside `F-S7-37`.
