# S-21 — The security descriptor parser, read against the specification

**Type:** slice
**Reviewed at commit:** `4c440d41` of `explore/design-challenges`
**Size:** 6 kernel types read field by field against `[MS-DTYP]` and `[MS-ADTS]`; 9 wire-format cases
exercised against the live parser; 2 repairs, 4 regression tests, 8 golden values unchanged
**Date:** 2026-08-13

## What it does

This session reads the kernel's security descriptor parsing and ACE canonicalisation against
Microsoft's published wire format rather than against its own tests, because its own tests cannot
answer the question. `GoldenAceHashTests` and the canonicalisation fixtures were computed from the
predecessor and copied byte for byte, so they prove **fidelity**, not **correctness**: a misreading
inherited from the old parser passes every one of them.

**Six discrepancies were found. Two are repaired, four are findings.** Two of the four can change a
permission the product reports, and neither is contained enough to fix in a review session.

**One correction to the prompt.** It names *ledger rows K13 and K15* and instructs replacing both.
`K15` is *Security descriptor parsing and ACE canonicalisation* and is this session's subject.
`K13` is *Dangerous-GUID catalogue* — `S-3`'s subject and an input to `K16` — and contains no
parsing. `K13` is **not** touched, because a row this session did not review must not be rewritten
by it. Recorded as `F-S21-6`.

## Shape

Six types, in the order a descriptor passes through them:

- `SecurityDescriptorParser` — raw `ntSecurityDescriptor` bytes to `ParsedSecurityDescriptor`. The
  self-relative header, the ACL header, the ACE bodies, SIDs and GUIDs.
- `ParsedSecurityDescriptor` and `ParsedAce` — pure data, no interpretation.
- `GenericRightsExpander` — `GENERIC_*` bits to their AD DS explicit equivalents.
- `AceNormalizer` — expansion, canonical ordering, `ace_hash`, deduplication.
- `AceCanonicalization` — the version stamp, currently `2`.
- `CanonicalAce` — the normalised output.

## Dependencies

- **Depends on:** nothing. `SecureAD.Kernel` is the lowest layer and the parser makes no OS call.
- **Depended on by:** `K16` (the dangerous-permission classifier), `C1` (the bundle's
  `security_descriptor` and `ace` tables), and every rule in branch E through those.
- **Layering violations:** none.

## Verified-safe

Checked against the specification and found correct. Recorded so they are not re-investigated.

- **The self-relative header offsets are right** — `Revision` at 0, `Control` at 2, `OffsetOwner`
  at 4, `OffsetGroup` at 8, `OffsetDacl` at 16, header 20 bytes (`SecurityDescriptorParser.cs:14-19`),
  matching `[MS-DTYP]` §2.4.6.
- **`SE_DACL_PRESENT` is what distinguishes an absent DACL from an empty one**, and it is read
  (`:82`). A cleared bit yields `DaclState.Null`, which is the NULL DACL that grants everyone full
  control — the opposite of an empty DACL, and the distinction the prompt asked about. Confirmed on
  the live parser: probe case C.
- **The ACE header is read correctly** — type, flags, size at `:168-170`, access mask at offset 4
  (`:208`), per `[MS-DTYP]` §2.4.4.1.
- **The object-ACE body order is right** — flags, then `ObjectType` only if `0x01`, then
  `InheritedObjectType` only if `0x02`, then the SID (`:269-302`), per §2.4.4.3. The two conditional
  GUIDs are the field most often got wrong and this reads them in the right order with the right
  bounds checks.
- **`IsObjectAceType` covers every object ACE type that can appear in a DACL** — `0x05`, `0x06`,
  `0x0B`, `0x0C`, plus `0x07` (`:376-383`). The callback object variants are present, which is the
  part a lab forest would never have shown.
- **Inheritance and propagation flags are masked correctly** — `OBJECT_INHERIT|CONTAINER_INHERIT`
  and `NO_PROPAGATE|INHERIT_ONLY` (`:210-211`), and `INHERIT_ONLY` survives into `CanonicalAce`. An
  `INHERIT_ONLY` ACE does not apply to the object it sits on, so preserving it is what lets a
  consumer avoid reporting a permission that grants nothing here.
- **SID parsing is right** — six-byte **big-endian** identifier authority against little-endian
  sub-authorities (`:342-360`), per `[MS-DTYP]` §2.4.2.2. Mixing those two endiannesses is the
  classic SID bug and this does not have it.
- **The generic rights mapping matches the directory's own, bit for bit** —
  `DS_GENERIC_READ 0x00020094`, `DS_GENERIC_WRITE 0x00020028`, `DS_GENERIC_EXECUTE 0x00020004`,
  `DS_GENERIC_ALL 0x000F01FF` (`GenericRightsExpander.cs:27-49`). Generic bits are cleared after
  expansion and expansion runs **before** hashing (`AceNormalizer.cs:72`), so the same permission
  written two ways hashes once.
- **The four-tier canonical order is the documented one** — explicit deny, explicit allow,
  inherited deny, inherited allow (`AceNormalizer.cs:244-256`), per `[MS-ADTS]` §5.1.3.
- **Callback allow and deny categorise correctly** — `0x0A` and `0x0C` are in the deny set
  (`:246-247`), so a conditional deny is not silently treated as an allow.
- **The ordering is total, so it does not depend on arrival order** (`:237`), which is what
  `F-S1-2` and canonicalisation version 2 were about.

## Findings

### F-S21-1 — A DACL that could not be read is reported as one that denies everyone

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `SecurityDescriptorParser.cs:100-110`, with `AceNormalizer.cs:34-40`. Confirmed on
  the live parser: probe case A — a DACL header declaring 2 ACEs whose entries all fail to parse
  returns `DaclState = Empty`, `DaclAces = 0`, `Errors = 2`. Probe case B — a genuinely empty DACL —
  returns `DaclState = Empty`, `DaclAces = 0`, `Errors = 0`. The two are identical in that field.
- **What happens to a user:** an empty DACL in Windows grants nothing to anybody — it is the most
  locked-down an object can be. An object whose permissions the product **could not read** is
  therefore reported as the safest object in the forest. It is not merely a wrong label: because
  `AceNormalizer` returns early for any state other than `Present`, the object gets an empty
  canonical ACE set and therefore an `ace_set_hash` over nothing, so under
  [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) it groups
  together with genuinely locked-down objects as one repeated pattern. An auditor scanning for
  dangerous permissions sees a clean object. The object may grant Everyone full control.
- **Why it is this way:** `DaclState` has three members — `Present`, `Null`, `Empty` — and there is
  no fourth for *could not be determined*. The code does try: the header's own ACE count is
  consulted at `:103-110` specifically to tell a truly empty DACL from one with no parseable ACEs.
  That check only fires when the header says zero. When the header says two and both fail, the
  first branch has already chosen `Empty`.
- **Options:** **(a)** add `DaclState.Unreadable`, set it when the declared ACE count is non-zero
  and the parsed count is zero, or when any ACE error was recorded. Costs: a member on a public
  enum, a new value in `C1`'s `dacl_state CHECK (dacl_state IN ('Present','Null','Empty'))`, and
  every consumer's switch. Changes no `ace_hash`. **(b)** leave `DaclState` alone and require every
  consumer to check `Errors` first. Costs nothing now and reproduces the predecessor's defect the
  first time a consumer forgets — which is the failure gate 4 exists for. **(c)** refuse the
  descriptor outright and record it in `unreadable_security_descriptor`, which already exists.
  Costs: an object with one bad ACE loses the good ones too.
- **Test cover:** none. No fixture contains a descriptor whose ACEs fail to parse, which is why the
  behaviour has never been seen. Probe case A is the first time it has been run.
- **Status:** REPAIRED 2026-08-13, after an owner decision the same day. Option **(a)**, widened:
  [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) adds `DaclState.Unreadable` **and**
  `DaclCompleteness`, because a fourth state alone does not catch the partial parse described above.
  Implemented in `SecurityDescriptorParser`, carried through `AceNormalizationResult`, and stored as
  `security_descriptor.dacl_state` and `dacl_completeness`.

  **Gate 4 improved the design and caught a real bug in the fix.** The record first asked for the
  declared entry *count* to be stored. `UnvouchedResultGateTests` refused a bare `int` on sight, and
  it was right: a header declaring zero entries and a header too truncated to read would both have
  reached a caller as `0` — this finding's own defect, one field over. The first draft really did
  reintroduce it, reporting a truncated ACL header as `Empty`. The count became a closed set of
  outcomes and the truncated header became `Unreadable`. `0037` is corrected in place to record it.

### F-S21-2 — Normalisation destroys the stored ACE order, so a non-canonical DACL cannot be seen

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `AceNormalizer.cs:54` sorts with a total order; `CanonicalAce.cs:19-30` has no field
  for the position the ACE occupied in the DACL as stored. `ParsedAce.cs:16-25` has none either, so
  the only record of arrival order is the transient list order inside `ParsedSecurityDescriptor`.
- **What happens to a user:** Windows evaluates a DACL **in stored order** and stops at the first
  matching entry. A canonical DACL puts denies first, so a deny wins. A **non-canonical** DACL — one
  where an allow precedes a deny for the same trustee — grants the access instead, and that is a
  shape an attacker deliberately leaves behind, because tooling that assumes canonical order reports
  the deny and the system honours the allow. This product sorts every DACL into canonical order
  before storing it, so it will report the deny. It cannot report that the order was wrong, cannot
  evaluate the object the way Windows will, and cannot tell an auditor that the DACL it read was not
  in canonical form — because after the sort there is nothing left that says so.
- **Why it is this way:** the sort exists to make `ace_hash` and `ace_set_hash` deterministic, and
  for that purpose it is correct and necessary — a hash that depended on arrival order would report
  a change every time the directory returned entries differently. The defect is not the sort. It is
  that the sort is lossy and nothing records what was lost.
- **Options:** **(a)** carry the original index on `CanonicalAce` and store it beside the canonical
  ordinal. Changes no `ace_hash`, because the index is not a hash input; costs a column and a
  decision about what `ace.ordinal` means. **(b)** compute a single `was_canonical` boolean per
  descriptor during parse and store it on `security_descriptor`. Much cheaper, answers *is this
  suspicious* but not *what was the real order*. **(c)** do nothing and accept that the product
  cannot see this class of misconfiguration.
- **Test cover:** `AceNormalizerTests` covers that a non-canonical input is sorted; nothing covers
  that the original order is recoverable, because it is not.
- **Status:** REPAIRED 2026-08-13, after an owner decision the same day. Option **(b)**:
  [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md) records one
  boolean per descriptor, judged during the existing parse while the entries are still in arrival
  order, and stored as `security_descriptor.dacl_was_canonical` with a partial index on the `0`
  rows.

  **Option (a) was withdrawn rather than deferred.** This document offered a per-entry ordinal, and
  it should not have: `security_descriptor.raw_bytes` was already in the schema, so the original
  order was never lost from a bundle at all — only from the canonical projection over it, and
  re-parsing recovers it exactly. An ordinal column would have stored a fact the bundle already
  held, which is the near-duplicate mechanism [`0025`](../decisions/0025-the-run-library-is-a-managed-root.md)
  argues against by name. The cheap question is now a query; the exact one is answered from the
  bytes when something needs it.

### F-S21-3 — A high-bit offset threw out of a parser contracted to record damage

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `[MS-DTYP]` §2.4.6 declares `OffsetOwner`, `OffsetGroup`, `OffsetSacl` and
  `OffsetDacl` as `ULONG`. They were read with `ReadInt32LittleEndian`. An offset above `0x7FFFFFFF`
  became negative, passed the `>= rawSd.Length` bounds check because a negative number is not
  greater, and then threw from the range expression that followed. Confirmed: probe case D returned
  `THREW ArgumentOutOfRangeException` before the repair.
- **What happens to a user:** the parser's own comment says one bad object must not fail a whole
  capture. A descriptor with a corrupt or hostile offset threw an unhandled exception out of a
  `public static` method whose entire contract is to return errors rather than raise them. Depending
  on where capture catches, that is one object lost or one partition lost.
- **Why it is this way:** `ReadInt32LittleEndian` is the obvious call and the difference only shows
  on values no directory produces. No fixture had one, so nothing ever exercised it.
- **Test cover:** none before this session. Now `WhenDaclOffsetHasTheHighBitSet_…` and
  `WhenOwnerOffsetHasTheHighBitSet_…`.
- **Status:** REPAIRED 2026-08-13. All three offsets read unsigned; the DACL bound is compared
  unsigned. The specification is unambiguous and the fix is contained. Mutation-tested both
  directions.

### F-S21-4 — An owner offset past the end was dropped in silence

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** the old guard was `ownerOffsetValue > 0 && ownerOffsetValue < rawSd.Length`, with no
  `else`. Confirmed: probe case E returned `owner=<null> errors=0` before the repair.
- **What happens to a user:** an object's owner holds `WRITE_DAC` implicitly — an owner can rewrite
  the permissions on the object whatever the DACL says, so the owner is a security-relevant fact in
  its own right. A malformed descriptor produced a null owner and an empty error list, which reads
  as *this object records no owner* rather than *this object's owner could not be read*. That is the
  same conflation as `F-S21-1`, one field over.
- **Test cover:** none before this session. Now `WhenOwnerOffsetIsPastTheEnd_…`, with
  `WhenGroupOffsetIsZero_…` holding the other side so a legitimately absent field stays silent.
- **Status:** REPAIRED 2026-08-13. An offset of zero still means absent, per §2.4.6; any other
  out-of-range offset is recorded. Mutation-tested both directions.

### F-S21-5 — Every unrecognised ACE type is accepted silently and counted as an allow

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `AceType` names 10 of the 17 types in `[MS-DTYP]` §2.4.4.1. `TryParseAce` casts the
  raw byte with `(AceType)aceType` (`:236`, `:309`) and records nothing when the value is not a
  member. Confirmed: probe case H — `0x04`, `0x0D`, `0x0F`, `0x11`, `0x12`, `0x13` and `0x7F` each
  produced a `ParsedAce` with an undefined enum value and **zero errors**. `AceNormalizer`'s
  `GetCategory` (`:246-255`) tests only for the four deny types, so anything unrecognised is
  categorised as an allow.
- **What happens to a user:** two directions, and they are not symmetric. An unknown type counted as
  an allow is a permission reported that may not exist — noise, and recoverable. But nothing
  distinguishes *a type we understand* from *a type we do not*, so if a future consumer switches on
  `AceType` and falls through to "not an allow", an entry that **does** grant access becomes a
  permission the product never reports. That is the failure the session prompt names by name.
  Nothing today reaches that state, because `K16` is the only consumer and branch `E` is unbuilt.
- **Why it is this way:** the enum's own comment says *"only the types relevant to AD DACL/SACL
  processing are included"*, which was a reasonable scope. The gap is that an excluded type is
  indistinguishable from an included one after the cast.
- **Options:** **(a)** record an error when the byte is not a defined member, leaving the ACE in
  place. Cheap and contained; risks noise on `0x04` compound ACEs, which are legal in a DACL and
  rare. **(b)** add the missing members so the cast is always defined, and decide per type whether
  it is deny, allow or neither. **(c)** make `GetCategory` fail closed by treating an unrecognised
  type as its own category rather than as an allow.
- **Test cover:** none. No fixture contains an ACE type outside the ten.
- **Status:** OPEN 2026-08-13. **Not repaired**, because the specification does not say what a
  reader must do with an unrecognised type, so no option here is forced by it — which is this
  session's own bar for a repair. Owed to `K15`, noted against `K16`.

  > **Downgraded 2026-08-13 to a note, after verification. I overstated this finding twice.**
  >
  > **First overstatement: the classifier.** This finding implied a future consumer might treat an
  > unknown type as *not an allow* and drop a real grant. `DangerousPermissionClassifier.Classify`
  > opens with `if (!Enum.IsDefined(aceType)) return CannotClassify(…)` — *"an unrecognised type may
  > grant in a way this code does not model"*. `K16` had already solved it, the same way it solved
  > the unrecognised GUID. The risk was never live.
  >
  > **Second overstatement: the evidence.** The proposed repair was to record a parse error. That
  > would have been wrong twice over. `BundleWriter` writes `ace.AceType.ToString()`, and .NET
  > renders an undefined enum value as its number — verified: `0x04→"4"`, `0x12→"18"`,
  > `0x7F→"127"` — so **the bundle already records every unrecognised entry**, and
  > `SELECT … WHERE ace_type GLOB '[0-9]*'` already finds them. Recording an error would have
  > duplicated a fact the evidence holds, which is the mistake `F-S21-2` caught over `raw_bytes` and
  > which I nearly repeated. And it would have gone in `security_descriptor_error`, whose own
  > comment says it exists so a descriptor that *failed to parse* is not confused with an object
  > that grants nothing — an unrecognised type parses perfectly.
  >
  > **What was actually repaired**, and it is small: `IsCanonicalOrder` judged arrival order using
  > `CategoryOf`, which maps any undefined type to *not a deny*. So `dacl_was_canonical` was decided
  > partly by a guess, and an ordinary DACL with an unmodelled entry ahead of a deny would have been
  > reported as reordered. It now skips entries it cannot classify, and the answer means *the
  > entries I recognised were in order*.
  >
  > **What was bound**, which is the part with lasting value: the `ace_type` fallback was an
  > **accident** of `Enum.ToString()`, and the entire query surface for *what did we not model*
  > rested on it. `BundleWriterTests` now holds it in both directions — an `(int)` cast and a
  > normalise-to-`"Unknown"` tidy-up each fail the build.

### F-S21-7 — since `0036`, the product classifies an entry that should not exist

- **Severity:** maintainability — **downgraded from correctness-risk on 2026-08-13 after reading
  the specification.** The verdict is correct; its stated reason was not.
- **Confidence:** verified
- **Evidence:** `DangerousPermissionClassifier.cs:174-178` returned
  `NotDangerous("An audit entry records access; it grants none.")` for `SystemAudit` and
  `SystemAuditObject`. That sentence describes a **SACL**. Since
  [`0036`](../decisions/0036-capture-never-requests-the-sacl.md) there are no SACLs: verified that
  `ParseAcl` has exactly one call site and it is the DACL span, that `SecurityMasks.Sacl` appears
  nowhere in `next/src`, and that header offset 12 is never read. So an audit-typed ACE can now only
  reach the classifier from inside a **DACL**, where `[MS-DTYP]` §2.4.5 does not permit it.
- **What happens to a user:** nothing. **This is the correction to what this finding first said.**
  `[MS-DTYP]` §2.5.3.2 evaluates a DACL over allow, deny and their object and callback forms; audit
  types take no part in it, and every Microsoft description of `SYSTEM_AUDIT_ACE` places it in a
  SACL. Such an entry **grants nothing wherever it sits**, so `NotDangerous` is right. What was
  wrong was the sentence beside it, which justified the verdict by appeal to a structure the product
  no longer reads.
- **What this finding first claimed, and why it was wrong.** It said the product makes a positive
  claim of safety about a malformed entry and should answer `CannotClassify` instead. That reasoned
  from the code and from `0036` without reading the access check algorithm. Reading it settles the
  outcome in the code's favour.
- **The inference that does *not* follow, stated because it is tempting.** §2.5.3.2's case list
  omits the deny-callback and callback-object types, which certainly do grant and deny. The list is
  illustrative, not exhaustive, so *"absent from the case list, therefore harmless"* is invalid in
  general. It is safe for audit types only because every other source independently places them in a
  SACL. This is also why `Classify`'s `!Enum.IsDefined → CannotClassify` guard stays: for a type
  nobody has documented, failing closed is still the only honest answer.
- **Options considered:** **(a)** change the verdict to `CannotClassify` — **rejected**, it would
  make the product less accurate, not more. **(b)** remove `SystemAudit` and `SystemAuditObject`
  from `AceType` — **rejected on inspection**, `IsObjectAceType` needs `0x07` to read the object-ACE
  body layout, and without it the trustee SID would be read from the object-flags field and a
  garbage value produced in silence; naming them is also what lets the anomaly be queried by name.
  **(c)** keep the verdict, correct its reason, and report the anomaly elsewhere — **taken**.
- **Test cover:** `DangerousPermissionClassifierTests.AnAuditAceGrantsNothingAndIsNotDangerous`
  asserts the verdict, which is unchanged and needed no re-derivation.
  `BundleWriterTests.AnAuditEntryInADaclIsStoredByNameSoTheAnomalyCanBeFound` holds the query the
  handover depends on.
- **Status:** PARTLY REPAIRED 2026-08-13. The reason is corrected in the classifier and `0036`
  carries the sweep it owed. **The remaining half is handed to ledger row `E1`**: an audit entry in
  a DACL means something wrote a descriptor that should not exist, which is a fact about the
  customer's forest rather than a permission, and branch `E` is where findings are made. No new
  evidence is required — `ace.ace_type` already stores the type by name.

  is absent from `IsObjectAceType`, so its SID would be read from the object-flags field and a
  garbage trustee produced with no error. It is unreachable today only because the SACL is never
  parsed. It becomes reachable the moment it is. See `Not reviewed`.

### F-S21-6 — The session prompt names the wrong ledger row

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `docs/next/sessions/S-21-the-security-descriptor-parser.md:6` and `:130` name
  *ledger rows K13 and K15* and instruct replacing both. `WHAT-THE-OLD-APP-HAD.md` row `K13` is
  *Dangerous-GUID catalogue*; row `K15` is *Security descriptor parsing and ACE canonicalisation*.
- **What happens to a user:** nothing directly. What happens is that a session following its brief
  literally rewrites the status of a row it never reviewed, which is how a ledger stops being
  evidence. The likely intent was `K15` and `K16`, or `K15` alone.
- **Status:** REPAIRED 2026-08-13 by not doing it. `K15` is replaced; `K13` is untouched and this
  finding is the record of why.

## What was got wrong

Three mistakes in this session, all mine, all caught.

**A mutation test very nearly recorded a false result.** After reverting the unsigned-offset repair
from the baseline held outside the repository, the suite still reported the failure — which reads as
*the repair does not work*. The revert was fine; the build was stale. `dotnet build --no-incremental`
followed by `dotnet test --no-build` returns 931 passing. **Mutation testing in this repository must
force a non-incremental build between mutating and reverting**, or a correct revert can be misread
as a surviving defect, which would have been recorded here as a finding that does not exist.

**I duplicated an entry in the solution file.** Adding the missing documents, I appended the `S-21`
prompt without checking it was already listed. Caught by counting occurrences afterwards rather than
by anything structural; removed.

**I stripped the byte-order mark from the solution file.** `WriteAllLines` does not preserve it, and
a `.sln` carries one by convention. It showed up as a deleted first line in `git diff` and was
restored. This is why the rule says to read the diff rather than count it — the line was invisible in
the file and obvious in the diff.

## Open questions for the owner

> **Both answered 2026-08-13, the same day, and implemented.** Recorded in
> [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) and
> [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md). The questions
> are left as written because the costs stated below are what the decisions were taken against.

Both are product decisions and both are cheap now and expensive later, because each implies a
column in a schema that is finished but not yet written to at scale.

1. **`F-S21-1`** — should `DaclState` gain an `Unreadable` member? Today an unreadable DACL is
   reported as the safest possible object. The alternative is that every consumer must remember to
   check `Errors`, which is the arrangement the predecessor had.
2. **`F-S21-2`** — should the product be able to see a non-canonical DACL? The cheap form is one
   boolean per descriptor. Without it, a deliberately reordered DACL is invisible and this product
   will report the deny that Windows will not honour.

## Not reviewed

- **The SACL is never parsed at all.** `OffsetSacl` at header offset 12 is not read and no constant
  for it exists. That is a defensible scope for a permissions audit — the SACL is the audit policy,
  not the access policy — but it is not written down anywhere as a decision, and `ParsedAce`'s own
  summary says *"parsed from a binary security descriptor DACL or SACL"*, which promises more than
  the parser delivers. No row owns it. Raised here, not resolved.

  > **Resolved 2026-08-13, the same day.** The owner decided the product does not capture SACLs.
  > [`0036`](../decisions/0036-capture-never-requests-the-sacl.md) records it, and it turns out the
  > better argument was already in the code: `CaptureSearchRequestFactory` restricts the mask to
  > owner, group and DACL precisely so that a capture runs as an ordinary authenticated user and
  > nobody has to grant an audit tool a privilege on their domain controllers. This session
  > under-credited that comment by calling the behaviour undocumented; what was missing was
  > authority, not reasoning. `ParsedAce`'s summary is corrected, and `0036` names the cost out loud
  > — audit misconfiguration, such as no auditing on `AdminSDHolder`, is out of scope for this
  > product.
- **`K16`, the dangerous-permission classifier**, is out of scope by the prompt. `F-S21-1`,
  `F-S21-2` and `F-S21-5` all land on it and are noted against its row.
- **`C1`'s writer** — whether `ace.ordinal` is the canonical index or the original one is a storage
  question. `F-S21-2` is noted against it.
- **`ParseBase64`** and the `AceSetHash` type were read but nothing in them bears on the wire
  format.
