# S-61: Anchoring the schema catalogue to Microsoft

**Your task is to build one test and let it tell you what is wrong.** Do not correct any catalogue
entry before the test exists and fails on it. A correction made ahead of the test is a correction
this session cannot prove, and proving it is the whole point.

Closes `F-S60-2`, and `F-S60-1` as a consequence. Both are recorded in
`S-60-an-independent-review-of-the-security-layer.md`.

---

## Why this session exists

`S-60` reviewed the security layer against Microsoft sources and found the logic sound. It found no
defect in descriptor parsing, mask interpretation, generic-right mapping, ACE ordering, deny
handling or classification structure.

**It found two defects in the data.** Two entries in `SchemaGuidCatalog.EmbeddedEntries()` publish
real Microsoft GUIDs under the wrong extended-right names, and one of those names does not exist in
Active Directory at all.

The reason they survived is the finding that matters. `SchemaGuidCatalogTests` validates the
catalogue thoroughly — every GUID parses, every GUID is lowercase, no LDAP name repeats, no GUID
repeats within a kind, every kind is represented, multi-meaning lookups return every meaning. All
of that is **structure**. The only test that checks *content* is
`WhenARuleSpecificationNamesAGuid_ThenTheCatalogueAgreesWithIt`, and it checks against internal rule
specifications.

Rule specs name dangerous rights. So an entry is validated if and only if it is dangerous, and
every ordinary entry in the table has **no correctness anchor of any kind**. Both defects fall in
that set. So do 74 entries nobody has checked.

**`S-60` verified 26 of 100 entries and found 2 wrong.** Do not read that as a rate to extrapolate —
the 26 were mostly extended rights, chosen because they drive verdicts. Read it as a reason to
expect that the 74 have not been checked by anyone, ever.

---

## The baseline

Branch `explore/design-challenges`, commit `38f0952b`.

**Record the suite count and tree state before you start.** `S-60` did not, and had to reconstruct
context it should have measured. Do not inherit that.

The catalogue as it stands:

| Kind | Entries |
| --- | --- |
| `ExtendedRight` | 37 |
| `Attribute` | 30 |
| `PropertySet` | 15 |
| `ObjectClass` | 13 |
| `ValidatedWrite` | 5 |
| **Total** | **100** |

Counted from `SchemaGuidCatalog.cs` by construction-function call. If your count differs, **that is
a finding** — say so before proceeding.

---

## What to build

A test that pins **every** embedded entry's GUID and LDAP name to Microsoft's published value. The
owner's instruction is that scope: not extended rights only, not the dangerous ones only.
All one hundred.

Where it lives is your judgement — a new file beside `SchemaGuidCatalogTests.cs`, or added to it.
Prefer whichever leaves the failure message readable when forty entries are wrong at once.

### Where Microsoft publishes each kind

| Kind | Source | Field |
| --- | --- | --- |
| `ExtendedRight` | *Extended Rights* index, then each `r-*` page | `Rights-GUID` |
| `ValidatedWrite` | *Validated Writes* index, then each `r-*` page | `Rights-GUID` |
| `PropertySet` | *Property Sets* index, then each `r-*` page | `Rights-GUID` |
| `Attribute` | Each `a-*` page under AD Schema | `System-Id-Guid` |
| `ObjectClass` | Each `c-*` page under AD Schema | `Schema-Id-Guid` |

All three control-access indexes hang off *Control Access Rights (AD Schema)*.

**Note the field changes with the kind.** Extended rights, property sets and validated writes carry
`rightsGuid`; attributes carry `schemaIDGUID` published as `System-Id-Guid`; classes carry
`schemaIDGUID` published as `Schema-Id-Guid`. An entry checked against the wrong field will look
wrong when it is right, and this is the most likely way to manufacture a false finding here.

---

## What is doubtful, and why

### 1. The three entries `S-60` says are wrong

`S-60` asserts the following. **Verify each independently against the Microsoft page. Do not take
them from this brief.** If your reading and `S-60`'s disagree, that is the finding — record it and
do not adjust either.

| Line | The catalogue says | `S-60` claims Microsoft says |
| --- | --- | --- |
| 280 | `fec364e0-…` is `DS-Replication-Get-Changes-All-Extended` | `Do-Garbage-Collection` |
| 285 | `ee914b82-…` is `DS-Replication-Monitor-Topology` | `Abandon-Replication` |
| — | *(absent)* | `DS-Replication-Monitor-Topology` is `f98340fb-7c5b-4cdb-a00b-2ebdfa115a96` |

`S-60` also claims `DS-Replication-Get-Changes-All-Extended` **is not a defined extended right at
all** — that it appears nowhere in Microsoft's index. That claim is cheap to check and worth
checking, because it is the one that decides whether line 280 is a mislabelling or an invention.

**The reason to distrust this table is the same reason `S-59` exists.** `S-58`'s session stated a
wrong claim about GUID presence confidently across two commits and several reports, and caught it
only when it finally measured. `S-60` is a different session making claims about GUID presence.
Measure.

### 2. The entries nobody has checked

Seventy-four. `S-60` did not look at them, so there is no prior claim to agree or disagree with —
only the test's output. Expect this to be the bulk of the session, and expect the attribute and
class entries to be the slowest, since each needs its own page.

**A wrong name is as much a defect as a wrong GUID.** Line 280 has a correct GUID and a fabricated
name, and it is the name that reaches the screen and the name that
`ClassifyExtendedRight` matches against `DangerousExtendedRights` and `ReplicationRights`. Pin both.

### 3. Two GUIDs legitimately mean two things

The test must not treat a repeated GUID as an error.

- `bf9679c0-0de6-11d0-a285-00aa003049e2` is both the `Self-Membership` validated write and the
  `member` attribute.
- `72e39547-7b18-11d1-adef-00c04fd8d5cd` is both the `Validated-DNS-Host-Name` validated write and
  the `DNS-Host-Name-Attributes` property set.

Both are genuine schema properties and both are already modelled correctly — `FindByGuid` returns a
set, and `ClassifyScoped` disambiguates by mask bit. `SchemaGuidCatalogTests` already pins the
two-meaning and three-meaning cases. **A test that flattens the catalogue to a GUID-to-name map
will break them.** Key by `(GUID, kind)`.

If your reading of Microsoft finds a *third* meaning for either, or a dual meaning for a GUID the
catalogue holds singly, record it — do not silently widen the table.

### 4. Whether the shipped table is even the right place to be strict

`SchemaGuidCatalog` is two-layer: a captured forest schema takes precedence over the shipped table
(lines 107–122), on the reasoning that a captured name is a fact about the forest under audit and a
shipped one is a general claim.

So a strict test constrains only the fallback. **That is the correct thing to constrain and it is
worth being clear why:** the fallback is what an offline bundle re-read uses, and what any run that
did not read the schema partition uses. It is the path with no forest to correct it.

Do not extend the test to captured entries. A forest may legitimately publish a name Microsoft does
not, and a test that forbids it would fail on a correct capture.

---

## Then, and only then, the correction

Once the test exists and fails:

1. Correct the entries it names, from the Microsoft page, not from this brief.
2. Add `DS-Replication-Monitor-Topology` under its real GUID if the test shows it absent.
3. Increment `SchemaGuidCatalog.Version`. It is documented as moving "when entries are added,
   removed or corrected", and a bundle records which table named its GUIDs.
4. Re-run. The test proving the fix is the deliverable — not the fix.

**Do not correct anything the test does not name.** If you believe an entry is wrong but the test
passes it, the test is incomplete; fix the test, not the entry.

---

## Watch for

- **`SchemaGuidCatalog.Version` has consumers.** It is written into bundles. Check what reads it
  before moving it — `BundleReader.Open` already refuses a bundle whose `canonicalization_version`
  differs, and it is worth knowing whether catalogue version is treated the same way or not.
  `S-60` did not check this.
- **The architecture gates.** `AreaFileGateTests.EveryCapabilityNamesATestThatExists` ties
  `docs/areas/` capabilities to tests that must exist. Adding a test is safe; renaming or moving an
  existing one may not be. `ArchitectureDocumentationTests` and `ConceptRegistryTests` are also
  live.
- **Documentation tests exist for catalogues.** `CapturedAttributeCatalogDocumentationTests` and
  `PermissionClassificationDocumentationTests` suggest a convention that a catalogue's
  documentation is itself gated. Check whether `SchemaGuidCatalog` has one before assuming a
  content change is code-only.
- **`WhenAGuidWasShippedWrongOnce_ThenTheCatalogueDoesNotResolveToItAgain`** already exists and
  pins previously-corrected GUIDs. The entries you correct belong in it.

---

## Out of scope

Named so that a session which finds them does not start pulling.

- `F-S60-3` — `AclSize` and `AclRevision` unread in `SecurityDescriptorParser`. Low, and it has an
  open dependency on the collection layer.
- `F-S60-4` — SACLs not parsed. Informational, not a defect.
- `CapturedSchemaGuidReader.cs`, including the line 222 hazard about sending `ClassifyScoped` down
  the wrong branch. `S-60` did not read it. It is review work, not this session's.
- The four security test bodies. `S-60` read no test body in either session.
- The collection layer.

---

## What this session should leave behind

- One test pinning 100 entries to Microsoft, keyed by `(GUID, kind)`.
- The catalogue corrected only where that test failed.
- `SchemaGuidCatalog.Version` moved, if the correction warrants it.
- A record of **every** disagreement between your reading and `S-60`'s, in either direction,
  including the ones where `S-60` turns out to have been right.

That last one matters more than it looks. `S-60` checked 26 entries and claimed 2 were wrong. If
you check 100 and find `S-60` was also wrong about something, that is worth more to the next
session than a clean result.
