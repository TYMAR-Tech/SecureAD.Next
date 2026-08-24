# Security descriptors: parsing and canonicalisation

**Code:** `next/src/SecureAD.Kernel/Security/`
**Layer:** Kernel — pure logic, no directory, no database, no Windows-only API.

Turns the raw bytes Active Directory stores in `nTSecurityDescriptor` into a list of permissions
that can be compared between two runs.

---

## What this is for

Comparison is the product. A customer's question is *what has moved since last month*, and that
answer is only trustworthy if **no change** and **written differently** are told apart.

A directory can express the same permission several ways. The same right can be written as a single
shorthand bit or as the specific mask it stands for. The same set of entries can be stored in any
order. Compared naively, a forest nobody touched reports a change on every object, and the report
becomes noise a customer learns to ignore.

So this subsystem does two separate jobs, in two passes, deliberately kept apart:

1. **Parsing** — what the bytes said, with no interpretation. Knows the wire format, knows nothing
   about comparison.
2. **Canonicalisation** — a comparable form. Knows about comparison, knows nothing about bytes.

---

## How the pieces fit

```
raw bytes
   │
   ├─ SecurityDescriptorParser.Parse ──────────► ParsedSecurityDescriptor
   │                                                 owner, group, DaclState,
   │                                                 DaclCompleteness, DaclWasCanonical,
   │                                                 ParsedAce[] (as stored)
   │
   └─ AceNormalizer.Normalize ─────────────────► AceNormalizationResult
                                                     CanonicalAce[] (sorted, deduplicated,
                                                     each with a SHA-256 ace hash)
                                                        │
                                                        └─ AceSetHash.Of ──► one hash per object
```

The normalisation pass, in order: expand shorthand rights, sort into canonical order, hash each
entry, discard duplicates by hash.

**Expansion happens before hashing.** That is what makes the same permission written two ways hash
to one value and collapse to one entry rather than two.

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `SecurityDescriptorParser` | Parses raw binary `ntSecurityDescriptor` bytes. Entry points are `Parse` and `ParseBase64` |
| `ParsedSecurityDescriptor` | What the bytes said: owner, group, DACL state, control flags, entries, parse errors |
| `ParsedAce` | A single entry as stored, with no interpretation of what its rights mean |
| `AceType` | The entry type byte, named |
| `DaclState` | Whether the DACL is `Present`, `Null`, `Empty`, or `Unreadable` |
| `DaclCompleteness` | Whether the DACL yielded every entry its header declared: `Complete`, `Incomplete`, `Unknown` |
| `GenericRightsExpander` | Rewrites shorthand rights into the AD-specific bits they stand for |
| `AceNormalizer` | The normalisation pipeline: expand, order, hash, deduplicate |
| `CanonicalAce` | One entry in comparable form, carrying its hash and the version that produced it |
| `AceNormalizationResult` | The canonical entries for one object, with the DACL facts carried through |
| `AceCanonicalization` | The version stamped onto each canonical entry, and the ordering category |
| `AceSetHash` | The hash of a whole set of entries, as one value |
| `Sid` | A security identifier between its two forms — stored bytes and `S-1-5-…` text |
<!-- TYPES:END -->

Each type carries its own reasoning in its XML documentation, including the Microsoft sources it is
anchored to. **That is the reference; this page is the orientation.** Read the type when you need to
know what a field means or why it exists.

---

## Rules that no single type owns

**The DACL, and only the DACL.** Capture never requests the SACL, so nothing here ever describes an
audit entry. Any type that appears to offer one is wrong.

**Three ways to hold no entries, not two — and they mean opposite things.** A `Null` DACL grants
everyone full control. An `Empty` DACL grants nobody anything. An `Unreadable` DACL makes no claim
at all. Collapsing any of these into "zero permissions" reports an object the product could not read
as the most locked-down object it is possible to be. `DaclState` exists to make that collapse
impossible, and no consumer may treat `Unreadable` as safe.

**A partly read DACL stays `Present`.** It genuinely is present. The shortfall is carried beside it
by `DaclCompleteness`, not by pretending the state is something else.

**Expansion is for comparison and severity, never for semantics.** Reading an expanded mask as what
a stored entry *grants* manufactures rights the domain controller would not honour —
[MS-DTYP] 2.4.3 states the access-check algorithm does not map shorthand bits already attached to an
object. The raw mask stays on `ParsedAce` and the expanded one on `CanonicalAce`, so both remain
available and which is which is never in doubt.

**Disorder is not damage, but it is not neutral either.** A DACL that arrives out of canonical order
is common and must normalise to the same form as one that arrives ordered. But Windows evaluates a
DACL in **stored** order and stops at the first match, so an allow placed before a deny grants access
the sorted form would deny. Sorting destroys that fact, so `DaclWasCanonical` is judged before
anything is sorted and carried forward.

**Nothing here throws on damaged input.** Damage is recorded and carried forward. A parser that
throws turns one bad descriptor into a failed run.

**No audit configuration can be concluded from this layer.** `AceType` defines `SystemAudit` and
`SystemAuditObject`, and the classifier handles audit types — but the SACL offset in the descriptor
header is never read, so no SACL is ever parsed. Capture never requests one. The audit handling is
defensive, because the classifier is callable directly, and an audit entry reaching it means a
malformed descriptor rather than a SACL. **The enum and the handling imply a capability the parser
does not exercise**, so a reader must not take either as coverage of audit settings.

**Completeness has one known blind spot.** `DaclCompleteness.Complete` is set when the parsed entry
count equals the declared count. The ACE walk is bounded by the declared count and the descriptor's
end rather than by the ACL's own `AclSize`, so on a malformed descriptor the shortfall can be made
up from bytes past the DACL's declared extent — and the result is reported as completely read when it
was not. Not reachable from a healthy domain controller; it matters for hand-crafted or corrupt
descriptors. Recorded as `P-7` in [the punch list](../../PUNCH-LIST.md).

---

## What an operator can do

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory — a synthetic descriptor proves the
parser handles those bytes, not that a domain controller sends them.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| read a security descriptor the way the directory meant it | `SecurityDescriptorParserTests` |  |
| trust that permission normalisation has not silently changed | `GoldenAceHashTests` |  |
| tell an object that grants nothing from one that grants everyone everything | `SecurityDescriptorParserTests.WhenTheDaclIsAbsent_ThenTheStateIsNullWhichGrantsEveryoneEverything` |  |
| be certain a DACL that could not be read says so rather than looking locked down | `SecurityDescriptorParserTests.WhenTheDaclDeclaresEntriesAndNoneParse_ThenTheStateIsUnreadableRatherThanEmpty` |  |
| be certain a DACL read only in part admits the shortfall | `SecurityDescriptorParserTests.WhenTheDaclYieldsFewerEntriesThanItDeclared_ThenItStaysPresentAndSaysItIsIncomplete` |  |
| be certain a DACL header that could not be read is never reported as complete | `SecurityDescriptorParserTests.WhenTheDaclHeaderCannotBeReadAtAll_ThenTheStateIsUnreadableAndCompletenessIsUnknown` |  |
| see that permissions were stored in an order that grants more than the tidy form suggests | `SecurityDescriptorParserTests.WhenAllowPrecedesDeny_ThenTheDaclIsRecordedAsNotCanonical` |  |
| be certain damage in one entry is reported rather than thrown | `SecurityDescriptorParserTests.WhenAnAceIsTruncated_ThenTheDamageIsReported` |  |
| be certain a shorthand "full control" right is expanded to what it actually grants | `GenericRightsExpanderTests.WhenGenericAllIsSet_ThenTheFullSpecificMaskReplacesIt` |  |
| be certain a shorthand write right is expanded before it is judged | `GenericRightsExpanderTests.WhenGenericWriteIsSet_ThenWritePropertyReplacesIt` |  |
| be certain shorthand and specific rights on one entry both survive expansion | `GenericRightsExpanderTests.WhenGenericAndSpecificAreMixed_ThenBothSurvive` |  |
| be certain an entry with no shorthand right is left alone | `GenericRightsExpanderTests.WhenNoGenericBitIsSet_ThenTheMaskIsUnchanged` |  |
| be certain a deny entry is ordered ahead of an allow, whatever order it arrived in | `AceNormalizerTests.WhenAllowPrecedesDenyOnTheWire_ThenDenySortsFirst` |  |
| be certain an explicit entry is ordered ahead of an inherited one | `AceNormalizerTests.WhenBothExplicitAndInherited_ThenExplicitSortsFirst` |  |
| be certain the same permissions produce the same fingerprint whatever order they arrived in | `AceNormalizerTests.WhenTheSameAcesArriveInEitherOrder_ThenTheCanonicalFormIsIdentical` |  |
| be certain a changed trustee changes the fingerprint | `AceNormalizerTests.WhenTheTrusteeDiffers_ThenTheHashDiffers` |  |
| be certain a changed right changes the fingerprint | `AceNormalizerTests.WhenTheAccessMaskDiffers_ThenTheHashDiffers` |  |
| be certain an inherited entry is not confused with an identical explicit one | `AceNormalizerTests.WhenTwoAcesDifferOnlyByInheritance_ThenBothSurvive` |  |
| tell an object with no permissions from one whose permissions could not be read | `AceNormalizerTests.WhenComparingANullDaclWithAnEmptyOne_ThenTheyAreDistinguishable` |  |
| be certain an absent DACL says so rather than reporting no entries | `AceNormalizerTests.WhenTheDaclIsNull_ThenNormalizationSaysSoRatherThanReportingNoAces` |  |
| be certain damage found while parsing is carried forward, not dropped | `AceNormalizerTests.WhenParsingReportedDamage_ThenNormalizationCarriesItForward` |  |
| be certain no damage is invented where parsing reported none | `AceNormalizerTests.WhenParsingReportedNoDamage_ThenNormalizationInventsNone` |  |
| be certain every entry records the canonicalization version that produced it | `AceNormalizerTests.WhenNormalized_ThenEachAceRecordsTheCanonicalizationVersionThatProducedIt` |  |
| be certain a name against a permission is the principal the directory named | `SidTests.AWellKnownSidIsWrittenTheWayWindowsWritesIt` |  |
| be certain a malformed identifier is refused rather than shortened into a different one | `SidTests.ATruncatedSidIsRefusedRatherThanShortened` |  |
| read the same account of descriptor parsing in the document and the code | `SecurityDocumentationTests` |  |

---

## Why it is this way

**One parser, one normaliser.** Raw bytes are read once. A second reader is a second interpretation
of an offset, and the two disagree silently — the entries come out looking plausible and are not the
ones the directory holds. A second normaliser is worse: the canonical form is what stored hashes are
computed over, so two runs of the same directory would compare as changed and the product would
report drift that did not happen.

**One SID implementation.** A second would drift, and a drifted SID parser puts the wrong name
against a permission.

**The canonicalisation version is stated in the Kernel, not on the bundle schema.** The number
describes this component's own output, not the storage it happens to be written to — and the Kernel
is the lowest layer and cannot reference the bundle. Changing it invalidates every stored hash and
every golden value in the tests, so it changes only as a deliberate decision.

It is currently **3**. Version 2 added the entry type to the hash inputs, because version 1 hashed
three of the four fields that define an entry, so two entries differing only by type collided and
one was silently dropped. Version 3 added the condition bytes a callback entry carries, because
version 2 hashed everything that distinguishes an unconditional entry and nothing that distinguishes
a conditional one — so *allow X when Department = IT* and *allow X when Department = HR* collided,
and one was discarded before it was written.

**One hash per object, not per entry, for comparison.** Asking whether an object's permissions
changed by reading every entry of every object is the query that makes comparison too slow to use.
An empty set still has a hash, so a reader never has to decide what a missing value means.

**There are two hashes, and only one of them is authoritative.** The `security_descriptor` table is
keyed on the SHA-256 of the bytes the controller sent, with `raw_bytes` stored beside it — that is
the evidence, and it is order-sensitive. `ace_set_hash` is a separate, deliberately order-insensitive
projection used only to make run-to-run comparison affordable. *Allow X, Deny X* and *Deny X, Allow X*
are different descriptors, so an order-insensitive hash must never be the authoritative state.

The evidence hash is cryptographic on purpose, and not out of caution about a rare event: a collision
would not corrupt a row, it would silently attribute one object's permissions to another — the single
failure an audit tool cannot have. `byte_length` sits beside it so a collision must agree on two
things rather than one.

**Descriptors are deduplicated across the forest.** A forest does not hold one descriptor per object;
it holds a few thousand distinct ones repeated across millions of objects, mostly by inheritance.
Measured at 4.81 GB per 100k objects stored per object, against 1.24 GB deduplicated.

## Two deliberate divergences from the design review

Both look like defects if you read the archived Microsoft source review without this page. **Neither
should be "corrected".**

**Generic rights are expanded before hashing.** The review's repair order says to remove generic
expansion from stored ACEs, eliminate sorting and deduplication of raw evidence, and preserve stored
order. Taken literally that would remove the comparison hash the product depends on. The concern is
met a different way: the raw mask stays on `ParsedAce`, the expanded mask goes on `CanonicalAce`,
`DaclWasCanonical` is judged before anything sorts, and `raw_bytes` preserves the stored order
exactly. Nothing is lost; it is recorded in two places instead of one.

**There are two read paths, on purpose.** The `ace` table is the canonical comparison projection.
`ObjectPermissions` reads the stored DACL from `raw_bytes` in stored order **with nothing
deduplicated**, which is what recovers the entries and the ordinal that canonicalisation sets aside.
A reader who finds only the `ace` table has found the projection, not the evidence.

---

## What reads this

- `Audit/Capture/BundleCaptureSink.cs` — every descriptor captured from the directory
- `Audit/Sysvol/SysvolCapture.cs` — descriptors on GPO files in SYSVOL
- `Evidence/ObjectPermissions.cs` — re-parsing stored bytes when exact detail is needed

The bundle keeps the raw bytes, which is why this subsystem does not carry exact counts or the
original entry order. The cheap question is answered by a stored flag and queryable across a whole
forest; the exact one is answered by re-parsing the evidence when something actually needs it.
