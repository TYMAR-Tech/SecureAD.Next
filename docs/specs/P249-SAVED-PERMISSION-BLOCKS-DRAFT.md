# P-249: bounded saved-permission blocks inside SQLite

**Status: DRAFT CONTRACT — candidate B's final isolated implementation, offline verification,
Permissions paging and contrast I are now owner-approved; candidate C and adoption are not.**

The exact approval and stopping rule are recorded in [WHAT-THE-PRODUCT-IS.md](../WHAT-THE-PRODUCT-IS.md),
“Owner-approved final bounded P-249 trial”. Approval gates below are satisfied only for that scope;
they do not authorize additional experiments or production adoption. If this attempt is not worthwhile,
return to finishing Stage 7 and then the remaining rules rather than another storage experiment.

This contract proposes how to save and retrieve permission classifications, not how to decide them.
Active production remains judgement format **41**; no trial optimization is adopted. The retained
format-43 candidate is a design/source reference only. Normative words below describe obligations
of a proposed candidate, not claims about shipping behavior or completed verification.

## 1. Purpose, authority and boundary

A customer must be able to open part of an object's saved permission reading without first loading
all of it, while retaining every saved answer and an honest statement of what remains unloaded.
This is Stage 6 permission evidence: ownership findings, permission-derived control proofs and later
chained paths to Tier 0 remain distinct products. A saved risky right is not requester authorization,
a completed takeover, credential extraction or a path to Tier 0.

Authority is [the governing handoff](../WHAT-THE-PRODUCT-IS.md#what-securead-is), specifically
“Bounded saved-permission blocks — design-only handoff”, and [the work queue](../PUNCH-LIST.md)
P-249/P-200/P-254/P-255. [JUDGEMENT-HALF.md](JUDGEMENT-HALF.md) §2b governs ordered permissions,
missing inputs and versioned generations. Its acceptance companion's AC-24, AC-35, AC-41/42,
AC-55/56, AC-59, AC-62, AC-70/71 and AC-84 constrain this representation: preserve raw evidence,
resource identity, provenance, uncertainty and occurrences without inventing authorization.
AC-84 does not make a storage position a cross-run remediation identity.

Only classification persistence/retrieval changes. Preserve evidence → derivation → judgement,
security calculations, stage admission, genuine proof storage, existing transaction boundaries
(one classification transaction per object), cancellation/rollback and final generation publication.
No cross-object batching, parallel workers, cross-generation sharing, incremental findings, external
payload files, migration or legacy readers. No reclassification during completed-run browsing.
No live AD, recapture, original-result regeneration/deletion, discovery activation, production-budget
changes, commit or push. Existing uncommitted work and frozen/historical artifacts stay in place.

### Source anchors, not a second description to maintain

The proposal replaces the classification use of `PermissionClassificationStorage` and its calls to
`SharedPermissionStorage`; it does not replace actual control-proof uses. The required values are
anchored to `PermissionClassification.cs`, `Evidence/ObjectPermissions.cs`, the Kernel permission
and schema records, and the actual consumers identified in §9. The retained source reference is
`next/artifacts/p249-object-storage/build-candidate-ef6b2a701e82451ab1f481aa9ed5a01c/candidate.patch`,
not `mutation-write-source.patch`, which contains deliberate defects.

The predecessor's `SecureAD.Infrastructure/Storage/MaterializedAclPayload.cs` is technique evidence
only: a local string dictionary and binary records. Its normalized/sorted/deduplicated inputs,
expanded generic rights, merged null/empty strings, missing Next fields and whole-object reader are
not acceptable here. Its object-detail interpretation is not a completed-run reading model for Next.
The original application remains read-only.

## 2. Chosen representation and versions

Use **ordered bounded BLOB rows in the judgement SQLite file**, with small relational directories
for objects, groups, occurrence locations, large values and shared schema support. A BLOB is a byte
payload, not another file. No compression in either first experiment.

Two distinct candidates, never one combined optimization claim:

- **B / chunked JSON**: retain format 43's logical fields, JSON property names and enum/string
  meanings where practical; split descriptor, entries, rights and schema records into framed records
  and externalize oversized values into *in-database* continuation records. No string dictionary.
  This cannot be byte-identical to a format-43 whole-object JSON document. The framing, directory,
  publication validation and caller work are part of B's measured cost.
- **C / compact encoding**: same logical records, directories, summaries, bindings, validation and
  API as B; replace only record encoding with the binary codec and block-local dictionary in §5.
  No added computation sharing, compression, cache tuning or proof redesign.

Proposed isolated judgement format numbers are **44 for B, 45 for C**, subject to checking they are
still unused immediately before a separately approved implementation. Neither number is allocated
in production by this draft. Block envelope version = 1; logical record contract version = 1;
codec IDs = `JsonFramesV1` and `BinaryFramesV1`; browsing projection version = 1. Classifier producer
version and schema-catalogue semantic version remain the values that produced the answers; a storage
rewrite must not pretend that those semantics changed. All versions are recorded, not inferred.
Each candidate build accepts only its own complete format. Unknown envelope/codec/required field/
semantic version is an explicit unsupported-format refusal, never best-effort skipping or fallback.

### Experimental bounds (not production security limits)

| Unit | Proposed candidate bound | Overflow action |
|---|---:|---|
| Physical block payload, including codec dictionary/framing | 65,536 bytes | Close block and continue in the next block |
| One framed logical record | 8,192 encoded bytes | Move variable fields/collections to typed continuations |
| Inline string | At most 256 UTF-16 code units, and only if record fits | Store exact string as a large-value reference |
| Binary block dictionary | At most 512 strings and 16,384 bytes of UTF-16 content combined | Write a literal/reference instead; reset at next block |
| Variable-value fragment | At most 4,096 source bytes | More fragments; base64 plus framing must fit the 8,192-byte record bound |
| One API response | At most 64 item headers, 65,536 returned variable-content bytes | Continuation token; no hidden load-all loop |
| One page/value operation | At most 8 blocks / 526,080 encoded bytes including envelopes, plus bounded indexed metadata | Continue at a precise cursor, even within one item |
| Metadata query window | At most 64 fixed-size rows (plus one look-ahead row), at most 8 windows per operation | Keyset continuation, never an unbounded manifest list |

The page budget counts blocks read for schemas and dictionaries too, not only entry blocks. These are
candidate I/O/working-set units chosen for an experiment, not accepted user-visible page sizes, wall-
clock cancellation guarantees, total object/forest limits or proposed production defaults. Their
adequacy must be measured. A value with millions of bytes produces more fragments, not a shortened
answer, an “unsupported security analysis” result or an omitted object. Arithmetic/SQLite capacity
exhaustion fails the generation explicitly; it never publishes a subset. Counts and offsets are
checked nonnegative 64-bit integers; conversion to array lengths follows validation and is bounded.

## 3. Lossless logical records

Every list below preserves order and repeated values unless expressly a *navigation projection*.
No trimming, case folding, GUID reformatting, generic-right expansion, ACE normalization or
serialization-default omission. Null, empty string, empty byte sequence, null collection and empty
collection have distinct tags where the model permits them. Required nulls are invalid, not empty.
Unknown raw ACE type text and unknown mask/flag bits survive; unknown *contract* enum values refuse
an unsupported result instead of silently mapping to a known verdict.

| Record | Required saved fields and distinctions |
|---|---|
| Product | Evidence seal; judgement generation; nullable derivation generation; producer version; schema version; `HasCapturedSchema`; storage/codec/projection versions; independent expected object, parsed-entry and classified-right totals; completion state |
| Object descriptor | Exact `DistinguishedName`; `Availability` (`Read`, `Unreadable`, `NotAttempted`); nullable `UnreadableReason`; nullable `Owner`; `DaclState` (including null versus empty versus unreadable); `DaclCompleteness` (`Complete`, `Incomplete`, `Unknown`); `DaclWasCanonical`; `IsDaclProtected`; ordered `Errors`, including duplicates; exact source binding from §4 |
| Owner or entry trustee | `Sid`; nullable `Name`, `DistinguishedName`, `DomainFqdn`, `UnresolvedReason`, `WellKnownRole`, `Meaning`. Preserve the difference between a missing trustee/owner and a trustee with nullable attributes; do not merge identical builtin SIDs across target resources |
| Raw permission occurrence | Original `Ordinal`; exact `AceType` text; full trustee; `AccessMask` as the exact 32 bits (including sign bit); nullable `ObjectTypeGuid`, `InheritedObjectTypeGuid`; `IsInherited`; raw byte `InheritanceFlags`, `PropagationFlags`; separate `HasObjectType`, `HasInheritedObjectType`; exact non-null `ApplicationData`, including empty |
| Entry interpretation | `Summary`; `RightsAreComplete`; `Scope.AppliesTo`, `Scope.Inheritance`; ordered rights with independent count; nullable object-type and inherited-object-type schema references |
| Each right | Position within this entry; `Right.Name`, exact `Right.Bits`, `Right.IsNamed`; `Assessment.Verdict`, `Assessment.Reason`, nullable `Assessment.RightName`. Preserve `Dangerous`, `DangerousInCombination`, `NotDangerous`, `CannotClassify` separately |
| Schema support | Exact `Guid`; ordered `Definitions` of exact `Guid`, `LdapName`, `Kind`, `Source`; nullable `PropertySetMembers` (null is not empty); ordered `AmbiguousNames`. Definitions and member/name repetitions survive |
| Structural provenance | Object/source key, zero-based occurrence position, original ordinal, zero-based right/collection position, producer/schema/projection versions and semantic integrity digest; none is inferred from the page number |

`OwnerRightsEntryIsPresent` and trustee `HoldsThePermission` are computed properties of existing
models. Do not recompute the former from a loaded subset. Save their existing projection results
for browsing (with projection version), independently reconciled against the full input during
writing; preserve the underlying values as well. Preserve the current summary/counting semantics
in §9, not a new risk scale. No security calculation is moved into the reader.

Raw descriptor bytes remain in sealed Evidence, not copied into each block. Save an exact source
reference and descriptor digest; a descriptor missing at capture has an explicit absence tag, not
the digest of an empty descriptor. The stored raw entries are those produced from original descriptor
bytes, **not** the sorted/deduplicated `ace` projection or `captured_object.ace_count`. Do not invent
raw fields that the existing permission model never supplied; Evidence remains the raw-byte authority.

## 4. Identity, searchable directories and manifests

### 4.1 Binding capsule

Every root uses `B = (EvidenceSeal, JudgementGenerationId, DerivationGenerationId-or-explicit-null,
ProducerVersion, SchemaVersion, HasCapturedSchema)`. Encode these typed values with lengths/null tags,
not delimiter-concatenated strings. Compare both generation IDs and the exact evidence seal with the
selected `JudgementDescription`; retaining the same DN or version is not sufficient.

An object capsule `O` adds the sealed Evidence `captured_object.object_id`, exact DN, nullable object
GUID, `coverage_id`, captured domain FQDN, and the coverage row's naming-context DN/kind and controller.
It also records nullable source `descriptor_id` plus SHA-256 of original descriptor bytes when one
exists, or the explicit descriptor-absence state. Numeric IDs are file-local under the evidence seal;
they are never global identities. DN lookup follows the existing lookup convention only to resolve
one object; all subsequent references use its numeric ID and exact stored capsule. No new DN
canonicalization or SID-only target matching. A binding adapter must carry these existing captured
identities to storage without changing evidence schema, parsing or permission calculations.

Occurrence key = `(B, source object ID, position)`, where position is the dense zero-based sequence
in `ObjectPermissions.Entries`. Store `Ordinal` independently: it is the original descriptor index
and may have gaps if parsing was incomplete. Preserve the current strictly increasing ordinal
invariant; reject duplicate ordinal keys without dropping duplicate ACE *values at different ordinals*.
Do not renumber gaps or deduplicate identical entries. Right key appends right position. Value keys
append field kind and nested list positions, so identical strings in different fields are still
separately attributable. Schema references append exact identifier plus generation-local schema ID
and semantic digest. Resource scope is the captured object/coverage, not the trustee's domain inferred
from its SID. No reuse across a different B, O, ordinal or occurrence position.

### 4.2 SQLite directory contract

Names are proposed storage names, not DDL applied by this draft. All child tables have checked foreign
keys with generation/object components; a numeric row ID alone is never a sufficient reference.
Use NOT NULL/CHECK/unique constraints and reader validation; foreign keys alone do not prove length,
sequence or semantic equality. Blob-bearing tables use rowid tables for bounded blob access.

| Table | Key and contents |
|---|---|
| `pc_product` | One B; Writing/Complete; format versions; independent expected totals and object-set digest; actual reconciled totals; ordered object-manifest root |
| `pc_object` | `(generation, source_object_id)`; O; source/producer expectations; descriptor header reference; aggregate totals; publication state; ordered stream-manifest root |
| `pc_block` | `(generation, owner_kind, owner_id, stream_kind, sequence)` unique; fixed envelope fields; bounded BLOB; stored-byte digest. Owner is an object or generation-local schema record, never an implicit “last object” |
| `pc_stream` | Same owner and stream kind; record count, byte length, block count, first/last record keys, semantic digest and ordered manifest digest. Manifest leaves are the indexed block-directory rows, not a single growing array |
| `pc_occurrence` | `(generation, object_id, position)`; unique original ordinal; group ID; entry-header block/record locator; right count; right-stream locator; entry semantic digest; fixed entry-risk category. This is a narrow locator, not another copy of the raw entry or interpretation |
| `pc_group` | `(generation, object_id, group_id)`; exact SID reference; first occurrence; first trustee reference; complete entry/right/risk/unknown totals; denial flag; complete saved rights-summary reference. Indexed by first occurrence |
| `pc_value` | `(generation, owner_kind, owner_id, value_id)`; field/list ownership key; kind; explicit null/empty/present tag; total bytes/code units/items as applicable; stream locator and semantic digest |
| `pc_schema` | `(generation, schema_id)`; B; exact GUID reference; GUID digest lookup bucket; definition/member/ambiguity counts and null flags; support stream and semantic digest; complete state |

Required indexes: object ID primary key; DN resolution bucket with exact full-value comparison;
occurrences by `(generation, object_id, position)` and `(generation, object_id, group_id, position)`;
groups by first occurrence; streams/blocks by owner/kind/sequence; values by owner/value ID; schema
GUID digest bucket. Grouping uses exact ordinal SID equality *within one target only*. For very long
DN/SID/GUID values, index a SHA-256 bucket plus length and compare full values as bounded streams;
a hash hit is not equality and hash collisions must not merge records. Identity strings use the same
large-value continuation as other strings, not unbounded SQL TEXT fetched by a paging query.

A directory row carries only fixed-width values or bounded references. `pc_occurrence` deliberately
retains one small row per entry: selecting a principal must not require decoding every object's
block. This costs row inserts and indexes (about 5.9 million occurrence rows at the documented forest
shape); it avoids the old per-entry interpreted JSON and classification-only shared-proof writes.
This trade-off must be measured, not sold as eliminating all per-entry work. No per-right SQL row
is required: right records have bounded indexed stream ranges.

### 4.3 Ordered integrity

Each block envelope contains magic `SAPB`, envelope/record/codec versions, B digest, owner kind/ID,
object-capsule digest where applicable, stream kind, zero-based sequence, logical byte offset,
payload length, record-start/continuation counts, first/last record key and SHA-256 of stored payload.
The directory repeats those locating fields; the two must agree. A framed record carries kind,
record key, byte length and typed field tags. Continuations additionally carry parent key, fragment
index, byte/item offset, total length/count, and final flag. Endianness/length rules are in §5.

The version-1 envelope is exactly 224 bytes, outside the 65,536-byte payload allowance, in this order:
magic (4); envelope/record/codec versions (2 each); owner kind and stream kind (1 each); judgement GUID
(16); B digest (32); O digest (32, all zero only for a schema owner); owner ID, sequence and logical
payload offset (8 each); payload length, record-start count and continuation count (4 each); first
and last record keys (32 each); payload digest (32). Integers are little-endian. A record key is kind
(1), zero reserved bytes (7), parent ID, item position and fragment position (8 each). Nonapplicable
positions are zero, distinguished by record kind; unused/reserved values must not carry hidden data.
Owner kinds are 1=object and 2=schema; stream kinds are 1=descriptor, 2=entries, 3=rights, 4=values,
5=schema, 6=projections. Byte offsets exclude envelopes and are contiguous within their stream.
The SQLite BLOB contains envelope followed by payload; directory columns permit validation of its
bounded length before fetching it. All-byte integrity includes the envelope through the manifest leaf.

A stream manifest hashes a domain tag, B/O identity, stream kind, expected counts/lengths, then the
ordered fixed-size block leaf records (including their digests). Object root covers descriptor,
occurrence/right/value stream roots, group projection digest and ordered schema-reference bindings.
Product root covers objects in source-object-ID order. Digests use a canonical typed logical encoding
independent of JSON property formatting/dictionary IDs/block partitioning; the bytes-digest separately
covers the actual encoding. No ambiguous concatenation; null/type/length/list position are included.

Validation rejects duplicate/gapped/reordered block or fragment sequences; overlapping/missing offsets;
wrong first/last keys; zero-progress fragments; overflow/negative lengths; early final markers; missing
final markers; trailing bytes or records; orphan directory/payload references; wrong ownership or
schema role; wrong digest; and unsupported tags. A repeated ACE at its own position is valid, but a
second payload record for the same position is not. Required references resolve exactly once.

## 5. Codec, large-value continuation and working memory

Logical records are descriptor header, owner/trustee, entry header, right, schema header/definition,
ordered string-list item, value fragment, and saved browsing projection. Variable fields use a tagged
`Null`, `Empty`, `Inline` or `Reference` representation. Collections have explicit null/present tags,
independent count and ordered item records; a large schema record is not one giant JSON token.

Record framing is kind (1 byte), record key (32), body byte length (4), then the body; the 8,192-byte
limit includes these 37 bytes. Kinds are 1=descriptor, 2=trustee, 3=entry, 4=right, 5=schema header,
6=schema definition, 7=ordered string-list item, 8=value fragment, 9=projection, 10=stream end.
The duplicate kind in the key must agree. Parent ID is object ID for its descriptor, occurrence
position for entry/rights, schema ID for schema records, and value/group ID for their typed records;
the envelope fixes the owner namespace. Kind plus parent/item/fragment positions disambiguates keys.
The body has no recursive embedded collection. B uses named JSON fields; C uses ordered numbered
fields with tag (1), checked byte length (ULEB128), then typed bytes. Field numbers are assigned in
the order below, starting at 1 per record; all are required, with explicit nullable tags where needed.

| Record | Version-1 body field order |
|---|---|
| Descriptor | DistinguishedName, Availability, UnreadableReason, Owner reference, DaclState, DaclCompleteness, DaclWasCanonical, IsDaclProtected, Entries reference/count, Errors reference/count |
| Trustee | Sid, Name, DistinguishedName, DomainFqdn, UnresolvedReason, WellKnownRole, Meaning |
| Entry | Ordinal, AceType, Trustee reference, AccessMask, ObjectTypeGuid, InheritedObjectTypeGuid, IsInherited, InheritanceFlags, PropagationFlags, HasObjectType, HasInheritedObjectType, ApplicationData reference, Summary, RightsAreComplete, AppliesTo, Inheritance, Rights reference/count, ObjectType support reference, InheritedObjectType support reference |
| Right | Name, Bits, IsNamed, Verdict, Reason, RightName |
| Schema header | Guid, Definitions reference/count, PropertySetMembers nullable reference/count, AmbiguousNames reference/count |
| Schema definition | Guid, LdapName, Kind, Source |
| String-list item | List kind (errors, property members, ambiguity names or summary names), exact string value |
| Value fragment | Value kind, parent field tag, source byte offset, total source bytes, total UTF-16 units if text, final flag, payload bytes |
| Projection | Scope kind (object/group), entry count, right count, group count, dangerous-entry count, combination-entry count, four per-right verdict counts, HasDenials, OwnerRightsEntryIsPresent, owner/first-trustee HoldsThePermission, rights-summary reference (nullable for object) |
| Stream end | Record count, byte length, entry count, right count, semantic digest |

Enums other than raw ACE text use the exact version-1 named vocabulary encoded as strings in B and
length-delimited ASCII names in C, not inferred numeric enum ordinals. A reference encodes owner kind,
owner ID, stream kind, record/value ID, count/length, and semantic digest; an entry schema reference
also binds exact GUID and support role. Required fields occur exactly once in order; unknown, duplicate
or missing fields refuse. The canonical semantic digest walks this same typed field order with literal
string code units and fixed-width counts, without dictionary IDs, locators or physical byte offsets;
source binding and ordered parent/item identities prefix each logical value. Transport references are
resolved to their logical content/digest, so B and C partitioning cannot change an answer digest.
Stream-end records are validation trailers, excluded from their own semantic digest and data-record
count. Their byte length counts framed data records only; the directory separately accounts for all
physical payload bytes, including trailers and dictionary definitions. Hash/count domains must never
refer to their own serialized digest or confuse these logical and physical lengths.

**B:** length-prefixed UTF-8 JSON records in each block, with the retained field meanings and explicit
nulls. Variable collections and oversized entries are represented by header/reference plus child
records, not a serialized whole-object array. Byte fragments are base64 of at most 4,096 source bytes;
include expansion in sizing. Valid short strings use ordinary JSON escaping; strings containing lone
UTF-16 surrogates use the exact-code-unit large-value representation, never replacement characters.
A bounded counting pass or bounded record writer externalizes fields before an 8,192-byte record can
be exceeded. Do not serialize the entire entry/string first to decide whether it fits.

**C:** fixed little-endian scalar integers (mask/right bits retain all 32 bits; flags are bytes),
strict one-byte booleans/tags, checked unsigned LEB128 lengths/positions with at most ten bytes and
minimal representation. Signed values other than raw masks retain their declared signed width.
Strings use exact UTF-16LE code units, not normalization or replacement fallback. This may cost more
than UTF-8 for unique ASCII text; dictionary benefit must earn that cost. GUID *strings* remain exact
strings; generation GUIDs have a specified fixed 16-byte RFC-order representation. A block dictionary
assigns IDs by first appearance, using ordinal exact-string equality and full collision comparison.
IDs are block-local, backward references only; null and empty have distinct reserved tags. Add a
string only while both dictionary bounds fit; otherwise encode it as a literal or large-value
reference. No cross-block, cross-object or global string dictionary. Discard dictionary at block end,
including on cancellation/error. Header/dictionary/record lengths must fit the same block bound.

C variable-value tags are 0=null, 1=empty, 2=literal, 3=large-value reference, 4=dictionary definition,
5=dictionary reference. A literal has ULEB128 code-unit/byte length followed by exact content; a
dictionary definition has the next dense ID and a nonempty bounded string literal, and a dictionary
reference has an already defined ID. Definitions occur at first use within a record, not in a
whole-object prepass. IDs start at zero in each block and must not exceed the count/byte ceilings.
Large-value references use the binding/length form above. Non-string fields cannot use dictionary
tags; a nullable enum still retains a distinct null tag. Invalid tag/type combinations refuse.

**Continuation:** a large entry has a small header, independently positioned right records and
references for its strings/application bytes/support. A large string is exact UTF-16LE fragments
with code-unit-aligned offsets; API text slices must not split a valid surrogate pair (an isolated
surrogate is preserved as evidence, not repaired). A schema support value has a header then ordered
definition/member/ambiguity records, whose strings can themselves continue. Application data is raw
byte fragments in C and base64 fragments in B; never decode a callback condition or discard its bytes.
A rights/errors/member list can span any number of blocks. End records reconcile total counts and
lengths; zero-length values use their explicit empty tag rather than an absent continuation.

At most one bounded record buffer, one block buffer, one 4 KiB fragment buffer, and the bounded
binary dictionary are owned by an encoder/decoder. A decoder checks block length before fetching a
payload; a malformed claimed length never drives an allocation. It validates a complete block before
exposing its records. A page builder additionally retains only the bounded response (§2); it must
not hold every visited block. Byte/content budgets and object-count ceilings jointly bound response
objects; memory accounting includes strings, reference objects and collection slots, not just BLOBs.
Measure actual retained managed memory separately from these serialized-byte bounds.

The existing producer and evidence parser still materialize one object's input in this first candidate.
That is explicitly **not** a bounded end-to-end judging claim. The storage writer adds no second
whole-object JSON/string/byte-array copy and retains no forest of produced objects. Structural and
projection passes may enumerate the existing single-object input more than once without rerunning
classification. SQLite page cache, journals, protected-file hashing and producer memory are additional
costs; a 64 KiB block is not a 64 KiB process-memory cap.

## 6. Independent reconciliation and complete publication

Before encoding, the producing stage supplies an expectation capsule independent of block assembly:
source object identity; parsed entry count from `ObjectPermissions.Entries`; original ordinal sequence
digest; full raw-entry semantic digest; classified entry/right counts and complete classified-answer
digest from the producer result. Count rights by enumerating original producer right lists, not emitted
records or SQL rows. Validate raw entries against their classification counterparts. Record descriptor
header-declared ACE count separately where the existing parse can establish it, otherwise unknown;
it is not the expected parsed count and must never erase `Incomplete` or `Unknown` evidence.

The object loop supplies an independent expected source-object set/count, under the evidence seal,
using the captured object identity stream; do not use `control_object` count, because that table can
also hold uncaptured naming-context-root coverage records. A stable source-ID-ordered set digest and
aggregate parsed-entry/right expectations are kept separately from the block manifest. Aggregate
progress counters advance only after successful object commit; an aborted/retried object cannot count
twice. For unordered callers, use an in-database keyed expectation ledger and ordered bounded scan,
not an in-memory forest-wide set. No additional capture or evidence rewriting is required.

Within **one transaction per classification object**:

1. Check B, versions, current producer result and its independent expectation capsule; insert Writing
   object/expectation rows. Duplicate target publication is a failure, not `INSERT OR REPLACE`.
2. Save descriptor, ordered entry/right/value blocks and schema references; create thin locators and
   full-object/group projections without consulting a loaded page. No fragment commits separately.
3. Stream-decode the persisted object and referenced support through the candidate reader, boundedly,
   without re-running the classifier. Reconcile every field through the canonical semantic digest,
   raw/ordinal digest, entry/right/list lengths, group membership and aggregates against the pre-encoding
   expectations. Also reconcile locators/manifest leaves with actual blocks and foreign keys.
4. Only then mark this object Complete and commit. Object transaction failure/cancellation removes
   its fragments, projections, expectations and newly inserted schema identities together.

This full stored-object validation is **writer work** and belongs inside measured whole judging;
it is not a free untimed step hidden by the comparison. The input semantic digest must be computed
by a direct model walker, not by re-decoding the same encoder output. Equality tests independently
compare actual typed values too, so an omitted field in a digest implementation is not a closed loop.

After the source loop, reconcile the object set and aggregate object/entry/right totals against the
independent expectations; require every object Complete, all required schema support Complete and
no orphan records. Seal the classification product and its ordered root. Existing later-stage checks
and existing judgement generation sealing/publication still decide whether customers can open it.
An object marked Complete inside a partial generation is not visible as a completed run. A findings-
only generation lacking this product stays explicitly unavailable for classifications, not empty.

Deleting the last block *and* shortening its manifest cannot validate: the pre-encoding counts,
ordinal and answer digests still require its data. Deleting an entire object must fail against the
source-object set/count; removing one right must fail independent right counts/digests even if entry
count is unchanged. Test deletions before sealing as well as sealed-byte corruption. Hashes detect
binding/damage under protected immutable-file handling; they are not signatures that defeat an attacker
who can replace evidence, expectations and every seal together.

## 7. Schema reuse with rollback safety

Producer memoization already supplies reused `PermissionSchemaSupport` objects; do not add a second
schema-interpretation cache. Store exact support once per **judgement generation and exact GUID**.
An identifier alone is never permission to reuse an existing row.

Choose transaction-local writer memoization for the first candidate, not an unbounded generation-wide
cache of database IDs. Retain at most 64 support descriptors and 64 KiB of small immutable comparison
content; evict/requery on overflow without changing meaning. Large support stays in SQLite and is
compared as a stream. This bound affects work, not what support is saved.

For every supplied support value: validate its exact identifier and all ordered fields/null states;
compute its canonical length/digest while streaming. Find exact GUID matches through the digest bucket,
then compare complete canonical content, including definitions, provenance, null/empty property members
and ambiguity lists, before reuse. A digest match is an accelerator, not proof of equality. Same exact
GUID with different support is a conflict: fail/roll back the object, do not overwrite, union lists or
accept first/last writer wins. Different GUID strings with a hash collision remain separate identities.

Reference equality is not sufficient: `IReadOnlyList` does not make its underlying collection immutable.
The first candidate compares current incoming content even on a memo hit. A future immutable producer
token shortcut would be separate work and is not assumed in the speed claim. On success memoized IDs
may be used only within that transaction. On rollback/disposal discard all pending identities; the next
object/retry verifies the committed database afresh. Previously committed support survives a different
object's rollback. No cache keyed only by GUID or carried to another connection/generation.

## 8. Producing stages and genuine control proof storage

In the scoped flow, the first object pass writes descriptor coverage and observes candidates. Detailed
control assessment follows admission. Classification production belongs to that first pass, whether
or not the target is later admitted. It must not wait for or retain objects until all later products
exist. Empty control-edge results, unreadable descriptors and an unassessed target remain distinct.

Do not populate `permission_entry`/`shared_proof_value` merely to save classifications. First-pass
ungated assessment and later admitted assessment continue using `SharedPermissionStorage`,
`SharedProofStorage`, `ControlEdgeStorage`, Full Control/ownership/requester proof associations and
their existing transactions. These products keep their own evidence requirements and fingerprints.
Do not let a control-proof row become the classification's source of truth, or force proof readers
to decode browsing blocks. Real proof persistence must create/reuse the permission values it actually
needs even when no classification-only shared row exists. Test both stage orders and later-target
reuse. No change to control counts, group-held permission counts, member/route attribution, admission
budgets or the authoritative Tier-0 definition is implied.

Classification `Complete` does not assert later control/path stages Complete. Generation publication
continues requiring each scheduled product's existing status. Cancellation in a later stage must not
publish an earlier successful classification as a completed judgement. Source/resource and generation
binding must remain intact across all these separately timed stages.

## 9. Bounded retrieval contract and real consumers

### 9.1 Operations and result shapes

These are proposed API contracts, not new public members added by this session. Keep their implementation
internal until a real external caller requires exposure; retain the existing reader/service boundaries.
Every operation accepts a cancellation token and a protected selected-generation identity. Shell work
runs through the existing background-read boundary, not a shared connection or new parallel worker pool.

| Operation | Inputs | Result and bound |
|---|---|---|
| `ReadPermissionHeader` | Exact selected generation; resolved object ID | B/O; descriptor scalar states and bounded owner/error references; producer/schema flags; complete saved totals; group count; manifest root; first group/entry cursors. No occurrence payload scan |
| `ReadPermissionGroups` | Object binding; after-first-occurrence cursor; response bounds | Next group headers in first-occurrence order, their complete saved totals/summary references, exact first trustee, `Next`; at most 64, with large values deferred |
| `ReadPermissionEntries` | Object binding; `All` or one exact saved group ID; cursor; response bounds | Ordered entry headers and bounded right/value content; original position and ordinal on every entry; complete selected-population totals, complete-item count in this page and `Next` |
| `ReadPermissionRights` | Exact occurrence binding; next right position; bounds | Ordered saved right records, complete right count, references for large names/reasons, `Next`; no classifier invocation |
| `ReadPermissionValue` | Bound field/value handle; expected next byte/code-unit/item offset; bounds | Verified typed fragments, total length/count, `Next`; for errors, schema collections, application data and oversized strings as well as entry fields |
| `VisitCompletePermissionClassification` | Object binding; bounded consumer; cancellation | Stream descriptor, all occurrences/rights/support/values in order; issue a completion receipt only after counts and semantic digests reconcile. Consumer back-pressure prevents prefetch accumulation |
| Existing `ReadPermissionClassification` whole-object contract | DN resolved to exact O; cancellation | A complete `SavedPermissionClassification` for this format, or explicit refusal/cancellation. If retained for callers that deliberately materialize, it is documented as unbounded in total object size and never used to implement pages |

`EntryHeader` is **not** a `ClassifiedPermissionEntry` with an empty `Rights` or `ApplicationData` in
place of unread content. Page models use explicit `Loaded(value)` / `Deferred(handle, totalLength)`
and collection progress; null/empty are saved values, not loading states. A record header is bounded
because all variable fields can be references. A first page can therefore make progress even when
its first entry has a huge application-data value or thousands of support items. There is no “one
oversized item may exceed the limit” escape clause. Typed handles are explicit, not lazy getters that
perform I/O or retain an entire reader/connection. No eager `ToList`, full JSON document, schema catalogue
reconstruction or whole-object result sits behind these operations.

Locator spans specify first block sequence and record byte offset plus record count/last key; large
collections have child stream locators. Fetch a block only after validating its directory length,
identity and version, verify its full bounded payload hash, then read selected framed records. Sparse
group entries seek via the occurrence index, not by scanning intervening unrelated payload. Charge
the entire fetched block against the visit budget even if only one record is used. At most one decoded
block/dictionary is retained while processing; no generation-wide or object-wide read cache.

A response may contain fewer than 64 items because its byte/block budget is exhausted. It then carries
a strictly advancing cursor; it does not claim end-of-list. If only metadata/header progress fitted,
say so explicitly. Never emit the same completed occurrence twice when resuming within its rights or
values. Right/value operations resume separately by exact parent binding. An end marker is accepted
only when the saved selected-population counts and stream end agree; `Next = null` never means merely
“this query happened to return no rows”. Total entries never mean number of fragments or right rows.

### 9.2 Ordering, grouping, filtering and totals

Default all-entry order is original occurrence position; expose the original ordinal separately.
Groups are exact SID groups within this target, in order of first occurrence, with the first occurrence's
trustee used for the group heading. Within a group preserve captured occurrence order. Do not sort by
name, ACE type, verdict or canonical ACL order. Each entry still retains its own trustee values even
when other entries in the group have different display details. This matches the current permission
section's grouping instead of borrowing the predecessor's normalization.

Version 1 supports **only `All` or one exact group selector**, plus right/value selection by bound key.
No free-text, name sort or risk filter is implemented silently. Unsupported query/order requests are
explicitly refused, never evaluated against loaded rows. Highlighting remains a display toggle, not a
filter and not another classification pass. This narrow index surface is an engineering decision for
the first candidate; adding another user-visible search/filter needs its own accepted behavior.

Totals are saved over the entire object and each complete group, before paging:

- Parsed entry total, classified-right total and group total are separate. Neither expands group
  membership nor counts authorization routes.
- Entry-risk precedence matches the existing `PermissionEntryViewModel.Risk`: an entry with any
  `Dangerous` right counts once as Dangerous; otherwise any `DangerousInCombination` counts once in
  combination; otherwise neither. Do not count the same entry in both headings or replace entry
  counters with right counts.
- Keep independent per-right verdict totals, including `CannotClassify`; that last right count powers
  the current unknown-right notice. A zero risk count does not establish that every right was understood.
- Group `HasDenials` preserves the existing ACE-type display mapping. The rights summary preserves
  the existing rule: distinct exact right names in first-seen order; “Full control” if that existing
  summary rule finds it, otherwise up to the first three names and the exact remaining distinct count.
  This is saved presentation, not a new claim of effective access. Large names continue as values.
- Save `OwnerRightsEntryIsPresent`, descriptor/error totals and applicable notices' underlying facts
  over the complete input. Keep Control/Findings counters' existing separate status; a classification
  total cannot fill them in.

Compute these projections from the full original producer result using bounded passes and, where
distinct-name/group working sets exceed bounded memory, keyed rows inside the same object transaction.
Do not add a forest-wide dictionary. Independently reconcile every projection against the decoded
saved entries before object completion. Hash buckets for grouping/distinct names need full equality
checks. Counts may duplicate facts for fast browsing, but are covered by the publication digest and
validation, not unchecked second answers.

### 9.3 Continuation, validation lifetime and cancellation

An opaque cursor has version, B/O digest, product/object root, query kind, selector/group identity,
ordering version, next occurrence/right/value position, block/record/fragment offset where needed,
and the response-bound profile. Validate all of it against the selected protected file; never trust a
caller-supplied count, SQL fragment or offset. Cursor integrity checking is not authentication. A cursor
from another object, field, source, generation, selector, codec or unsupported ordering refuses; it
does not restart at zero or switch to the latest generation. UI previous-page navigation may retain
a bounded cursor history, not all earlier result pages.

The existing protected-file opening establishes immutable file/seal and generation binding once for
that selected lifetime. Its whole-file verification cost is part of first-use measurements, not hidden
inside a later warm page figure. Publication already validated ordered manifests and all answers.
At page time validate the header, indexed references, requested block hashes and decoded structure;
do not rescan every object or rebuild the whole object's manifest to show each page. With a trusted
protected published file, off-page integrity rests on that opening/publication validation, not a claim
that a first-page read decoded off-page answers. A replaced/changed file revokes the selected lifetime.
The full traversal additionally reconciles all blocks and totals before its final receipt.

Missing product, missing object, incomplete publication, unsupported version, malformed/damaged block,
duplicate record, bad schema reference, binding mismatch and generation change are distinct refusal
reasons internally. None becomes success with an empty list. On a page failure discard that response;
if a later page reveals damage, revoke the object's usable result and totals rather than leave an
apparently complete earlier screen. Missing captured evidence and unsupported *analysis* remain saved
semantic states, separately displayed from unavailable *storage*, unloaded pages and cancellation.

Check cancellation before each query, each row/frame/fragment, block hash/copy increments (at most
8 KiB), before object completion/commit, and before handing a response to the caller. Dispose readers,
commands and transactions on all exits. Commit is the linearization point: cancellation observed before
it rolls back the entire object; cancellation arriving after a successful commit must not double-count
or retry that object, and still prevents final generation publication when the run is cancelled.
A cancelled page yields no successful partial page or empty result. On tab/object/run changes the
linked token and selected-generation check prevent old content being published into the new view.

SQLite work is synchronous in Microsoft.Data.Sqlite, even through its async ADO.NET methods;
[Microsoft's limitation](https://learn.microsoft.com/dotnet/standard/data/sqlite/async) means a token
check is not proof of interruption during a native call. Keep SQL bounded/indexed, retain existing
busy/command timeout behavior and measure the longest uninterruptible query/commit. Do not change
journaling/cache/durability to claim cancellation. Where blob streaming is used, follow
[the documented rowid requirement](https://learn.microsoft.com/dotnet/standard/data/sqlite/blob-io):
otherwise `GetStream` can materialize the whole value. Here each physical BLOB is bounded anyway.
No promised millisecond cancellation bound until deterministic in-operation tests and timings support it.

A full traversal is streaming verification, not a successful whole-object result until its completion
receipt. A consumer that stops early must mark it abandoned; it cannot publish final totals/exports as
fully verified. A retained whole-object materializer either fills the original complete record shape
or throws/refuses; it may not return its accumulated prefix or replace a large value with empty data.
There is no legacy-format reader involved: this distinction concerns two APIs for one new format.

### 9.4 Actual caller changes required before bounded browsing can be claimed

Paths below are relative to `next/`. They identify integration work, not edits authorized now.

| Caller | Required behavior in an approved implementation |
|---|---|
| `src/SecureAD.Judgement/JudgementReader.PermissionClassifications.cs` | Expose bounded operations and complete traversal; keep any explicitly retained whole-object method honest. Never implement a page by calling the existing whole-object method |
| `src/SecureAD.Shell/Services/OpenedRunResults.cs` | Preserve protected file lifetime, `Current` check before/after read, linked stopping token and explicit unavailable product handling for each page/handle |
| `Services/IAssetSource.cs`, `AssetReadRequest.cs`, `BundleAssetSource.cs` | Carry bounded requests/results through the captured selected-run request. Existing background dispatch owns connections; do not introduce a shared connection or fire-and-forget reads |
| `ViewModels/AssetsViewModel.Object.cs`, permissions branch of `ReadSectionAsync` | On successful completed classification, read header → first group page → first selected group's entry page. **Remove the preceding whole evidence `ReadPermissions` from this branch**; otherwise the supposedly paged screen still loads every raw entry |
| `ViewModels/ObjectSections.cs`: `PermissionsSectionViewModel`, `PrincipalGroupViewModel`, entry/right models | Consume page-specific models, saved full totals/summaries and deferred value states. Replace `GroupBy`/`ToDictionary`/`SelectMany` over all entries and page-derived counters; no append-until-entire-object collection |
| `ViewModels/ObjectViewModel.cs` | Extend selected-section suspend/cancel/revision handling to page/value operations, as it already does for other delayed sections |
| Overview/Evidence branches and raw-only permission fallback | They currently use whole captured permissions. They are **not** made bounded by this classification candidate and must not be included in a bounded-browsing claim. Keep explicit classification refusal; no saved-page failure may silently switch to raw-only success or restart analysis |
| `tests/.../Judgement/SavedPermissionClassificationTests.cs`, `tests/.../Shell/OpenedRunResultsTests.PermissionClassifications.cs` | Retain historical tests/evidence; add focused contract and actual-caller checks after approval. Current whole-object tests alone cannot prove boundedness |
| `BenchmarkSuite4/P251StorageComparisonBenchmarks.cs` and retained comparison adapters | Existing whole-object calls are historical. Do not edit them; a separately approved adapter must measure explicit whole/page operations and consume all blocks for equality |

No production rule/control evaluator consumes this saved classification reader in the identified
call chain; later proof production must remain independent (§8). Merely adding APIs while leaving
the eager Shell path unchanged is an infrastructure result, not completed bounded browsing.

### 9.5 Visible behavior proposed for later explicit approval

Recommendation: keep the existing two-pane principal/entry grouping and highlight toggle. Window
both principal and entry lists, replacing the previous window rather than retaining every page.
Preserve selected principal identity; first opening selects the first saved principal. Keep object-wide
counters separate from the selected principal's totals. Proposed new progress text is
“Showing {first}–{last} of {total} principals” and
“Showing {first}–{last} of {total} entries for this principal”, with “Previous” and “Next” actions.
An oversized field is explicitly “Saved value not fully loaded” with “Read more”; it is not shown as
blank, shortened without notice or evidence-incomplete. Empty collections use the existing descriptor
state explanations, not a fabricated 1–0 range. Large schema/error lists use the same explicit progress.

Practical cost: the administrator takes another action to see later data; benefit: opening one part
does not require every entry or large value to be in memory. These wording/layout/navigation details
are **proposals requiring owner approval**, including the bounded previous-page history and long-value
presentation. Until approved, a storage/API experiment may measure paging headlessly but must leave
the shipping UI unchanged and must not claim the user-facing workflow is fixed.

## 10. Bounded implementation and correctness verification proposal

**None of this section is execution approval.** Recommended first approval is B's storage/API and
offline correctness work only, without changing production format selection or UI. Retain an isolated
candidate source/build location and leave active format 41 untouched while evaluating the design.
If adoption is later approved, replace the superseded production path; do not retain parallel old/new
production writers, dormant format switches, fallback readers or permanent transition scaffolding.
Preserve historical source/tests/artifacts separately.

The bounded B implementation scope is the classification schema/writer/reader, a source-binding
adapter carrying existing Evidence identities, saved browsing projections, and service-level bounded
read contracts. Do not change evidence parsing, classification/security rules, admission, genuine
proof schemas or SQLite settings. The actual Shell view-model replacement in §9.4 needs the separate
§9.5 presentation approval; without it, test service/API callers offline and identify that limitation.
C is a later, separately approved codec substitution only, not permission to widen B's scope.

Use synthetic/offline fixtures plus the already supplied sealed copied input. No new preservation
copies of original inputs merely to begin work; create only isolated output/build/test artifacts and
necessary approved working copies. Verify inputs read-only against their recorded seals/identities.
Never regenerate original results. No tests matching this markdown to code: tests check saved values,
actual caller behavior, retained evidence and relevant external authority.

### New checks that must genuinely fail under the corresponding defect

| Check family | Required examples and deliberate defect |
|---|---|
| Every field | Typed original versus decoded comparison, including null/empty optional strings/collections, unknown raw ACE text and mask bits, GUID-presence flags independent of nullable GUIDs, callback bytes, trustee meaning, owner/errors, scope, every per-right verdict/reason/name and all schema provenance. Remove/change one field at a time and show its focused check fails |
| Occurrence identity | Identical ACE values at distinct ordinals; original noncanonical order; gaps from incomplete parsing; same builtin SID on distinct targets/resources. Drop, reorder, normalize or misbind an occurrence; prove detection without another malformed field causing the failure |
| Sizes and continuation | Zero, one, exactly-bound and one-past-bound records/blocks/dictionaries/pages; one entry spanning many blocks; one huge string, reason, schema definition/member list and application-data value; valid surrogate pair at a split and lone surrogate; dictionary-full fallback. Remove final fragment, overlap offsets, reuse wrong parent or allocate from a claimed huge length |
| Independent completeness | Remove final block and repair manifest; remove object and repair product manifest; remove right and repair local count; corrupt/omit aggregate and projection values. Leave independent producer/source expectations intact and prove publication refuses |
| Damage/unsupported versions | Wrong byte length/hash, duplicate/missing locator, trailing bytes, unknown required tag/codec/projection version, wrong schema GUID/content, entry/right count discrepancy. Verify selected page refuses and no success-with-empty fallback occurs |
| Binding | Exchange blocks/cursors/schema refs between same-DN objects in different evidence/generations, different target scopes, or right/value positions; change explicit-null derivation binding to an ID. Every read must reject wrong B/O/position without analytical replay |
| Schema conflicts/rollback | Same exact GUID with different definition, source, ordering, members-null versus empty, ambiguity list or content despite reused object identity; forced hash collision; failed new schema insert followed by retry; same GUID already committed for an earlier object. A GUID-only or reference-only cache must fail these tests |
| Transaction/publication | Deterministically cancel during fragment writing, validation, before commit and after committed object/before generation publish; simulate write failure; retry without stale schema IDs or doubled totals. No partial object/product becomes visible |
| Truly bounded callers | Observe actual rows/blocks/bytes/allocations retained by first/group/entry/value calls; a large object with an enormous first field must return a header/reference within bounds. A defect calling the whole-object reader or raw evidence ACL before a page must be detected. Old pages are released, not accumulated |
| Correct totals and presentation source | Dangerous entry also carrying combination/unknown rights, group spanning pages, unknown right only on last page, owner qualifier only on last page, summary's fourth distinct right after page boundary. Saved complete totals/summaries remain correct when only page one is loaded |
| Later stages | Scoped descriptor/candidate pass then admitted control assessment; ungated immediate control assessment; genuine shared proof rows reused by later work. Classification no longer populates proof-only storage, yet all control/ownership/member/path answers and counts remain identical |
| Cancellation/read lifetimes | Cancel while a right/string/schema/application continuation is actually in progress, while a database operation is outstanding where reproducible, and while replacing selected run/tab/object. No late successful page, leaked lease/connection or swallowed cancellation |

For new behavior tests only, isolate short TEMP/TMP **before any test-assembly loading, including
discovery**. Work one check at a time; explicitly rebuild each deliberate defect, run the focused
check, restore and explicitly rebuild again. Retain failed attempts, mutation/build identities and
the final restoration evidence. Then run relevant existing regression suites and coverage according
to repository practice; no frozen hash/fixture edits. Do not restart completed historical mutation
campaigns or claim their results automatically cover the new candidate.

P-254 (orphan gate scans retained `next/.t` sources) and P-255 (SQLite Error 14 in the offline journey,
not isolated to a cause) remain open. Do not remove/move historical sources to pass the gate, silently
exclude the failing tests, or call the suite clean on a shorter-path retry. Record these qualifications;
any repair is separate bounded work. Correctness/adoption claims must state which checks remain blocked.

## 11. Measurement design — two finite, separately approved contrasts

### 11.1 What these experiments do not diagnose

The 133.74-second returned lab run and 229.85-second cache-trial outlier remain unexplained. The
fine-grained timing ledger did not establish instrumentation overhead; nested timings are not added
to their parents. Storage work is a candidate improvement, not a diagnosis of either execution.
Neither changing machines/runtimes nor improving a fresh local run proves the cause of an old one.

P-249 format-43 and P-200 comparisons are completed historical campaigns. Their outputs, binaries,
sources, failed attempts and outliers remain retained. Historical timings are not fresh controls.
Use format 43 only to inspect its logical source design; do not rerun it, pre-P-248 comparisons or
prior mutation campaigns under this proposal. More cache memory was not automatically a failure,
and a larger file/memory cost must be judged in absolute practical terms rather than relabelled loss.

### 11.2 Fixed scope and provenance before a timed run

For each approved contrast use a separate copy of the retained full-answer comparison adapter;
record its source hash, output assembly hashes, build configuration, actual loaded library/runtime
paths/versions, architecture, host/processor and source patch/hash including uncommitted candidate
changes. Record input paths/seals/hashes, Evidence and Derivation identities, evaluation date,
17-rule configuration and disabled requester/discovery policy. Build provenance belongs to each
individual timing, not merely to the branch name. Preserve original/frozen runners unchanged.

Keep the supplied 2026-09-19 sealed copied input/derivation, output placement, runtime, connection
settings, cache sizes, journal/durability, page size, temporary storage, transaction boundaries and
admission policy identical. Record observed settings read-only in an untimed preflight. Do not tune
P-200 settings at the same time. If inputs/configuration/build identity diverge, stop the comparison
instead of treating the run as matched. No added fine-grained rule/storage timers inside judging.

Select a deterministic set of **at most eight** readback objects in untimed preparation from the
retained answers: empty/missing/unreadable or incomplete examples where present, median nonempty by
entry count, largest entry count, largest right count, largest saved variable value and richest schema
support; fill ties by source object ID, deduplicate and report absent categories. Synthetic oversized
fixtures cover categories absent from the lab but are reported separately, never as lab captures.
Persist the selected IDs and selection rules in comparison artifacts before changing the candidate.
Equality verification still covers **all objects, entries, rights and values**, not only these eight.

### 11.3 Execution allowance to request, not execution performed

| Contrast | Fresh judging sequence | Meaning and stop boundary |
|---|---|---|
| I: 41 versus B | A / B / B / A, exactly four fresh judging processes | Run current-format-41 A before introducing the isolated B optimization. Compare complete storage/API package to production; do not attribute the entire delta solely to chunk size |
| II: B versus C | B / C / C / B, exactly four fresh judging processes under a new approval | Only after B correctness/review. Run a fresh frozen-B control before introducing C. Hold logical record/page partition policy, projection/index/schema-reuse behavior and validation work fixed; only encoding/dictionary and consequent encoded lengths differ |

No automatic fifth run, extra block-size/cache sweep, host change, reprofile or combined “best of”
result. Keep failed attempts/outliers and explain missing pairs. If a bound or defect must change,
stop and propose a new bounded contrast rather than quietly continuing the same experiment.
Implementation approval alone does not authorize these processes or measurement-harness changes.

After each output, allow at most **three fresh reader processes**, each visiting the selected objects
once: (1) opening + paged browsing/continuations, (2) complete streaming consumption, (3) deliberate
whole-object materialization. Thus at most twelve reader processes per contrast, with no hidden
iteration/warm-up campaign. The format-41 reader lacks true paging/streaming APIs: mark those operations
not available, and measure its actual eager whole-object cost in process (3). Do not implement a fake
41 page by loading all data and charging only slicing time. A UI's baseline first visible result can
be compared to that eager cost, explicitly labelled as different read scope.

Record these intervals separately:

- **First use:** protected Evidence/Derivation/Judgement opening and seal checks. Call it process-first,
  not disk-cold unless OS cache state was actually controlled; record filesystem cache uncertainty.
- **First useful permission view:** header, first group window, first selected group's entry/right
  content and necessary bounded values, plus separate end-to-end time including opening. Declare all
  deferred fields; a header with no rights loaded is not equivalent to a fully visible first page.
- **Subsequent pages:** each group/entry/right/value continuation latency and bytes/blocks; include
  later, last and oversized-field pages. Report the distribution/max and selected-object identities,
  not only a pooled average. Exhaust all relevant cursors in this workload but do not retain all pages.
- **Complete object:** consume all descriptor/entry/right/schema/value blocks with final reconciliation,
  separately from explicitly building the complete object graph. Compare complete materialization
  with 41 materialization; report streaming gains as streaming gains. Reading page one is never a
  whole-object speedup.

All comparison code creating fresh results works on isolated outputs from copied sealed evidence;
it does not overwrite retained results. Outside timed reading intervals, compare every answer with
the corresponding fresh control across all blocks, including all §3 fields, counts, order and explicit
states, plus the retained adapter's 28 common result categories and genuine proof products. A direct
typed comparison, not only the candidate's own hashes, supplies an independent check. Newly generated
generation IDs necessarily differ between runs: first verify each output's exact bindings to its own
published IDs, then compare with an explicit paired-generation mapping. Do not erase provenance
fields wholesale to make the comparison pass.

### 11.4 Metrics and interpretation

Include whole judging wall/CPU time, final database size, allocated bytes, managed-heap and process
peak memory with baseline/absolute values, GC collection counts **and actual GC pause duration**,
first/page/full read latencies and allocation/retention, bytes/blocks visited, and cancellation latency
with rollback integrity. Write-time full validation and saved summaries are part of whole judging.
Use runtime cumulative GC pause duration sampled outside the interval where supported and verified;
do not call Gen2 count or percent time in GC a measured pause duration. If actual pause duration
requires new tracing, request it separately and report the metric unavailable rather than assume no
pauses or mix traced candidate runs with untraced controls. Any new adapter instrumentation itself
must be identified; do not claim its overhead was established by the old ledger.

Forced cancellation/rollback checks are separate untimed verification runs at defined in-progress
boundaries, not a token timer that fires after the work has already finished. Their bounded case list
is §10, not a new open-ended profiling campaign. Measure elapsed cancellation response in those runs
and note native-call/commit limits without changing production timeouts or budgets.

Report both adjacent matched pairs and all individual measurements; averages/medians alone cannot
establish repeatability. Correctness, binding, explicit completeness and rollback are hard gates.
A speed claim needs the complete measured workload, not fewer writes or a smaller file. For resource
trade-offs report absolute and relative costs: an extra **35 MB** or a **46 ms** read is not automatically
unacceptable, nor automatically acceptable. Explain whether it affects opening, each click, a rare
full object or whole-run memory, and ask the owner to accept that concrete cost before adoption.
No acceptance threshold is invented from the lab.

### 11.5 Customer-scale limits of the evidence

The governing forest is roughly **347,000 objects, 5.9 million ACEs, nine domains**, deep DNs averaging
about 97 characters, historically about 9 million control edges and 1.3 million delegations. The
roughly 8,383-object lab (8,407 objects in the retained comparison's input) cannot establish its peak
object/value sizes, schema diversity, cross-domain trustee distributions, memory headroom or budgets.

This draft caps buffers, not total security processing. Thin occurrence indexes, manifests and schema
sharing must be assessed against that forest shape before a production recommendation. A later
separately approved offline scale fixture should cover object-size skew and long/unique values as
well as totals/domains, documenting unknown real distributions; a multiplied small ACL fixture is not
representative evidence. No such fixture/harness/run, production limit or discovery budget is approved
here. Do not extrapolate lab timings linearly or change production defaults on their strength.

## 12. Decision and approval boundary

Engineering recommendation: review and implement **B before C**, retaining SQLite and per-object
atomicity, strict losslessness, bounded value continuations, thin group/occurrence indexes, saved
complete projections and transaction-local conflict-checked schema reuse. These are design decisions
proposed here, not questions asking the owner to select libraries or encodings.

Practical costs to evaluate: more metadata/index rows and integrity work; a full validation pass at
write time; extra navigation for later pages; remaining one-object producer memory; and possible
UTF-16 binary size cost when strings do not repeat. Benefits are removal of whole-object storage
copies, independently addressable saved answers and explicit bounded browsing—not an established
speedup. No concrete latency/memory trade-off is accepted before new evidence exists.

Remaining owner-only approvals are:

1. Whether to authorize the bounded B implementation/offline-verification scope in §10 next. No
   unresolved security semantics require the owner to restate accepted requirements.
2. Whether to accept the concrete paging/large-value behavior and wording in §9.5 for a later Shell
   integration. Keeping today's visible behavior while doing only a storage/API trial is an explicit
   alternative; it cannot be presented as completed bounded browsing.
3. Whether to authorize contrast I's finite adapter/measurement scope, then separately C/contrast II
   if B warrants it. Completed historical campaigns remain closed.
4. Whether to adopt a candidate after the measured customer-facing speed/memory/read/cancellation
   trade-offs and verification qualifications are reported. Customer-scale acceptance and any later
   production budget/default decision are separate and still outstanding.

This draft changes no UI, rule, active format, analysis stage or budget. P-200's outlier and P-254/P-255
are not resolved by writing it. No builds, tests, measurements or original-result regeneration are
needed merely to review this contract.
