# S-1 — Security descriptor parsing and ACE canonicalisation

**Type:** slice
**Reviewed at commit:** `8bf0090a`
**Size:** 10 files, 780 lines
**Date:** 2026-08-10

## What it does

Turns the raw bytes Active Directory stores in `nTSecurityDescriptor` into a list of permissions
that can be compared between two runs. Without it the product could read a directory but could not
say what changed in it: every permission would be an opaque blob, and two descriptors that grant
identical access but were written differently would look like a change.

The comparison is the product. A customer's question is "what has moved since last month", and the
answer is only trustworthy if "no change" and "written differently" are told apart. That is the
whole job of this component.

## Shape

Parsing and canonicalisation are two passes, deliberately separate. The first is about the wire
format and knows nothing about comparison; the second is about comparison and knows nothing about
bytes.

| Type | Owns |
|---|---|
| `SecurityDescriptorParser` | Bytes to typed values: owner, group, DACL state, ACEs. The only entry points are `Parse` and `ParseBase64` |
| `ParsedSecurityDescriptor`, `ParsedAce` | What the bytes said, with no interpretation |
| `DaclState` | Whether the DACL is `Present`, `Null`, `Empty`, or `Unreadable` |
| `DaclCompleteness` | Whether the DACL yielded every entry its header declared: `Complete`, `Incomplete`, `Unknown` |
| `AceType` | The ACE type byte, named |
| `GenericRightsExpander` | `GENERIC_*` bits to the AD-specific rights they stand for |
| `AceNormalizer` | Expand, order, hash, deduplicate |
| `CanonicalAce`, `AceNormalizationResult` | The comparable form, and what came with it |
| `AceCanonicalization` | The version stamped onto each canonical ACE |
| `PermissionWordingWriter` | An entry said in words an administrator reads: `Full control`, `Write member`, `Modify owner`. Names GUIDs by the right beside them, because one GUID can name two things |
| `PermissionWording` | Those words, and whether every bit of the mask had one |
| `PermissionRight` | One of those words with the mask bits that produced it, so a verdict can attach to a right rather than to the whole entry, and whether this build had a word for it at all |
| `PermissionScopeWriter` | How far an entry reaches, in the ACL editor's own words: `This object only`, `This object and all descendant objects`, `Descendant user objects`. Verified against Microsoft Learn 2026-08-18, including that the directory service treats every object as a container - so `CONTAINER_INHERIT_ACE` is the flag that carries, and the file system's folder/file split does not divide the directory |
| `PermissionScope` | Those words, and whether the entry was set on the object or inherited |
| `Sid` | A security identifier between its two forms - the bytes the directory stores and the `S-1-5-…` text a bundle records. One implementation, because a second would drift and a drifted SID parser puts the wrong name against a permission |

## Dependencies

- **Depends on:** nothing. `BinaryPrimitives`, `SHA256` and `Text` are the whole of it, which is why
  it targets plain `net8.0` and needs no directory, no database and no Windows.
- **Depended on by:** nothing yet. In the previous implementation it had five consumers and they
  were exactly the five that handle raw security descriptors — the stored-ACE writer, the SYSVOL
  ACE writer, the rule evaluator, and live ACL reads. The rebuild's equivalents are not written.
- **Layering violations:** none.

## The three behaviours that matter

Each is a way ACL tooling commonly goes wrong, and each has its own tests.

### A null DACL is not an empty DACL

Both carry zero ACEs and they mean opposite things. A **null** DACL — no DACL at all — grants
everyone full control. An **empty** DACL — a DACL that is present and lists nothing — grants nobody
anything. Reporting "0 permissions" for both is the difference between "wide open" and "locked
down".

`DaclState` exists so the two cannot collapse into a count, and it distinguishes a third case:
`Present`, meaning there are ACEs to read. `AceNormalizer` carries the state through untouched, so
a caller holding an empty ACE list can still say which of the two it is holding.

> **Corrected 2026-08-13 in [`S-21`](../history/S-21-the-security-descriptor-parser.md), as `F-S21-1`.** There
> are **three** ways to hold an empty ACE list, not two, and `DaclState` distinguishes only two of
> them. A DACL whose header declares entries that then fail to parse also yields `Empty` — the same
> value as a DACL that genuinely lists nothing. So the sentence above is true of a well-formed
> descriptor and false of a damaged one, and it is the damaged one that matters: *locked down* is
> the answer the product gives for an object it could not read. The parse errors are recorded
> separately, but nothing obliges a caller to look at them, which is the arrangement this rebuild
> exists to stop. Whether `DaclState` gains an `Unreadable` member is an open owner question.
>
> **Answered the same day.** It does, per
> [`0037`](../decisions/0037-an-unreadable-dacl-says-so.md) — and there turned out to be a *fourth*
> case as well, a DACL that yielded some of what it declared. That one stays `Present`, because it
> is, and the shortfall is carried by `DaclCompleteness` beside it.

### `GENERIC_ALL` and its expansion are the same permission

A right can be written as the single `GENERIC_ALL` bit or as the specific-rights mask it stands
for. The directory treats them identically. Compared unexpanded they differ, so a run would report
a permission change on an object nobody touched.

`GenericRightsExpander` rewrites the four generic bits into their AD DS equivalents per
MS-ADTS §5.1.3.2 and clears the generic bit. Expansion happens **before** hashing, which is what
makes the two spellings hash to the same value and deduplicate to one ACE rather than two.

### Deny sorts before allow, and disorder is not an error

The directory evaluates deny ACEs before allow ACEs, so the canonical order is: explicit deny,
explicit allow, inherited deny, inherited allow. Within a category, order is by trustee SID, then
access mask, then the two GUIDs, so the sort is total and no tie is left to insertion order.

A DACL that arrives out of that order is common and is not damage. It must normalise to the same
canonical form as one that arrives ordered, or two identical sets of permissions would compare as
different because of the order they were written in.

> **Qualified 2026-08-13 in [`S-21`](../history/S-21-the-security-descriptor-parser.md), as `F-S21-2`.** Right
> about the hash, incomplete about the security. Disorder is not damage, but it is also not
> *neutral*: Windows evaluates a DACL in **stored** order and stops at the first match, so a
> non-canonical DACL in which an allow precedes a deny grants the access that the canonical form
> would deny. That is a shape an attacker leaves deliberately, because tooling which assumes
> canonical order reports the deny while the system honours the allow. The sort is correct and
> necessary for hashing; what is missing is that it is lossy and nothing records what was lost.
> `CanonicalAce` keeps no original ordinal, so after normalisation the product can neither detect a
> non-canonical DACL nor evaluate one the way Windows will. Open owner question.
>
> **Answered the same day**, per
> [`0038`](../decisions/0038-a-descriptor-records-whether-its-dacl-was-canonical.md): the order is
> judged during the parse and recorded as one boolean per descriptor. `CanonicalAce` still keeps no
> ordinal, deliberately — the bundle already stores the descriptor's raw bytes, so exact order is
> recoverable by re-parsing and a per-entry copy would duplicate evidence already held.

## How a hash is built

Each canonical ACE carries a SHA-256 of ten fields, pipe-delimited: object GUID, trustee SID,
expanded access mask, object-type GUID, inherited-object-type GUID, whether it was inherited, the
inheritance flags, the propagation flags, the ACE type, and the application data as lowercase hex.
The same descriptor on the same object always produces the same hash, which is what makes
deduplication and cross-run comparison possible.

The ninth field, the ACE type, was added in canonicalisation version 2. Version 1 omitted it, so
two ACEs differing only by type hashed identically and one was silently discarded. See F-S1-2.

The tenth field, the application data, was added in canonicalisation version 3. Versions 1 and 2
omitted it, so two conditional ACEs granting the same rights under *different conditions* hashed
identically and one was silently discarded, as did a conditional entry beside an otherwise
identical unconditional one. It is empty for every non-callback ACE type. See `F-S58-11` in
[`S-58`](S-58-the-fix-brief.md).

`AceCanonicalization.Version` records which version of this pipeline produced a given ACE. It is
now `3`. Changing it invalidates every stored hash, so it changes only as a deliberate decision.

## Damage is reported, not thrown

A descriptor read from a live directory can be malformed, and one bad object must not fail a whole
capture. Every failure path returns a result carrying a message in `Errors` — a short descriptor, a
DACL offset past the end, a truncated ACE, an unparseable SID, invalid base64. Parse errors are
carried forward into the normalisation result rather than dropped.

## Verified-safe

- **The golden hashes are computed from the specification, not from the code** — every constant in
  `GoldenAceHashTests` was produced by a separate implementation of the written recipe, which was
  each time first shown to reproduce all eight known values of the preceding version from that
  version's recipe before being used to produce the new one's. That was done for version 2 and
  again for version 3. The assertions therefore check the implementation against the specification
  rather than against itself.
- **Ordering is total** — `AceNormalizer.CanonicalAceComparer` falls through category, trustee SID,
  access mask, both GUIDs and finally ACE type, so no two distinct ACEs tie. The canonical form
  does not depend on the order the ACEs arrived in, which
  `WhenTheSameAcesArriveInEitherOrder_ThenTheCanonicalFormIsIdentical` asserts directly.
- **Generic expansion clears its own bit** — asserted directly rather than inferred, since a
  generic bit left set would survive into a stored mask.
- **Nothing here reaches a directory, a disk or a clock** — the whole component is a pure function
  of its input.

**History.** This section claimed *"ordering is total"* earlier on 2026-08-10 when it was not:
`AceType` was absent from the comparer, so two ACEs differing only by type tied on every key. The
claim was withdrawn the same day and is restored above only now that it is true and has a test
behind it. The episode is recorded because the failure mode matters more than the entry — the point
of this section is that nobody re-checks what is in it, so a claim reasoned about rather than run
is more expensive here than anywhere else in the document.

## Findings

### F-S1-1 — The canonicalisation version moved projects

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** `next/src/SecureAD.Kernel/Security/AceCanonicalization.cs`, previously
  `src/SecureAD.Core/Evidence/SchemaConstants.cs:17`
- **What happens to a user:** nothing. The value is unchanged at `1`, and every golden hash
  reproduces.
- **Why it is this way:** the constant lived on the bundle's `SchemaConstants` alongside the
  storage schema version. The Kernel is the lowest layer and cannot reference the bundle, and the
  number describes this component's own output rather than the storage it is written to.
- **Options:** leave it here, which is what was done; or reintroduce a shared constants type, which
  would recreate the coupling the layering exists to prevent.
- **Test cover:** `GoldenAceHashTests.EveryGoldenAceRecordsCanonicalizationVersionOne` pins the
  value at `1` and asserts the code and the constant agree. *The test carries the version in its
  name, so it has been renamed twice since \u2014 to `...VersionTwo` for F-S1-2 and to `...VersionThree`
  for `F-S58-11`. The assertion is unchanged.*
- **Status:** REPAIRED, 2026-08-10 — the move is the repair; recorded so the divergence from the
  old layout is not read later as an accident.

### F-S1-2 — The ACE type is not part of the hash, so canonicalisation is not canonical

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** `next/src/SecureAD.Kernel/Security/AceNormalizer.cs` — `ComputeAceHash` hashes eight
  fields and `AceType` is not among them; `CanonicalAceComparer` compares category, trustee SID,
  access mask and the two GUIDs, and `AceType` is not among those either. Both were confirmed by
  probe tests on 2026-08-10, described under *Test cover* below.
- **What happens to a user:** two distinct ACEs are recorded as one, and which one survives depends
  on the order the bytes arrived in. Two collisions were demonstrated:
  1. A deny and an allow with the same trustee, mask, GUIDs and inheritance normalise to **one**
     ACE. The deny sorts first, so the allow is dropped.
  2. A plain `ACCESS_ALLOWED` ACE and an `ACCESS_ALLOWED_OBJECT` ACE carrying neither GUID also
     normalise to **one** ACE. Every hashed field is identical. This is the likelier of the two:
     the object-ACE flags field documents `0` as meaning neither GUID is present, so such an ACE
     is legal and indistinguishable from a plain one in every field this pipeline looks at.

  In case 2 the two ACEs tie on every comparison key, and `List<T>.Sort` is not stable, so **the
  surviving ACE's type depends on wire order**. Two objects with identical permissions, written in
  a different order, produce different stored records. That is the property canonicalisation exists
  to provide, and it does not hold.

  Downstream, the audit misreports the DACL; a compare between runs reports an ACE added or removed
  when the directory did not change; and any rule counting ACEs or asking who holds a right reads a
  DACL that lost a row.
- **Why it is this way:** carried unchanged from the previous implementation, which had the same
  defect. That implementation keyed `fact_ace` on `PRIMARY KEY (object_guid, ace_hash)`
  (`src/SecureAD.Infrastructure/Storage/DerivedStoreSchema.cs:81`), so the hash was already being
  used as an ACE's identity by storage while never covering the whole ACE.
- **What the format says:** Microsoft's
  [Access control entries](https://learn.microsoft.com/windows/win32/secauthz/access-control-entries)
  states that every ACE carries four things — the trustee SID, the access mask, **a flag that
  indicates the type of ACE**, and the inheritance flags. This pipeline hashes three of the four.
  [Access control lists](https://learn.microsoft.com/windows/win32/secauthz/access-control-lists)
  describes an ACL as a list of ACEs, with no uniqueness constraint, so nothing prevents a
  directory handing us a colliding pair.
- **Options:**
  1. **Add `AceType` to the hash and as a final tiebreak in the comparer, and move
     `AceCanonicalization.Version` to 2.** Fixes both the loss and the order-dependence. Costs the
     regeneration of every golden constant, which spends the "byte-identical to the old
     implementation" property. Recommended, and cheapest now: nothing is stored and no consumer
     depends on the current values.
  2. Key deduplication on `(AceType, AceHash)` and leave the hash alone. Preserves every golden
     constant and stops the row loss, but the comparer still returns 0 for a genuine tie, so the
     ordering stays arbitrary. Rejected on 2026-08-10 for that reason.
  3. Leave it and require every consumer to treat the hash as a within-category identity. Rejected:
     the old schema already did not, and gate 2 exists because this codebase has a history of the
     same question being answered differently in different places.
- **Test cover:** four permanent tests in `AceNormalizerTests` — both collisions survive as two
  ACEs, the canonical form is identical whichever order the ACEs arrive in, and a differing ACE
  type produces a differing hash. Each was mutation-tested in both directions: removing `AceType`
  from the hash fails all three of the first set, and removing the comparer tiebreak flips the
  order and fails the fourth.
- **Unverified:** how often real Active Directory emits an object ACE with no GUIDs. The format
  permits it; whether it occurs in the field is an empirical question, settled by scanning existing
  captures for `ace_type IN (5,6)` with both GUID columns null. This bore on urgency, not on
  whether the fix was right — collision 1 stood on its own — and it no longer blocks anything.

  **Verified 2026-08-19: it occurs. 12 of 12,600 entries**, measured on lab bundle
  `ad.lab-20260819-232425` — object ACEs carrying neither GUID, against 8,585 `AccessAllowedObject`
  and 1 `AccessDeniedObject` in total. So collision 2 is a case this forest actually contains and
  not only one the format allows. It is a default lab forest, which makes 12 the *floor* rather than
  a typical rate.
- **Status:** REPAIRED, 2026-08-10. `AceType` is the ninth hash field and the final ordering
  tiebreak, and `AceCanonicalization.Version` is `2`. The eight golden constants were recomputed
  from the written recipe by a calculator first validated against the version 1 values, so they
  were never read out of the code they now check.

  **Superseded in one detail, 2026-08-19.** The version is now `3` and the eight constants have
  moved again, because `F-S58-11` added application data as a tenth field by the same method. What
  this entry records about `AceType` is unchanged.

  The entry originally filed the same day said the defect was harmless as the code stood. That was
  wrong: it was reasoned from reading the code rather than running it, and a ten-minute probe
  contradicted it. Recorded because the mistake is more instructive than the repair.

## Open questions for the owner

- **Do object ACEs with no GUIDs occur in the field?** No longer blocking — the fix handles them
  either way — but worth knowing, because it determines whether any capture taken with version 1
  of this pipeline lost rows. Answerable by scanning existing captures for `ace_type IN (5,6)` with
  both GUID columns null.
- **Should the bundle schema key on `ace_hash` alone?** The previous implementation used
  `PRIMARY KEY (object_guid, ace_hash)`. That is now sound, because the hash covers the whole ACE.
  It is recorded here so the choice is made deliberately when the Evidence project defines its
  schema, rather than inherited.

**Settled on 2026-08-10.** Whether to recompute the golden constants. They were inherited from the
old implementation and proved the port changed nothing, which is recorded in commit `9ce95cf9`.
Fixing F-S1-2 necessarily moved them. The decision was to recompute rather than abandon them, and
to recompute from the written recipe rather than from the code's own output — so they went on
doing the job that never ends, guarding the pipeline against accidental change, while the job that
was finished stayed finished.

## Not reviewed

- **`PermissionClassifier`** — it shares the old folder and is a different component, K16, marked
  Rebuild because five places in the old product answer "is this right dangerous" and disagree.
  Nothing here classifies a right; this component reports what a right *is*.
- **SACL parsing** — `AceType` names the audit ACE types and `ParseAcl` would read a SACL, but only
  the DACL is parsed and normalised. The product audits access, not auditing policy.
- **Performance** — the parser and hasher were not measured. The old implementation's only
  performance record covers escalation-path traversal, group expansion and the control-edges query,
  none of which is this.
