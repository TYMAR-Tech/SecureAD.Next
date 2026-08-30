# Wave 1 — Kernel semantic safety

**Branch:** `correction/wave-1-kernel-semantic-safety`  
**Starting acceptance baseline:** `552e64e`  
**Status:** Implemented and validated; six unrelated Wave 0 failures remain

## Corrections

### ACL declared byte boundary (K-01)

`SecurityDescriptorParser` now reads and validates `AclSize`, refuses values smaller than the ACL
header or larger than the available descriptor tail, and parses ACEs only inside the declared ACL
span. Bytes after that boundary cannot become permissions.

Microsoft's ACL structure defines `AclSize` as the size in bytes of the complete ACL, including its
header, ACEs and potential unused memory. `AceCount` remains a separate completeness input.

### Stored generic-right semantics (K-02)

`DangerousPermissionClassifier` no longer expands the raw stored mask before deciding what an ACE
actually grants. A stored `GENERIC_ALL` or `GENERIC_WRITE` bit remains marked `Dangerous` as a
conservative attention signal, but its reason explicitly says:

- access-check does not map generic bits already stored in an ACE;
- mapped directory rights are not established as granted; and
- the entry remains dangerous potential requiring investigation/correction.

This preserves the earlier accepted conservative severity decision without manufacturing a grant.
`GenericRightsExpander` remains available for comparison/canonicalization. Persisting only expanded
canonical masks remains provenance/storage work for a later schema wave; rules must not consume those
masks as effective grants.

### Malformed dSHeuristics (K-03)

`HeuristicReadOutcome.Malformed` now distinguishes an invalid stated character from a short/absent
string that takes the documented default. An invalid character 16 excludes no groups conservatively,
keeps the raw character, and reports `IsComplete == false`.

The corrected AdminSDHolder model must persist this state rather than converting it to an empty mask.

### lastLogonTimestamp sentinel (K-06)

`long.MaxValue` is no longer treated as “No logon has been recorded” for `lastLogonTimestamp`.
Microsoft documents that maximum sentinel for `accountExpires`, not `lastLogonTimestamp`. Zero remains
the no-logon value used by the product. An unrepresentable maximum timestamp now returns no wording
instead of borrowing another attribute's semantics.

## Validation

- `SecurityDescriptorParserTests`: 60 passed.
- `DangerousPermissionClassifierTests`: 74 passed.
- Directory heuristic tests and Microsoft anchors: 32 passed.
- `DirectoryTimeTests`: 21 passed.
- Offline capture → derive → judge → read journey: passed.
- Full suite: 2,646 passed, six failed.

The six failures are the remaining expected Wave 0 acceptance tests for capture retry, Derivation
binding/state, Judgement scope and Shell wording. Both Kernel Wave 0 tests now pass.

## Compatibility and deferred work

- No Evidence/Derivation/Judgement schema version changed in this wave.
- Existing raw descriptors remain readable; corrected `ObjectPermissions` re-parsing uses the new ACL
  boundary immediately.
- Existing persisted canonical ACE rows still contain expanded comparison masks. Wave 2/3 must record
  semantic provenance/raw-vs-comparison meaning before derived permission rules consume them.
- `HeuristicReadOutcome.Malformed` is currently in-memory. Wave 4/5 must carry it through persisted
  Derivation products and typed rule uncertainty.
- DN parser corrections, catalogue-version persistence, security-parser versioning and typed `gPLink`
  absence remain scheduled work under the synthesis roadmap.
