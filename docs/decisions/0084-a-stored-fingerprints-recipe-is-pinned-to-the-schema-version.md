# 0084 - A stored fingerprint's recipe is pinned to the schema version

Date: 2026-08-23
Status: Accepted

Sits under [0001](0001-no-backward-compatibility.md) and
[0013](0013-the-bundle-is-no-longer-a-two-way-contract.md). Closes `F-0079-6`.

## Context

A bundle stores values that are hashes of a **formatted string** rather than of raw bytes. Their
meaning therefore depends on the recipe that produced them, and the recipe lives in the build.

There are three, and they were not handled alike:

| Value | Version inside the hash | Version stored beside it |
|---|---|---|
| `ace_hash` | no | `security_descriptor.canonicalization_version` |
| `ace_set_hash` | yes, `AceSetHash` prepends it | `security_descriptor.canonicalization_version` |
| `bundle.coverage_id` | no | nothing |

The descriptor pair are covered. `coverage_id` was covered by neither, and it is the one the run
library groups on: `RunSummaryViewModel.GroupKey` is `RunScope.Identity`, which is the stored string,
and `RunLibraryViewModel` groups a `PropertyGroupDescription` over it. Baseline selection walks the
runs sharing it.

**This is not hypothetical.** Commit `9a69305` on 2026-08-21 added the excluded-domain set to the
string. That was a correct fix for a real defect — two runs of an eight domain forest leaving out
different domains had been hashing alike — and it touched `CoverageId.cs` and its tests and nothing
else. `BundleSchema.Version` has moved exactly once, on 2026-08-20, the day before and unrelated.

The result was two groups in the library under one identical heading, because `GroupHeading` is built
from the **domain rows** while `GroupKey` comes from the **hash**. Two sources feed one visual group,
so when the key changed and the rows did not, the label hid the disagreement.

A sixteen character hex string looks the same either way. Nothing on screen distinguished *these runs
covered different ground* from *these runs were fingerprinted by different builds*.

## Decision

**Changing what goes into a stored fingerprint is a schema change. Raise `BundleSchema.Version` in
the same commit.**

A bundle written under the old recipe is then refused at open under `SchemaVersionUnsupported`,
by name, and never reaches the library to form a second group.

**Refused, not relabelled.** The alternative considered was putting a format version inside the
value — `1-3f2a9c8e1b4d5a67` — so a reader could say *this run predates the current scope recipe*.
It was refused. It lets an old-recipe bundle open and group **separately**, which is the failure
being fixed; it only pays off if stale runs should stay readable-but-distinguishable, and they should
not. The requirement is that like runs group together, and refusal answers that where labelling does
not.

**This is what `0001` already implies, made explicit for a case it did not name.** `0001` says
nothing is kept backward compatible and `0013` says the bundle is not a contract, so *a schema
mismatch is a broken build rather than an old file*. `BundleSchema.Version` was raised to 6 when the
`finding` table was added, on the reasoning that a build reading a version 5 bundle *"would report no
findings and be telling the truth about the table while lying about the forest."* A stale
`coverage_id` is that same shape: true about the string, false about what the run covered.

**It does not replace the sibling mechanisms, because they answer a different question.**
`AceSetHash` puts its pipeline version inside the hash so that two values from different pipelines
can never compare **equal** by coincidence — a false *unchanged* is the failure there. Here the
failure is unwanted **inequality**. Both remain correct where they are.

## Consequences

**`ProfileId` is out of scope, and that is a property rather than an exemption.** It is never
persisted — there is no `profile_id` column, and every use recomputes it from the forest name. A
recipe change re-derives every value at the same instant, so no stale value can exist.

**Old bundles become unopenable, not misread.** There is no migration and none is wanted: per `0001`
a bundle from another build is captured again rather than migrated. Under a customer this is a
recapture; before ship it costs nothing.

**Guarded, as far as a guard reaches.** `CoverageIdRecipeTests` pins a fixed input to the value the
recipe produces, keyed on the schema version, and fails with the consequence and the repair written
out. Keying by version shapes the obvious fix — add a row for the next version — so the repair
requires the bump to exist.

**What the guard cannot do**, stated so nobody assumes otherwise: it cannot force a constant to be
raised. Editing the pinned row in place still passes. That is a deliberate act against a message
saying not to, which is the standing every gate here has, and it is why this record exists as well as
the test.

**The rule is stated where it would be broken.** `CoverageId`'s own remarks carry it, because the
person who changes the recipe is reading that file and not this one.
