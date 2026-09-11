# Group Policy

**Area.** What the product reads about Group Policy: the objects in the directory, the files behind
them in SYSVOL, and what those files contain. Group Policy is where a permission on one object turns
into code running on many machines, which is why it is read at all.

This file is the starting point for any work in this area. It is meant to be read whole, in a few
minutes, and it is the only file that needs reading before we talk.

---

## What is decided

Moved. The records that govern this area are indexed in [`DECISIONS.md`](../DECISIONS.md); this
page no longer keeps a second copy of that index.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** A capability whose test does not exist, or does not pass, fails the build — so nothing
here can claim something the product does not do.

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank is the
honest answer for most rows and means unit-tested but not yet exercised against Active Directory -
a test with a synthetic descriptor proves the parser handles those bytes, not that a domain
controller sends them.

**The sixteen capabilities of the parsers have moved** into
`what-a-policy-declares.md` and
`what-a-policy-file-contains.md`, which now carry them
under *What an operator can do*. They are not repeated here.

**What is still owed to this section** are the seven types this area governs that no layer document
yet describes: `ISysvolFileReader`, `SmbSysvolFileReader`, `GpoTarget`, `GpoInventory` and
`SysvolCapture` in `SecureAD.Audit`, and `GpoSettingScope` and `RestrictedGroupRelationship` in
`SecureAD.Evidence`. This file is deleted when they are covered, not before.

---

## What has not been discussed

Moved to the punch list as `P-46` through `P-50`, where work that may need doing is tracked.
Nothing in this area is settled by their absence here.

---

## Open findings

| | | |
|---|---|---|
| — | none recorded for this area yet | — |
