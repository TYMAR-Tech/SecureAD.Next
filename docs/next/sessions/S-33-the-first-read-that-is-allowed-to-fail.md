# S-33 — The first read that is allowed to fail

## The state of the tree

Green at 933 tests. `S-32` is committed at `8eb399bf` and stopped deliberately at a green tree
roughly a third of the way through its brief; the rest of that brief is this session. Read
[`S-32`](S-32-the-files-behind-the-policies.md) for the whole argument — this brief assumes it
rather than repeating it.

**Read [`0044`](../../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md)
before anything else.** It is what this session builds, and it was written before the code so that
the code could not quietly decide something else.

## What this session is for

`S-32` ported the four Group Policy parsers and stopped. Nothing yet opens a file, so the six rules
— SEC-064, SEC-065, SEC-066, SEC-082, SEC-083, SEC-093 — are still inert, and a customer whose
Group Policy grants `SeDebugPrivilege` to Domain Users still gets silence.

Ledger rows **B14** (SYSVOL & Group Policy capture) and **B15** (the file-access seam). **B16** (the
parsers) is done.

## What is already settled, and must not be reopened

Four things. Three are the owner's, taken 2026-08-13; the fourth is a decision record.

1. **A SYSVOL failure does not fail the run.** `0044`.
2. **Alternate credentials are not supported.** The predecessor's `SmbSysvolFileReader` establishes
   an authenticated share connection with `WNetAddConnection2` and holds a `NetworkCredential` in
   memory. All of it comes out. The run uses the token it has, per
   [`0039`](../../decisions/0039-one-way-to-start-a-capture.md).
3. **How deep the permission read goes**, settled by
   [`0043`](../../decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md): the GPO
   root folder, every directory beneath it, every file whose contents are read, and every file under
   `Machine\Scripts` and `User\Scripts`. **Logon and startup scripts are in scope for SEC-082.**
4. **Where SYSVOL coverage lives**, settled by `0044`: its own type, beside the capture units rather
   than among them, and **not** part of `RunCoverage.AllDeclaredUnitsAreComplete`.

`0043` records that its cost estimate is arithmetic rather than measurement, and asks a later
session to write real numbers into it once a production forest is available. **That is not this
session** unless a forest happens to be at hand.

## The thing that makes this session different from every capture before it

Every read the product has ever done is fail-fast: a unit that could not be read returns before the
seal, so a bundle exists only when everything was read. **This is the first read that is allowed to
fail and still ship a bundle**, which is why `0044` exists and why the coverage record is the
delicate part rather than the file handling.

Three consequences the session must hold:

- **`SysvolCoverage` must have a reachable state in which it reports failure, and a test that
  reaches it.** `S-30` and `S-31` each shipped a value that could only ever say one thing, and
  `S-32` found a fifth gate whose scan matched things it did not mean. This is the same test in all
  three cases: *does the thing have a reachable state in which it says the other answer, and is
  there a test that reaches it?* SYSVOL is the one place in the product where partial coverage is
  genuinely expected, so it is the one place the record can be made to matter.
- **The counts are what give the partial state its edges**, which is the condition `0044` widened
  `0035` on. The GPO list comes from LDAP before any file is opened, so a run that could not read
  three folders out of four hundred knows which three. A record that says *partial* without naming
  them fails the condition the widening was granted under.
- **`RunCoverage.AllDeclaredUnitsAreComplete` stays free of SYSVOL.** Merging them turns an
  always-true invariant into a customer-facing verdict, which is the defect `F-S29-3` was raised
  about.

## Owed by `0044`, and easy to forget

**The remarks on `UnreadOutcomeIsUnreachableTests` are wrong the moment this session lands.** They
say a bundle exists only when everything was read. The test's *code* stays correct — it guards
`DomainCoverage.NotRead` and `ForestPartitionCoverage.NotRead`, and SYSVOL is neither — but its
stated reasoning stops being true. `0044` commits to correcting it. A correct test carrying a wrong
explanation is how the next session is misled.

## What ports, and what does not

Verified by reading the predecessor during `S-31` and `S-32`, not assumed.

**Ports with the credential mechanism removed.** `SmbSysvolFileReader` and the `ISysvolFileReader`
seam. The seam is good and its value is proven: it is what lets the capture module be tested without
a network. Keep it. `ReadSecurityDescriptorAsync` already takes a relative path, so `0043`'s depth
needs no new capability there.

**Needs adding to the seam.** Directory enumeration. `EnumerateRelativeFilesAsync` returns files
matching a pattern and cannot enumerate directories, which `0043` requires.

**Already done.** The new catalogue reads `gPCFileSysPath` and `gPCMachineExtensionNames`, so the
LDAP half of finding a GPO's files is built and tested. The four parsers are in
`SecureAD.Kernel/GroupPolicy` with 71 passing tests.

**Does not port — new work against the new conventions:**

- **The writers.** `SysvolSettingWriter` and `SysvolAceWriter` target `dim_gpo_setting` and
  `fact_sysvol_ace`, which do not exist here, and they take a raw `SqliteConnection` and run their
  own transactions. This product has one write path, `BundleWriter`.
- **The coverage record**, per `0044`.
- **The failure behaviour**, per the owner's decision.

## A caution from `S-32`, because it will recur

The gates fire on ported code, and they are usually right. `S-32` found five, of which one was a
genuine silent false negative in the product and three were guards matching outside their concept.
Two rules that came out of it:

- **Gate 4 exempts a *type*, not a member.** `GpoClientSideExtensionCatalog` exists as a separate
  type only because exempting the combined type would have exempted the parsing along with the
  table. Expect the same shape when the capture module gains a constant.
- **`git grep` does not search untracked files.** A newly created file returns nothing and looks
  absent. `git add -N` first.

## Out of scope

The read side (`C16`–`C28`) and the GUI, which follow this session. Certificate services. The
unresolved-reference classifier (`F-S30-2`). Measuring `0043`'s cost against a production forest.
Widening SEC-082's stated description to name scripts — `0043` records that scripts are in scope for
the capture; whether the rule's own wording changes is the owner's.

## Finish by

- The seam ported with the credential mechanism removed, and directory enumeration added
- SYSVOL settings and the folder permissions captured to `0043`'s depth and written through
  `BundleWriter` into tables designed under `0035`, not carried over from the predecessor's schema
- A `SysvolCoverage` record with a reachable failed state, a test that reaches it, and counts that
  name what was missed
- `UnreadOutcomeIsUnreachableTests`' remarks corrected, per `0044`
- The six inert rules named, with what the product should say when Group Policy was not assessed.
  Draft wording was written during `S-32` and is **not owner-approved**; it is in that session's
  transcript and should be put in front of him rather than adopted
- A slice document, `docs/next/S-33-the-first-read-that-is-allowed-to-fail.md`

## Housekeeping

Carried from `S-32`, none of it blocking:

- **`docs/decisions/README.md` holds a second, hand-maintained index** that stops at `0035`, so
  `0036`–`0042` are missing from it. The real index is `docs/DECISIONS.md`, generated by
  `next/tools/Build-DecisionIndex.ps1` and enforced by `DecisionIndexTests`. Nothing tests the
  hand-kept one, which is why it drifted. Delete it in favour of a link, or generate it too.
- **`next/tools/Read-Bundle.ps1`** is untracked and nobody has run it. Exercise and commit it, or
  delete it. It has now survived two sessions on that basis.
- Untracked and deliberately not committed: `next/ad.lab-20260815-010309/` (a captured bundle),
  `tmp-bundle-query/`, `next/tools/row-a7.txt`, `next/tools/row-a9.txt`.
