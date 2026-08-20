# 0043 - A GPO's file permissions are read below the root folder

Date: 2026-08-13
Status: Accepted

Taken by the owner in discussion on 2026-08-13, during `S-32`. The session brief
([`S-32`](../next/sessions/S-32-the-files-behind-the-policies.md)) named this question explicitly as
one to decide rather than build to a guess, and left it out of scope until the discussion happened.
This record is that discussion's outcome. It governs ledger rows `B14`, `B15` and `B16`.

## Context

A Group Policy Object is two things, and each carries its own permissions.

- The **directory object** in AD, whose ACL is already captured and which SEC-080 evaluates.
- The **SYSVOL folder** holding the files that domain-joined machines download and apply, whose
  file permissions are what SEC-082 evaluates and what nothing currently reads.

The two are maintained independently, and either confers control. A GPO whose directory object is
locked down perfectly is still fully modifiable by anyone who can write its files, because the files
are what machines actually apply. That is why SEC-082 exists as a rule separate from SEC-080, and
why SEC-080 carries an `also_writable_via_sysvol` enrichment flag rather than treating the directory
ACL as the whole answer.

**The predecessor read one descriptor per GPO: the root folder's, and nothing beneath it.**
`SysvolCaptureModule.CaptureFolderDaclAsync` passes `GpoRootFolder` - the empty relative path - to
`ISysvolFileReader.ReadSecurityDescriptorAsync`. The reader seam has always accepted any relative
path; only the caller was restricted.

Windows file permissions flow downward by inheritance, so the root folder normally does describe
everything beneath it. **Normally is the problem.** Inheritance can be switched off on a subfolder,
and an explicit entry can be placed on a single file. Where that has happened, the root descriptor
no longer describes what is below it, and a product that reads only the root does not report
uncertainty - it reports that the GPO has no non-administrative writers. That is a positive
statement of safety about a Critical rule, made without evidence, which is the one thing this
product must not do.

The concrete case that decided it: **a GPO's startup or logon script folder delegated to a team that
maintains scripts.** Inheritance is broken on `Machine\Scripts\Startup\` and write access granted.
The root folder still shows administrators only. Startup scripts run as `SYSTEM` on every machine
the GPO targets, so the delegated team holds fleet-wide code execution, and a root-only capture
reports the GPO clean.

**Cost was the argument for stopping at the root, and it does not survive the arithmetic.** A
descriptor cannot be inferred - a directory listing does not carry one - so the cost is one read per
path examined, and the question is how many paths. A GPO folder's shape is fixed by the Group Policy
format rather than by the customer, and runs to roughly ten to twenty-five items, of which eight to
twelve are directories. Several hundred GPOs therefore cost a few thousand descriptor reads, which
parallelise across GPOs (`ISysvolFileReader` is documented as safe for concurrent reads) and are
small beside the forest-wide directory capture already running. The unbounded case is reading
*every* file, which a GPO shipping a software-installation package makes expensive; that is not what
this record adopts.

## Decision

**The capture reads a security descriptor for the GPO root folder, for every directory beneath it,
and for every file the product opens anyway.** Precisely, per GPO:

1. the root folder;
2. every subdirectory, recursively;
3. every file whose contents are read - `Machine\Registry.pol`, `User\Registry.pol`,
   `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`, and each XML file the Group Policy
   Preferences `cpassword` scan enumerates;
4. every file beneath `Machine\Scripts` and `User\Scripts`.

**Logon and startup scripts are in scope for SEC-082.** The rule's description names `Registry.pol`
and `GptTmpl.inf`; scripts are effective policy on the same footing and are more directly
exploitable than either, and no argument for excluding them was found. Item 4 exists because items 2
and 3 do not reach them: the script *folder* is covered by the directory walk, but an entry placed
on an individual script file is not, and script folders hold few enough files that reading each is
bounded.

**Every other file is not read**, and that is the boundary this record draws. Software-installation
payloads, ADM and ADMX templates and any other content beneath a GPO folder are outside it. A
permission granted on one of those and nowhere else is not detected. This is the one thing given up,
and it is stated here rather than left to be discovered.

**Each captured entry is recorded against the path it was read from**, and records whether it was
inherited. Storing only the entries that diverge from the root would make the common case cheaper to
store, but leaves a reader unable to distinguish a path whose permissions match the root from a path
that was never examined - the distinction [`0002`](0002-absent-view-means-degraded-run.md) exists to
protect.

**A failure to read a descriptor does not fail the run**, per the owner's decision recorded in the
`S-32` brief, and is recorded rather than passed over. What a customer must never see is SEC-082
reporting no writers when the honest answer is that the product did not look.

## Consequences

**SEC-082 and SEC-080's union flag change meaning.** They move from "no non-administrative principal
can write the GPO's root folder" to "none can write the root, any directory beneath it, the policy
files, or the scripts". That is a wider and more useful claim, and it is the claim the rule's own
description was already making.

**Timings are unmeasured, deliberately.** The estimates above are arithmetic, not measurement. The
owner's position is that the cost be measured against a real production forest when one is
available, and this decision revisited if the measurement contradicts the estimate. **A later
session that measures it should record the numbers here.** Nothing about the design depends on the
estimate being right - if it is wrong, what changes is the depth, and this record is what that
change has to overturn.

**The directory walk is the part with an unbounded tail**, and the reason is worth naming so it is
watched rather than rediscovered. Files beneath a GPO are unbounded and this record does not read
them; directories are bounded in every normal GPO but not by anything the format guarantees, and an
extracted installation tree is the case that could hold many. If measurement shows a GPO where the
directory count is the cost, the remedy is a cap that reports having been hit, not a silent one.

**Nothing here is an operator setting.** Consistent with [`0017`](0017-capture-reads-the-whole-forest.md),
[`0034`](0034-capture-excludes-a-shipped-noise-list.md) and
[`0042`](0042-dns-zones-and-records-are-out-of-scope.md): there is no configuration that makes a run
read shallower or deeper. If the depth changes, it is because this record changed.
