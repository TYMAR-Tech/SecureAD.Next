# S-33 — The first read that is allowed to fail

> **This records session S-33 as of 2026-08-10. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

Ledger rows **B14** (SYSVOL & Group Policy capture) and **B15** (the file-access seam). `B16`, the
parsers, was `S-32`'s and its row is corrected here rather than changed.

Green at 963 tests, up from 933.

## What changed, in one sentence

Group Policy settings live in files on a share called SYSVOL rather than in the directory, and until
this session nothing opened one — so a customer whose policy granted `SeDebugPrivilege` to Domain
Users got silence. Now the files are read, and — the part that took a decision record — **a run that
cannot read some of them still produces a valid audit, provided it says exactly which ones it
missed.**

## Why that is a bigger change than it sounds

Every read this product has ever done is fail-fast. A part of the directory that could not be read
ends the run before anything is sealed, so a bundle existing has meant *everything was read*. That
is [`0003`](../decisions/0003-refuse-to-reanalyse-an-incomplete-capture.md), and a great deal is
built on it.

[`0044`](../decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md) makes SYSVOL the
single exception, on the owner's judgement of 2026-08-13. The reasoning is about deployments rather
than about code: SYSVOL is a file share, permission problems on file shares are ordinary rather than
exceptional, and a run that died because one policy folder out of four hundred was locked down would
be unusable in the field.

The risk that buys is precise: **a refusal becoming a silence.** A policy nobody could open must
never produce the same evidence as a policy that configures nothing, because those are opposite
findings that look identical if the evidence is an empty result. Most of the design below is about
that one sentence.

## What was built

**The seam** — `ISysvolFileReader` and `SmbSysvolFileReader`. Ported, with two changes.

The predecessor's alternate-credential machinery is gone: it opened an authenticated share session
with `WNetAddConnection2` and held a password in memory for the reader's lifetime. A run uses the
token it already has, per [`0039`](../decisions/0039-one-way-to-start-a-capture.md).

More important, **the predecessor returned `null` both for "this file is not there" and for "we were
not allowed to look"**, logging the reason at debug level and discarding it. That was survivable
while a failure ended the run — the run was gone anyway. It is not survivable now, because the run
continues and that discarded sentence is the only account of the failure that would ever reach an
operator. Every method now returns `Result<T>`, so the two answers cannot be confused, and directory
enumeration was added because [`0043`](../decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md)
needs it and the old seam could only match files.

**The capture** — `SysvolCapture`, `GpoInventory`, `GpoTarget`. Nothing in the capture returns early
on a failure; every failure is caught, attributed to the policy it happened under, and carried into
the coverage record. It reads to `0043`'s depth: the policy's folder, every folder beneath it, every
file whose contents are read, and everything under `Machine\Scripts` and `User\Scripts` — because a
logon script anybody can rewrite runs on every machine the policy reaches, and the predecessor's read
stopped at the root folder and could not see it.

**The coverage record** — `SysvolCoverage` and `GpoCoverage`, held beside the capture units rather
than among them.

**Eight tables**, written through `BundleWriter` like everything else. The predecessor's
`dim_gpo_setting` and `fact_sysvol_ace` writers did not port: they took a raw connection and ran
their own transactions, and this product has one write path. Folder permissions reuse the existing
`security_descriptor`, `ace` and `trustee` tables, so a trustee found on a policy folder is judged by
the same classifier as one found on a directory object — the predecessor's parallel table could
disagree with the main one about what an access mask meant.

## The one thing this session was most likely to get wrong

`S-30`, `S-31` and `S-32` each shipped a value that could only ever give one answer. The question is
always the same: *does this thing have a reachable state in which it says something else, and is
there a test that reaches it?*

Three answers here.

**The overall outcome is derived, not supplied.** `SysvolCoverage.Of` computes *read*, *partly read*
or *not read* from the policy outcomes themselves, so no caller can declare success over a set of
failures.

**The per-policy outcome has three states, not two.** A policy is a folder tree: its settings can be
readable while the permissions on its scripts folder are not. Reporting that as *read* would tell a
customer his policy was examined when part of it was not.

**The failure states are tested, and the tests were mutation-tested.** That last step earned its
keep. Swallowing every recorded failure left all eleven capture tests green, because the test named
`APolicyWhoseScriptsFolderIsRefusedIsReadOnlyInPart` was passing for an unrelated reason — paths with
no fixture descriptor were being recorded as having vanished. **It was green while measuring nothing
about the refusal it is named for.** The fixture was corrected and the mutation now fails it. This is
recorded rather than quietly fixed because it is the third instance of the same defect in four
sessions.

## What `AllDeclaredUnitsAreComplete` still means, and why SYSVOL is not in it

`RunCoverage.AllDeclaredUnitsAreComplete` is an internal consistency check: capture is fail-fast, so
it is true in every bundle a reader can open. It is kept because it enforces
[`0027`](../decisions/0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md) against some
future writer, not because it varies.

SYSVOL coverage is the opposite kind of value — one that genuinely varies and is meant to be read.
**Merging them would convert an always-true invariant into a customer-facing verdict, which is the
defect `F-S29-3` was raised about.** They are kept apart on purpose.

`UnreadOutcomeIsUnreachableTests`' remarks are corrected here, as `0044` commits to. Its code needed
no change — it guards `DomainCoverage.NotRead` and `ForestPartitionCoverage.NotRead`, and SYSVOL is
neither — but its stated reasoning, *a bundle exists only when everything was read*, stopped being
true of a bundle as a whole the moment this landed. A correct test carrying a wrong explanation is
how the next session is misled.

## The six rules, and what the product should say

SEC-064, SEC-065, SEC-066, SEC-082, SEC-083 and SEC-093 have had no evidence to read since the
catalogue was written. They now do. The wording below was **decided by the owner on 2026-08-13** and
is the product's position; the reading layer that renders it is owed.

**When Group Policy could not be read at all**, the rules say *not assessed*, with the counts and the
reason the share gave — `0 of 400 policies were examined; the account running the audit was not
allowed to read \\contoso.com\SysVol`. The reason is always what the file system actually said and is
never invented; a failure arriving without a usable reason says so rather than guessing.

**When Group Policy was read only in part**, the rules **report what was found, with a caveat carried
beside the result** — not in a coverage section a reader may never open. The alternative considered
was suppressing the findings entirely, and it was rejected: one unreadable folder would hide real
problems in the other 399 policies, and a screen showing nothing looks exactly like a clean result.
The caveat is what makes the gap visible.

**The policies that were missed are named** — display name and identifier, not a count. An
administrator told that three policies were skipped has been told something is wrong; told *which*
three, he has been told what to go and look at.

## Findings

**F-S33-1 — a test that passed while measuring nothing.** `APolicyWhoseScriptsFolderIsRefusedIsReadOnlyInPart`
was green for a reason unrelated to its name, and a mutation that swallowed every recorded failure
did not break it. Fixed within the session; recorded because the pattern has now appeared in `S-30`,
`S-31`, `S-32` and here, and because it is the category that makes everything downstream of a check
look verified when it is not. **Decision: every new guard in this session was mutation-tested in both
directions before the session closed.**

**F-S33-2 — the foreign keys the schema cannot declare.** The SYSVOL settings tables carry `gpo_guid`
without a foreign key to `sysvol_gpo_coverage`, because a policy's settings are written while it is
being read and its coverage row states an outcome not known until the read is over. Foreign keys
*are* enforced in this database, so a declared reference refused every settings row. The same
ordering `domain_coverage` has. Stated in the schema rather than left to be rediscovered.

## What is not done

The reading layer (`C16`–`C28`) and the GUI, which is what would put the wording above in front of
anybody — nothing renders a SYSVOL finding yet. `0043`'s cost estimate is still arithmetic rather
than measurement, and still owed a production forest. Whether SEC-082's own stated description should
name scripts is the owner's and was not taken.
