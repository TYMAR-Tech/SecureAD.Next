# Punch list

Work the documentation identified that the code has not done.

**One line per item.** Reasoning that explains *how the product works* belongs in the layer docs, not
here. This file exists to be read in one sitting — if it stops being readable in one sitting it has
stopped working.

**Nothing here is scheduled.** Items are recorded so they are not lost between sessions, and are
deliberately not fixed during a documentation pass.

Status: `open` · `blocked` (a named input is missing) · `decision` (needs an owner ruling) ·
`conflict` (sources disagree)

---

## Kernel / Security

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-14 | A confidential-attribute read is reported as a takeover on `READ_PROPERTY` alone, without consulting `CONTROL_ACCESS` | decision | soften the sentence now, or wait for layer 3 |
| P-15 | Class schema is not captured, so *attributes applicable to this object* cannot be answered | blocked | capture change |
| P-13 | `DaclWasCanonical` is a `bool` where the evidence supports four states | blocked | capture of forest functional level and `fDontStandardizeSDs` |
| P-7 | The DACL walk is bounded by `AceCount` alone; `AclSize` and `AclRevision` are never read — and a lab bundle shows a one-entry disagreement this would explain | open | — |
| P-16 | `PASSWD_CANT_CHANGE` is stated as current state; it is enforced by permissions, not by the bit | open | — |
| P-12 | `DaclState` has four of the six states the review recommended — `Absent` is folded into `Null`, `NotRetrieved` has no equivalent | open | — |
| P-10 | The classifier mixes ACE semantics, capability and risk, and reads raw evidence directly | open | layer 3 first |
| P-11 | Risk vocabulary may have leaked into the parsing and wording layers | open | — |
| P-1 | The early-stop correction may itself over-generalise, and the sweep that found it was never completed | decision | owner ruling |

### Detail, where one line is not enough

**P-14.** Microsoft requires `READ_PROPERTY` **and** `CONTROL_ACCESS` to reach a confidential
attribute, possibly from different entries. `ClassifyAttributeRead` tests only the attribute name and
says *"reading it is the whole attack"*. It over-reports, which is the safe direction, but it is the
entry-level-as-principal-level claim that R19 forbids — the same fault already corrected for
`WRITE_OWNER`. Either soften the sentence to say this entry supplies one half, or answer it properly
in [planned effective access](planned/effective-access.md).

**P-15.** Needs class attribute definitions, superclass inheritance, and applicable auxiliary and
dynamic auxiliary classes. MS-ADTS inheritance uses the **most-specific structural class plus
applicable dynamic auxiliary classes**, not every class in the `objectClass` chain, so unioning
`objectClass` yields a larger set than AD applies. Unblocks four recorded items at once and cannot be
worked around later — a bundle captured without it can never answer these questions.

**P-1.** `AceCanonicalization` states flatly that AD examines every entry to the end of the DACL.
That is correct for simple access, but control access rights and validated writes **do** terminate at
the first applicable entry, and the specification warns against applying the general early-stop
algorithm to all AD rights. The original claim was reported corrected in six places, then three more
were found incidentally; no systematic sweep was ever done.

**P-7, and the open finding it may explain.** `docs/areas/what-a-permission-means.md` carried an
open finding, `F-4`, with real lab evidence:

> The `ace` table and the re-parse of the same descriptor disagree by one entry on `OU=test01` in
> `ad.lab-20260821-014720` — 57 against 56 — while the descriptor reports
> `dacl_completeness=Complete`.

**These are very likely the same defect.** The walk is bounded by the declared entry count and the
descriptor's end rather than by the ACL's own `AclSize`, and completeness is asserted when the parsed
count equals the declared count — so a descriptor can be reported `Complete` while the two readings
of it differ. `F-4` is the observed symptom; P-7 is the mechanism.

Consequence stated in the finding itself: *"An entry count an operator reads may be short, and a
permission may not be listed."* That is the one thing an audit tool cannot do, so this is the
highest-priority open item in the subsystem despite its low review severity.

Not yet established which of the two readings is correct.

---

## Audit / Capture

| ID | Item | Status | Blocked on |
|---|---|---|---|
| P-19 | `EveryPublicTypeInTheCaptureProjectIsNamedByACaptureSliceDocument` scanned four types while claiming nineteen — green for months | open | — *(gate widened during the rewrite; the finding is kept because the shape recurs)* |
| P-20 | `F-S44-2` — the catalogue's three test suites are a closed loop anchored to the rules already written, and it has no external anchor | open | a reconciliation fixture naming every predecessor attribute or a written omission |
| P-21 | `0065` is decided and unimplemented; every run taken before it lands is permanently silent on the trust attributes | open | — |
| P-22 | `F-S40-1` — `0040` decided a failed domain is read again from another controller, and nothing walks that path | open | — |
| P-23 | Gate 5b is recorded as blocked on an entry point that now exists (`CaptureRun`) | decision | whether to turn it on |
| P-24 | `F-S23-4` — six captured attributes have no consumer among the sixty-two rules; three are named attack surfaces the product holds data for and says nothing about | open | rules at branch E |
| P-25 | `F-S23-5` — six rules need SYSVOL and nothing in the directory answers them; ten per cent of the catalogue is inert and nothing says so | open | B14/B15 |
| P-26 | `F-S7-37`, `F-S7-39`, `F-S7-40` — three claims about how a real controller behaves that no test in this repository can settle | blocked | lab session |

**P-19 detail.** The check read `typeof(CapturedAttributeCatalog).Assembly` filtered to
`SecureAD.Kernel.Capture`, which is four types. Its name and its failure message both said *the
capture project*. The fifteen public types in `SecureAD.Audit.Capture` were never scanned.

The fault arrived **by repair**: S-24 moved the catalogue into the kernel, this check failed loudly,
and the fix pointed the scan at the catalogue's new neighbours rather than at the component the test
is named for — a different set, checked against the same document, passing. Widened during this
pass, and it immediately named twelve types no document mentioned. Recorded rather than closed
because this is the third time a check in this repository has passed while measuring nothing, and
the second time the cause was a repair that preserved the assertion and moved the subject.

---

Recorded so they are not lost. Each belongs to its own pass.

| ID | Item | Subsystem | Status |
|---|---|---|---|
| `#20` | GPO link precedence — the deep review and S-58 flatly contradict each other | group policy | **conflict** |
| `#17` | `ProvesTheControllerAnswered` counts LDAP 91 as an answer, so a certificate fault can produce a forest finding | audit/connect | open |
| `F-S40-1` | `0040`'s retry from another controller is decided, and nothing walks it | audit/connect | open |
| `#19` | `gPLink` option bits are documented in the archive but never verified first-party | group policy | blocked |
| `#22` | `SecurityTemplateParser` accepts nonconformant encodings without labelling them | group policy | open |
| `#21` | `DnHelper` decides escaping from the preceding character rather than from the escape sequence | kernel/naming | open |
| P-2 | `SchemaVersionUnsupported` has no test — zero references in the test project | evidence/bundle | open |
| P-3 | `BundleWriter` writes the build's canonicalisation version, not the version carried on the entries | evidence/bundle | open |
| P-17 | Eleven tracked files are zero bytes, including three `.cs` files and a `.csproj` | repository | open |
| P-18 | `CaptureRunEndToEndTests` fails intermittently on a disposed SQLite handle | tests | open |

**P-17 detail.** A predecessor finding cleared the *untracked* empty files and left the tracked ones,
on the grounds that deleting tracked files is a repository change rather than a tidy-up. Those
specific files are now gone, but eleven remain:

```
next/src/SecureAD.Shell/Services/BundleTreeSource.cs
next/src/SecureAD.Shell/Services/ITreeSource.cs
next/src/SecureAD.Shell/ViewModels/SectionView.cs
next/tools/SchemaProbe/SchemaProbe.csproj
next/tools/_repoint-repository-root.ps1
next/tools/_run-inbound-next.ps1
next/tools/check-instruction-claims.ps1
next/tools/delink-archived-documents.ps1
next/tools/restore-documents-to-baseline.ps1
next/tools/tmp-probe.ps1
next/tests/.c8-row.tmp
```

`SchemaProbe.csproj` being empty means that tool cannot build, which is consistent with it not
appearing in the solution. The reasoning from the original finding still applies: **a name that
claims a task and a file that does nothing is worse than no file, because a later reader assumes it
works** — and `check-instruction-claims.ps1` and `delink-archived-documents.ps1` name tasks directly
relevant to this rewrite.

**P-18 detail.** `EveryObjectTheControllerServedIsStored` failed once with
`System.ObjectDisposedException: SQLitePCL.sqlite3`, then passed in isolation and on two subsequent
runs. Low severity but it corrodes the oracle: *"A test that fails at random trains a reader to
re-run rather than to look, and the day it fails for a real reason it will be re-run too."*

**`#17` detail — adjudicated 2026-09, and the original line was wrong.** It said the ladder treats
91 as proof of *refused protection*. It does not: `ConnectionFailureReason.Of` maps 91 to
`ProtectedChannelFailed`, which is a distinct reason and a correct one. The fault is one entry
further on. `ProvesTheControllerAnswered` lists `ProtectedChannelFailed` alongside
`CredentialsWereRejected` and `ProtectionWasRefused`, and that list is the gate `0018`'s amendment
put in front of the forest finding. So a 91 on rung 1 plus any failure on rungs 2 and 3 satisfies
the gate, and an undeclared run ends at *"a controller accepting nothing signed leaves its LDAP
traffic open to alteration in transit."* A broken LDAPS certificate on 636 plus a firewall on 389
reaches it — a certificate fault accusing a customer's forest.

**Microsoft settles it.** 0x5b is *"Cannot establish the connection"*
([Return Values](https://learn.microsoft.com/previous-versions/windows/desktop/ldap/return-values)).
That is the client failing to connect, with nothing in it about the server having responded. 49 and
8/13 are result codes a controller sent; 91 is not.

**How it survived the amendment.** The amendment has three cases and `ConnectionSecurityTests` has a
test for each — 81, 49, and unclassified. The fourth entry in the same list was carried over without
being re-asked. The `P-19` lesson again, from the other direction: *ask what the check's subject is,
not only whether it passes.*

**The remedy, so the fix pass need not re-derive it.** Drop `ProtectedChannelFailed` from
`ProvesTheControllerAnswered`. That routes an all-91 walk to the no-answer branch, whose message
currently offers name, host and firewall — true but understated for a TLS failure, so that branch
wants a third variant beside the existing `timedOut` one, saying the transport could not be
established and naming the certificate. Add the missing test.
`ConnectionFailureReason`'s comment calls 91 *"the transport could not be established - in practice,
TLS"*; the *in practice, TLS* half is inference rather than the citation, and it is what makes 91
look like an answer. Recorded in [`_DRIFT.md`](_DRIFT.md).

**`#20` detail.** The deep review says link order 1 is highest precedence and warns against
`Count - Order + 1`. S-58 lists that same expression under *what must not change*, saying the last
GPO in the sequence has the highest precedence. Neither cites a specific Microsoft page. **Settle
against Microsoft; do not prefer the later document.**

**`#21` carries a durable point** beyond the parser itself: prefer `objectGUID` or `objectSid` over
DN-string equality for cross-source identity. That is what `#18` got wrong when joining SYSVOL
evidence to directory objects.

---

## Deferred features

| Item | Where |
|---|---|
| Effective access evaluation — layers 3 and 4, requirements R8, R10, R11, R12, R16, R20 | [`planned/effective-access.md`](planned/effective-access.md) |

---

## Closed

Findings checked against the code and confirmed already fixed are **not listed here**. Git history and
the archive hold them, and repeating them made this file longer than the documentation it supports.

Two exceptions, because they are easy to mistake for gaps on a future sweep:

- **`#14` was refuted, not fixed.** `MembersOfPropertySet` returning a nullable list already
  distinguishes *empty* from *unknown*. Do not reopen.
- **R9 and R18 are implemented but uncited.** `searchFlags`/`systemFlags` capture answers R9;
  `WellKnownSidRole` answers R18. A citation in the layer doc would stop every future sweep
  rediscovering them.
