# How a failure is reported

**Code:** `next/src/SecureAD.Kernel/Result.cs`, `AuditError.cs`, `IRunLog.cs`
**Layer:** Kernel — how an operation says it did not succeed, and what stops that being optional.

This is the mechanism behind the product's oldest rule: *found nothing* and *could not compute* must
never look alike. Everything that reports a failure to an operator — a domain that would not answer,
a bundle that would not open, a setting that could not be saved — arrives as one of these two types.

Where a particular failure is produced, and what it says, belongs to the page for that code. This
page is about the vocabulary all of them use.

Was bound by FailureReportingDocumentationTests, a documentation gate retired on 2026-09-11,. The tables below are bound **in both directions**
against the code — a category or severity the code declares and this page does not name fails the
build, and so does a row here naming one that does not exist.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `Result` | The outcome of an operation that can fail: either a value, or the error explaining why there is not one |
| `AuditError` | A structured failure — its category, its stable code, how much it matters, what went wrong and what it was about |
| `ErrorCategory` | Which subsystem the failure came from |
| `ErrorSeverity` | Whether a result survived the failure |
| `IRunLog` | Where a run says what it is doing, and what went wrong while it did |
| `RunLog` | The logs a caller can choose when it has nowhere to write |
| `RunLogDetail` | One named value on a log line, so the quoting rule has a single owner |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions: a public type of
this component missing from it fails the build, and so does a row naming something that is not one.
Other pages name these types constantly — almost every signature in the product mentions one — and a
mention is not a claim.

## The return type is the whole mechanism

`AuditError` on its own has been built before, in the implementation this one replaces. It had the
categories, the severity, and a formatter that forbade a freeform code, and it was constructed by no
production code at all. The reason was structural rather than careless: every operation returned a
value, a `bool`, or threw, so producing a structured error was optional work with no compiler
pressure behind it — and optional work at two hundred call sites does not happen.

`Result` is what removes the option. An operation returning one cannot hand back a value without
having decided what happens when it cannot, and a caller cannot reach the value without
acknowledging the alternative. `Result.Match` collapses both outcomes into a single value, so
neither branch can be forgotten, and `Result.Value` throws rather than returning a default, so a
caller that skipped `Result.IsSuccess` fails loudly instead of silently reporting nothing found.

## Exceptions are still right, for a different thing

An exception is for a defect: a null argument, a violated invariant, a bug. A `Result` is for an
outcome the operation is expected to meet. The rule of thumb the code follows is that if a
reasonable run can produce it, it is a `Result`; if only a broken build can, it is an exception.
That is why `AuditError.Create` throws on a blank reason or a blank description rather than
returning a failure — a failure with nothing to say is a defect in the calling code, not something
an operator should be shown.

## An unassigned result is not a success

`Result` is a struct, so `default(Result)` is reachable without going through either factory, and
the dangerous reading of it is *succeeded with no value*. Success is tracked explicitly so that
reading is impossible: a default result reports itself as a failure carrying the code
`Evidence.UninitializedResult`, whose description says it was read before being assigned. It is
surfaced as a diagnosable error rather than thrown from a property getter, so it appears in output
as something to fix rather than as a crash.

## The code cannot be invented at the call site

`AuditError.Code` is formatted `Category.Reason` and is built by `AuditError.Create` from the
category and a short reason, so the code and the category cannot drift apart and no call site can
compose a string of its own. `AuditError.Context` — the subject the failure was about, a
distinguished name, a domain, a file path — may be null, because some failures have no subject, but
it is stated at every construction rather than defaulted. A defaulted parameter is a decision
nobody makes.

## The categories are added when something produces one

<!-- CATEGORIES:BEGIN -->

| Category | What it covers |
|---|---|
| `Capture` | Reading the directory during a capture |
| `Evidence` | Reading or writing an evidence bundle |
| `Shell` | The operator's own settings — where the run library is, and what else they have told this installation |

<!-- CATEGORIES:END -->

Deliberately short. The implementation being replaced declared fourteen categories with a matching
error-code enum each, and thirteen of the fourteen were referenced only by their own declaration and
a formatter overload, because nothing was ever obliged to produce one. A category is added here when
a subsystem actually surfaces a failure, which is how `Shell` arrived.

## Two severities, and only one of them means there is no answer

<!-- SEVERITIES:BEGIN -->

| Severity | What it means |
|---|---|
| `Degraded` | The operation continued and its result is usable, but something was lost |
| `Failed` | The operation did not produce a result |

<!-- SEVERITIES:END -->

The distinction is the difference between an audit that is missing a domain and an audit that is
missing. A reader who cannot tell them apart cannot tell a partial answer from no answer, and a
partial answer presented as a whole one is the one thing this product must not do.

---

## What is built

**The test is the evidence; this table is only the index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

These rows were carried by an area file the rewrite deleted and were left behind by that pass. Restored 2026-08-24 after an audit of all eight deleted area files found 48 such rows.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a failure carries a code derived from what went wrong and why | `AuditErrorTests.CreateDerivesTheCodeFromTheCategoryAndReason` |  |
| be certain a failure cannot be raised without a reason | `AuditErrorTests.CreateRejectsAnEmptyReason` |  |
| be certain a failure cannot be raised without a description | `AuditErrorTests.CreateRejectsAnEmptyDescription` |  |
| be certain reading the value of a failed result throws and names the code | `ResultTests.ReadingTheValueOfAFailedResultThrowsAndNamesTheCode` |  |
| be certain a failed result is never mistaken for a successful one | `ResultTests.AFailedResultIsNotSuccessful` |  |
| be certain an uninitialised result is not mistaken for success | `ResultTests.ADefaultResultIsNotMistakenForSuccess` |  |
| be certain an uninitialised result reports a self-describing error | `ResultTests.ADefaultResultReportsASelfDescribingError` |  |
| be certain no public member returns a bare count that cannot say whether it looked | `UnvouchedResultGateTests.NoPublicMemberReturnsABareCount` |  |
| be certain no public member returns a collection that cannot say whether it looked | `UnvouchedResultGateTests.NoPublicMemberReturnsACollectionThatCannotSayWhetherItLooked` |  |
| be certain that gate reads the real public surface rather than a copy | `UnvouchedResultGateTests.TheGateReadsTheRealPublicSurface` |  |
| be certain the exemptions to that gate are still earning their place | `UnvouchedResultGateTests.TheCatalogueExemptionsAreStillEarningTheirPlace` |  |
