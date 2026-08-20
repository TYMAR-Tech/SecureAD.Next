# S-10 — Politeness: the limits a domain controller sets, and what capture does about them

Inventory row **B7**. Capture runs against a customer's production directory, during their working
day, on servers that are also authenticating everyone in the building. This is the document that
says how hard it pushes and on what authority.

Bound to the code by `PolitenessDocumentationTests`, which compares the table below with the limits
`ServerLimits` names. Per [`README.md`](README.md) §When a document counts as documentation, this
file is not documentation until that test holds it to the code.

## There is no request rate limit, and that is deliberate

The obvious way to be polite is a speed limit: so many requests per second per controller, with a
setting an operator can turn down. This product does not have one, and the reason is that it would
be measuring the wrong thing.

**One request is a page of up to a thousand objects.** What a controller actually spends on a
capture is objects read, temporary-table pressure and bytes serialised — none of which is
proportional to how many requests arrived. A budget of twenty-five requests a second can be honoured
exactly while the load varies by an order of magnitude, depending on how large the objects are and
whether their security descriptors were asked for. So the number an operator sets and the load a
server feels are only loosely related.

And there is a second problem, which is that the limit could not bind. This product asks one
question at a time and waits for the answer, so its rate is one request per page round trip — for a
page of a thousand objects carrying security descriptors, well under one request per second. A
ceiling of twenty-five is not a ceiling; it is a number in a settings file. An operator choosing
between presets labelled by their effect on production, and getting no change in what a server
experiences, is worse off than an operator with no choice at all, because the setting reads as a
lever and is not one.

So this document owes two things instead. The server's own limits, named rather than guessed. And
the constraint that does the work.

## The constraint that does the work

> **Requests are never pipelined.** This product places one request at a time on a domain
> controller.

This is the whole of the product's politeness, and it is worth stating as a rule rather than
leaving as a property of how the code happens to be arranged today. A constraint that holds only
because nobody has yet written the obvious optimisation is a constraint nobody is keeping.

It is held by `SerializedDirectoryAccessGateTests`, which fails the build if a fan-out shape —
`Task.WhenAll`, `Task.Run`, `Parallel.ForEach` and their relatives — appears anywhere in the
capture project. That is gate 1's shape: a correct mechanism with a boundary obliging its use.

**It is a correctness rule and not only a courtesy.** The state a controller keeps between the
pages of one paged search comes out of a single per-controller budget, `MaxResultSetSize`, and when
that budget fills the controller **discards the oldest** intermediate results. Concurrent paged
searches against one controller can therefore truncate each other — silently, and only on forests
large enough for someone to have wanted the concurrency. That is finding F-S7-12, and it is the
same class of failure as the paging defect in [`S-9`](S-9-the-capture-unit.md).

The guard has an empty allowlist and a test that fails when it stops being empty. When derived
analysis lands in this project and genuinely wants parallel work on evidence already captured, the
intended answer is to narrow the guard to the code that touches a directory — not to exempt a file.

## Where pressure actually comes from

Not from request count. From, roughly in order:

- **Whether security descriptors are in the requested attributes.** They are, on every object;
  there is no audit without them. The schema permits `nTSecurityDescriptor` values into the tens of
  kilobytes, so this is the largest single term in what a capture costs.
- **Page size**, which decides how much of the above is assembled at once.
- **Filter cost.** A filter a controller cannot serve from one index falls back to scanning, and
  the fallback lands in `MaxTempTableSize`. Capture's filter is the cheapest one that can express
  "every object except two classes", and capture requests no sort control.
- **How many units target one controller.** One, by the decision recorded in
  [`S-9`](S-9-the-capture-unit.md).

## The limits, and what capture does about each

Every default below is the documented default from
[View and set LDAP policy in Active Directory by using Ntdsutil.exe](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil).
They are *defaults*. An administrator may lower any of them, and may raise most of them — but not
without limit: Windows Server 2008 and later impose **hardcoded ceilings that override the policy
whenever the policy is set higher**
([Windows Server 2008 and newer domain controller returns only 5000 values in an LDAP response](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response)).
Page size caps at 20,000, query duration at 1,200 seconds, temporary table size at 100,000 records,
and **values per attribute at 5,000** whatever the policy says.

That last one is the one with teeth, and Microsoft's own example is this product's exact use case:
ask for the members of a group with more than five thousand members and five thousand come back.
Raising the policy does not change it. Only range retrieval does — inventory row B8.

None of the ceilings binds anything capture asks for: it requests pages of a thousand and a time
limit of two minutes, both far below. They are recorded because an administrator who has raised a
limit may reasonably expect it to apply, and it may not.

In the code each row is a `ServerLimit`, and the four columns of one are its name, that default,
what the controller does when the limit is reached, and what capture does about it. The fourth is
never "nothing": a limit capture does not respect is a limit capture will meet, and the answer has
to say at least what happens then.

<!-- LIMITS:BEGIN -->

| Limit | Documented default | What capture does |
|---|---|---|
| MaxPageSize | 1,000 objects | Pages every search and asks for exactly this many. It never issues an unpaged subtree search |
| MaxQueryDuration | 120 seconds | Sets the same limit on the request. Because every search is paged, it bounds a page rather than a partition, so a large partition never needs a raised limit — which Microsoft advises against |
| MaxValRange | 1,500 values | Range-retrieves every multi-valued attribute in the catalogue — inventory row B8 |
| MaxConnIdleTime | 900 seconds | Does not deliberately hold an idle connection, and treats a closed one as a failure rather than as the end of the results. See below |
| MaxResultSetSize | 262,144 bytes | Never runs two paged searches against one controller, which is the only way to compete for this budget |
| MaxPoolThreads | 4 threads per processor | Occupies at most one. Recorded because it is the ceiling any future fan-out would be spending — inventory row B5 |
| MaxConnections | 5,000 connections | Holds one at a time |
| InitRecvTimeout | 120 seconds | Binds and searches immediately after connecting |
| MaxTempTableSize | 10,000 records | Keeps the filter cheap and requests no sort control. This is where a badly shaped filter actually lands |
| MaxNotificationPerConnection | 5 requests | Registers none. A run is a photograph of a forest at one moment |
| MaxActiveQueries | 20 searches, and not enforced | Nothing. It is listed so that it is not cited — see below |

<!-- LIMITS:END -->

### The idle timeout, in particular

`MaxConnIdleTime` closes a connection the client has left silent for fifteen minutes, and returns
an LDAP disconnect notification when it does. It is worth its own paragraph because capture is
deliberately serialised and a large forest is minutes of work, so "could a connection go idle?" is
a fair question to ask of this design.

Between two pages, no. The gap is one write to the bundle, and no page can outlast
`MaxQueryDuration` anyway. Between two passes over the same partition, no — the same is true.
Between two units, the question does not arise: a unit opens its own connection and closes it.

**What matters is not whether it happens but what happens if it does.** A closed connection must
surface as a failed request, and a failed request must never be read as the end of the results.
That is the same defect as the paging one, arriving by a different route, and it is the reason this
limit is recorded rather than dismissed as inapplicable.

### `MaxActiveQueries` is listed so that it is not cited

It once bounded concurrent searches and returned `busy` past twenty. Microsoft records that it has
**not been enforced since Windows Server 2003** and does not appear in that version's tooling. A
limit that looks like a safety margin and is not one is exactly what a later session would lean a
concurrency decision on. The real constraint on concurrency is `MaxResultSetSize`.

## When a request fails

Capture is fail-fast: a naming context it cannot read ends the run. That is what makes retrying
worth doing rather than what makes it unnecessary — without it, one stalled request throws away
everything read so far, and a capture is minutes of work against a production server somebody had
to schedule.

The policy lives in `RetryPolicy` as a table of `DirectoryFailure` entries, each carrying a
`FailureResponse`, and it turns on one distinction: **whether the failure left the conversation
with the controller intact.**

A paged read holds an opaque bookmark that only means something inside one live conversation. If
the conversation survives, the same request can simply be sent again. If it does not, the bookmark
died with it — and a paged read **cannot be resumed from the middle**, because LDAP has no way to
say "carry on from object forty thousand". So there are three possible answers and no fourth:

- **Retry the request.** Same connection, same bookmark, after a wait.
- **Restart the naming context.** New connection, from the first page, discarding what the
  abandoned attempt read rather than merging it. This costs time and costs nothing else: a capture
  is not a frozen instant anyway — it is read page by page over minutes and the forest changes
  underneath it — so a partition read from the start half an hour later is no less accurate.
- **End the run**, naming the naming context and the point reached.

**Three attempts at a request, and one restart of a naming context.** Three because two of these
failures are a controller saying it is under load, and a client that answers "I am busy" by asking
harder is making the situation worse; the first wait is five seconds and doubles. One restart
because one gives a network blip a free recovery, while a second is a loop with a plausible excuse.

<!-- RETRY:BEGIN -->

| Failure | Code | What capture does |
|---|---|---|
| Busy | 51 | Waits and asks again, up to three attempts. The conversation is intact and the bookmark is still good |
| Unavailable | 52 | As for Busy. If three attempts do not recover it, the controller is genuinely gone and the failure says so rather than surfacing as an uninterpretable timeout |
| ServerDown | 81 | Reconnects and reads the naming context again from its first page. The connection is gone, so the bookmark is gone; sending it again would offer the controller a bookmark it has no memory of |
| Timeout | 85 | Reads the naming context again from the start. The client stopped waiting, so whether the controller still holds the paging state is not knowable — and reusing a bookmark on a guess is how a partial capture becomes undetectable |
| TimeLimitExceeded | 3 | Ends the run. The identical request meets the identical limit, so retrying is a loop with a wait in it. The real remedy is a smaller page, which is a change to how the loop asks rather than a response to a failure — inventory row B6 |
| AdminLimitExceeded | 11 | Ends the run, naming the limit. This is a mismatch between the product and the forest's LDAP policy and will recur on every attempt |
| Unrecognised | any other | Ends the run. An unrecognised failure is not assumed harmless: retrying something nobody has reasoned about is how a request that half-succeeded gets sent twice |

<!-- RETRY:END -->

Codes at or below 80 are the LDAP protocol's own result codes, reported by the controller. Above
that they are the client library's, reporting a failure that never reached one — which is exactly
why 81 and 85 are the two that end the conversation.

### Offering a different controller

When a naming context fails, the alternative that usually works is not another attempt but
**another domain controller**. A domain partition can be re-read on any controller of that domain;
the configuration and schema partitions can be re-read on *any* controller in the forest, since
every one of them holds a copy — which is convenient, because those are the two whose loss would
otherwise sink a whole run.

So the failure of a naming context is a **decision point**, not just an outcome. Capture reports
the failed unit and the controllers that could serve it instead, and something above it answers.
Two things follow, and both are deliberate:

- **Capture does not ask the question itself.** It reports and waits to be told. A dialog belongs
  to the window, which is a layer above the evidence; putting one here would be presentation
  reaching into capture.
- **The automatic answer is the default, not the fallback.** An audit tool gets scheduled, and a
  run that blocks at 03:00 on a dialog nobody sees has done nothing by morning while still holding
  a connection. So the policy above is what happens unless somebody is present to answer
  differently.

**There is no option to skip a naming context and carry on.** A partial forest is not a smaller
audit, it is an audit whose silences mean nothing, and a button that produces a cleaner-looking
report by reading less of the forest is a button somebody clicks at 02:00. The run completes the
forest or it fails.

**None of this is built, and that is deliberate.** No capture of this product's predecessor, across
many production forests, has ever failed during capture — so the dialog, the candidate-controller
list and the hand-off are machinery for an event nobody has observed. The decision point is named
here and the automatic policy is built; the rest waits for a failure to justify it.

## The guards were mutation-tested

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | `Task.WhenAll` added to a file that talks to a directory | The fan-out rule fires | `NoFileBothTalksToADirectoryAndFansOutItsWork` fired |
| 2 | `Task.WhenAll` added to a file that does **not** talk to a directory | Nothing fires — this is the case the rule must permit | Nothing fired |
| 3 | The directory-detection pattern changed to match nothing | The self-test fires rather than the guard passing on an empty conjunction | `TheScannerReadsTheCaptureProjectAndBothPatternsMatch` fired |
| 4 | `MaxConnIdleTime`'s default changed to 600 seconds in the limits table | The default check fires | `EveryLimitCarriesTheSameDocumentedDefaultInBothPlaces` fired |
| 5 | The `MaxValRange` row renamed, so a limit the code names is undescribed | The first direction fires | `TheDocumentDescribesEveryLimitTheCodeNames` fired |
| 6 | `ServerDown`'s documented code changed from 81 to 82 | The code check fires | `EveryFailureCarriesTheSameCodeInBothPlaces` fired |
| 7 | The `Timeout` row renamed, so a failure the policy answers is undescribed | The first direction fires | `TheDocumentDescribesEveryFailureThePolicyAnswers` fired |
| 8 | `ServerDown` answered by resending the request rather than restarting | The conversation check fires | `AFailureThatEndsTheConversationIsNeverAnsweredByResendingTheRequest` fired |
| 9 | An unknown failure code answered with `Busy` rather than the catch-all | The answer check fires | `EveryPossibleFailureCodeGetsAnAnswer` fired |

Mutation 2 is the one worth reading twice. A guard that fires on everything is as useless as one
that fires on nothing, and the rule here is deliberately narrower than "capture is
single-threaded": running several naming contexts at once is expected and safe. That mutation is
the evidence the guard permits it.

Every mutation was confirmed present in the file before the result was believed, and every one was
reverted.

## What this document and its test cannot tell you

**Whether capture is polite in practice.** Nothing in the rebuild has issued a request. The test
binds the table to the limits the code names and to the two values the code uses — page size and
time limit — and the guard forbids the shapes that fan work out. It cannot prove that the code
awaits each page before requesting the next, because there is no code that requests a page yet:
that is inventory row B6.

**Whether these values are the right values for a given forest.** They are the documented defaults.
A forest that has lowered `MaxPageSize` simply returns smaller pages and the paging loop never
notices; a forest that has lowered `MaxQueryDuration` may return `timeLimitExceeded` on a page, and
what capture does then belongs to B6's retry behaviour, which is not built.

**What a capture actually costs a controller.** Nobody has measured it. The nearest thing to a
number is the owner's production observation quoted above, and it measures wall-clock for a whole
run rather than load on a server. F-S7-13 records the related gap — that nobody has priced what
removing capture-side exclusion added — and both want the same instrument on the same forest.
