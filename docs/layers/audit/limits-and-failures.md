# What a controller's limits oblige

**Code:** `next/src/SecureAD.Audit/Capture/ServerLimits.cs`, `RetryPolicy.cs`
**Layer:** Audit — speaks to a customer's directory.

The limits a domain controller places on LDAP work, and what capture does when a request fails.

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `ServerLimits` | The table of limits, compiled into the assembly. Reads nothing and cannot fail |
| `ServerLimit` | One limit: its name in the controller's own query policy, the default Microsoft documents, what the controller does when it is reached, and what capture does about it |
| `RetryPolicy` | What capture does when a request fails, and the two budgets — three attempts at a request, one restart of a naming context |
| `DirectoryFailure` | One way a request can fail: its LDAP name and result code, the first wait, the response, and both halves of why |
| `FailureResponse` | `RetryTheRequest`, `RestartTheUnit` or `EndTheRun` — the three states a paging bookmark can be in |
<!-- TYPES:END -->

Each type carries its own reasoning in its XML documentation, including the Microsoft sources it is
anchored to. **That is the reference; this page is the orientation.**

---

## What this is for

A capture is the heaviest thing this product ever does to a customer's machine: a subtree search of
every partition in a forest, against a server that is also authenticating everybody's logons. Two
things follow, and they pull in the same direction rather than against each other.

**The obvious one is courtesy.** An audit tool that degrades a domain controller is one a customer
runs once.

**The one that matters more is correctness.** Every limit here, when it is reached, produces a
partial answer or a broken conversation — and the failure mode of both is a capture that reports
less of a forest than exists while looking exactly like one that read all of it. `MaxValRange` turns
a ten-thousand-member group into fifteen hundred members. `MaxConnIdleTime` closes a connection
whose paging bookmark is the only thing that knows where the read had got to. So the limits are not
a politeness budget with a correctness footnote. They are the same subject twice.

---

## There is no rate limit, and that is a decision

A client-side requests-per-second budget would measure the wrong thing. What a controller spends on
a capture is objects read, temporary-table pressure and bytes serialised — none of which is
proportional to how many requests were sent. One request is a page of up to a thousand objects, so
a rate expressed in requests can be met exactly while the load varies by an order of magnitude.

**A setting that reads as a lever over production impact and is not one is worse than no setting,
because an operator will believe it.**

What replaces it is not a smaller number. It is a constraint — **requests are never pipelined** —
held by a build guard rather than by a value in a settings file. `SerializedDirectoryAccessGateTests`
fails the build if a fan-out shape appears anywhere in the audit project. The thing that actually
protects a customer's controller is that only one request from this product is ever in flight
against it, and that is also what keeps two paged searches from competing for the one
`MaxResultSetSize` budget a controller relieves by discarding the oldest intermediate results.

---

## The limits

Every value is the documented default from
[View and set LDAP policy in Active Directory by using Ntdsutil.exe](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil).
They are *defaults*: an administrator may change any of them, and a forest that has raised or
lowered one is not misbehaving. Capture treats them as the smallest thing it may assume, never as a
promise.

**Every limit says what capture does about it, and never nothing.** A limit capture does not respect
is a limit capture will meet, and the answer has to say at least what happens then.

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

`MaxConnIdleTime` closes a connection the client has left silent for fifteen minutes and returns an
LDAP disconnect notification when it does. It gets its own paragraph because capture is deliberately
serialised and a large forest is minutes of work, so *could a connection go idle?* is a fair
question to ask of this design.

Between two pages, no — the gap is one write to the bundle, and no page can outlast
`MaxQueryDuration` anyway. Between two units the question does not arise: a unit opens its own
connection and closes it.

**What matters is not whether it happens but what happens if it does.** A closed connection must
surface as a failed request, and a failed request must never be read as the end of the results. That
is the paging defect arriving by a different route, and it is why this limit is recorded rather than
dismissed as inapplicable.

### `MaxActiveQueries` is listed so that it is not cited

It once bounded concurrent searches and returned `busy` past twenty. Microsoft records that it has
**not been enforced since Windows Server 2003** and does not appear in that version's tooling. A
limit that looks like a safety margin and is not one is exactly what a later session would lean a
concurrency decision on. The real constraint on concurrency is `MaxResultSetSize`.

---

## When a request fails

Capture is fail-fast: a naming context it cannot read ends the run. That is what makes retrying
worth doing rather than what makes it unnecessary — without it, one stalled request throws away
everything read so far, and a capture is minutes of work against a production server somebody had to
schedule.

The policy is `RetryPolicy`, a table of `DirectoryFailure` entries each carrying a
`FailureResponse`, and it turns on one distinction: **whether the failure left the conversation with
the controller intact.**

A paged read holds an opaque bookmark that only means something inside one live conversation. If the
conversation survives, the same request can be sent again. If it does not, the bookmark died with it
— and a paged read **cannot be resumed from the middle**, because LDAP has no way to say *carry on
from object forty thousand*. So there are three answers and no fourth:

- **Retry the request.** Same connection, same bookmark, after a wait.
- **Restart the naming context.** New connection, from the first page, discarding what the abandoned
  attempt read rather than merging it. This costs time and costs nothing else: a capture is not a
  frozen instant anyway — it is read page by page over minutes while the forest changes underneath
  it — so a partition read from the start half an hour later is no less accurate.
- **End the run**, naming the naming context and the point reached.

**Three attempts at a request, and one restart of a naming context.** Three because two of these
failures are a controller saying it is under load, and a client that answers *I am busy* by asking
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

**An unknown code gets an answer rather than nothing.** `RetryPolicy.FailureFor` always returns a
`DirectoryFailure`; an unlisted code returns `Unrecognised`, which ends the run. A lookup that can
return *no instruction* is the shape that produces a swallowed exception at the call site.

---

## Do not change without reading this

**Do not add a fourth `FailureResponse`.** The three exist because there are exactly three states a
paging bookmark can be in: still good, gone, or not worth pursuing. A fourth would have to describe
a bookmark that is partly good, and there is no such thing.

**Do not answer `ServerDown` or `Timeout` by resending the request.** Both mean the conversation
ended, so the bookmark went with it, and resending offers the controller a bookmark it has no memory
of. `AFailureThatEndsTheConversationIsNeverAnsweredByResendingTheRequest` is the check that holds
this, and it names all five responses so that a change to any of them fails rather than a change to
one.

**Do not add a resume.** Anything that appeared to resume a paged read would be a partial read
reported as complete, which is the failure the whole subsystem exists to prevent.

**Do not raise `MaxQueryDuration` to make a large partition fit.** Under paging the limit bounds one
page, not a partition, so a partition never needs a raised limit — and Microsoft advises against
raising it. A page that cannot be assembled in two minutes wants a smaller page.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a busy controller is retried a bounded number of times and then the run ends | `PartitionCaptureTests.AControllerSayingItIsBusyIsAskedThreeTimesAndThenTheRunEnds` |  |
| be certain no part of the product opens two directory conversations at once | `SerializedDirectoryAccessGateTests` |  |
