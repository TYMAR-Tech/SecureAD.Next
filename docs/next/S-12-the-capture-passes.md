# S-12 — The capture passes

**Type:** slice
**Inventory row:** B6 — per-domain LDAP capture module
**Lands in:** `SecureAD.Audit`
**Date:** 2026-08-12

---

## What this is, in one paragraph

This is the first thing in the rebuilt product that does something to a customer's directory rather
than describing what would be done. It takes one partition and one connection, issues a search,
takes a page, asks for the next, finishes any attribute the controller would not send at once, and
stops when the controller says there is nothing left. Everything before it — the catalogue of what
to ask for, the shape of the request, the limits, the reader — was a description. This is the part
that runs.

The code is [`PartitionCapture`](../../next/src/SecureAD.Audit/Capture/PartitionCapture.cs), with
[`CapturePlan`](../../next/src/SecureAD.Audit/Capture/CapturePlan.cs),
[`PartitionCoverage`](../../next/src/SecureAD.Evidence/PartitionCoverage.cs),
[`DirectoryPage`](../../next/src/SecureAD.Audit/Capture/DirectoryPage.cs) and
[`IDirectoryChannel`](../../next/src/SecureAD.Audit/Capture/IDirectoryChannel.cs) beside it.
`CapturePassesDocumentationTests` holds this document to it. Per [`README.md`](README.md)
§When a document counts as documentation, this file is not documentation until that test holds.

## The failure this exists not to have

> **A paged search ends when the controller returns an empty bookmark. There is no way to tell that
> from a search whose bookmark was thrown away.**

A client that follows a subordinate referral in the middle of a paged search has the bookmark
overwritten inside the LDAP runtime. The application reads an empty one on the first page and
concludes it has read everything. A thousand objects out of nine million, no error, and a report in
which every finding is true and the absence of every other finding means nothing — with nothing on
the screen distinguishing the two.

**And it cannot be detected from the answer.** This is worth stating precisely, because the obvious
instinct is to look for a tell. Microsoft's description of the defect is that there is none: *"the
paged cookie it receives is empty and thus the application ends the query. In a network trace, you
can verify that the paged query **does** return a non-empty cookie along with one or more
referrals"* ([LDAP paged queries with subordinate referrals are not chased
properly](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased)).
The controller behaved correctly. The client library discarded the answer. By the time the loop sees
anything, the evidence is gone, and the article's Resolution section reads in full: *"There is
currently no resolution for the problem."*

So this component does not try. It refuses to make the claim.

> **A partition is never reported as read whole unless the connection has said that referral chasing
> was off.**

The check is the first thing the loop does, before a request is sent, and it reads the policy
actually in force on the connection rather than assuming the policy that was supposed to be applied.
That is why [`IDirectoryChannel`](../../next/src/SecureAD.Audit/Capture/IDirectoryChannel.cs) reports
it: a setting that is only correct if somebody remembered is not a mechanism.

Two tests are the evidence, and they are a pair on purpose. One runs the loop against a controller
holding two and a half thousand objects on a connection that chases referrals and asserts that
**nothing is sent at all**. The other runs the identical controller with chasing off and asserts the
partition is read. Either alone would prove less than it looked like proving.

## What a completed pass returns, and why it is a type

> **There is one successful outcome, it is a `PartitionCoverage`, and the loop is the only thing
> that can make one.**

"Ran without throwing" is not a statement that a partition was read. A capture that reads the first
page of a forest and stops also runs without throwing. So the claim is not a flag on a result that a
caller might not look at, and it is not the absence of an error. It is the existence of a record that
can only come into being at the moment the controller said there was nothing more to send, on a
connection that could not have chased anything.

Everything else is an `AuditError` and ends the run. Capture is fail-fast — a naming context it
cannot read fully produces no bundle — so there is no partial success, nothing to check afterwards,
and no third state that a later reader has to learn the meaning of.

The record carries two things that are caveats rather than counts. `ContinuationReferences` is the
controller's own statement of what else exists below what was searched, which
`ContinuationReferenceReconciliation` compares against what the run planned. And
`ReferralsSuppressed` says whether this unit was asked to produce none at all, because *"nothing was
mentioned"* and *"we asked not to be told"* are different facts and rendering the second as the first
is what [`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids.

## Every way a pass can end

Each row is a code the loop actually produces. The table is held to the code in both directions: a
code with no row fails the build, and a row naming no code fails it too.

<!-- ENDINGS:BEGIN -->

| Ending | What happened | Why it is not survivable |
|---|---|---|
| ConnectionIsToAnotherController | The connection handed in is to a different host from the one the unit names | One controller per unit is what makes a failure name one unit unambiguously. Reading from whichever host answered would make the coverage record say something it cannot support |
| ReferralPolicyNotAppliedToConnection | The connection reports a referral policy other than None | A paged search on such a connection ends after its first page reporting success, and nothing in the result says so. No partition is read on it at all |
| ControllerCapabilitiesWereNotRead | The connection cannot say which controls the controller advertises | The domain-scope control is sent only where it is advertised, so an unread capability list silently drops the second line of the referral defence. A defence that is quietly absent is worse than one that was never claimed |
| PagedSearchWasNotPaged | A response carried no paging control | The controller did not say whether there is more. An answer that cannot say it was the last one is not the last one, and treating it as one is how part of a forest is reported as the whole of it |
| PagedSearchRepeatedItsCookie | The controller handed back the same bookmark it was given | The next request would be the request just made, forever. The read stops rather than looping or settling for what it has |
| DirectoryRequestFailed | A request failed, and the retry policy ran out of answers | The policy in [`S-10`](S-10-politeness.md) has already tried what it is allowed to try: three attempts at a request, one restart of the naming context |
| CapturePlanReadsNoDomain | A plan was built that names no domain partition | Every forest has at least one domain. A plan holding only the configuration and schema partitions would seal a bundle with no principals, no permissions and nothing to audit, while looking like a capture that worked |

<!-- ENDINGS:END -->

### An empty page is not one of them

A controller may return a page with no objects on it and still report success. Microsoft is explicit:
that *"indicates that the server was unable to retrieve a page of results, due to a timeout or other
reason, but has not completed the search request"*, and the correct behaviour is to keep asking
([ldap_get_next_page_s](https://learn.microsoft.com/windows/win32/api/winldap/nf-winldap-ldap_get_next_page_s#remarks)).
So the loop follows a bookmark whatever the page contained, and only a bookmark decides.

That is deliberately **not** the rule [`S-11`](S-11-reading-what-a-controller-returns.md) applies one
layer down, where a block of an attribute that carries no values is a failure. The two look alike and
are not: an attribute retrieval is bounded by progress because the controller has already said there
are more values, while a paged search is bounded by the bookmark because the controller has not said
anything of the kind. What stops the page loop spinning is the one thing that would make it spin —
the same bookmark twice — and that is a stated ending above.

### The three things a bookmark can mean are a type

`PageCompleteness` is on every `DirectoryPage`, and it exists because "no bookmark" is two different
answers: **NotPaged**, meaning the response carried no paging control and the controller said nothing
about whether there is more, and **LastPage**, meaning it said there is nothing more. The third,
**MoreToCome**, carries the bookmark to send back. A nullable array with the difference explained in
prose beside it would have worked and would have put the distinction where a reader has to notice it;
this puts it where the compiler does. It is the same move [`S-11`](S-11-reading-what-a-controller-returns.md)
makes with `AttributeCompleteness` and for the same reason.

The same applies to what an object says about itself. `ObjectCompleteness` on every `CapturedObject`
says whether every attribute capture asked about came back. Most objects will say some did not,
because the whole catalogue is asked for on every object and most objects have no value for most of
it — and that is exactly why the fact travels with the object rather than being inferred later from
an empty list, since an attribute is equally absent when it was never set and when the reader was not
permitted to see it.

## Which naming contexts a run reads

A forest is read partition by partition, never domain by domain — [`S-9`](S-9-the-capture-unit.md)
says why. `CapturePlan` is the list.

**Nothing is discovered here.** The plan is built from what it is handed: the forest's domain
partitions, its configuration and schema partitions, and the list of partitions the chosen controller
publishes about itself. Working out which is which is branch A's, and the reason it is kept there is
that a partition list alone cannot tell a domain from an application partition —
`DC=DomainDnsZones,DC=example,DC=com` is spelled exactly as a domain is, and the only reliable answer
is in the configuration partition's cross-references. A component that guessed from the name would be
right on every forest anybody builds to test it and wrong at a customer.

**The configuration and schema partitions are read first.** They are a few thousand objects once per
forest and they are what everything else is interpreted against: a permission naming a schema
identifier means nothing until the schema partition has been read, per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md). Capture is fail-fast, so a run that
is going to fail on them should fail in its first minute rather than after three hours of a
customer's largest domain.

**Everything published and not planned is recorded.** The DNS application partitions are out of scope
per the DNS scope decision of 2026-08-11, and anything else the controller mentions is out of scope
because nobody has decided it is in. Either way the run says which, rather than saying nothing.

**Every unit is confirmed against what the controller publishes**, using `CaptureUnit.ConfirmServedBy`
— which B4 built and left without a caller. It costs nothing here, because the published list is
already in hand, and discovering at hour two that a controller was never going to answer for a
partition costs the whole capture. Inventory row A8, preflight, is where the same question is asked of a
live connection before anything is read; this row does not wait on it.

## Where range retrieval is driven from

A domain controller will not return more than a fixed number of values for one attribute of one
object, and the rest have to be asked for a block at a time — [`S-11`](S-11-reading-what-a-controller-returns.md).
That component decides *which block*. This one is what asks, because asking is a request and requests
belong here.

> **An object's outstanding blocks are fetched between two pages, on the same connection, and never
> inside a page.**

The paged search is halfway through the partition while this happens, which is the part worth
justifying rather than assuming. It is safe because a range retrieval is a **base-scope search of one
object with no paging control**: it creates no paging state of its own, so it cannot compete with the
search already in flight for the controller's `MaxResultSetSize` budget — the budget that F-S7-12
records a controller relieving by discarding the oldest intermediate results. What *would* disturb the
search in flight is a referral being followed on the same session, and referral chasing is off,
checked before the first request. It is the same mechanism, seen once more from another side.

The alternative was to collect every unfinished attribute and drain them after the last page. It was
refused because it means holding every part-read object for the length of a partition, which works on
a lab forest and exhausts a machine on a customer's — and it buys nothing, since the bookmark sits in
the controller's cache for exactly as long either way.

**An object leaves the loop complete or the loop fails.** `CapturedObject` refuses one carrying an
attribute still marked as having more to fetch, so nothing downstream can be handed the first fifteen
hundred members of a ten-thousand-member group and mistake them for the group.

## Two things about the request that changed here

Both live in `CaptureSearchRequestFactory`, because it is the one place permitted to build a search,
and both are described in [`S-9`](S-9-the-capture-unit.md)'s table alongside everything else.

**The security-descriptor flags control is now sent**, asking for owner, group and DACL and never the
SACL. `nTSecurityDescriptor` is requested on every object, and the SACL — the audit half of a
descriptor — is privileged: retrieving it is one of the operations Microsoft lists as failing with
insufficient access rights for a caller without the privilege behind it
([ldap_bind_s](https://learn.microsoft.com/windows/win32/api/winldap/nf-winldap-ldap_bind_s#remarks)).
What that buys a customer is that **a capture runs as an ordinary authenticated user**: nobody has to
grant an audit tool a privilege on their domain controllers before it will read anything, and the
product never holds the audit configuration of a forest it was asked only to inspect permissions on.

**A second kind of request exists**: the range retrieval, base scope, one object, one ranged attribute
name, not paged. It carries the same security-descriptor flags and not the domain-scope control, which
asks a controller not to generate referrals below a domain root and has nothing to apply to a search
of a single object.

## How this is tested, and what the tests do not reach

There is no forest in a build agent, so the loop runs against a **controller model** written from the
articles cited above: it serves at most a page at a time and returns a bookmark while there is more,
returns none on the last page, will not put more than `MaxValRange` values of one attribute in one
response, answers a range retrieval under the ranged name it served, and marks the final block with
the wildcard. It can also be told to misbehave in each of the specific ways the endings table names.

That reaches: a partition of two and a half thousand objects read in three pages; a connection that
chases referrals refused before a single request leaves; a ten-thousand-member group finished across
nine further requests, at the 1,500 default and again at the 5,000 ceiling; an empty page followed
rather than believed; a repeated bookmark refused; a controller saying it is busy asked three times
with the wait doubling; a connection lost and the naming context read again from the start, once and
not twice.

**What it does not reach is the wire.** Whether a production controller behaves as the model does is a
claim about a server, and no test in this repository can settle it. Three things are owed to the lab
session and recorded rather than implied by a green test: the spelling of a ranged name (F-S7-37,
already open), whether a controller tolerates a base-scope search between two pages of a paged search
(F-S7-39), and what a client actually sees when a controller evicts a paging bookmark from its cache
(F-S7-40).

**And it cannot tell you that anything has ever run.** This component is a library. It has no caller,
because choosing a controller and opening a connection is branch A and writing what it reads to a
bundle is branch C, and neither exists. Gate 5b — every public type reachable from something that runs
— therefore stays blocked, and what is missing is not this row but an entry point. That is stated
plainly in [`README.md`](README.md) §Status rather than being quietly satisfied by declaring this row
a root, which would be choosing the answer.

## The guards were mutation-tested

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | The referral-policy check inverted, so a chasing connection passes it and a correct one does not | Both halves of the pair fire | `AConnectionThatChasesReferralsIsRefusedBeforeAnyRequestIsSent` and `TheSameControllerIsReadWhenChasingIsOff` both fired, with fourteen others |
| 2 | The paging-control check made unreachable | An answer that never mentioned paging is read as the last page | `AnAnswerWithNoPagingControlIsNotTheLastPage` fired, and **only** it — sixteen others passed, which is what shows the check is narrow |
| 3 | The repeated-bookmark check made unreachable | The loop spins on a controller handing its bookmark back | **The test did not finish.** Still running when it was stopped after forty-five seconds. That is the failure the check exists to prevent, observed directly rather than as an assertion |
| 4 | The `PagedSearchRepeatedItsCookie` row deleted from the endings table | The first direction fires | `TheDocumentDescribesEveryWayAPassCanEnd` fired |
| 5 | An invented ending added to the table | The other direction fires | `TheDocumentDescribesNoEndingThatCannotHappen` fired |
| 6 | The scan pattern changed to match nothing | The self-test fires rather than the checks passing on an empty set | `TheScannerReadsTheLoopAndTheDocumentAndItsPatternMatches` fired |
| 7 | The SACL added to the security-descriptor flags the request asks for | The S-9 request check fires | `EveryPropertyOfTheSearchIsDescribedAndDescribedCorrectly` fired |
| 8 | The capability check made unreachable | A connection that cannot say what the controller advertises is read anyway | `AConnectionThatCannotSayWhatTheControllerAdvertisesIsRefused` fired, and only it |

Every mutation was confirmed present in the file *and compiled* before the result was believed, and
every one was reverted and the whole suite re-run green afterwards. Mutations 1, 2, 3 and 8 were run
against the final form of the loop, after the refactor described below.

**Three things went wrong doing this, and all three are worth reading.**

**The first run of mutation 1 passed.** The mutation was confirmed present in the source file, the
tests were run, and all sixteen passed — because `dotnet test` had not rebuilt, so the run measured
the unmutated assembly. A mutation that reaches the file and not the build produces a green run that
looks like evidence the guard is unnecessary, which is the same shape as every other check in this
repository that passed while measuring nothing. Every mutation above therefore builds explicitly and
then tests with `--no-build`. That is finding F-S7-41.

**A refactor silently blinded the scanner.** The endings were first written as direct calls to
`AuditError.Create`; tidying five of them behind a `Refuse` helper meant the document check's pattern
no longer matched them, so it was comparing two much smaller sets and finding them consistent. It
failed loudly only because the self-test asserts a floor on how many endings the scan finds. That
floor was written for exactly this reason and it is the only thing that caught it.

**A cancelled mutation run left the mutation in the file.** The revert was in a `finally` block, and
a `finally` does not run when the command is cancelled from outside. It was caught by checking the
file immediately afterwards rather than by the safety net. Mutations that can hang are now applied
and reverted through the editor rather than the shell, and the file is checked after any interrupted
run.


## What this row does not own

- **Choosing a controller, or opening a connection.** Branch A. What is built here is the shape of
  the hand-off — `IDirectoryChannelFactory`, which exists because one line of the failure policy
  demands it: when a failure ends the conversation with a controller the paging bookmark dies with
  it, and the answer is to read the naming context again from its first page on a *fresh* connection.
  A component handed a connection could not do that, so it could not implement the policy it is
  meant to be applying, and the budget of one restart per naming context would live nowhere.
- **Writing anything down.** Objects go to an `ICapturedObjectSink` as each one is finished, rather
  than being returned in a list — a forest partition is millions of objects and a list of them is a
  design that works in a lab and runs a machine out of memory at a customer. What implements it is
  the bundle writer, inventory rows B9 and B10, and it does not exist.
- **Deciding which partitions exist.** `CapturePlan` is given them.
- **Two passes over the same objects.** The old implementation read every object twice, once for
  identity and once for permissions, and the reason was never recorded. There is one pass here: the
  whole attribute catalogue is requested on every object in one request, and the security-descriptor
  flags control that made the second pass look necessary is simply on the first one. If a measurement
  ever shows that page sizes suffer for it, that is a change to the page size rather than a second
  enumeration of a nine-million-object forest.
