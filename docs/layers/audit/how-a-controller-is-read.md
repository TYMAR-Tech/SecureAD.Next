# How a controller's answer is read

**Code:** `next/src/SecureAD.Audit/Capture/PartitionCapture.cs`, `IDirectoryChannel.cs`,
`DirectoryPage.cs`, `LdapEntryReader.cs`, `AttributeValues.cs`, `AttributeRange.cs`,
`CapturedObject.cs`, `ContinuationReferenceReconciliation.cs`, `BundleCaptureSink.cs`,
`CaptureRun.cs`
**Layer:** Audit — speaks to a customer's directory.

The part that runs: take one partition and one connection, issue a search, take a page, ask for the
next, finish any attribute the controller would not send at once, and stop when the controller says
there is nothing left.

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `CaptureRun` | The run driver: walks the plan's units in order, reads SYSVOL, and seals the bundle |
| `CaptureRunResult` | What a run produced: the outcome, the directory it wrote into, and why it ended badly if it did |
| `RunCompletion` | `Sealed` or `Ended`. Two endings and no third, because a bundle that is not sealed is not evidence |
| `PartitionCapture` | The loop: one naming context read whole, restartable once |
| `IDirectoryChannel` | The seam between the product and a customer's forest — and the thing that reports the referral policy actually in force |
| `IDirectoryChannelFactory` | How a connection is opened, and reopened when a failure ends the conversation. It exists because a component handed a connection could not restart a unit on a fresh one |
| `DirectoryPage` | One answer: the entries, whether there is more, the bookmark, and the partitions mentioned on the way past |
| `PageCompleteness` | `NotPaged`, `MoreToCome` or `LastPage` — because "no bookmark" is two different answers |
| `LdapEntryReader` | One entry as a controller returned it, and the rules for turning what it carries into typed values |
| `AttributeValues` | The values of one attribute, and whether they are all of them, as one type |
| `AttributeCompleteness` | `Complete`, `MoreToFetch` or `NotReturned` |
| `AttributeRange` | One block of an attribute's values. The only place in the product that spells a range specifier |
| `CapturedObject` | One finished object. Refuses construction while any attribute is still unfinished |
| `ObjectCompleteness` | Whether every attribute capture asked about came back |
| `ICapturedObjectSink` | Where finished objects go, one at a time rather than as a list |
| `BundleCaptureSink` | The join between capture and storage. Deliberately thin: it maps and decides nothing |
| `ContinuationReferenceReconciliation` | What the references revealed — and whether it could see anything at all |
| `PartitionCoverage` | What one pass over one naming context on one controller actually read, and the grounds on which the run may say that was all of it |
<!-- TYPES:END -->

Each type carries its own reasoning in its XML documentation, including the Microsoft sources it is
anchored to. **That is the reference; this page is the orientation.**

---

## The claim this refuses to make

> **A paged search ends when the controller returns an empty bookmark. There is no way to tell that
> from a search whose bookmark was thrown away.**

A client that follows a subordinate referral in the middle of a paged search has the bookmark
overwritten inside the LDAP runtime. It reads an empty one on the first page and concludes it has
read everything.

**And it cannot be detected from the answer.** Microsoft's description of the defect is that there
is no tell: *"the paged cookie it receives is empty and thus the application ends the query. In a
network trace, you can verify that the paged query **does** return a non-empty cookie along with one
or more referrals"*
([LDAP paged queries with subordinate referrals are not chased properly](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased)).
The controller behaved correctly. The client library discarded the answer. By the time the loop sees
anything, the evidence is gone.

So this component does not try to detect it. It refuses to make the claim.

> **A partition is never reported as read whole unless the connection has said that referral chasing
> was off.**

The check is the first thing the loop does, before a request is sent, and it reads the policy
**actually in force on the connection** rather than assuming the policy that was supposed to be
applied. That is why `IDirectoryChannel` reports it: a setting that is only correct if somebody
remembered is not a mechanism.

Two tests are the evidence and they are a pair on purpose. One runs the loop against a controller
holding two and a half thousand objects on a connection that chases referrals and asserts that
**nothing is sent at all**. The other runs the identical controller with chasing off and asserts the
partition is read. Either alone would prove less than it looked like proving.

---

## How the pieces fit

```
CaptureRun ── walks the plan's units in order
   │
   └─ PartitionCapture.ReadAsync ── one unit, restartable once
        │
        ├─ IDirectoryChannelFactory.Connect ──► IDirectoryChannel
        │      reports DomainController, ReferralChasing, SupportedControls,
        │      NamingContextsServed, SecurityLevel, IsComplete
        │
        ├─ SendAsync ──► DirectoryPage
        │      Entries (LdapEntryReader each), PageCompleteness,
        │      PagingCookie, ContinuationReferences
        │
        ├─ per entry: LdapEntryReader.ValuesOf ──► AttributeValues
        │      and while MoreToFetch: ForAttributeBlock ──► Continue
        │                                     └──► CapturedObject.Create
        │
        └─ ICapturedObjectSink ──► BundleCaptureSink ──► BundleWriter
                                        └──► PartitionCoverage
```

---

## There is one successful outcome and it is a type

> **A partition read whole produces a `PartitionCoverage`, and the loop is the only thing that can
> make one.**

*"Ran without throwing"* is not a statement that a partition was read. A capture that reads the
first page of a forest and stops also runs without throwing. So the claim is not a flag on a result
that a caller might not look at, and it is not the absence of an error. It is the existence of a
record that can only come into being at the moment the controller said there was nothing more to
send, on a connection that could not have chased anything.

Everything else is an `AuditError` and ends the run. Capture is fail-fast — a naming context it
cannot read fully produces no bundle — so there is no partial success, nothing to check afterwards,
and no third state a later reader has to learn the meaning of.

The record carries two things that are caveats rather than counts. `ContinuationReferences` is the
controller's own statement of what else exists below what was searched. And `ReferralsSuppressed`
says whether this unit was asked to produce none at all, because *nothing was mentioned* and *we
asked not to be told* are different facts and rendering the second as the first is what
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) forbids.

It also carries the `ConnectionSecurityLevel` the connection reached, and that is not decoration. A
Windows Server 2025 controller strips confidential attributes from an unencrypted search and returns
**no error to the client**, so a partition read on a low rung can be missing values with nothing
else in the bundle recording their absence. That is `F-S24-1`, and it is why the rung is stored per
partition rather than logged.

---

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
| DirectoryRequestFailed | A request failed, and the retry policy ran out of answers | The policy in [limits and failures](limits-and-failures.md) has already tried what it is allowed to try: three attempts at a request, one restart of the naming context |
| CapturePlanReadsNoDomain | A plan was built that names no domain partition | Every forest has at least one domain. A plan holding only the configuration and schema partitions would seal a bundle with no principals, no permissions and nothing to audit, while looking like a capture that worked |
| ExclusionDoesNotMatchDeclaredDomain | An exclusion key, attested naming context or attested DNS name does not match the exact domain pairing discovered for this forest | An exclusion authorizes omission of one exact domain. Applying it to another domain, or accepting a reconstructed pairing, would seal evidence whose declared scope and attestation contradict each other |

<!-- ENDINGS:END -->

---

## Three states a page can be in

`PageCompleteness` is on every `DirectoryPage`, and it exists because "no bookmark" is two different
answers: **NotPaged**, meaning the response carried no paging control and the controller said
nothing about whether there is more, and **LastPage**, meaning it said there is nothing more. The
third, **MoreToCome**, carries the bookmark to send back.

A nullable array with the difference explained in prose beside it would have worked and would have
put the distinction where a reader has to notice it. This puts it where the compiler does.

`DirectoryPage.From` is the one place that decides which of the three a response was, because two
channels deciding separately would be two opinions about when a partition has been read.

**An empty page is legitimate.** A controller may return one and still report success, meaning it
could not build a page this time and has not finished. What is not legitimate is being handed the
same bookmark back — then the next request is the request just made, and the loop is a spin.

---

## The limit that makes attribute reading hard

> **A domain controller will not return more than a fixed number of values for one attribute of one
> object, and an administrator cannot lift that limit out of the way.**

The number is `MaxValRange` in the forest's LDAP policy, **1,500 by default**. Raising it works only
up to a point: Windows Server 2008 and later carry **hardcoded ceilings that override the policy**,
and for this limit the ceiling is **5,000 values**. Microsoft's own worked example is this product's
exact use case — a policy set to 25,000, and a query for the members of a group with more than 5,000
members returning 5,000
([Windows Server 2008 and newer domain controller returns only 5000 values in an LDAP response](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response)).

**What it looks like from the client's side.** Microsoft's description is broader than a single tidy
rule: the results *"may appear truncated or incomplete. In some occasions, you may not get any
results."* There is no error, no warning and no count. The one unambiguous sentence is the remedy:
where an attribute has more values than the limit, *"you must use value range controls in LDAP to
retrieve values that exceed the MaxValRange value"* — and for a group larger than a server will
serve at once, range retrieval is *"the only way to enumerate all members"*
([Enumerating groups that contain many members](https://learn.microsoft.com/windows/win32/ad/enumerating-groups-that-contain-many-members)).

### Asking for the rest

Values are asked for a block at a time, by naming the attribute with a range option after it:

```text
member;range=0-999
```

The two numbers are zero-based indexes of the first and last value wanted, and `*` in place of the
second means "and all the remaining ones"
([Attribute Range Retrieval](https://learn.microsoft.com/windows/win32/adsi/attribute-range-retrieval)).

**A block is a thousand values.** Microsoft's guidance is to ask for as many as the server will
serve, but that *"to enable an application to work correctly with all Windows servers, a maximum
number of 1000 should be used."* A thousand is the largest number that is safe everywhere rather
than a compromise.

**How a block says it was the last one.** The controller answers under the ranged name it actually
served, and on the final block it puts `*` in place of the high number instead of echoing what was
asked for: ask for `member;range=101-200` on a group of 150 and the name that comes back is
`member;range=101-*`
([Using IDirectorySearch and IDirectoryObject for Range Retrieval](https://learn.microsoft.com/windows/win32/adsi/using-idirectorysearch-and-idirectoryobject-for-range-retrieval)).
That wildcard, and nothing else, ends a retrieval. Not an empty block, not a short block, and not a
count that looks about right.

**The next block is computed from what arrived, not from what was asked for.**
`AttributeRange.NextAfter` takes the count returned, so a controller that served fewer values than
requested — which it is entitled to do, and which is what a lowered `MaxValRange` looks like from
the client's side — is followed rather than skipped over.

**Nothing else in the product spells a range.** `AttributeRange` owns the specifier, and
`RangeSpecifierGateTests` fails the build if the text appears anywhere else under `next/src/`. A
second speller is a second opinion about where a block ends, and the two do not disagree loudly —
both produce a plausible name, one of them gets fewer values, and nothing says so.

**This component asks for nothing.** It produces the *name to ask for*. Building a request belongs
to `CaptureSearchRequestFactory`.

### Which attributes are range-retrieved

Every multi-valued one, and the question is never asked about an attribute by name. Whether an
attribute can hold many values is `CapturedAttribute.Cardinality` and is derived from there. A
hand-kept list of "the attributes that need range retrieval" agrees with the catalogue on the day it
is written and stops agreeing the first time somebody adds a multi-valued entry. The failure is
silent and the symptom is a large group reported small.

---

## Three things an entry can say

`AttributeCompleteness` is carried on every answer.

<!-- COMPLETENESS:BEGIN -->

| State | What the response looked like | What a caller may conclude |
|---|---|---|
| Complete | The attribute came back under its own name, or a retrieval ran to the block the controller marked with the wildcard | These are all the values. This is the only state that entitles anyone to say "these are the members" |
| MoreToFetch | The attribute came back under a ranged name whose high bound was a number rather than the wildcard | What is here is the beginning of the values and must never be presented as the values. The answer carries the block to ask for next |
| NotReturned | The response did not carry the attribute at all, under its own name or a ranged one | That the attribute did not come back. Not that the object has none — see below |

<!-- COMPLETENESS:END -->

The third state is the one that costs something to keep, and it is kept deliberately.

**An absent attribute is not a fact about the forest.** An attribute is missing from an entry when
it was never set. It is equally missing when the reader was not permitted to see it: an attribute
marked confidential in the schema is withheld from a caller without `CONTROL_ACCESS` on it, and it
is withheld *silently* — the value simply is not there, exactly as though it had never been set
([Mark an attribute as confidential](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential)).
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) forbids rendering the second as the
first.

**Telling the two apart is not this layer's job.** What the schema's `searchFlags` and `systemFlags`
give is whether an attribute *could* have been withheld — never whether it *was*. Nothing on the
wire says so, and a second cause exists the flags cannot see at all: the unencrypted-connection case
above. So this layer's contribution is that `NotReturned` is a distinct state, and no code
downstream can reach an empty list of values without having been handed the fact that the attribute
never arrived.

### Where a retrieval is allowed to stop

> **There is no limit on the number of blocks, and there is no partial answer.**

A cap on rounds sounds prudent and is the defect this exists to remove. A cap that is reached has to
do one of two things: return what it has, or fail. Returning what it has is precisely the behaviour
that turns a ten-thousand-member group into a fifteen-hundred-member one, and putting a large number
on it does not change what it is — it changes how rarely it happens, which makes it harder to find
rather than less harmful.

What bounds the loop instead is **progress**. `LdapEntryReader.Continue` refuses a block that did not
advance, and each refusal has its own name: `RangeRetrievalAnsweredAboutAnotherAttribute`,
`RangeRetrievalStoppedAnswering`, `RangeRetrievalMadeNoProgress`. A failure ends the run, because
capture is fail-fast. The loop cannot spin and it cannot settle for a prefix.

**A partial read cannot describe itself as anything else.** The values and the statement of
completeness are one type, not a list with a flag beside it that a caller might not look at.

---

## Reading a value once it is in hand

Each conversion returns either the value or a stated failure. None substitutes anything: a value
that cannot be read is reported as unreadable, because a substituted value reads like a fact about
the forest.

<!-- CONVERSIONS:BEGIN -->

| Reads a value as | Method | What it refuses |
|---|---|---|
| Text | AsText | Bytes that are not valid UTF-8, rather than replacing them. A distinguished name silently corrupted attributes an object to a container that does not hold it |
| Raw bytes | AsBytes | A value that arrived as text, rather than re-encoding it and hoping |
| A whole number | AsInteger | Text that is not a number. Read at 64 bits, because directory timestamps are 100-nanosecond intervals since 1601 and do not fit in 32 |
| A GUID | AsGuid | Anything that is not exactly sixteen bytes |
| A security identifier | AsSid | Bytes the platform will not accept as a SID. A SID misread by one byte is a permission attributed to the wrong principal |

<!-- CONVERSIONS:END -->

---

## Where range retrieval is driven from

> **An object's outstanding blocks are fetched between two pages, on the same connection, and never
> inside a page.**

The paged search is halfway through the partition while this happens, which is the part worth
justifying rather than assuming. It is safe because a range retrieval is a **base-scope search of
one object with no paging control**: it creates no paging state of its own, so it cannot compete
with the search already in flight for the controller's `MaxResultSetSize` budget. What *would*
disturb the search in flight is a referral being followed on the same session, and referral chasing
is off, checked before the first request.

The alternative was to collect every unfinished attribute and drain them after the last page. It was
refused because it means holding every part-read object for the length of a partition, which works
on a lab forest and exhausts a machine on a customer's — and it buys nothing, since the bookmark
sits in the controller's cache for exactly as long either way.

**An object leaves the loop complete or the loop fails.** `CapturedObject.Create` refuses one
carrying an attribute still marked `MoreToFetch`, so nothing downstream can be handed the first
fifteen hundred members of a ten-thousand-member group and mistake them for the group. The
`ObjectCompleteness` an object carries says whether every attribute capture asked about came back.
Most objects will say some did not, because the whole catalogue is asked for on every object and
most objects have no value for most of it — which is exactly why the fact travels with the object
rather than being inferred later from an empty list.

---

## Where the objects go

`ICapturedObjectSink` takes each object as it is finished rather than returning a list, because a
forest partition is millions of objects and a list of them is a design that works in a lab and runs
a machine out of memory at a customer.

`BundleCaptureSink` implements it and is deliberately thin: it maps what capture produces onto what
the bundle expects and decides nothing. Three things about it are load-bearing.

**The sink is told a partition is starting before the first request.** An object must be attributed
to its partition the moment it is written, and a receiver cannot work out either the rung this
connection reached or whether the domain-scope control was sent. A restart announces the partition
again; a sink that has already seen one open refuses, which is the guard that stops a restarted unit
being recorded twice.

**A descriptor the forest holds that this product could not parse is stored as an unreadable one,
not dropped and not fatal.** A value *this product* cannot represent is a defect in this product and
ends the run; a descriptor *the forest holds* that could not be read is a fact about the customer's
directory and belongs in the evidence. Conflating them is how a real finding gets discarded as a bug
in the reader. An earlier draft wrapped the parse in a `catch`, which would never have fired and
would have made every malformed descriptor look well-formed.

**The catalogue decides how a value is stored, not the runtime type of the value.** This once chose
by inspecting whether the value happened to be a `string` or a `byte[]`, which meant the shape of
the wire decided the shape of the evidence. A live directory sends text as bytes, so every text
attribute in the forest was about to be stored as binary — and the first real capture died on `cn`,
three objects in, against the writer's own guard. That guard was right; this was wrong.

`CaptureRun` walks the plan's units in order and is fail-fast. On any failure the partial evidence
file is left where it is and `run-outcome.json` is written beside it, per
[`0029`](../../decisions/0029-a-run-that-ends-badly-says-so.md). The evidence is never given the name a
reader asks for until the seal, so there is nothing a later run can mistake for a finished bundle.

---

## Do not change without reading this

**Do not read the referral policy from anywhere but the connection.** Assuming the policy that was
supposed to be applied is the whole failure this component exists to refuse.

**Do not treat a response with no paging control as the last page.** An answer that cannot say it
was the last one is not the last one.

**Do not put a cap on range-retrieval rounds.** See above; a cap that is reached must either lie or
fail, and the lie is silent.

**Do not drop an attribute that did not arrive.** `NotReturned` with no values is the distinction
between *we were not allowed to look* and *there is nothing there*.

**Do not collect unfinished objects and drain them at the end of a partition.** It exhausts a
machine at a customer and buys nothing.

**Do not let a second component decide what a `PageCompleteness` is.** `DirectoryPage.From` is the
one place.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory — a controller model built from the
articles cited above is not a domain controller.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be sure a partition larger than one page is read to the end | `PartitionCaptureTests.APartitionLargerThanAPageIsReadToTheEnd` |  |
| be certain the run never wanders to another controller by following a referral | `PartitionCaptureTests.AConnectionThatChasesReferralsIsRefusedBeforeAnyRequestIsSent` |  |
| be certain the identical controller is read once chasing is off | `PartitionCaptureTests.TheSameControllerIsReadWhenChasingIsOff` |  |
| be certain a connection that cannot say what the controller advertises is refused | `PartitionCaptureTests.AConnectionThatCannotSayWhatTheControllerAdvertisesIsRefused` |  |
| be certain an answer carrying no paging control is not mistaken for the last page | `PartitionCaptureTests.AnAnswerWithNoPagingControlIsNotTheLastPage` |  |
| be certain a controller that hands the same bookmark straight back is refused rather than looped | `PartitionCaptureTests.ABookmarkHandedStraightBackIsRefusedRatherThanResent` |  |
| see the objects a run could not follow reach the coverage record | `PartitionCaptureTests.ContinuationReferencesReachTheCoverageRecord` |  |
| be certain a cancelled capture stops rather than reporting itself finished | `PartitionCaptureTests.ACancelledCaptureStopsRatherThanFinishing` |  |
| get a group's full membership, past the limit a server will return in one response | `LdapEntryReaderTests.AGroupLargerThanTheServersValueLimitIsReadInFull` |  |
| be certain a first, partial response is never mistaken for the whole answer | `LdapEntryReaderTests.TheFirstResponseDoesNotClaimToBeAllOfThem` |  |
| tell an attribute that was absent from one that was present and empty | `LdapEntryReaderTests.AnAbsentAttributeIsNotReportedAsAnEmptyOne` |  |
| be certain a paged read that stalled is reported as a failure rather than an ending | `LdapEntryReaderTests.ABlockThatAdvancedByNothingIsAFailureAndNotAnEnding` |  |
| be certain no second place in the product spells a range specifier | `RangeSpecifierGateTests` |  |
| have a capture run end to end and produce a readable bundle | `CaptureRunEndToEndTests` |  |
