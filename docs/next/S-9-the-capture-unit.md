# S-9 — The capture unit, and the search it issues

Inventory row **B4**. What capture reads in one go, what the search asking for it looks like, and —
just as important — the three other ways of doing it that were refused.

Bound to the code by `CaptureUnitDocumentationTests`, which builds the real search request and
compares it with the table below. Per [`README.md`](README.md) §When a document counts as
documentation, this file is not documentation until that test holds it to the code.

## The problem this exists for

A **naming context**, or partition, is one of the separately held trees a domain controller serves.
Every forest has one per domain, plus a configuration partition and a schema partition shared by
the whole forest, plus — usually — two DNS partitions.

Capture reads a forest by searching each partition from its root. That is the obvious way to do it,
and done naively it is broken.

A paged subtree search based at the root of a domain naming context **does not stay inside that
domain**. The controller answers with the objects it was asked for and also with *subordinate
referrals*: pointers to the configuration and schema partitions, the DNS zone partitions, and every
child domain recursively, down the whole tree. If the client follows them — which is what an LDAP
client does unless told otherwise — then, in Microsoft's words, "the chasing is happening on the
same LDAP session, wiping the paged cookie returned in the primary query in the client LDAP
runtime." The application sees an empty cookie, concludes it has read everything, and stops. It may
instead fail with an operational error. Microsoft's article is titled
[LDAP paged queries with subordinate referrals are not chased properly](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased),
and its Resolution section says in full: *"There is currently no resolution for the problem."* What
it offers instead is four ways to avoid it.

**What that costs a customer.** A capture reads the first page of a domain — a thousand objects out
of nine million — reports no error, and the audit is performed against a fraction of the forest
that the report presents as the whole of it. Every finding is true and the absence of every other
finding is meaningless, and nothing on the screen distinguishes the two. That is the one thing an
audit tool cannot do.

**Why it is easy to lose.** The avoidance is two small things — a setting on the connection and a
control on the request — and neither explains itself where it is written. Both look like minor
performance precautions. Remove either and the capture still works perfectly against any forest
with no child domains, which is every test forest anyone builds. It fails on the first customer
forest with one, and it fails by succeeding. That is why the policy lives in one place with a
build guard on it, and why this document exists at all: a correctness property that is invisible
at the point it is lost has to be written down somewhere a reader will look.

## What a capture unit is

**One naming context, on one domain controller.** Never one domain.

That distinction is the whole decision. A domain is not a unit of reading, because a search based
at a domain root is offered four other partitions on the way past. A partition is, because a search
based at a partition root and told to follow nothing reads that partition and stops.

A unit carries three things, and no more. The type is `CaptureUnit`, and the kind is
`NamingContextKind`:

| Field | What it is |
|---|---|
| Naming context | The distinguished name of the partition root, exactly as the controller reported it |
| Kind | Domain, Configuration or Schema — see below for the one decision that turns on it |
| Domain controller | The host this unit is read from |

**Which** partitions a run reads is not decided here. Today the answer is every domain partition
plus the configuration and schema partitions, because
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) and inventory row B2 require the
last two to be read on purpose; the DNS application partitions are out of scope per the DNS scope
decision of 2026-08-11. That list belongs to inventory row B6. B4 decides only that the unit is a
partition and that a unit follows nothing.

**One controller per unit.** Chosen before the run starts and recorded. The reason is attribution
rather than load — the configuration and schema partitions are a few thousand objects once per
forest and place no meaningful pressure anywhere — but capture is fail-fast, so a controller
serving two units makes a failure ambiguous about which unit it ended. A forest with a single
domain controller is a stated fallback, so this is a preference with a defined exception rather
than an invariant.

**The name.** Not a shard. "Shard" belongs to a parallel fan-out across several controllers at
once, which this product does not do — inventory row B5 defers it against a measured trigger. A name
for machinery that does not exist teaches a reader something untrue about the design, and it would
do it every time somebody opened the file. The unit here is a correctness boundary, not a
parallelism one, and it is named for what it is. If fan-out is ever built, it will reintroduce its
own vocabulary rather than find the word waiting and assume the machinery is there too.

## Preflight belongs here, and is called from branch A

A unit names a controller. Whether that controller actually serves that partition is a question
with two possible moments: before the run, or when the search fails.

Under fail-fast the second is expensive. Discovering at hour two that a controller was never going
to answer for a partition costs the whole capture, and a forest is only readable as it stands
today. Asking every chosen controller once, before anything is read, costs one round trip per unit.

So `CaptureUnit.ConfirmServedBy` is built here, in B4, and takes the `namingContexts` list a
controller publishes about itself in its RootDSE. **Inventory row A8 — preflight validation — is where
it is called**, and that row is not yet decided. Splitting it this way is deliberate: B4 owns
whether a unit is well formed, A8 owns when the question is asked. If the check lived in A8 it
would not exist yet, and an obligation belonging to two undecided rows belongs to neither.

The comparison is an exact, case-insensitive string match. Both sides are strings a controller
produced, so no distinguished name is parsed and no second interpretation of a DN is created to
disagree with the kernel's `DnHelper`. An empty partition list is treated as a failed question, not
as an answer of no.

## The search

Every value below is checked against the request the code builds.

<!-- REQUEST:BEGIN -->

| Property | Value | Why |
|---|---|---|
| SearchBase | the unit's naming context root | The partition root itself, never a container beneath it. See the first refusal below |
| Scope | Subtree | The partition is read whole. `0017` forbids capture-side exclusion, so there is no subtree left out |
| Filter | `(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone)))` | An exclusion, never an inclusion. Every object is captured whatever its class, so a dangerous permission on a vendor object nobody anticipated is still read. The two excluded classes are the DNS scope decision, stated once in the attribute catalogue and built from it here |
| Attributes | every attribute in the captured attribute catalogue | The whole catalogue on every unit rather than a per-unit subset. An attribute an object does not have is simply absent from the entry, so a superset costs nothing on the wire, and a second list is a second thing to keep in step with [`S-8`](S-8-captured-attribute-catalogue.md) |
| SizeLimit | 0 | No client-imposed limit; paging governs. Stated rather than left at its default, because a size limit and a page size are easy to confuse and one of them silently truncates a capture |
| TimeLimit | 120 seconds | `MaxQueryDuration`'s documented default. Under paging this bounds one page, not a partition — see [`S-10`](S-10-politeness.md) |
| PageSize | 1000 | `MaxPageSize`'s documented default. Asking for more gains nothing; asking for less multiplies round trips |
| ReferralChasing | None | The correctness. Set explicitly, never left at the default — Microsoft's own remedy is phrased "as referrals are chased by default, use ldap_set_option with flag LDAP_OPT_REFERRALS to turn off referral chasing" |
| DomainScopeControl | 1.2.840.113556.1.4.1339, non-critical | `LDAP_SERVER_DOMAIN_SCOPE_OID`, which tells a controller not to generate continuation referrals at all. Sent only on domain partitions, and only where the controller advertises the OID in its RootDSE. Non-critical means a controller that does not recognise it answers anyway rather than failing the search |
| SecurityDescriptorFlags | Owner, Group, Dacl | `LDAP_SERVER_SD_FLAGS_OID`, `1.2.840.113556.1.4.801`. `nTSecurityDescriptor` is asked for on every object, and without this the server decides which parts of it to send. The SACL — the audit half — is deliberately not among them: retrieving it is privileged, so asking for it would mean a customer had to grant an audit tool a privilege on their domain controllers before it would read anything. Never the SACL, on any request |

<!-- REQUEST:END -->

The last two are two halves of one policy and neither is redundant. Chasing-off carries the
correctness: it is a property of this client and holds against every controller. The domain-scope
control is a second line and depends on the server honouring it. A design resting on the control
alone would be resting on a server behaviour it cannot check.

There is a second control in the same API that also suppresses referrals — `SearchOptionsControl`
with the domain-scope option, OID `1.2.840.113556.1.4.1340`. Either would work. This one is used
because it is the one Microsoft's guidance on the paging defect names, and because it does exactly
the one thing wanted rather than carrying a bag of search options. Anyone reaching for the other
should know it exists and that the choice was made rather than stumbled into.

### A paged search is one request per page

The controller returns each page with an opaque bookmark — a **cookie** — and the next request has
to carry it back, or the search starts again from the beginning. So the factory builds two kinds of
request: the first page, and a next page carrying the cookie the previous response returned. Asking
for a next page with an empty cookie is refused outright, because an empty cookie means the last
page has already been sent, and asking again would read the partition twice.

**This is where the defect above shows up, or fails to.** A paging loop ends when the controller
returns an empty cookie. A client that chased a referral mid-search reads an empty cookie on the
first page, so the loop ends immediately — and *there is no way to tell that from a partition that
genuinely fitted in one page*. The end of a capture and a capture that never started look
identical from inside the loop. That is why paging and referral policy are built as one thing here
rather than as two precautions in two places.

Reading the cookie back off a response belongs to the component running the loop, inventory row B6.
What B6 must not do is treat an empty cookie as proof of completeness without knowing nothing was
chased.

### There is a second shape, and it is not paged

An attribute with more values than a controller will send at once has to be asked for a block at a
time, and each block is a further request. So the factory also builds a **range retrieval**: base
scope, one object, one attribute name carrying a range option, no paging control and no domain-scope
control — a search of a single object has nothing below it to be referred to. It carries the same
security-descriptor flags as everything else.

It is built here for the same reason everything else is: a second place that builds a search request
is a second referral policy. When and on which connection it is issued is inventory row B6's decision,
and is written down at [`S-12`](S-12-the-capture-passes.md).

**One place builds this request.** Not a convention — a build failure. `DirectorySearchGateTests`
fails if a search request is constructed, or a referral option assigned, anywhere but in
`CaptureSearchRequestFactory`, and if any referral option other than `None` appears in production
code at all. That is gate 1's shape: a correct mechanism with a boundary obliging its use. It
exists because the correctness here is invisible at the moment it is lost.

## What was refused, and why the refusals are written down

Microsoft lists four avoidances. Three are refused, and refusing them is the part of this decision
that would otherwise be lost — the next person looking for a faster capture will find the same
article and the same second bullet.

<!-- REFUSED:BEGIN -->

| Avoidance refused | Why | Finding |
|---|---|---|
| Basing the search below the domain root | It works, and it means enumerating containers and searching each one. Objects sitting directly in the domain root, and any container the enumeration did not think of, are then never read — and nothing says so. That is precisely the incompleteness `0017` refuses, arrived at by accident instead of by an operator ticking a box | — |
| Searching the global catalog | The one a later session will reach for, because it looks like one server, no referrals and the whole forest in a single pass. It is wrong three ways and all three are silent: a filter term naming an attribute absent from the catalog is *evaluated as false*, a requested attribute absent from it is simply not returned — and `attributeSecurityGUID`, which B2 added so a property-set permission can be expanded into what it really grants, is not in it — and objects in an application directory partition are not replicated to it at all | F-S7-10 |
| Chasing referrals and handling the cookie carefully | There is nothing to handle carefully. The cookie is overwritten inside the LDAP runtime; the application never sees the moment it happens | F-S7-4 |

<!-- REFUSED:END -->

The fourth — turn chasing off and enumerate the partitions deliberately — is the one chosen, and
what makes it strictly better rather than merely acceptable is that the avoidance and an existing
requirement are the same act. The product needs the configuration and schema partitions read on
purpose anyway, per `0014` and B2. Nothing is being done for the sake of the defect.

## Continuation references are evidence, not noise

Turning chasing off stops the client following a referral. It does not stop the server sending one:
"If referral chasing is not enabled and a subtree search is performed, the search will return all
objects within the specified domain that meet the search criteria. The search will **also return
referrals** to any subordinate domains that are direct descendants"
([Referrals](https://learn.microsoft.com/windows/win32/ad/referrals)).

It would be easy to treat them as noise. Together they are the controller's own statement of what
else exists below the point searched, so `ContinuationReferenceReconciliation` compares them
against the partitions the run planned to read. Anything left over is a partition the run did not
know about, and it becomes a coverage entry rather than silence. That is finding F-S7-11, and it is
the strongest reason the referral policy belongs to B4 rather than to B6 or B7 — it is the same
decision seen from the other side.

**And the reconciliation can be blind.** The domain-scope control asks a controller not to generate
continuation referrals *at all*. Where it was sent and honoured, that unit contributes nothing, so
"nothing left over" from it means *we asked not to be told*, not *there is nothing*. Reported as a
finding of no unplanned partitions, that would be the product telling a customer something false.
So the result carries `IsComplete`, false whenever any unit suppressed its referrals or a reference
could not be read, and per [`0002`](../decisions/0002-absent-view-means-degraded-run.md) an
incomplete result is never rendered as an empty one. That is finding F-S7-28, found while building
this row.

## The guards were mutation-tested

A guard nobody has watched fail is a guard nobody has watched.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | A search request constructed in `CaptureUnit.cs` | The construction rule fires | First attempt was **refused by the compiler** — the type was not in scope in that file, so nothing was shown. Repeated with the `using` added: `OnlyTheFactoryBuildsASearchRequest` fired |
| 2 | `RequiredReferralChasing` changed to `External` | The chasing rule fires | `NothingEverAsksForReferralsToBeChased` fired |
| 3 | The `Scope` row in the table above changed to `OneLevel` | The document check fires | `EveryPropertyOfTheSearchIsDescribedAndDescribedCorrectly` fired |
| 4 | The `PageSize` row renamed, so the search has a property the document does not describe | The other direction fires | `TheDocumentDescribesNoPropertyTheSearchDoesNotHave` fired |
| 5 | The `REQUEST:BEGIN` marker renamed | The parse refuses rather than reading nothing | Three checks fired, including the scanner self-test |
| 6 | The global-catalog refusal reworded so it no longer refuses | The refusals check fires | `EveryRefusedAvoidanceIsNamed` fired for that avoidance |

Every mutation was confirmed present in the file before the result was believed, and every one was
reverted. Mutation 1 is recorded twice on purpose: a mutation the compiler refuses proves nothing
about the guard, and counting it would have been counting a compiler error as evidence.

## What this document and its test cannot tell you

That any search has ever been issued. Nothing in the rebuild issues one: the component that runs
the passes is inventory row B6. What is bound here is the request a factory builds — a real
`SearchRequest`, constructed and asserted on with no directory present — and a build guard that
nothing else in the tree may build one. That the request *actually issued* is this one is gate 5b,
which needs an entry point to trace from and unblocks on B6.

That split is stated rather than glossed, on the precedent of gate 5 and of B2's own binding, which
was split for the same reason. A test that inspected an empty set of search requests and reported
them all correct would be the exact failure this repository has committed three times.

It also cannot tell you that the reasons above are good reasons, or that the fourth avoidance was
the right one. Those need a reader.
