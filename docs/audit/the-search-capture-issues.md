?# The search capture issues

**Code:** `next/src/SecureAD.Audit/Capture/CaptureUnit.cs`, `CapturePlan.cs`,
`CaptureSearchRequestFactory.cs`
**Layer:** Audit — speaks to a customer's directory.

What capture reads in one go, which partitions a run covers, every request the product builds — and
the three other ways of reading a forest that were refused.

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `CaptureUnit` | One naming context on one domain controller: the whole of what capture reads in one go, and the boundary it never crosses |
| `CapturePlan` | The list of units, what the forest declared, and what this run deliberately leaves alone |
| `CaptureSearchRequestFactory` | The one place in the product permitted to build a search request or assign a referral option |
<!-- TYPES:END -->

`NamingContextKind` — Domain, Configuration or Schema — lives in the Evidence layer, because a
coverage record has to name the kind of partition it describes long after the capture ended.

Each type carries its own reasoning in its XML documentation, including the Microsoft sources it is
anchored to. **That is the reference; this page is the orientation.**

---

## The failure this exists not to have

A **naming context**, or partition, is one of the separately held trees a domain controller serves.
Every forest has one per domain, plus a configuration partition and a schema partition shared by the
whole forest, plus — usually — two DNS partitions.

Capture reads a forest by searching each partition from its root. That is the obvious way to do it,
and done naively it is broken.

A paged subtree search based at the root of a domain naming context **does not stay inside that
domain**. The controller answers with the objects it was asked for and also with *subordinate
referrals*: pointers to the configuration and schema partitions, the DNS zone partitions, and every
child domain recursively. If the client follows them — which is what an LDAP client does unless told
otherwise — then, in Microsoft's words, "the chasing is happening on the same LDAP session, wiping
the paged cookie returned in the primary query in the client LDAP runtime." The application sees an
empty cookie, concludes it has read everything, and stops.

Microsoft's article is titled
[LDAP paged queries with subordinate referrals are not chased properly](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased),
and its Resolution section reads in full: *"There is currently no resolution for the problem."* What
it offers instead is four ways to avoid it.

**What that costs a customer.** A capture reads the first page of a domain — a thousand objects out
of nine million — reports no error, and the audit is performed against a fraction of the forest that
the report presents as the whole of it. Every finding is true and the absence of every other finding
is meaningless, and nothing on the screen distinguishes the two.

**Why it is easy to lose.** The avoidance is two small things — a setting on the connection and a
control on the request — and neither explains itself where it is written. Both look like minor
performance precautions. Remove either and the capture still works perfectly against any forest with
no child domains, which is every test forest anyone builds. It fails on the first customer forest
with one, and it fails by succeeding.

---

## What a capture unit is

**One naming context, on one domain controller.** Never one domain.

That distinction is the whole decision. A domain is not a unit of reading, because a search based at
a domain root is offered four other partitions on the way past. A partition is, because a search
based at a partition root and told to follow nothing reads that partition and stops.

A `CaptureUnit` carries three things and no more:

| Field | What it is |
|---|---|
| Naming context | The distinguished name of the partition root, exactly as the controller reported it |
| Kind | `NamingContextKind` — Domain, Configuration or Schema |
| Domain controller | The host this unit is read from |

**One controller per unit.** The reason is attribution rather than load — the configuration and
schema partitions are a few thousand objects once per forest and place no meaningful pressure
anywhere — but capture is fail-fast, so a controller serving two units makes a failure ambiguous
about which unit it ended.

**The name is not "shard".** Shard belongs to a parallel fan-out across several controllers at once,
which this product does not do. A name for machinery that does not exist teaches a reader something
untrue about the design, and it would do it every time somebody opened the file. The unit here is a
correctness boundary, not a parallelism one.

**A unit is confirmed against what its controller publishes.** `CaptureUnit.ConfirmServedBy` takes
the `namingContexts` list a controller reports in its own RootDSE and refuses a unit that host does
not serve. The comparison is an exact, case-insensitive string match: both sides are strings a
controller produced, so no distinguished name is parsed and no second interpretation of a DN is
created to disagree with the kernel's `DnHelper`. **An empty partition list is a failed question,
not an answer of no.**

Under fail-fast, asking early is what makes this worth doing. Discovering at hour two that a
controller was never going to answer for a partition costs the whole capture, and a forest is only
readable as it stands today. Asking costs one round trip per unit.

---

## Which partitions a run reads

`CapturePlan` is the list. **Nothing is discovered here** — the plan is built from what it is handed:
the forest's domain partitions with a controller for each, its configuration and schema partitions,
the list of partitions the chosen controller publishes, and the list of partitions the forest
declares that this run does not read.

Keeping discovery out is not tidiness. A partition list alone cannot tell a domain from an
application partition, because `DC=DomainDnsZones,DC=example,DC=com` is spelled exactly as a domain
is, and the only reliable answer is in the configuration partition's cross-references. A component
that guessed from the name would be right on every forest anybody builds to test it and wrong at a
customer.

**The configuration and schema partitions are read first, and the ordering is a decision.** They are
a few thousand objects once per forest and they are what everything else is interpreted against — a
permission naming a schema identifier means nothing until the schema partition has been read, per
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md). Capture is fail-fast, so a run
that is going to fail on them should fail in its first minute rather than after three hours of a
customer's largest domain.

**What the run does not read is stated by the forest, not inferred here.** An earlier version
computed it by subtracting the units it planned from the partition list it had planned *from*, which
is empty by construction — so a run that saw one domain of nine reported nothing missing. That is
`F-S28-1`. The list now arrives from the forest's own cross-references.

**`DeclaredDomains` is the denominator, and it is never trimmed.** `CapturePlan.Excluding` removes a
domain from the units and deliberately leaves the declaration alone, because the forest still
declares the domain that was left out. Trimming it would make the run report full coverage of a
forest it did not fully read — `F-S28-1` arriving by the front door. The plan becomes `IsComplete`
false instead, which is true and is what the caller has an attestation for.

**`IsComplete` compares counts, not names, and says so.** Two lists of the same length naming
different domains would satisfy it. That cannot happen while every unit is built from the
declaration, and the counts are compared because a unit is identified by its naming context while a
declaration is a DNS name — matching them would mean this type deciding that a controller's host
name is a domain's DNS name, which is true only while controllers are reached through `dnsRoot`.

---

## One place builds a search request

**Not a convention — a build failure.** `DirectorySearchGateTests` fails if a `SearchRequest` is
constructed, or a referral option assigned, anywhere but in `CaptureSearchRequestFactory`, and if
any referral option other than `None` appears in production code at all.

That is the shape of gate 1: a correct mechanism with a boundary obliging its use. It exists because
a second place that builds a search is a second referral policy, and the first sign that the two
disagree is a customer's report covering a fraction of their forest and saying nothing about it.

The factory builds nine requests. One of them is the capture search; the other eight are how a run
finds out what to capture and proves it can.

| Request | What it asks | Shape |
|---|---|---|
| `ForUnit` | the first page of one partition | subtree, paged, the whole attribute catalogue |
| `ForNextPage` | the next page, carrying the bookmark | as above, plus the cookie |
| `ForAttributeBlock` | one block of one attribute of one object | base scope, not paged |
| `ForRootDse` | what this controller is and serves | base scope, empty base |
| `ForCrossReferences` | which partitions the forest has, and which are domains | one level, `crossRef` |
| `ForSiteTopology` | every controller, what it holds, and where it sits | subtree, paged |
| `ForSubnets` | which address ranges belong to which site | one level, paged |
| `ForPasswordSettingsContainer` | whether the fine-grained password policies can be read | base scope |
| `ForRoleOwner` | which controller holds an operations master role | base scope |

Three of these carry reasoning that is easy to lose:

**`ForCrossReferences` is the only authoritative answer to which naming contexts are domains.** A
controller's `namingContexts` lists what that one controller holds, which in a forest of several
domains is its own domain and no other. `nCName`, `systemFlags` and `dnsRoot` are the three
attributes, and each is load-bearing.

**`ForCrossReferences` is not paged, and nothing has to notice.** A forest has one cross-reference
per partition. An unpaged search that exceeded the server's page size would answer
`sizeLimitExceeded` with a truncated entry list, and a caller reading only the entries would take
the truncation for the whole answer — the same failure as the paging defect, from the other side.
`LdapDirectoryChannel` throws on any result code that is not success, so a truncated answer never
reaches a reader as a page. `ForSiteTopology` and `ForSubnets` *are* paged, because a large
organisation declares thousands of subnets.

**`ForPasswordSettingsContainer` can prove a read succeeded and cannot say why one failed.** Active
Directory answers a caller who lacks list access with *no such object*, the same code an absent
container would produce. What preflight records is therefore *could not be read*, carrying the
controller's own words, rather than a claim about why.

---

## The capture search itself

Every value below is checked against the request the code builds.

<!-- REQUEST:BEGIN -->

| Property | Value | Why |
|---|---|---|
| SearchBase | the unit's naming context root | The partition root itself, never a container beneath it. See the first refusal below |
| Scope | Subtree | The partition is read whole. `0017` forbids capture-side exclusion, so there is no subtree left out |
| Filter | `(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone)))` | An exclusion, never an inclusion. Every object is captured whatever its class, so a dangerous permission on a vendor object nobody anticipated is still read. The two excluded classes are the DNS scope decision, stated once in the attribute catalogue and built from it here |
| Attributes | every attribute in the captured attribute catalogue | The whole catalogue on every unit rather than a per-unit subset. An attribute an object does not have is simply absent from the entry, so a superset costs nothing on the wire, and a second list is a second thing to keep in step with [the attribute catalogue](the-attribute-catalogue.md) |
| SizeLimit | 0 | No client-imposed limit; paging governs. Stated rather than left at its default, because a size limit and a page size are easy to confuse and one of them silently truncates a capture |
| TimeLimit | 120 seconds | `MaxQueryDuration`'s documented default. Under paging this bounds one page, not a partition — see [limits and failures](limits-and-failures.md) |
| PageSize | 1000 | `MaxPageSize`'s documented default. Asking for more gains nothing; asking for less multiplies round trips |
| ReferralChasing | None | The correctness. Set explicitly, never left at the default — Microsoft's own remedy is phrased "as referrals are chased by default, use ldap_set_option with flag LDAP_OPT_REFERRALS to turn off referral chasing" |
| DomainScopeControl | 1.2.840.113556.1.4.1339, non-critical | `LDAP_SERVER_DOMAIN_SCOPE_OID`, which tells a controller not to generate continuation referrals at all. Sent only on domain partitions, and only where the controller advertises the OID in its RootDSE. Non-critical means a controller that does not recognise it answers anyway rather than failing the search |
| SecurityDescriptorFlags | Owner, Group, Dacl | `LDAP_SERVER_SD_FLAGS_OID`, `1.2.840.113556.1.4.801`. `nTSecurityDescriptor` is asked for on every object, and without this the server decides which parts of it to send. The SACL — the audit half — is deliberately not among them: retrieving it is privileged, so asking for it would mean a customer had to grant an audit tool a privilege on their domain controllers before it would read anything. Never the SACL, on any request |

<!-- REQUEST:END -->

The last two are two halves of one policy and neither is redundant. **Chasing-off carries the
correctness**: it is a property of this client and holds against every controller. **The
domain-scope control is a second line** and depends on the server honouring it. A design resting on
the control alone would be resting on a server behaviour it cannot check.

There is a second control in the same API that also suppresses referrals — `SearchOptionsControl`
with the domain-scope option, OID `1.2.840.113556.1.4.1340`. Either would work. This one is used
because it is the one Microsoft's guidance on the paging defect names, and because it does exactly
the one thing wanted rather than carrying a bag of search options.

### A paged search is one request per page

The controller returns each page with an opaque bookmark — a **cookie** — and the next request has
to carry it back, or the search starts again from the beginning. Asking for a next page with an
empty cookie is refused outright, because an empty cookie means the last page has already been sent
and asking again would read the partition twice.

**This is where the defect shows up, or fails to.** A paging loop ends when the controller returns
an empty cookie. A client that chased a referral mid-search reads an empty cookie on the first page,
so the loop ends immediately — and *there is no way to tell that from a partition that genuinely
fitted in one page.* That is why paging and referral policy are built as one thing here rather than
as two precautions in two places.

### The second shape is not paged

An attribute with more values than a controller will send at once has to be asked for a block at a
time. `ForAttributeBlock` is base scope, one object, one attribute name carrying a range option, no
paging control and no domain-scope control — a search of a single object has nothing below it to be
referred to. It carries the same security-descriptor flags as everything else.

It is built here for the same reason everything else is: a second place that builds a search request
is a second referral policy.

---

## What was refused

Microsoft lists four avoidances. Three are refused, and the refusals are written down because the
next person looking for a faster capture will find the same article and the same second bullet.

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
purpose anyway. Nothing is being done for the sake of the defect.

---

## Continuation references are evidence, not noise

Turning chasing off stops the client following a referral. It does not stop the server sending one:
"If referral chasing is not enabled and a subtree search is performed, the search will return all
objects within the specified domain that meet the search criteria. The search will **also return
referrals** to any subordinate domains that are direct descendants"
([Referrals](https://learn.microsoft.com/windows/win32/ad/referrals)).

Together they are the controller's own statement of what else exists below the point searched, so
`ContinuationReferenceReconciliation` compares them against the partitions the run planned to read.
Anything left over is a partition the run did not know about, and it becomes a coverage entry rather
than silence. A forest that has grown a partition is exactly the forest whose owner does not know it
has one.

**And the reconciliation can be blind.** The domain-scope control asks a controller not to generate
continuation referrals *at all*. Where it was sent and honoured, that unit contributes nothing, so
"nothing left over" from it means *we asked not to be told*, not *there is nothing*. Reported as a
finding of no unplanned partitions, that would be the product telling a customer something false. So
the result carries `IsComplete`, false whenever any unit suppressed its referrals or a reference
could not be read, and per [`0002`](../decisions/0002-absent-view-means-degraded-run.md) an
incomplete result is never rendered as an empty one.

---

## Do not change without reading this

**Do not base the search below a partition root.** It works, and it silently loses the objects
sitting directly in the root and anything in a container the enumeration did not think of.

**Do not turn the filter into an inclusion list.** It is an exclusion so that a dangerous permission
on a vendor object nobody anticipated is still read. The two excluded classes come from
`CapturedAttributeCatalog.UnreadObjectClasses`, so the DNS scope decision is stated once.

**Do not ask for the SACL.** Retrieving it is privileged, so asking would mean a customer had to
grant an audit tool a privilege on their domain controllers before it would read anything.

**Do not leave `ReferralChasing` at its default.** Microsoft's own remedy is phrased as an
instruction to set it. A policy that happens to be safe is not a policy.

**Do not make the domain-scope control critical.** Non-critical means a controller that does not
recognise it answers anyway rather than failing the search.

---

## What this document and its test cannot tell you

That any of these reasons are good reasons, or that the fourth avoidance was the right one. Those
need a reader.

---

## What is built

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.**

**Confirmed in lab** is the date the owner saw this working against a real forest. Blank means
unit-tested but not yet exercised against Active Directory.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be refused a run that would read no domain at all | `CapturePlanTests.APlanThatReadsNoDomainIsRefused` |  |
| see one unit of work planned for every domain in the forest | `CapturePlanTests.AForestWithSeveralDomainsPlansAUnitForEach` |  |
| see a plan called complete only when it covers every declared domain | `CapturePlanTests.APlanCoveringEveryDeclaredDomainIsComplete` |  |
| be told a plan is not complete when it leaves a declared domain out | `CapturePlanTests.APlanThatDoesNotCoverEveryDeclaredDomainIsNotComplete` |  |
| be sure the configuration and schema partitions are read before anything is interpreted | `CapturePlanTests.TheConfigurationAndSchemaPartitionsAreReadFirst` |  |
| see each domain read from the controller chosen for it, not from whichever answered first | `CapturePlanTests.EachDomainIsReadFromItsOwnController` |  |
| learn that a partition the forest declares went unread, instead of it vanishing | `CapturePlanTests.APartitionTheForestDeclaresAndTheRunDoesNotReadIsRecorded` |  |
| trust that list even when the controller publishes an incomplete picture of itself | `CapturePlanTests.TheUnreadListDoesNotDependOnWhatTheControllerPublishes` |  |
| be stopped before a run starts, rather than part-way through, when a controller cannot serve a partition | `CapturePlanTests.APartitionTheControllerDoesNotServeIsRefusedBeforeTheRunStarts` |  |
| tell a controller that answered "none" from one whose question failed | `CapturePlanTests.AControllerThatPublishesNothingIsAFailedQuestionRatherThanAnAnswerOfNo` |  |
| rely on every property of the capture search being described, and described correctly | `CaptureUnitDocumentationTests.EveryPropertyOfTheSearchIsDescribedAndDescribedCorrectly` |  |
| be certain the document describes no property the search does not have | `CaptureUnitDocumentationTests.TheDocumentDescribesNoPropertyTheSearchDoesNotHave` |  |
| read why each refused way of reading a forest was refused | `CaptureUnitDocumentationTests.EveryRefusedAvoidanceIsNamed` |  |
| be certain no other part of the product builds a search or sets a referral option | `DirectorySearchGateTests` |  |
