# S-7 â€” Capture, and what the product is allowed to see

**Type:** slice
**Reviewed at commit:** `HEAD` of `master` at the time of writing
**Size:** 12 ledger rows decided, 1 new document, 1 new test file, 2 edited documents
**Date:** 2026-08-10

---

## The four questions for the owner, with a recommendation on each

These four are not technical. Each has a recommendation and what it costs both ways, and each is
answerable without reading the rest of this document.

### 1. B2 â€” what the product reads out of the directory

> **Answered 2026-08-10. Yes, with two additions and one correction.** The extended-rights container
> and the schema partition are read on every capture. `attributeSecurityGUID` is added, so a
> property-set permission can be expanded into what it really grants. Matching is on the GUID; the
> name is for display only. The reasoning below is kept because the additions rest on it, and
> because the "shipped catalogue stays" item that was originally listed here has been struck â€” it
> was already decided by [`0014`](../decisions/0014-capture-reads-the-schema-partition.md) and
> already built, and restating a finished decision as an open one invites attention it does not
> need.

**The question.** Capture requests a named list of attributes. Whatever is not on that list is not
in the bundle, is not in any report, and cannot be added later without recapturing the forest. So
the list is the ceiling on everything the product can ever say.

**What the old product read.** A hand-enumerated set per object class â€” identity, group type,
account control, delegation, password and certificate attributes â€” versioned, so a bundle could
state which set produced it. "No capture-everything strategy" was written down as a position, not
arrived at by accident, and the version stamp is the reason a bundle can be re-read years later and
still say what it was allowed to see. That part is good and is kept.

**What it did not read.** The schema partition and the extended-rights container. This matters more
than it sounds. A permission in Active Directory is scoped by a GUID, and base-schema GUIDs are the
same in every forest â€” but every forest also carries vendor extensions and locally created
attributes whose GUIDs are generated at creation and exist nowhere else. Without reading the schema,
those are permanently unnameable, and the old control-graph builder matched nine GUIDs hardcoded in
its own file, so a permission scoped to any other GUID produced **no edge at all**: not assessed and
found safe, never examined. [`0014`](../decisions/0014-capture-reads-the-schema-partition.md)
already decided that capture reads them. This row is where that decision is paid for.

**Recommendation.** Read three things, and nothing on faith:

1. The security-relevant attribute set per object class, as today â€” enumerated, versioned, and
   explicitly not everything.
2. The schema partition and the extended-rights container, per `0014`. The cost is fixed rather
   than proportional to the forest â€” a few thousand objects, once per forest, not once per domain â€”
   and it needs no privilege beyond reading the directory.
3. Nothing whose only justification is that it might be useful.

And make the catalogue answerable in both directions: an attribute nothing reads is dead weight in
every bundle forever, and a rule that needs an attribute the catalogue does not request is a build
failure rather than a silently empty finding. That is the same failure gate 4 exists for, one level
up.

**What reading more costs.** Every attribute is bytes multiplied by object count multiplied by the
number of passes, and this product operates at forests where that multiplication is the difference
between a capture that finishes and one that does not. There is a second cost that is easy to miss:
an attribute marked confidential in the schema is not returned to a caller who lacks `CONTROL_ACCESS`
on it, and it is not returned as an error â€” it simply is not there, exactly as though it were
unset ([Mark an attribute as confidential](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential),
[Search-Flags](https://learn.microsoft.com/windows/win32/adschema/a-searchflags), bit 128). So every
attribute added to the catalogue adds a case where "absent" means either "not set in the forest" or
"we were not allowed to read it", and [`0002`](../decisions/0002-absent-view-means-degraded-run.md)
requires those to be told apart. That is real work per attribute, not a free addition.

**What reading less costs.** Whatever is not read can never be reported, and the customer cannot
tell the difference between "this is not a risk in your forest" and "we never looked". A bundle is
the only evidence of a forest as it stood; nobody can go back and re-read last quarter.

**Why this is not a feature about extended rights.** A permission's GUID can mean one of five
things, and which one depends on the bit in the access mask beside it: an attribute or an object
class, both of which live in the schema partition; and an extended right, a property set or a
validated write, **all three of which live in the extended-rights container**. Microsoft states this
outright â€” property sets and validated writes are not extended rights, but are stored there "for
convenience", distinguished by the `validAccesses` value on each entry, 256, 48 and 8 respectively
([Control Access Rights](https://learn.microsoft.com/windows/win32/ad/control-access-rights)). So one
container read resolves three of the five namespaces, and a product that cannot read it cannot
resolve a property-set permission either.

That is not academic. The password-reset delegation is two entries, not one: Control Access scoped
to `User-Force-Change-Password`, an extended right, plus Write Property scoped to
`User-Account-Restrictions`, a property set. Both GUIDs come from the same container. A delegation
bundle therefore needs no special notion of an extended right â€” the old `AcePattern` shape, an
access mask plus two GUIDs plus inheritance, already describes both â€” but it does need the container
read, or half its patterns are matched against numbers typed in by hand.

**Which is why `attributeSecurityGUID` joins the list.** A property set names no attributes; each
attribute points back at the set it belongs to, through `attributeSecurityGUID` on its schema entry.
Without that, the product can say "grants Write on Account Restrictions" and cannot say what that
is. With it, the product can say what the permission actually reaches â€” which is where F-S7-6 lives.

---

### 2. B3 â€” the OU exclusion filter

> **Answered 2026-08-10, and the answer went further than the question.** Capture-side exclusion is
> removed entirely and B3 is **Delete**, not Rebuild. Capture reads the whole forest; scope is
> applied at the reading layer and never to the evidence. Recorded as
> [`0017`](../decisions/0017-capture-reads-the-whole-forest.md), which supersedes the recommendation
> that follows. The reasoning below is kept because it is what led there â€” every argument for making
> an exclusion loud turned out to be an argument for not having one.

**The question.** An operator can tell the product not to read a container. That is also a hole in
the evidence, and a report that does not say so is a report that claims an unexamined container was
examined and found clean.

**Recommendation. Keep exclusions; change what an exclusion means.** Three parts:

- An exclusion is recorded in the bundle as a named gap and appears in the report at the same
  prominence as a finding, not in a footnote. This is
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) applied to capture rather than to
  derived views: missing output is a fact about the capture, never about the forest.
- The refusal to exclude a security-critical container is **stated back to the operator**. Today it
  is silent â€” `CN=Managed Service Accounts` is dropped from the exclusion list at construction and
  the operator is not told, so an operator who asked to exclude it believes he did. The refusal is
  right. The silence is the defect, and it is the same class of defect as a check that passes while
  measuring nothing.
- The report says plainly that an exclusion is not a guarantee of absence. It cannot be: a group
  outside the excluded container can hold members inside it, which is why the old code applied the
  filter at three sites rather than one, and B11 classifies exactly that case.

**What keeping exclusions costs.** Every report grows a section describing what was not looked at,
and every finding near an excluded subtree needs qualifying. Coverage arithmetic gets a second kind
of denominator â€” objects not read because they could not be, and objects not read because nobody
asked for them.

**What removing exclusions costs.** Some customers cannot run the product at all. Segregation of
duty, a subsidiary under separate legal control, or a container an auditor is contractually not
permitted to enumerate are all real, and the alternative to a scoped audit is not a full audit, it
is no audit. Refusing exclusions makes the product's evidence purer and its deployment narrower.

---

### 3. B4 â€” the unit of capture

> **Answered 2026-08-11. Rebuild confirmed, and the unit is one naming context, never one domain.**
> The finding below was re-derived from Microsoft's documentation rather than inherited, and it held.
> What it did not say is which avoidance to use and which to refuse. Capture chases nothing and
> enumerates every naming context deliberately; it does not search the global catalog, which is the
> avoidance that looks cheapest and is silently wrong three ways (F-S7-10). See Â§B4 and B5 below
> for the full reasoning and what each choice costs.

**The question, as posed.** Whether to carry the shard machinery now. B4 and B5 are answered
separately, because reading the map and the directory's own behaviour splits them.

**What I found.** The old design treated "one domain, one domain controller, one search base" as the
unit of *parallelism*. It is also the unit of *correctness*, and that half is not written down
anywhere. A subtree search based at the root of a domain naming context does not stay inside that
domain: the server returns subordinate referrals for the Configuration naming context, the Schema
naming context, the DNS zone partitions, and every child domain recursively
([Searching Domain Contents](https://learn.microsoft.com/windows/win32/ad/searching-domain-contents),
[Referrals](https://learn.microsoft.com/windows/win32/ad/referrals)). Worse, Microsoft documents
that a **paged** search that chases subordinate referrals is broken: the paged cookie is overwritten
and the search ends silently after the first page, or fails with an operational error, and the
documented remedies are to base the search below the domain root, turn referral chasing off, or use
the domain-scope control
([LDAP paged queries with subordinate referrals](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased)).

Every capture this product performs is a paged subtree search from a domain root. A silent stop
after the first page is a capture that reports a thousand objects out of nine million and says
nothing went wrong â€” the exact failure an audit tool cannot have.

**Recommendation.** Rebuild B4 now as the unit of capture â€” one naming context, one domain
controller, one scope, and an explicit referral policy â€” and rename it away from "shard", because
"shard" names the parallelism that is being deferred. The referral decision belongs to this type and
is a correctness property, not a tuning knob.

---

### 4. B5 â€” shard fan-out, and whether to carry it now

> **Answered 2026-08-11. Defer confirmed, and the reason changed underneath it.** The original
> reason was that nobody had measured the benefit. There is also a **documented cost**: a domain
> controller holds the state that makes a paged search resumable in one shared per-controller
> budget, and discards the oldest when it is full (F-S7-12). So fan-out is not free speed. The
> trigger is restated below as one measurement rather than a wish, and it now also prices what
> [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) added (F-S7-13). See Â§B4 and B5.

**Recommendation. Defer it.** Build capture to read one naming context at a time into one store.

**What deferring costs.** A large forest takes longer in wall-clock time â€” serially rather than up
to N domains at once. That is the whole cost, and it is a cost in patience rather than in
correctness.

**What carrying it now costs.** The map priced it, and the price is not the concurrency. It is a
database file per capture unit, a hand-maintained subset of the schema for those files, a merge, a
source-scanning test that exists solely to detect drift in the hand-maintained list, and coverage
that is written twice because the first number is provisional by construction. Five pieces of
machinery, none of which the product's *output* depends on, all of which have to be correct before
anything runs at all â€” and their only justification is a wall-clock number that nobody in the
rebuild has measured. The one measurement that exists is in `BenchmarkSuite1`, which the ledger
already defers for precisely this reason.

**The trigger.** A measured capture of a forest at the size this product must handle on day one,
taken once B6 runs. `0013` states outright that frozen lab captures "do not give scale", so the
baseline cannot be taken in the lab and the trigger must name where it is taken. **This is the one
question in this session that a wrong answer makes expensive**: capture built simply and made
concurrent later touches the writers, and if the writers assume a single connection the retrofit is
not free. It is still far cheaper than the reverse, which is five pieces of untested machinery
between the rebuild and its first working run.

---

## What it does

Capture is everything between "we know which domains and controllers we are pointed at" and "every
fact the directory stated is recorded, with a coverage record saying how much of it we actually
got". If it vanished, the product would have nothing to analyse: every rule, every grid and every
report reads a bundle that capture wrote.

This session decided the disposition of the first twelve of its twenty-three components. It wrote no
production code. Capture is the ceiling on the product â€” whatever the audit does not read out of the
directory, it can never report on â€” which is why the twelve were decided together rather than one at
a time by whoever happened to build the next one.

## Shape

- [`WHAT-THE-OLD-APP-HAD.md`](../next/WHAT-THE-OLD-APP-HAD.md) â€” rows B1 to B12, each with a disposition, the project it lands
  in, and the document it owes before the row can be called done.
- This document â€” the decision and its cost for each, and the four owner questions above.
- `next/tests/SecureAD.Next.Tests/Documentation/CaptureDispositionDocumentationTests.cs` â€” binds the
  table below to the ledger in both directions, per README Â§When a document counts as documentation.

## Dependencies

- **Depends on:** the map's B branch; decisions `0002`, `0003`, `0008`, `0013`, `0014`, `0015`; and
  Microsoft's documentation of LDAP administration limits, referral generation, range retrieval and
  confidential attributes, cited inline.
- **Depended on by:** every future capture session. B6 is the row gate 5b unblocks on.
- **Layering violations:** none introduced. Directory reads stay in `SecureAD.Audit`, which
  `GreenfieldGateTests` already enforces.

<!-- DISPOSITIONS:BEGIN -->

| Component | Disposition | Lands in |
|---|---|---|
| B1 | Rebuild | `SecureAD.Audit` |
| B2 | Rebuild | `SecureAD.Audit` |
| B3 | Delete | n/a |
| B4 | Rebuild | `SecureAD.Audit` |
| B5 | Defer | `SecureAD.Audit` |
| B6 | Rebuild | `SecureAD.Audit` |
| B7 | Rebuild | `SecureAD.Audit` |
| B8 | Rebuild | `SecureAD.Audit` |
| B9 | Rebuild | `SecureAD.Evidence` |
| B10 | Rebuild | `SecureAD.Evidence` |
| B11 | Rebuild | `SecureAD.Evidence` |
| B12 | Rebuild | `SecureAD.Evidence` |

<!-- DISPOSITIONS:END -->

## The decisions, and what each costs

#### B1 â€” Capture settings: Rebuild, and most of it does not come across

Eighteen settings; five have no consumer anywhere in capture. They are range-validated, shipped as
defaults, editable in the Settings dialog, and written into the bundle â€” so a bundle records that a
capture ran with a sixty-minute shard timeout that nothing enforced. The sharpest is the failover
flag: capture builds one connection per pass from its assigned controller and never fails over, so
the flag describes a capability that does not exist and an operator who turns it on is worse off
than one who never saw it.

Only settings something reads are carried, and the three named presets â€” which vary exactly one
number between them â€” are not three profiles and should not be presented as such.

One thing the map could not have seen. A domain controller closes an idle LDAP connection after
fifteen minutes by default (`MaxConnIdleTime`, 900 seconds,
[LDAP administration limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil)).
A per-controller rate limit slow enough to leave a connection silent for that long gets it closed by
the server. So the queries-per-second setting and the connection's lifetime are one question, and
the settings type cannot treat them as two independent numbers.

**Cost:** the Settings dialog loses controls, which some operator somewhere has set. That is the
point â€” they never did anything.

#### B2 â€” Captured attribute catalogue: Rebuild, and it grows

Owner question 1 above. Rebuild rather than Port because the catalogue gains a whole partition it
never read, and because the relationship between the catalogue and the rules that consume it goes
from convention to a checked one.

**Cost:** every bundle grows by the schema and extended-rights read, which is a fixed few thousand
objects per forest. The larger cost is the discipline: an attribute cannot be added without naming
what reads it, and a rule cannot be written against an attribute nobody captured.

#### B3 â€” OU exclusion filter: Delete, and the feature goes with it

Owner question 2 above, and [`0017`](../decisions/0017-capture-reads-the-whole-forest.md).

The session began intending to rebuild this and make an exclusion loud. Working through what an
exclusion actually hides turned every argument for loudness into an argument for removal. An
exclusion at capture leaves the dangerous permission visible and its holder anonymous; understates
by exactly its own size any count of what an inherited entry reaches; leaks group members in; and
fully hides only the delegation set on the excluded container, which is the one thing an auditor
would ask about it. Meanwhile the guard defending it worked on distinguished names, and a group
managed service account can be created anywhere, so it defended a place rather than a kind of thing.

The deciding facts were two. Capture is the cheap half of a run â€” paged at up to a thousand objects
per request, network-bound, minutes rather than hours â€” so the feature was buying little. And a
capture-side filter can be added later in a few lines, whereas a bundle with a hole in it can never
be filled, which makes removal the recoverable direction.

**Cost.** Every run now reads and analyses what an exclusion would have skipped, and the amount is
unmeasured â€” several hundred thousand objects for the customer that motivated the original feature.
That cost lands in the same place as B5's deferred question, and the same baseline settles both.
Scope, as a reading filter, saves no run time at all: the graph must be complete for a path *through*
a scoped container to an unscoped target to be found, and the per-object work that could be skipped
is the inexpensive part. Scope buys a report a customer will read, not a run that finishes sooner.

**What is salvaged.** The concept of a declared scope, which moves to the reading layer and lives in
the sidecar beside notes and suppressions per
[`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md); and the
evidence-based recommendation service, which changes what it recommends rather than how it works.
**What is not:** the protected-container guard, the exclusion attestation, and one meaning of
*in forest but not captured*, which narrows to an uncaptured domain.

#### B4 â€” The unit of capture: Rebuild, and it stops being called a shard

Owner question 3 above, answered 2026-08-11 in Â§B4 and B5. The map's own note is that the right name is currently occupied by a type
with no production consumer at all; the type that is actually produced is declared in the LDAP
namespace under a different name. Renaming is free now and is not free later.

**Cost:** the word "shard" leaves the vocabulary while the concept it named is deferred, so a future
session that reinstates fan-out reintroduces a word rather than finding it waiting. That is
deliberate â€” a name for machinery that does not exist is how the old tree ended up with five
comments naming a deleted type.

#### B5 â€” Shard fan-out: Defer

Owner question 4 above, answered 2026-08-11 in Â§B4 and B5. This is the only Defer in the twelve.

**Cost:** stated in full above. Capture is slower until the trigger fires, and a later retrofit is
not free.

#### B6 â€” Per-domain capture passes: Rebuild, and it is the critical path

Three passes over one naming context â€” objects, group memberships, security descriptors â€” each
paged, each rate-limited, each emitting its own coverage record. Two things come across unchanged
because they are right: security descriptors are fetched without the audit portion, which is what
lets capture run as an ordinary authenticated user with no special privilege; and a failure in one
pass does not kill the others.

Two things do not. The object pass and the security-descriptor pass each run a full enumeration over
the same object set, differing only in the attributes requested â€” two full reads per naming context.
The reason is real, but no measurement was recorded, so the decision cannot be revisited by anyone.
The rebuild either merges the passes or records the number. And a run that lost three domains of
twelve currently ends in the same state as one that lost none, because the seal is computed from
analysis health and never consults coverage â€” which already holds the truth, per module per domain.

**Cost:** this row cannot run alone. It needs somewhere to write, so the storage rows are on the
path with it; B6 is the first thing that *runs*, not the first thing that finishes.

#### B7 â€” Paging, retry and politeness: Rebuild, and there is one budget per controller

The map found the defect: a fresh rate limiter is built per capture unit and again per Group Policy
read, so two passes against the same controller do not share a budget and the server sees twice the
rate the operator agreed to. One budget per controller hostname per run.

The limits themselves are the server's and are named rather than guessed. A single search returns at
most `MaxPageSize` objects, 1000 by default, and a client that wants more must use the paged
control. A single search gets `MaxQueryDuration` seconds, 120 by default, after which the server
returns `timeLimitExceeded` â€” and Microsoft's own guidance is that the fix is a better query, not a
longer timeout. Windows Server 2008 and later impose hard ceilings above any configured policy
([hardcoded LDAP limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response)).
A query too broad to be served from an index is served by scanning, governed by `MaxTempTableSize`,
which is 10,000 records by default â€” this is the mechanism by which one careless filter turns a
capture into an outage on a production controller, and it is a fact about the filter, not about the
rate limit.

**Cost:** honouring the server's limits rather than the operator's preference means some captures are
slower than the operator asked for, and the product has to say so rather than quietly comply.

#### B8 â€” Attribute extraction: Rebuild, merged into one reader

Two files doing one job, split along no visible line, both parsing identifiers out of binary
attributes. The map is explicit that the split is sediment from two deleted modules rather than a
design. Merged.

The load-bearing requirement is not the merge. A multi-valued attribute with more values than the
server's `MaxValRange` â€” 1500 by default, and capped at 5000 on Windows Server 2008 and later
whatever the policy says â€” comes back **truncated, not failed**. The client must ask for values by
range, `member;range=0-999` and onwards, and must handle the wildcard case at the end
([Attribute Range Retrieval](https://learn.microsoft.com/windows/win32/adsi/attribute-range-retrieval),
[Enumerating groups that contain many members](https://learn.microsoft.com/windows/win32/ad/enumerating-groups-that-contain-many-members)).
A reader that does not do this reports Domain Users as having 1500 members and reports it calmly.
That is this product telling a customer something false, so it is bound by a test over a group
larger than the limit rather than left to a comment.

**Cost:** a test that needs a group of several thousand members, which means a fixture rather than a
lab.

#### B9 â€” Object writer: Rebuild, in the bundle project

Lands in `SecureAD.Evidence` rather than in capture. That forces the seam the old tree did not have:
capture hands over typed values, and the writer never sees a `SearchResultEntry`. The old tree's
sediment â€” two grab-bag helper files, and an ACE writer that executes table-creation SQL in its own
constructor â€” are both symptoms of that boundary not existing.

With B5 deferred there is no merge, so resolving each object's parent stops being a static method
called after one. It becomes a single pass at the end of capture over one store, and the only
remaining reason it cannot be done inline is that a parent may sit in a page not yet read.

**Cost:** one mapping step per object between capture and storage, which is allocation on the hottest
path in the product. It buys a storage layer that is testable without a directory.

#### B10 â€” ACE writer: Rebuild, and it owes a hash the old one never computed

[`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md) requires a
canonical ACE-set hash per object, so that objects sharing an identical permission set can be
grouped and a customer can name a delegation the product does not recognise. It says outright that
this is cheap while the schema is being designed and expensive afterwards, and that without it only
the rejected approach â€” customer-authored pattern definitions â€” remains available. This row is where
that bill arrives.

The old writer stores each ACL twice on purpose, normalised for querying and compressed for exact
display, and that is sound. It also counts inherited entries and drops them, which forces the read
side to reconstruct inheritance later. Under `0013` the schema is free, so whether inherited entries
are stored is now an open choice rather than an inherited constraint â€” F-S7-2.

**Cost:** the hash is computed during capture over every object's canonical ACE set, on the pass that
is already the most expensive. Not computing it is cheaper today and forecloses the only acceptable
answer to unrecognised delegations.

#### B11 â€” Group membership and unresolved members: Rebuild, categories carried

The four-value classification is the part worth keeping, and it is kept as knowledge rather than as
code: *the forest list is unknown*, *in-forest but not captured*, *genuinely cross-forest*, and
*captured domain, name missing*. Only the second counts against coverage or falsifies an operator's
attestation that an excluded container held nothing relevant. They exist as a type because behaviour
was once derived from the wording of the message shown to the user, so rewording a sentence silently
changed a metric and a grid column. That is `0002` in a different costume, and the reason the type
survives a rewrite that discards its implementation.

Deferring B5 does not simplify this. The cross-*shard* replay disappears; the cross-*domain* problem
does not, because a group in one domain can hold a member in a domain captured later or not at all.

**Cost:** four categories is four things a report has to explain, where one count would be simpler
and would be a lie.

#### B12 â€” Principal resolution: Rebuild, and one state is now permanent

The old writer resolves identifiers only against objects it captured â€” no directory call â€” so it
emits two states where the table supports richer ones. The component that would have filled the rest
in is a live lookup in branch H, and [`0008`](../decisions/0008-live-verification-is-removed.md)
deletes branch H. So in the rebuild an unresolved identifier stays unresolved permanently, and per
`0002` it must never be rendered as a fact about the forest.

I considered leaving this row undecided, because what the product *says* about an identifier it
cannot name is genuinely unsettled. It is the same question `0014` leaves open for an unnameable
GUID and `0015` leaves open for an ACE matching no pattern, and all three deserve one answer. But
that is a question about wording, not about disposition: the component is rebuilt in the bundle
project either way. Recorded as F-S7-1 rather than used as an excuse to leave the row blank.

**Cost:** the product will show identifiers it cannot name, and must do so honestly rather than
hiding them. A hidden unresolvable trustee is a permission attributed to nobody.

### What is on the critical path, and in what order

1. **B2**, because it decides what every later component has to carry, and because a bundle captured
   without an attribute cannot gain it later.
2. **B4** and **B7**, because they are how a search is issued at all, and both hold correctness
   properties rather than tuning.
3. **B8**, because without range retrieval the group pass is wrong rather than slow.
4. **B6**, which is the first component that runs and the row gate 5b unblocks on. It cannot run
   without somewhere to write, so the storage rows are on the path beside it â€” B6 is the first thing
   that runs, not the first thing that is finished.
5. **B9** through **B12**, as B6's output lands. B10 should not be last, because `0015`'s hash is a
   schema decision and schema decisions get expensive in the order they are made.
6. **B1** and **B5** last. B1 shapes what an operator may ask for, which is worth deciding after
   there is something to ask it of; B5 waits on its trigger. **B3 is not on the path at all** â€” it is
   deleted, and nothing replaces it in capture.

## B4 and B5 â€” decided 2026-08-11

This session was asked to test the two provisional dispositions rather than confirm them, on the
precedent of B3, which entered as Rebuild and left as Delete. Both survived. Neither survived
unchanged: B4 gains three refusals it did not have, and B5's reason was replaced with a better one.

### B4 â€” Rebuild, and the unit is a naming context

**What the finding was, and whether it held.** F-S7-4 says a paged subtree search based at a domain
root can stop after one page and report success. It was re-derived from Microsoft's own article
rather than taken from the ledger, and it held in every particular. Microsoft states there is **no
resolution** and lists four ways to avoid it. What the first pass did not do is choose among the
four, or say what happens to the ones not chosen â€” and that turns out to be where the decision is.

**What capture will do.** Every search is based at the root of **one naming context**, and referral
chasing is set to `None` explicitly. The naming contexts are enumerated deliberately and read one at
a time. **Which** naming contexts are in scope is not B4's to decide â€” B4 decides that the unit is a
naming context and that a unit follows nothing. Today the answer is the domain partitions plus the
configuration and schema partitions, because
[`0014`](../decisions/0014-capture-reads-the-schema-partition.md) and the B2 decision require the
last two to be read on purpose; the DNS application partitions are **not** in scope and never were,
and the reason had never been written down until F-S7-16. That the avoidance and the existing
requirement are the same act is what makes this avoidance strictly better than the others rather
than merely acceptable.

Two smaller choices go with it. Referral chasing is set rather than left alone, because the default
is not "off": for the API this product uses, a search with no referral preference chases *external*
referrals ([`ReferralChasingOption`](https://learn.microsoft.com/dotnet/api/system.directoryservices.referralchasingoption?view=net-11.0-pp)),
and a policy that happens to be safe today is not a policy. And `DomainScopeControl` â€” the managed
name for `LDAP_SERVER_DOMAIN_SCOPE_OID`, which tells a controller not to generate continuation
referrals at all â€” is sent **non-critical** on domain-partition searches, after checking that the
OID appears in the controller's `supportedControl`. Non-critical means a controller that does not
recognise it ignores it and answers anyway, rather than failing the search; the chasing-off setting
carries the correctness and the control is a second line.

**What is refused, and why it matters that it is written down.**

- *Basing the search below the domain root*, which is the first remedy Microsoft lists. It works,
  and it means enumerating containers and searching each one. Objects sitting directly in the domain
  root, and any container the enumeration did not think of, are then not read â€” and nothing says so.
  That is precisely the incompleteness [`0017`](../decisions/0017-capture-reads-the-whole-forest.md)
  refuses, arrived at by accident instead of by an operator ticking a box.
- *Searching the global catalog*, which is the second remedy and the one a later session will reach
  for, because it looks like one server, no referrals, and the whole forest in a single pass. It is
  wrong three ways and all three are silent. This is F-S7-10 and it is written into B4's document,
  not left as a comment.
- *Chasing referrals but handling the cookie carefully.* There is nothing to handle carefully. The
  client's paged cookie is overwritten inside the LDAP runtime; the application never sees the
  moment it happens.

**One thing that came out of refusing the first two.** With chasing off, the controller still
*returns* the subordinate referrals â€” it just does not follow them. The old design would have
discarded them as noise. They are better than that: taken together they are the controller's own
statement of what else exists below that point. So a capture unit reconciles the continuation
references it received against the set of units the run planned, and anything left over is a
partition the run did not know about and must record as a coverage gap rather than ignore. That is
F-S7-11, and it is the strongest reason the referral policy belongs to B4 rather than to B6 or B7.

**What the decision costs.** Capture gains a planning step it did not have: something must enumerate
the naming contexts before any search is issued, and that enumeration is now load-bearing rather
than incidental. A forest with an unusual partition layout â€” a trimmed application partition, a
domain whose controller is unreachable â€” surfaces as a coverage entry rather than as silence, which
is right and is also more entries for a report to explain. And "shard" leaves the vocabulary, so a
future session reinstating fan-out reintroduces the word instead of finding it waiting.

**What refusing this would have cost.** A capture that reads the first page of a nine-million-object
forest, reports no error, and produces a report a customer signs. There is no version of this
product that can survive that, which is why B4 is a correctness row and not a performance one.

### B5 â€” Defer, and the trigger is now falsifiable

**What was wrong with the original reason.** It was an argument from absence: five pieces of
machinery justified only by a wall-clock number nobody has measured. That is a good argument and it
is one-sided. It says fan-out has an unproven benefit; it does not say fan-out has a cost.

**It has a cost, and it is documented.** A domain controller works on LDAP requests with a bounded
worker pool â€” `MaxPoolThreads`, four threads per processor, which Microsoft says "determines the
maximum number of threads per-processor that can work on LDAP requests at the same time". More
importantly, between the individual searches that make up one paged search, the controller keeps
intermediate state so the next page is fast, and the total it will keep for that purpose is one
budget: `MaxResultSetSize`, 262,144 bytes by default. When it fills, the controller **discards the
oldest intermediate results**
([LDAP administration limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil)).
Concurrent paged searches against one controller compete for that budget. Losing paged-search state
without being told is the same shape of failure F-S7-4 names, reached from the other direction. That
is F-S7-12.

It does not bite everywhere. The old design spread shards across different controllers, one per
domain, and that spreads the budget too. It bites exactly where `0014` and B2 now send the product:
the configuration and schema partitions exist on **every** controller, so those units have nowhere
to spread to, and they are the units the product cannot do without.

One thing recorded so a later session does not rediscover it wrongly: `MaxActiveQueries`, the limit
that returns a `busy` error at twenty concurrent searches, is documented as **no longer enforced**
from Windows Server 2003 onward. It is not a live constraint and must not be cited as one.

**The trigger, stated precisely.** One measurement, taken once, answering three questions at the
same time â€” B5's, F-S7-3's two-passes question, and the price of `0017`.

- **What is measured.** Wall-clock of a complete single-threaded capture, broken down per naming
  context and per pass; objects read per second per controller; and, separately, wall-clock of
  derived analysis over the same bundle. Alongside them, a count of every `busy`,
  `timeLimitExceeded` and `sizeLimitExceeded` response and every connection the server closed.
- **Where it is taken.** On a customer or pilot forest, by B6's own instrumentation, written into
  the bundle's coverage record so it is evidence rather than a note in someone's session.
  [`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) records that frozen lab
  captures do not give scale, so a lab number cannot fire this trigger and saying so is the point.
- **Against what size.** A forest at or above the scale `BenchmarkSuite1` records on the analysis
  side â€” nine million control edges â€” because that is the only recorded number about this product at
  scale and the ledger keeps that suite for exactly this moment.
- **When it fires.** Only if capture wall-clock **dominates** derived-analysis wall-clock *and* a
  single-threaded capture does not finish inside the customer's maintenance window. If analysis
  dominates, B5 stays deferred permanently and the effort belongs to analysis instead â€” which is
  what `0017` already predicts, and which that measurement would confirm or refute.

**The measurement `0017` left owing.** `0017` removed capture-side exclusion, so every run now reads
and analyses regions it used to skip, and it justified that partly by asserting that capture is the
cheap half of a run and analysis the expensive one. That assertion is plausible and unmeasured,
which per [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) is
not a source. It lands on the same baseline B5 is waiting for and is answered by the same run rather
than by a second one. That is F-S7-13.

**What deferring costs.** A large forest takes longer in wall-clock than it might â€” serially rather
than up to N domains at once. If the trigger ever fires, the retrofit is not free: it touches the
writers, and a writer that assumed a single connection has to be revisited. That is the whole cost,
and it is a cost in patience plus a bounded amount of later work.

**What carrying it now would cost.** Five pieces of machinery â€” a database file per unit, a
hand-maintained shard table list, a merge, a source-scanning test whose entire job is to detect
drift in that hand-maintained list, and coverage written twice because the first number is
provisional by construction â€” all of which must be correct before anything runs at all, and none of
which changes a number a customer sees. Against a benefit nobody has measured and a documented
server-side budget it would contend for.

### What this changes for two neighbouring rows

**B6 â€” the row gate 5b unblocks on.** Not decided here, and two obligations are recorded against it.
Its passes run per naming context per capture unit, not per domain, which is a different loop than
the one the map describes. And B6 carries the instrument: the measurement B5's trigger needs and the
measurement F-S7-3 needs are the same measurement, so B6 is where it is taken. Neither changes B6's
disposition, which stays Rebuild.

**B17 â€” shard schema and merge.** Out of scope and not decided. Recorded so it is not decided by
inertia: B17 exists only to serve B5's fan-out and has no other consumer, and the map's own
Would-do-differently Â§3 says its hand-maintained table list should not exist at all. When that row
comes up, **Delete** is the honest starting hypothesis and "Defer, because B5 is deferred" is the
answer to be suspicious of. That is F-S7-14.

**B11 is unaffected.** Its four unresolved-member categories were already checked against a deferred
B5 and survive: the cross-*shard* problem disappears with fan-out, the cross-*domain* problem does
not.

### F-S7-19 â€” The per-controller rate limit is correctly built, correctly wired, and cannot engage

- **Severity:** maintainability
- **Confidence:** verified for the mechanism; **inferred** for the rate, from the owner's measurement
- **Evidence:** `DcRateLimiter` is a `TokenBucketRateLimiter` per controller hostname with
  `TokenLimit` and `TokensPerPeriod` both set to the configured rate, a one-second replenishment
  period, `QueueLimit = int.MaxValue` so callers wait rather than being rejected, and
  `lease.IsAcquired` checked. It is acquired inside `SendRequestAsync`, the single wrapper every
  capture page passes through, and again at the ranged-member call site and in the SYSVOL builder.
  Nothing is missing. But the token is taken and then the **whole page round trip is awaited**
  before the loop returns for another, so the achievable rate is `1 / (time for one page)`. To reach
  the default of 25 requests per second a page of up to a thousand objects carrying
  `nTSecurityDescriptor` â€” which the schema permits up to 132,096 bytes per object â€” would have to
  complete in 40 milliseconds. The owner's production measurement, nine domains at three concurrent
  in 30 to 40 minutes, puts the observed rate under one request per second per controller across a
  wide range of assumed object counts.
- **What happens to a user:** an operator chooses between three presets labelled by their effect on
  production â€” Safe, Balanced, Fast â€” and the choice changes nothing a domain controller
  experiences. That is worse than having no setting, because it reads as a lever over production
  impact and is not one. It also means nobody has ever tuned what actually generates load.
- **Why it is this way:** the limiter counts *requests*, and a request is a page of up to a thousand
  objects. Cost on a controller is objects read, temporary table pressure and bytes serialised â€”
  none of which is proportional to request count. The unit being limited is not the unit that costs
  anything.
- **Resolution:** the limiter and the `PerDcQpsLimit` setting are removed, and the three presets go
  with them. Decided by the owner 2026-08-11 on the grounds that the product is deliberately
  designed never to pipeline requests, so the limiter has no future consumer either.
- **Confirmation available, and cheap:** count how often `AcquireAsync` blocks over one real run
  before deleting. If the answer is never, the argument is settled by measurement instead of by the
  arithmetic above. Not done, because the decision does not depend on it.
- **Test cover:** none of the existing tests assert that the limiter ever delays anything.
- **Status:** RESOLVED by decision, as of 2026-08-11. Named by ledger rows B1 and B7.

### F-S7-20 â€” Deleting the rate limiter makes "requests are never pipelined" load-bearing, and nothing enforces it

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** requests are paced today by structure, not by policy. `DirectCaptureModule.ExecuteAsync`
  awaits each of its three passes in turn; each pass opens one connection, awaits each page before
  requesting the next, and disposes the connection at the end. That serialisation is the only reason
  F-S7-19's limiter never fires. Nothing states it as a requirement and no test holds it.
- **What happens to a user:** nothing today. The exposure is a later session. With the limiter gone,
  a `Task.WhenAll` around page fetches â€” an obvious-looking optimisation on a capture someone wants
  faster â€” silently multiplies the load placed on a customer's production domain controller, with no
  ceiling and nothing to notice it. The old limiter would have caught that; its removal is what
  makes this matter.
- **Why it is this way:** the constraint was never a decision. It fell out of writing the passes
  sequentially, and while a limiter existed nobody needed it to be one.
- **Options:** state it in B7's document as a design constraint, and hold it with a guard â€” every
  directory request in the capture project issued through one serialised path, so a parallel fetch
  fails the build rather than reaching production. That is the shape of gate 1: a correct mechanism
  with a boundary obliging its use. Not built this session; no gate work was in scope.
- **Test cover:** none. This finding is the request for it.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B7.

### The rate limiter and the forest-partition controller, 2026-08-11

Two owner decisions from the same conversation as the DNS scope. Both touch rows already decided as
Rebuild and change no disposition.

**Client-side rate limiting is removed.** Not repaired, not carried, not deferred â€” removed, along
with `PerDcQpsLimit` and the Safe / Balanced / Fast presets that vary only that number. The
mechanism is sound and cannot engage (F-S7-19), and the product is deliberately designed never to
pipeline requests, so it has no future consumer either. Carrying it would be lines of code
defending against a condition the design forbids.

The obligation this transfers is real and is recorded as F-S7-20: the serialisation that makes it
safe must become a stated constraint with a guard, rather than an accident of how the passes were
written.

**The configuration and schema partitions get their own domain controller.** Chosen at preflight
and recorded in the bundle like any other unit's controller, so that no controller serves two units.
The reason is attribution rather than load â€” both partitions are a few thousand objects once per
forest and place no meaningful pressure anywhere. Under fail-fast, a controller serving two units
makes a failure ambiguous about which unit it ended; one controller per unit removes that.

Two partitions, one controller between them. A forest with a single domain controller is a stated
fallback rather than a failure, so this is a preference with a defined exception and not an
invariant â€” otherwise a small forest fails a rule that exists for tidiness. Preflight validates that
the chosen controller serves the partition before the run starts, rather than discovering it
mid-capture when failing costs the whole run.

### F-S7-21 â€” The settings panel discards eight of the nine settings it shows, and reports success

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `SettingsViewModel.LoadFrom(CaptureSettings)` reads nine values in â€”
  `PerDcQpsLimit`, `LdapPageSize`, `LdapTimeoutSeconds`, `MaxDomainConcurrency`, `RetryCount`,
  `GroupExpansionMaxDepth`, `GroupExpansionMaxNodes`, `GroupExpansionMaxMinutes`,
  `EscalationPathMaxDepth`. `BuildCaptureSettings()` writes one back:
  `new() { PerDcQpsLimit = PerDcQpsLimit }`. Every other property of the new object falls to its
  compiled default. `ShellViewModel` wires the panel's `IsApplied` signal straight to
  `_main.ApplyCaptureSettings(vm.BuildCaptureSettings())`, which replaces the active settings
  wholesale, and then sets the status text to *"Settings applied â€” {profile} profile"*.
- **What happens to a user:** an operator picks **Comprehensive All Objects** at step 2 of the audit
  wizard, then opens Settings for any reason at all â€” to check a timeout, to change nothing â€” and
  presses Apply. The capture filter mode silently reverts to Known Security Classes. So do the page
  size, the LDAP timeout, the domain concurrency, the retry count and all four analysis limits. The
  product then tells them the settings were applied. Nothing errors, and the eight lost values are
  the ones the panel had just displayed.
- **Worse in one respect:** `CaptureFilterMode` is not in `LoadFrom` at all, so the panel destroys a
  setting it never showed and cannot show.
- **Why it is this way:** `BuildCaptureSettings` constructs a fresh record rather than copying the
  loaded one and overwriting the edited fields. `CaptureSettings` already has `Withâ€¦` helpers that
  do exactly that and are used elsewhere. This is one line written the wrong way round, and nothing
  detects it because no test compares what goes in against what comes out.
- **What it does not do:** it does not make a bundle lie. `capture_filter_mode` is written into the
  bundle from the settings that actually ran, so a bundle honestly records Known Security Classes.
  The operator is misled; the evidence is not.
- **Sharpened by F-S7-19:** the single property that survives the round trip is `PerDcQpsLimit`,
  which is the one being deleted. Once the rate limiter goes, `BuildCaptureSettings` preserves
  nothing at all.
- **Options:** for the rebuild this is not a repair, it is a shape to avoid â€” a settings surface that
  round-trips must be proved to round-trip, by a test that loads a non-default value for every
  setting and asserts it survives. That belongs with B1, which already owes a document naming every
  setting and the code that reads it; the same binding should hold that every setting the surface
  displays is a setting the surface preserves.
- **Test cover:** none in either tree.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B1. Found while checking whether the
  capture filter mode is ever presented to an operator â€” it is, at step 2 of 5 on the linear path,
  which makes this live rather than dead UI.

## Verified-safe

Things checked and found sound, recorded so they are not re-investigated.

- **Reading security descriptors without the audit portion.** This is why capture needs no special
  privilege and runs as an ordinary authenticated user. Carried unchanged at B6.
- **Versioning the attribute catalogue.** A bundle that cannot state what it was allowed to see
  cannot be read honestly years later. Carried at B2.
- **The four unresolved-member categories.** Checked against what they are used for â€” coverage and
  attestation â€” and each one is distinguishable and load-bearing. Carried at B11.
- **Storing each ACL twice, normalised and exact.** Two consumers with genuinely different needs.
  Carried at B10.
- **The ledger's completeness tests.** Run against the edited rows; all four pass, so the twelve
  edited rows are still exactly twelve real map components with declared dispositions.

## Findings

### F-S7-1 â€” What the product says about a name it cannot resolve is still unsettled

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `0014` Â§Consequences leaves it open for an unnameable GUID; `0015` Â§Consequences
  leaves it open for an ACE matching no pattern; B12 raises it for an unresolvable identifier.
- **What happens to a user:** three different parts of the product will each invent an answer to the
  same question, and at least one will render "we could not name this" as blank space â€” which reads
  as "there is nothing here".
- **Why it is this way:** each decision record correctly declined to settle a question outside its
  own scope. Nobody owns the union.
- **Options:** one answer covering all three, decided before the first of them ships; or three
  answers and the near-certainty that they disagree, which is the failure K16 was rebuilt to undo.
- **Test cover:** none. There is no code yet.
- **Status:** OPEN, as of 2026-08-10. Named by ledger row B12.

### F-S7-2 â€” Whether inherited access control entries are stored is now a free choice

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** map B10 â€” inherited entries are counted and skipped, which is why the read side has
  to reconstruct inheritance; `0013` frees the schema.
- **What happens to a user:** nothing directly. It decides whether an object's effective permissions
  can be shown without a reconstruction step that can itself be wrong.
- **Why it is this way:** the old schema was a contract with an application that is being deleted.
- **Options:** store them, and pay in rows on the largest table in the bundle; or keep skipping them
  and keep the reconstruction, which must then be one implementation rather than several.
- **Test cover:** none. There is no code yet.
- **Status:** OPEN, as of 2026-08-10. Named by ledger row B10.

### F-S7-3 â€” Two full enumerations per naming context, with no recorded measurement

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** map B-capture Would-do-differently Â§4.
- **What happens to a user:** a capture takes roughly twice as long as it might, or does not â€” nobody
  can say, which is the finding.
- **Why it is this way:** security descriptors need a control the other attributes do not, and are
  large enough that batching them together would inflate page sizes. That reasoning is plausible and
  was never measured.
- **Options:** merge the passes and page smaller; or keep two passes and record the number that
  justifies them, so the next person can revisit it.
- **Test cover:** none.
- **Status:** OPEN, as of 2026-08-10. Named by ledger row B6.

### F-S7-4 â€” A paged search from a domain root can stop silently after one page

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** [LDAP paged queries with subordinate referrals are not chased properly](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased).
  A domain controller returns subordinate referrals for the Configuration and Schema naming
  contexts, the DNS zone partitions, and every child domain recursively; under paging the client's
  cookie is overwritten by the chased referral, so the application sees an empty cookie and stops.
- **What happens to a user:** a capture reads the first page of a domain, reports no error, and the
  audit is performed against a fraction of the forest that the report presents as the whole of it.
- **Why it is this way:** it is a documented interaction between two LDAP features, with no fix â€” the
  Microsoft article says so outright. It is avoided rather than repaired.
- **Options:** turn referral chasing off and enumerate the naming contexts deliberately; or use the
  domain-scope control, which suppresses continuation referrals when searching a domain root. Both
  are documented remedies. Enumerating deliberately is preferred, because the product needs the
  Configuration and Schema partitions anyway per `0014` and should read them on purpose.
- **Test cover:** none in the rebuild. This is a property of the search request, so it is bound by
  B4's document rather than left to a comment.
- **Status:** OPEN, as of 2026-08-10. Named by ledger row B4.

### F-S7-5 â€” The classifier matches on names, and captured names will not be the same names

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `DangerousPermissionClassifier` looks a GUID up in the catalogue and compares the
  resulting name against seventeen string literals, among them `"User-Force-Change-Password"` and
  `"DS-Replication-Get-Changes"`; its own remarks say "The names are looked up in the schema
  catalogue; no GUID is [hardcoded]". Meanwhile an entry in the extended-rights container carries
  two names â€” `cn`, which is `User-Force-Change-Password`, and `displayName`, which is
  `Reset Password` â€” and `0014` asks for the friendly one.
- **What happens to a user:** on a forest where the schema read *succeeded*, the flagship detections
  â€” password reset and both halves of DCSync â€” return `CannotClassify` instead of `Dangerous`,
  because the captured name does not match the literal. Capture improving would make classification
  worse. K16's four-state verdict prevents the unforgivable version of this, since `CannotClassify`
  is never read as safe, but the detection is still lost.
- **Why it is this way:** K16 was built against a shipped catalogue only, where one name per GUID was
  the whole truth. B2 introduces a second source of names and the seam between them was never
  specified.
- **Note the asymmetry:** the attribute anchors â€” `member`, `userAccountControl`,
  `msDS-KeyCredentialLink` â€” are unaffected, because an attribute's `lDAPDisplayName` in the schema
  is the same string. The mismatch is specific to the extended-rights container, which is exactly
  where the two naming fields diverge.
- **Options:** match on the GUID and treat every name as display text, which is the decision taken
  at B2 and means K16 changes; or capture `cn` and pin matching to it, which preserves K16 and makes
  the product's classification depend on a name rather than an identifier. The first is right and
  costs a change to finished code.
- **Test cover:** none. The collision cannot occur until capture exists.
- **Status:** OPEN, as of 2026-08-10. Named by ledger row B2, which is the row that introduces it.

### F-S7-6 â€” The password-reset delegation may grant far more than a password reset

- **Severity:** breaks-for-user, if confirmed
- **Confidence:** **suspected â€” needs-environment.** Read the two halves of this separately.
- **Evidence, verified:** the `User-Account-Restrictions` property set contains, on Windows Server
  2012 and later, `Account-Expires`, `Pwd-Last-Set`, `User-Account-Control`, `User-Parameters`,
  `ms-DS-User-Account-Control-Computed`, `ms-DS-User-Password-Expiry-Time-Computed` and
  **`ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity`**
  ([User-Account-Restrictions](https://learn.microsoft.com/windows/win32/adschema/r-user-account-restrictions)).
  Two of those, `userAccountControl` and `msDS-AllowedToActOnBehalfOfOtherIdentity`, are on K16's
  own list of dangerous attributes, the second being the basis of resource-based constrained
  delegation takeover.
- **Evidence, not verified:** that the delegation wizard's password-reset task grants the **property
  set** rather than `pwdLastSet` alone. The only support for that is the previous product's own
  bundle definition, whose comment reads "Write Account Restrictions (for pwdLastSet)". That is our
  own code, not a source.
- **What happens to a user, if confirmed:** the helpdesk delegation almost every organisation has
  performed also hands write access to the constrained-delegation attribute on every user in the
  container. Per [`0015`](../decisions/0015-a-bundle-names-a-pattern-it-never-explains-one-away.md)
  the bundle may name the pattern and may not excuse it, so this must be reported rather than
  absorbed into a friendly label.
- **Why the caution:** this is the exact shape of the mistake
  [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) records â€”
  a plausible mechanism with a confirmed premise, written down as though a source existed. It does
  not, yet.
- **Options:** confirm in a lab â€” delegate the task in a test forest and read the resulting entries
  â€” then decide the wording; or ship nothing that asserts it. Nothing about capture depends on the
  answer: the product reads the entries a forest actually has and expands the set from that forest's
  own schema, so a customer with this pattern is reported correctly either way. What the answer
  changes is how prominent the finding is.
- **Priority:** low, and it does not need a lab set up for it. `0013` already requires a lab session
  to freeze captures as test assets before the old capture code is deleted; this belongs on that
  session's checklist.
- **Test cover:** none.
- **Status:** OPEN, as of 2026-08-10. Found at B2 and named by its row. The claim itself belongs to
  the delegation-bundle work at D4, on the same terms `0016` set for `F-S3-6`: it stays a suspicion
  until a lab settles it, and no assertion in the product may cite Microsoft for it.

### F-S7-7 â€” The product recommends excluding the container that holds key credential material

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** the audit dialog offers a button described as *"Add well-known low-signal system
  containers (TPM Devices, NTDS Quotas, Keys)"*. Microsoft's domain preparation for Windows Server
  2016 creates `CN=Keys` at the root of the domain with the description **"Default container for key
  credential objects"**, and grants Full Control on it to `Key Admins` and `Enterprise Key Admins`
  ([Domain-wide schema updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates)).
- **What happens to a user:** one click removes from the audit the default container for
  authentication key material, and with it the permissions that say who may write there. Key
  credentials are the same family as `msDS-KeyCredentialLink`, which K16 already classifies as
  dangerous because writing it is an impersonation technique.
- **On the other two:** `CN=TPM Devices` is doubtful rather than safe â€” `msTPM-OwnerInformation`
  carries `searchFlags 0x298`, which sets the confidential bit and the RODC-filtered bit, so the
  values are unreadable to an ordinary caller but the container's permissions remain an interesting
  delegation question. `CN=NTDS Quotas` was not verified either way and no claim is made about it.
- **Why it is this way:** the list appears to predate `CN=Keys` mattering, and nothing re-checked it.
- **Options:** under [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) the button cannot
  remove anything from the evidence, so the severity drops sharply on its own. What survives is the
  suggestion, which must not name `CN=Keys`, and the principle that a shipped list of "safe to
  ignore" locations decays and must be re-derived rather than typed.
- **Test cover:** none.
- **Status:** OPEN, as of 2026-08-10. Carried by the row that inherits the recommendation service,
  named from B3.

### F-S7-8 â€” The exclusion recommendation ignores control edges and escalation paths

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `LowSignalOuRecommendationService` counts objects, findings, control edges,
  escalation paths and Tier 0 objects, and then filters on
  `object_count >= N AND finding_count = 0 AND tier_zero_object_count = 0`. Control edges and
  escalation paths appear only in the `ORDER BY`.
- **What happens to a user:** a container holding five hundred control edges, or lying on escalation
  paths, can be recommended for exclusion provided no finding *targets* an object in it and no
  Tier 0 object *lives* in it. Control edges are the graph the escalation analysis runs on, so
  acting on the recommendation shortens paths for a reason nobody will connect to a checkbox ticked
  the previous quarter.
- **Why it is this way:** the two counts were computed for display and ranking, and the filter was
  written from findings alone.
- **Options:** put both counts in the filter. Under `0017` the consequence is confined to a report
  rather than the evidence, which makes it survivable rather than serious â€” but a recommendation the
  product makes is still something the product can be held to.
- **Test cover:** none.
- **Status:** OPEN, as of 2026-08-10. Carried by the row that inherits the recommendation service,
  named from B3.

### F-S7-9 â€” The ledger completeness tests did not check that a row has all its columns

- **Severity:** maintainability
- **Confidence:** verified â€” **found by committing it**
- **Evidence:** during mutation testing of the S-7 binding, row B3 lost its `Docs` and `Addresses`
  cells. All four ledger completeness tests continued to pass, because the disposition check reads
  cell 2 and the status check reads cell 4, and a row truncated after cell 4 satisfies both.
- **What happens to a user:** nothing directly, which is why it is maintainability rather than
  correctness. What it costs is the guarantee the ledger exists to give. `README` Â§The ledger states
  that each row names *"the documentation that must exist and be bound before the row is done"* and
  that *"code ported without its documentation is not a finished row"*. A row could lose that column
  and no build would notice, so a future session would read a row that owes nothing.
- **Why it is this way:** the tests were written to hold the ledger against the map â€” the two
  directions of *which components exist* â€” and the shape of a row was never the subject.
- **Repair:** `EveryLedgerRowCarriesEveryColumn` and `TheHeaderDeclaresTheExpectedColumns` added to
  `InventoryCompletenessTests`, with the expected columns declared once and checked against the
  table's own header so the two cannot drift.
- **Test cover:** the repair is the test cover; mutation-tested by removing a cell from a row and by
  adding one, and by altering the header.
- **Status:** REPAIRED, as of 2026-08-10.

### F-S7-10 â€” The global catalog cannot serve this capture, and it is the avoidance that looks cheapest

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** Microsoft lists "search the Global Catalog instead of the forest root domain NC" as
  the second way to avoid F-S7-4
  ([LDAP paged queries with subordinate referrals](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased)),
  with the caveat that all wanted attributes must be present there. Three things say they are not.
  A query filter naming an attribute absent from the global catalog has that expression **evaluated
  as false**, and a requested attribute absent from it is simply **not returned**
  ([Searching the Global Catalog](https://learn.microsoft.com/windows/win32/ad/searching-global-catalog-contents)).
  `attributeSecurityGUID` â€” the attribute the B2 decision added on 2026-08-10 so a property-set
  permission can be expanded into what it really grants â€” has **In Global Catalog: False**
  ([Attribute-Security-GUID](https://learn.microsoft.com/windows/win32/adschema/a-attributesecurityguid)).
  And objects in an application directory partition, which is what the DNS zone partitions are, are
  **not replicated to the global catalog at all**
  ([Application Directory Partition Replication](https://learn.microsoft.com/windows/win32/ad/application-directory-partition-replication)).
- **What happens to a user:** a capture that quietly reads a subset of the forest and cannot say so.
  A filter term silently evaluating false is a "we found nothing" that was really "we could not
  ask" â€” the same defect as a confidential attribute reading as unset, which `0002` already refuses.
- **Why it is this way:** the global catalog is genuinely the right answer for the problem it was
  built for, which is finding an object without knowing its domain. It is the wrong answer for
  reading a forest exhaustively, and the difference is not visible from the shape of the API. What
  makes it convincing is that `nTSecurityDescriptor` **is** in the global catalog
  ([Global Attributes](https://learn.microsoft.com/windows/win32/adschema/attributes-global)), so
  the one attribute a reader would check first is present.
- **Options:** none that keep the global catalog. It is refused, and the refusal is written into
  B4's document rather than left as a comment, because the next person to look for a faster capture
  will find the same article and the same second bullet.
- **Test cover:** none in the rebuild. Bound by B4's capture-unit document, which must name the
  refused avoidances and not only the chosen one.
- **Status:** OPEN as a standing constraint, as of 2026-08-11. Named by ledger row B4.

### F-S7-11 â€” Continuation references still arrive with chasing off, and they are evidence

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** "If referral chasing is not enabled and a subtree search is performed, the search
  will return all objects within the specified domain that meet the search criteria. The search will
  **also return referrals** to any subordinate domains that are direct descendants"
  ([Referrals (AD DS)](https://learn.microsoft.com/windows/win32/ad/referrals),
  [Searching Domain Contents](https://learn.microsoft.com/windows/win32/ad/searching-domain-contents)).
  Turning chasing off stops the client following them; it does not stop the server sending them.
- **What happens to a user:** in the bad case, a client that treats a continuation reference as an
  error ends a capture that was fine, or treats it as a result and writes an object that does not
  exist. In the good case â€” the one this finding argues for â€” the references are the controller's
  own statement of what else exists, and a partition the run did not plan for becomes a visible
  coverage gap instead of silence.
- **Why it is this way:** the old design read one domain per shard and had no reason to care what
  else the server mentioned. Once capture enumerates naming contexts deliberately per `0014` and B2,
  the two lists can be compared, and a comparison nobody makes is a check nobody has.
- **Options:** discard the references, which is what the old design effectively did; or reconcile
  them against the planned unit set and record the difference. Reconciling is chosen.
- **Test cover:** none in the rebuild. Bound by B4's capture-unit document.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B4.

### F-S7-12 â€” Paged-search state is one per-controller budget, and the controller discards the oldest

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `MaxResultSetSize`, default 262,144 bytes â€” "between the individual searches that
  make up a paged result search, the domain controller may store intermediate data for the clientâ€¦
  When this limit is reached, the domain controller **discards the oldest** of these intermediate
  results to make room to store new intermediate results." Alongside it `MaxPoolThreads`, four
  threads per processor, "also determines the maximum number of threads per-processor that can work
  on LDAP requests at the same time"
  ([LDAP administration limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil)).
  The same page records that `MaxActiveQueries` â€” the twenty-concurrent-search `busy` limit â€” has
  **not been enforced since Windows Server 2003**, so it must not be cited as a live constraint.
- **What happens to a user:** if capture ever fans out several paged searches at one controller, the
  controller can drop the state behind one of them under load. That is the same class of silent
  truncation as F-S7-4, and it would appear only on the forests large enough for fan-out to have
  been worth building.
- **Why it is this way:** the map priced fan-out as client-side machinery â€” files, merge, coverage â€”
  and the server's side of the bargain was never looked at. It is the second half of the same
  question B7 already asks about rate limiting: the limits are the server's, and they are named
  rather than guessed.
- **Options:** defer fan-out, which is what B5 does; or, if the trigger ever fires, spread units
  across controllers and treat the configuration and schema units â€” which exist on every controller
  and so cannot spread â€” as the case that constrains the design.
- **Test cover:** none. There is no code yet.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B5.

### F-S7-13 â€” Nobody has measured what removing capture-side exclusion added

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) Â§Context asserts that
  capture is "the cheap half of a run" and that derived analysis "is the part that takes the time,
  and it is combinatorial rather than linear". No measurement is cited for either half.
  [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) is the
  record that says a plausible mechanism is not a source.
- **What happens to a user:** the decision that every run reads and analyses the container an
  operator used to exclude may cost minutes or may cost hours, and nobody can say which. If it is
  hours, the customer who most needed the exclusion is the one who finds out.
- **Why it is this way:** `0017` was decided on evidence quality, which is the right axis, and the
  cost estimate was a supporting remark rather than the basis. It is still load-bearing now, because
  B5's deferral partly rests on it.
- **Options:** measure it on the same run that answers B5's trigger â€” it is the same instrument on
  the same forest â€” or leave two unmeasured claims propped against each other.
- **Test cover:** none. There is no code yet.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B5.

### F-S7-14 â€” B17 has no consumer other than the fan-out that is deferred

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** map B17 â€” the shard schema is "a hand-maintained list of seven DDL constants" whose
  only purpose is the per-shard database files, and the merge folds those files back; map
  Would-do-differently Â§3 says outright that "a test that exists to detect drift in a list is
  evidence that the list should not be hand-maintained". Map B5 names B17 as a dependency; nothing
  else does.
- **What happens to a user:** nothing directly. What it costs is a row decided by inertia â€” B5 is
  Defer, so B17 looks like Defer â€” carrying forward a hand-maintained list and a source-scanning
  test guarding it, for a component with no consumer.
- **Why it is this way:** B17 was a real answer to a real problem in a design that had shards. The
  design no longer has shards.
- **Options:** decide B17 on its own merits when its row comes up, with Delete as the starting
  hypothesis. Not decided here â€” this session's scope is B4 and B5.
- **Test cover:** none.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B17.

### F-S7-15 â€” The old capture already avoided F-S7-4, on two undocumented lines, with the wrong reason written beside them

- **Severity:** correctness-risk
- **Confidence:** verified â€” **by reading the old code after asserting otherwise**
- **Evidence:** `LdapConnectionManager.cs:232` sets `ReferralChasing = ReferralChasingOptions.None`
  on every connection, and `DirectCaptureModule.SecurityDescriptors.cs:130` â€” which holds the shared
  paging helpers for the whole module â€” adds `SearchOptionsControl(SearchOption.DomainScope)`. Both
  avoidances are already in place. The comment above the first says referrals cause "unexpected
  latency, partial results, and cross-domain inconsistency."
- **What happens to a user:** nothing today. The exposure is the rewrite. The comment names three
  plausible costs and not the actual defect, so a reader tidying the new code concludes the line is
  a performance precaution, removes it, and the capture keeps working perfectly against any forest
  without child domains â€” which is every lab. It fails silently on the first customer forest that
  has one.
- **Why it is this way:** whoever wrote it knew referrals were trouble and wrote down the trouble
  they had seen rather than the documented defect. Neither line has a test.
- **Options:** none that leave it as it is. This is the whole reason B4 is a Rebuild row rather than
  a Port: the property survives on two lines and a wrong comment, and B4's job is to make the build
  refuse to lose it.
- **Test cover:** none today, in either tree. Owed by B4's capture-unit document.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B4. Recorded because this session first
  described the defect as a live hole in the old product, which it is not.

### F-S7-16 â€” DNS coverage depends on where an administrator chose to store the zone

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** an Active Directory-integrated DNS zone can be stored in either of two places. The
  legacy scope puts it in the **domain** partition at `CN=MicrosoftDNS,CN=System,DC=â€¦`; the default
  since Windows Server 2003 puts it in the `DomainDnsZones` / `ForestDnsZones` **application**
  partitions ([Active Directory-Integrated DNS Zones](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/active-directory-integrated-dns-zones)).
  The old capture's search base is `defaultNamingContext` alone
  (`ForestDcPreflightService.cs:81â€“89`), so it reads the first and not the second. That it reads the
  first is not theoretical: `HighValueTargets.cs:48` lists `CN=MicrosoftDNS` as a **high-value
  container**, and four separate places exist solely to cope with the objects it returns â€”
  `IsBroadSidTargetTierZero` carve-outs pinned by `SEC-060` N2/E9 and `SEC-204` N3/E2/E3, and
  `DC=RootDNSServers,CN=MicrosoftDNS,CN=System` filtered out of coverage warnings in
  `ReportCoverageWarningBuilder.cs:89â€“90` and `FindingsService.Coverage.cs:169â€“170`.
- **What happens to a user:** two forests with identical DNS delegation get different reports. The
  one whose zones are in the domain partition has `CN=MicrosoftDNS` treated as a high-value
  container and its delegation assessed. The one whose zones are in the application partitions â€”
  which is the default, and therefore the common case â€” gets **no DNS findings at all**, and the
  report does not say that DNS was not examined. That is "found nothing" rendered
  indistinguishably from "never looked", which is what
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) exists to forbid. The risk being
  missed is real: write access to a DNS zone lets an attacker overwrite a name and put themselves in
  the path of traffic.
- **Why it is this way:** nobody chose it. The search base was set to the domain naming context, the
  DNS objects that happen to live inside it came along, and four workarounds accumulated to quieten
  them. The application partitions fell outside and nothing noticed. The three properties that would
  justify excluding the application partitions deliberately are all true â€” an application directory
  partition cannot contain security principals, its objects cannot hold DN-value references to a
  domain partition or the reverse so the control graph cannot route through it, and it replicates
  only to "that subset of domain controllers in the domain that actually run the DNS server" so
  one-controller-per-domain does not guarantee a controller that holds it
  ([About Application Directory Partitions](https://learn.microsoft.com/windows/win32/ad/about-application-directory-partitions)).
  None of them was the reason, and none of them justifies the *inconsistency*, which is the finding.
- **Options:** three, and they are a product question rather than a capture one. Assess DNS
  delegation everywhere â€” read the zone and container objects from both storage locations, never the
  record objects, of which a large forest holds hundreds of thousands. Or assess it nowhere, drop
  `CN=MicrosoftDNS` from the high-value containers, and say plainly in the report that DNS is out of
  scope. What is not available is the present position, which assesses it in some forests and
  silently not in others based on a storage choice with no security meaning.
- **Test cover:** the four workarounds are tested; the inconsistency is not, because no test asks
  the question.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B6, which owns the set of partitions
  capture reads. **Raised by the owner**, who remembered there had been a reason and was right that
  one existed â€” it is in `docs/rules/` and the old source, not in any document that explains it.
  This finding replaces an earlier version written the same day which claimed the DNS partitions
  were excluded deliberately for three good reasons and that nothing was captured. That was wrong.
  The correction is recorded rather than the original quietly edited, because how it was got wrong
  is the useful part: `SEC-204`'s carve-out was in the first search result and was read as defensive
  boilerplate instead of as evidence that these objects arrive in real captures. See F-S7-17.

### F-S7-17 â€” This session recorded an omission as unexplained without reading the old library

- **Severity:** maintainability
- **Confidence:** verified â€” **by being corrected**
- **Evidence:** F-S7-16's first version asserted that no record anywhere said why the DNS partitions
  were skipped. Two documents in `docs/rules/` and four sites in `src/` described the product's
  actual DNS behaviour. One of those documents was in the first search this session ran; it was read
  as a defensive carve-out and not pursued.
- **What happens to a user:** nothing directly. What it costs is the rebuild's central premise. The
  README says old documents are *source material* to be read like a specification someone handed
  you. A session that treats "I did not find it in the new library" as "it was never decided"
  produces exactly the confident, wrong, freshly-written document that
  [`0011`](../decisions/0011-rebuild-documentation-is-written-fresh-and-bound-by-tests.md) is meant
  to prevent â€” with a test binding it, which makes it look verified.
- **Why it is this way:** the session prompt correctly keeps sessions out of `docs/review/`, because
  a session that reads it starts proposing repairs to code being deleted. That instruction was
  generalised into avoiding the old library altogether, which it does not say. And a first search
  that returns a plausible-looking hit is more dangerous than one that returns nothing, because it
  feels like the search was done.
- **Options:** before recording any omission or absent rationale as unexplained, search the whole of
  `docs/` and `src/` for the behaviour, not only the new library â€” reading the old tree *for
  reasoning* is not the same act as reading it *for repairs*, and only the second is forbidden. And
  treat a carve-out, an exclusion or a filter in old code as evidence that the excluded thing
  occurs, never as boilerplate.
- **Test cover:** none, and probably none possible. This is a habit, not a mechanism.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B6 alongside F-S7-16.

### F-S7-18 â€” A group with no fixed identifier cannot be a privileged target, so DnsAdmins is invisible

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** `SEC-006` requires a finding's target to be a privileged group *"either by well-known
  RID or by being a privileged-group member via the closure table"*. The broad-principal rules use
  `RuleEvaluatorHelpers.IsBroadSidTargetTierZero`, whose identifier test is the fixed list
  `512, 516, 518, 519, 502` plus three structural distinguished-name patterns. `DnsAdmins` and
  `DnsUpdateProxy` are created when the DNS server role is installed and take identifiers from the
  domain's ordinary pool â€” Microsoft records the SID as `S-1-5-21-<domain>-<variable RID>` â€” so no
  fixed-identifier test can match them in any forest, and neither is a member of a privileged group,
  so the closure route does not reach them either. Neither group name appears anywhere in `src/`.
- **What happens to a user:** a permission that lets an ordinary account add itself to `DnsAdmins`
  is not reported. By Microsoft's own description that group *"has full control of all zones and
  records in the Active Directory domain"*, and Microsoft's own tooling treats non-privileged
  membership of it as a security finding. So the product is silent about a delegation an attacker
  can use, and silent in a way the customer cannot detect, because nothing says the group was not
  considered.
- **Why it is this way:** the privileged set is expressed as identifiers, and identifiers are the
  one thing these groups do not have in common across forests. It is a limit of how "privileged" is
  defined, not an oversight about DNS in particular. The same definition also omits Account
  Operators, Server Operators, Print Operators, Backup Operators, Replicators and Cert Publishers â€”
  recorded in `SEC-050` as a scope decision â€” but those have fixed identifiers 548 to 552, so they
  are a list to extend. `DnsAdmins` needs the definition itself to admit something other than a
  number.
- **Options:** none decided. When E3 is taken, the privileged set needs a way to name a group whose
  identifier varies by forest â€” matching on the group's own well-known name, or resolving it once at
  capture and recording the identifier it had in that forest, so the bundle states what it meant
  rather than the rule guessing later. The second fits the versioned-catalogue habit the capture
  rows already have.
- **Cost of deferring:** none in capture. **No capture change is required at all** â€” both groups are
  ordinary domain groups already read by the object pass, and their permissions are already in the
  bundle. Every bundle taken between now and whenever E3 is decided contains the evidence, so this
  can be answered against existing bundles rather than needing a recapture. That is what makes it
  safe to defer.
- **Test cover:** none. The gap is that no rule asks the question.
- **Status:** OPEN, as of 2026-08-11. **Raised and scoped by the owner** as future work while
  deciding DNS scope. Named by ledger row E3, which owns the privileged-principal set; the rules
  that would consume it are E18.

### The DNS scope decision, 2026-08-11

Recorded here because it was settled in the same conversation as B4 and B5 and touches rows this
session did not open. It is not a capture-row decision and changes no disposition.

**Out of scope.** The DNS application partitions, the zone objects, the record objects, and
`CN=MicrosoftDNS` as a high-value container. Nothing DNS-specific is captured. This states what is
already true â€” F-S7-16 established that the product assesses no DNS permission today and carries
four suppressions to hide the DNS objects that arrive by accident. Those suppressions, and the
`CN=MicrosoftDNS` entry in `HighValueTargets.HighValueContainers`, go with the decision rather than
being inherited.

**In scope, from objects already captured.** Membership of `DnsAdmins` and `DnsUpdateProxy`, and
dangerous permissions over those two group objects. This needs no capture change â€” F-S7-18 records
why it does not work today and what E3 has to grow for it to.

**What the product must say.** Precisely, and not loosely: *DNS zone and record permissions are not
assessed; DNS administrative group membership is.* A report that says "DNS not assessed" while
assessing `DnsAdmins` is the same confusion in the other direction.

**What it costs to add zone permissions later.** Historical coverage only. The work is additive â€”
more capture units of a type B4 already describes, one more object class in B2's catalogue, no
schema change because a zone is an object with an access control list like any other, and probably
no new detection because the dangerous-permission classification is generic. What cannot be
recovered is that bundles captured before the change contain no DNS objects, and comparisons across
the change are not comparable on that dimension until two runs exist on the new side. The mechanism
that keeps this honest â€” a versioned attribute catalogue, so a bundle states what it was allowed to
see â€” is already required by B2.

## B2, built 2026-08-11

The catalogue, its document [`S-8`](../next/S-8-captured-attribute-catalogue.md), and the test binding them.
Three open points came with the row, each created by something settled after B2 was written. All
three are answered in `S-8`; the findings below are the record of what they cost.

### F-S7-22 â€” B2's row and the fail-fast decision said opposite things about a failed schema read

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** ledger row B2 ended *"A failed schema read degrades the run rather than ending it"*.
  On 2026-08-11 the owner decided fail-fast â€” a unit that cannot be captured fully ends the run
  immediately â€” and B4 then made the schema partition a capture unit like any other, giving it its
  own domain controller specifically so that *"a failure names one unit unambiguously under
  fail-fast"*. The two sentences cannot both be true of the same partition.
- **What happens to a user:** under the older half, a forest whose schema could not be read would
  produce a bundle in which every GUID not in the shipped catalogue is unnameable â€” and per
  [`0014`](../decisions/0014-capture-reads-the-schema-partition.md) that is precisely the set that
  matters, because a locally created attribute's GUID exists in that forest and nowhere else. Per
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) each affected finding would then
  have to distinguish *unnameable* from *safe*, on every finding that touches one.
- **Why it is this way:** B2's row was written on 2026-08-10 and fail-fast was decided on
  2026-08-11. Nothing revisited the sentence.
- **Resolution:** fail-fast holds, and the row's sentence is struck. A forest whose schema partition
  cannot be read produces no bundle. Reading it needs no privilege beyond reading the directory and
  is a few thousand objects once per forest, so there is no customer who may run this product and
  may not read their own schema â€” a failure here is an availability fault, not a permission the
  customer withheld. B4 already requires the controller for that partition to be chosen and
  validated at preflight, so this fails in the first seconds rather than at hour two.
- **What it costs:** a forest where the schema partition is briefly unreachable yields nothing
  rather than most of an audit. It costs a run, and it never costs a wrong answer.
- **Test cover:** none possible here â€” this is a property of the capture run, owed by B6's
  capture-passes document.
- **Status:** RESOLVED by decision, as of 2026-08-11. Named by ledger row B2.

### F-S7-23 â€” An inclusion-list filter makes a dangerous permission on an unrecognised class invisible

> **Amended 2026-08-11, the same day it was written, and the amendment matters.** The version below
> said the second filter mode's *only* observed effect was DNS record objects. That was wrong. The
> owner remembered a customer whose single-sign-on product put credential child objects under every
> user account, and the evidence was still in the repository â€” in the product's own customer-facing
> readme and in `DirectoryTreeService`. The finding stands; its cost side was understated by a large
> margin. The correction is recorded rather than the original quietly rewritten, on the precedent of
> F-S7-16 and F-S7-17, because how it was got wrong is the useful part. See F-S7-26, and the
> decision section that follows the findings.

- **Severity:** breaks-for-user
- **Confidence:** verified
- **Evidence:** the previous product's `BroadCaptureFilter` names twelve object classes, and its own
  summary says it is *"shared between object enumeration and security-descriptor capture so that
  `fact_ace` rows always have a matching `dim_object` entry"*. An object of any other class is
  therefore not enumerated **and has no security descriptor read**. Its own comment names the
  motivating case â€” `enatelSSO*`, a vendor product's objects. The second filter mode,
  `ComprehensiveCaptureFilter`, is `(objectClass=*)` and was the only way to see them; its setting
  did not survive the settings panel (F-S7-21).
- **What happens to a user:** a delegation on a vendor application's objects, on a locally defined
  class, or on an administrative container installed by a product nobody remembers, is not assessed
  and not reported â€” and the report does not say it was not examined. That is "found nothing"
  rendered indistinguishably from "never looked", which `0002` forbids, and it is also flatly at
  odds with [`0017`](../decisions/0017-capture-reads-the-whole-forest.md).
- **Why it is this way:** the filter was written to keep irrelevant objects out of the tables, which
  is a real problem, and it was applied to the security descriptors as well because sharing one
  filter kept the two tables consistent. The cost of that sharing was never stated.
- **Resolution:** one filter, and it excludes rather than includes. Every object in every naming
  context capture reads is captured, whatever its class, with identity and its security descriptor;
  the enumerated classes get extra attributes on top. `dnsNode` and `dnsZone` are excluded by name
  per the DNS scope decision, because an exclusion is something a report can print and an inclusion
  list that happens not to mention DNS is a silence. The radio buttons go.
- **What it costs, corrected:** every vendor and application object in the forest now appears in the
  bundle with its access control list, **and so does every credential child object beneath a user or
  a computer** â€” which is the part the first version missed. The only figure anyone has put on that
  is *triple capture size*, and it rests on no measurement. See F-S7-26.
- **Test cover:** `CapturedAttributeCatalogTests.AnUnknownClassStillGetsItsSecurityDescriptor` and
  `NoExcludedClassIsAlsoEnumerated`.
- **Status:** RESOLVED by decision, as of 2026-08-11, and held pending the measurement in F-S7-26.
  Named by ledger row B2.

### F-S7-24 â€” Half of B2's binding cannot be built until there are rules to walk

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** B2 owes a test in both directions â€” an attribute nothing reads fails the build, and
  a rule needing an uncaptured attribute fails the build. The rebuild contains no rules. A test that
  walked the empty set of rules and reported that none of them wanted a missing attribute would
  pass, forever, while measuring nothing.
- **What happens to a user:** nothing today. The exposure is a later session reading a green test
  and concluding the catalogue is checked against the rules, when it is not â€” which is exactly the
  failure gate 5's original single wording committed, passing against fourteen types while nothing
  in the tree was reachable.
- **Options:** ship the empty check and rely on someone remembering; or split it the way gate 5 was
  split. Split, and say so in both the document and the test's own summary.
- **Resolution:** **B2a** is built â€” every attribute names at least one real ledger row as its
  reader, and no named row may reach `Done` while the attribute still has no code consumer, which is
  the decay half that makes the forecast more than paperwork. **B2b** is owed: a rule naming an
  attribute the catalogue does not request fails the build.
- **Test cover:** B2a is `CapturedAttributeCatalogDocumentationTests`. B2b has none, and this
  finding is the request for it.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row **E16 â€” Rule catalogue**, which is the row
  that unblocks it, with E18 to E22 supplying the rules to walk.

### F-S7-25 â€” Gate 4's collection exemption is now two types rather than one

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** gate 4 forbids a public member handing back a collection from a type that cannot say
  whether it managed to look. `SchemaGuidCatalog` was exempt, on the ground that it is a table
  compiled into the assembly which reads nothing and cannot fail.
  [`S-6`](S-6-vouched-returns.md) states that position under the heading *"The one exemption"*, and
  argues explicitly against widening: *"Bringing them in would need a second and a third exemption
  on a seventeen-type surface, which is how a rule becomes an allowlist."* Adding
  `CapturedAttributeCatalog` fires the gate on eight members and requires a second entry.
- **What happens to a user:** nothing directly. What it costs is the gate. An allowlist that grows
  once grows again, and the argument for the second entry is available verbatim for the third.
- **Why it is this way:** the exemption's reason is a property of a kind of type â€” a compiled table
  that cannot fail â€” rather than of one particular type, and the catalogue has that property
  exactly. `AttributesFor` cannot even return an empty answer, because the universal attribute set
  is always included.
- **Options:** give the catalogue a vouched return, which would mean every caller unwrapping an
  outcome that cannot fail; or extend the allowlist and make the extension visible. The first buys
  nothing and teaches callers to ignore an outcome, which is worse than the gate it satisfies.
- **Resolution:** extended, and recorded here rather than done quietly. Both decay halves now
  iterate every entry rather than the first, so a second exemption cannot ride along behind the
  first, and `UnvouchedResultDocumentationTests` requires every exempt type to be named in `S-6`
  with what ends it. **The test to apply to a third entry is that its reason is the same reason** â€”
  a compiled table that cannot fail â€” and not merely that it is inconvenient to change.
- **Test cover:** `TheCatalogueExemptionsAreStillEarningTheirPlace` and
  `TheCatalogueExemptionsHaveNotComeDue`, both over the whole allowlist.
- **Status:** OPEN, as of 2026-08-11 â€” open in the sense that it is a standing pressure rather than
  a defect to fix. Named by ledger row B2.

### F-S7-26 â€” "Triple capture size" is the only number anyone has, and it is a recollection

- **Severity:** correctness-risk
- **Confidence:** **verified as a claim, unverified as a fact.** Read those separately.
- **Evidence, verified:** the claim exists, is the product's stated reason, and is shown to
  customers. `SecurityModelReadmeWindow.xaml` reads: *"SecureAD captures known AD security-relevant
  object classes by default instead of every directory object. This avoids large volumes of
  smart-card, credential, vendor, and system objects that can **triple capture size** without
  improving the user and group risk picture. A future advanced mode may allow comprehensive
  all-object capture when needed."* The objects are named in `DirectoryTreeService`, whose comment
  calls them *"credential/SSO metadata objects nested under user accounts"*:
  `enatelSSOAccountParameter`, `enatelUserManagedAuth` and `enatelSSOStorageV3` from one customer's
  single-sign-on product, alongside `msDS-Device`, `msFVE-RecoveryInformation`,
  `msTPM-InformationObject` and `foreignSecurityPrincipal`, which are not site-specific at all.
- **Evidence, not verified:** the tripling itself, and the judgement attached to it. The number
  appears **once** in the entire repository, in that sentence. No measurement, benchmark, capture
  log or note supports it anywhere, and `BenchmarkSuite1` does not touch capture volume.
- **What happens to a user:** two opposite risks, which is why this is recorded rather than acted
  on. If the tripling is real and the rebuild ignores it, capture and analysis on a large forest get
  three times more expensive for objects that may carry nothing. If the tripling is exaggerated and
  the rebuild honours it, the product silently declines to examine the permissions on the most
  credential-bearing objects in the directory â€” the second half of the readme sentence, *"without
  improving the user and group risk picture"*, is a security judgement that was never written down
  anywhere else and never re-examined.
- **Why it is this way:** somebody hit a real problem at a real customer, fixed it, and wrote the
  reason into a user-facing screen instead of into a record that could be checked. This is
  [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) in its
  usual costume: a confident sentence with a plausible mechanism and no source.
- **The measurement, and the one question it must answer.** A production capture, with a sample
  pulled across and personal data stripped. Counting the objects settles the volume. What settles
  the *security* half is narrower and is the question to ask: **do any of these objects carry an
  access control entry that is not inherited from their parent?** If every one of them simply
  inherits the computer's or the user's permissions, then it holds no delegation of its own, and
  excluding it loses nothing but rows â€” the old judgement was right, and would then be right on
  evidence rather than on memory. If any carries a non-inherited entry, somebody has delegated
  control of credential material directly, and that is exactly what this product exists to find.
  The counts and the inherited-versus-not shape need no names, no key material and no personal data
  to answer.
- **How to run it.** `tools/Measure-CredentialChildObjects.ps1` in the predecessor repository,
  added 2026-08-11. Read-only; changes nothing, reads no credential material, and reduces every
  trustee either to a well-known name or to a bare relative identifier with the domain portion
  masked, so the output distinguishes *Domain Admins* from *one particular person* without exporting
  either. It counts exhaustively and inspects permissions on a sample, because reading a security
  descriptor per object is the expensive part; `-SampleSize 0` inspects everything. It prints the
  ratio the tripling claim rests on, and then answers the security question directly in words.
  Requires ordinary read access and no `SeSecurityPrivilege`, because the SACL is never requested.
- **Options:** hold at capture-everything and measure, which is the owner's decision of 2026-08-11;
  or exclude on the strength of the recollection, which would be inheriting a judgement rather than
  reviewing one.
- **Test cover:** none possible before the measurement exists.
- **Status:** OPEN, as of 2026-08-11. Re-pointed 2026-08-12 to ledger row **B20**: B6 is built and
  nothing runs, so it is no longer the row a measurement can attach to. The lab session
  [`0013`](../decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) already requires, to
  freeze captures as test assets before the old capture code is deleted, is where it belongs. The
  exclusion list itself is B2's.

### F-S7-27 â€” The confidential-attribute rule is not the one-line rule it looks like

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** [Search-Flags](https://learn.microsoft.com/windows/win32/adschema/a-searchflags)
  says bit 128 marks an attribute confidential and is *"ignored for base schema attributes
  (systemFlags=0x10)"*, and the confidential-attributes article says the same at more length. That
  reads as a clean rule: `systemFlags` `0x10` defeats `searchFlags` 128, so absence of a base-schema
  attribute can only mean unset. But Microsoft ships `msFVE-RecoveryPassword` â€” the BitLocker
  recovery key â€” with `systemFlags` `0x10` **and** `searchFlags` `0x298`, and `0x298` has bit 128
  set
  ([ms-FVE-RecoveryPassword](https://learn.microsoft.com/windows/win32/adschema/a-msfve-recoverypassword)).
  A published attribute carrying both at once contradicts the simple reading.

  **Corrected 2026-08-13 at S-24 â€” it does not contradict it.** The evidence above quotes the
  resolution and then reads past it. Bit 128 is *"**ignored** for base schema attributes"*, and
  ignored is not the same as *absent*: the bit may be stored on a base-schema attribute and simply
  has no effect. So `msFVE-RecoveryPassword` carrying `searchFlags` `0x298` â€” which is
  `8 | 16 | 128 | 512` â€” alongside `systemFlags` `0x10` is exactly what the documentation
  describes, not a counter-example to it. The confidential-attributes article's *"you cannot mark a
  base schema attribute as confidential"* is a statement about **effect**, not about what the
  schema will hold. Read that way the two articles agree, and the rule is a single line:

  > an attribute is effectively confidential when `(searchFlags & 128) != 0` **and**
  > `(systemFlags & 0x10) == 0`.

  This finding was opened because *ignored* was read as *cannot be present*. Nothing about the
  schema was ever in conflict.
- **What happens to a user:** nothing today, because no code interprets these flags yet, and the
  product does not request that attribute at all. The exposure is the interpretation: a component
  that applied the one-line rule would conclude that an absent value on a base-schema attribute is
  definitely unset, when it may have been withheld. That renders "we were not permitted to read
  this" as a fact about the forest, which is the single thing
  [`0002`](../decisions/0002-absent-view-means-degraded-run.md) exists to forbid.
- **Why it is this way:** the rule was inferred from one sentence in one article during the B2
  session and written into `S-8` as settled. It is the shape of mistake `0016` records â€” a plausible
  mechanism stated as though a source had confirmed it â€” committed in the same document that cites
  `0016` as a warning.
- **Options:** determine the real rule from a source or from a lab, and state it where absence is
  interpreted; or, until then, do not state one. The second is what `S-8` now does: capture records
  both flags, and B8 decides how they combine, having checked.
- **Test cover:** `LdapEntryReaderTests.AnAbsentAttributeIsNotReportedAsAnEmptyOne` holds the half
  that can be held: an attribute that did not come back is reported as `NotReturned` and never as
  an attribute with no values. Nothing tests the interpretation, because there is not one.
- **Status:** **RESOLVED â€” 2026-08-13 at S-24**, by reading the two articles against each other
  rather than one against a memory of the other. The rule is stated above. It was open from
  2026-08-11, and for that whole period the thing blocking it was a misreading contained in the
  finding's own evidence â€” which is the argument for opening the page rather than trusting a
  summary, made at this repository's expense.

  **B8's decision not to close it by assertion was still the right one**, and what it built stands:
  `NotReturned` remains a distinct state, so no code downstream can reach an empty list of values
  without also being handed the fact that nothing arrived. That mechanism is not withdrawn by this
  resolution â€” it is what the rule above now has something to attach to.

  **D3 inherits a larger question than this finding described, not a smaller one.** The flags decide
  whether an attribute *can* be withheld. They do not decide whether it *was*, and S-24 found a
  second and independent cause that has nothing to do with the schema: a Windows Server 2025
  domain controller returns confidential attributes **only over an encrypted connection**, and
  strips them from an unencrypted search with no error to the client
  ([Unexpected results for operations on confidential attributes on Windows Server 2025
  DCs](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/confidential-attributes-unexpected-behavior-using-windows-server-2025-dc)).
  So the interpretation D3 owes is a conjunction â€” confidential by flags, **and** unreadable by this
  run â€” and the second half is a fact about the connection, recorded as `F-S24-1`.

### F-S7-36 â€” "Absent from the entry" is stronger than the sources say

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** the rule as written during the B7 session says that past the server's value limit an
  attribute *"is absent from the entry"*. No first-party source found says that. Microsoft's account
  of what a client sees is broader and vaguer: results *"may appear truncated or incomplete. In some
  occasions, you may not get any results"*
  ([Windows Server 2008 and newer domain controller returns only 5000 values in an LDAP response](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response)),
  and the LDAP policy article says only that past `MaxValRange` *"you must use value range controls
  in LDAP to retrieve values that exceed the MaxValRange value"*
  ([LDAP administration limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil)).
  Both are compatible with the values arriving under a *ranged* name rather than not arriving at
  all, which is what the returned-name behaviour elsewhere in the documentation implies.
- **What happens to a user:** nothing, because the remedy is the same either way and B8 implements
  it. The exposure is to a later reader who takes the stronger sentence as licence to test for
  absence alone: a reader that looks only for a missing attribute misses the case where the
  attribute is present under a name it did not expect, and that reads as an object with no values.
- **Why it is this way:** the sentence was written to convey the danger, which it does, and it
  overshoots the evidence, which `0016` forbids.
- **Options:** state what the sources state â€” that past the limit the values do not come back under
  the name they were asked for, and that a reader must handle both a ranged name and nothing at all.
  That is what [`S-11`](../next/S-11-reading-what-a-controller-returns.md) does, and what the reader does:
  it looks for the ranged form first and treats a bare absence as its own state.
- **Test cover:** `LdapEntryReaderTests` covers both shapes â€” a ranged answer and an attribute that
  did not come back.
- **Status:** RESOLVED, 2026-08-11. The sentence appeared in exactly two places â€” `ServerLimits`
  and `AttributeCardinality`, both B7's and B2's â€” and both now say what the sources say: past the
  limit the values do not come back under the name they were asked for, and a reader must handle a
  ranged name and a bare absence alike. It is recorded rather than quietly fixed because the
  reasoning is what matters: the original sentence was true enough to act on and stronger than the
  evidence, which is the shape `0016` exists to catch, and the next person tempted to tighten it
  again should see why it is worded loosely.

### F-S7-37 â€” The wire form of a ranged name is modelled, not observed

- **Severity:** evidence-gap
- **Confidence:** verified
- **Evidence:** B8's tests run a whole range retrieval against a server model written from the
  documentation: it serves at most `MaxValRange` values per response, answers under the ranged name
  it served, and marks the final block with the wildcard. Every one of those behaviours is taken
  from Microsoft's articles rather than from a controller. The closest first-party statement about
  the *returned* name is about a client library rather than the wire â€”
  <i>"the attribute string would be `member;range=101-200`, but GetNextColumnName will return
  `member;range=101-*`"</i>
  ([Using IDirectorySearch and IDirectoryObject for Range Retrieval](https://learn.microsoft.com/windows/win32/adsi/using-idirectorysearch-and-idirectoryobject-for-range-retrieval)).
- **What happens to a user:** if a production controller spells a ranged name differently from the
  model, the reader finds no ranged form, falls through to the plain name, finds nothing there
  either, and reports the attribute as `NotReturned`. That is not silent â€” a group with members
  would report as an attribute that never arrived, which is visible and wrong rather than invisible
  and wrong â€” but it is still a capture that does not carry group membership.
- **Why it is this way:** there is no forest in CI, and the alternative was a test that looked at
  nothing.
- **Options:** confirm the wire form against a real controller in the lab session, and freeze one
  real ranged response as a test asset.
- **Test cover:** the rule is covered end to end against the model. The wire is not covered at all.
- **Status:** OPEN, as of 2026-08-11. Re-pointed 2026-08-12 to ledger row **B20**: B6 is built and
  issues the requests, but nothing calls it, so the row a lab session attaches to is the one that
  produces a run rather than the one that produces a loop.

### The credential child-object decision, 2026-08-11

Made by the owner after reading F-S7-23 and finding the evidence behind it. Three parts.

**BitLocker recovery objects are in scope.** Who may read a recovery key is a question this product
answers. `msFVE-RecoveryInformation` is captured and its access control list assessed, and that does
not depend on how the volume measurement in F-S7-26 turns out. This is the first time a
credential-bearing object class has been named as in scope, and it is what makes the next part
necessary rather than merely tidy.

**The product never captures a credential.** Permissions on credential material, never the material.
The recovery key sits on the same object as the permissions that protect it, one line apart, so this
is held by `CredentialAttributeGuardTests` rather than by a sentence: the build fails if the
catalogue ever names one of thirteen credential-bearing attributes, and it separately fails if the
permissions on such an object stop being captured â€” a guard satisfiable by simply avoiding the
object would quietly undo the decision above. A bundle is sealed, exportable, and forwarded by
customers to auditors and insurers.

**Capture holds at everything-but-DNS while the volume is measured.** Not because the volume concern
is dismissed â€” it is remembered, it is written into a screen customers read, and the objects are
real â€” but because the number behind it has never been checked and the judgement attached to it never
was either. The measurement is F-S7-26, and the mechanism for acting on it already exists: a named
exclusion, printed in the report the way DNS is. Nothing needs redesigning either way.

## B4 and B7, built 2026-08-11

The capture unit and the politeness rules. Documented at [`S-9`](../next/S-9-the-capture-unit.md) and
[`S-10`](../next/S-10-politeness.md), both bound by tests. Four findings, and three earlier ones close.

**The naming was decided rather than inherited.** The unit is `CaptureUnit`. Shard is gone with the
fan-out it named, and `ShardResult` â€” which map Naming Â§5 records as the obvious right name sitting
on a dead type â€” is not resurrected. No result type was created at all, because nothing produces
one yet and a type awaiting a consumer is the thing gate 5a exists to watch.

**Preflight was decided, and it lands in two halves.** B4 builds `CaptureUnit.ConfirmServedBy`,
which takes the partition list a controller publishes about itself and refuses a unit the chosen
controller does not serve. Ledger row A8 calls it. The check is built here rather than left to A8
because A8 is undecided, and an obligation belonging to two undecided rows belongs to neither â€” the
failure mode this session was warned about specifically.

**The serialisation guard was built.** F-S7-20 asked for one and this session built it, because the
alternative was to write "requests are never pipelined" into a document and leave nothing holding
it, which is the state that finding already describes.

### F-S7-28 â€” The domain-scope control suppresses the evidence the reconciliation depends on

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** the fourth avoidance Microsoft lists for the paging defect is "use the control
  LDAP_SERVER_DOMAIN_SCOPE_OID when searching, it turns off continuation referrals when searching
  domain roots"
  ([LDAP paged queries with subordinate referrals](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-paged-queries-subordinate-referrals-not-chased)),
  and the managed control's own summary is that it "instruct[s] the LDAP server not to generate
  referrals when completing a request"
  ([`DomainScopeControl`](https://learn.microsoft.com/dotnet/api/system.directoryservices.protocols.domainscopecontrol)).
  F-S7-11 requires that continuation references be reconciled against the planned unit set so an
  unplanned partition becomes a coverage entry. Where the control is honoured, no references
  arrive.
- **What happens to a user:** the two decisions were made separately and each is right. Together,
  unexamined, they produce a report saying no unplanned partitions were found when the truth is
  that the product asked not to be told. That is a "found nothing" that was really "could not ask"
  â€” the defect [`0002`](../decisions/0002-absent-view-means-degraded-run.md) exists to forbid, and
  the one thing an audit tool cannot do.
- **Why it is this way:** B4's referral policy was decided as two independent precautions, and the
  reconciliation was decided as a use for a by-product of the first. Nobody looked at what the
  second precaution does to that by-product.
- **Options:** drop the control, which weakens the belt-and-braces for no gain; reconcile only over
  units that did not suppress; or carry the suppression in the result. The third is chosen â€”
  dropping evidence quietly is the thing being guarded against, so the result carries the units
  whose references were suppressed and an `IsComplete` that is false whenever there are any.
- **Test cover:** `ContinuationReferenceReconciliation` and its `IsComplete`, described in S-9.
  What is **not** covered is the rendering: nothing yet stops a screen printing an incomplete
  result as an empty one, because there are no screens. That falls to branch I.
- **Status:** REPAIRED in capture, rendering owed, as of 2026-08-11. Named by ledger row B4.

### F-S7-29 â€” The referral-chasing default was cited from the wrong API

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** B4's ledger row stated that referral chasing is "left at the default, which for
  `LdapConnection` is External", citing
  [`System.DirectoryServices.ReferralChasingOption`](https://learn.microsoft.com/dotnet/api/system.directoryservices.referralchasingoption).
  That enum belongs to `DirectorySearcher`. This product uses
  `System.DirectoryServices.Protocols.LdapConnection`, whose `LdapSessionOptions.ReferralChasing`
  is a different type, `ReferralChasingOptions`, and whose documentation states no default at all.
- **What happens to a user:** nothing. The conclusion was right and the citation was not, which is
  the failure [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md)
  is about: a claim that is true and sourced from the wrong place survives until somebody checks
  the source, and then the whole paragraph is in doubt.
- **Why it is this way:** two similarly named enums, one of them in the namespace a search engine
  offers first.
- **Repair:** S-9 cites Microsoft's own statement instead â€” "as referrals are chased by default,
  use ldap_set_option with flag LDAP_OPT_REFERRALS to turn off referral chasing" â€” which is about
  the LDAP client runtime this product actually uses. The conclusion is unchanged: set it
  explicitly.
- **Test cover:** none possible. A citation cannot be tested. What *is* tested is that no referral
  option other than `None` appears in production code.
- **Status:** REPAIRED, as of 2026-08-11. Named by ledger row B4.

### F-S7-30 â€” Half of B4's binding cannot be built until something issues a search

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** B4's row owes a document "bound to the search request capture actually issues".
  Nothing in the rebuild issues one: connecting is branch A and running the passes is B6. A test
  inspecting the set of issued search requests would inspect an empty set and report it correct.
- **What happens to a user:** nothing directly. The exposure is a false sense of coverage â€” the
  same failure as gate 5's original wording, which passed against fourteen public types while
  nothing in the tree was reachable, and the same shape as F-S7-24 for B2.
- **Why it is this way:** the rows were sequenced so that the correctness decision lands before the
  component that would exercise it, which is right â€” deciding the referral policy after B6 exists
  would mean retrofitting it.
- **Options:** defer B4 until B6, which puts a correctness decision behind a mechanical one; or
  split the binding. Split, on the precedent of gate 5 and B2. **B4a** is bound now: a real
  `SearchRequest` is built and every documented property checked against it, and
  `DirectorySearchGateTests` fails the build if anything else in the tree constructs one or assigns
  a referral option. **B4b** is gate 5b, and comes due with B6.
- **Test cover:** `CaptureUnitDocumentationTests` and `DirectorySearchGateTests` for B4a. None for
  B4b, deliberately, and S-9 says so in its own words rather than implying coverage it lacks.
- **Status:** OPEN as B4b, as of 2026-08-11. Named by ledger row B6.

### F-S7-31 â€” A ledger-row edit truncated a registry row, for the fifth time

- **Severity:** maintainability
- **Confidence:** verified â€” it happened during this session
- **Evidence:** a partial-line match against `CONCEPT-REGISTRY.md` replaced the whole of the
  `Operation outcome` row, leaving `| Operation outcome | Result |` and dropping its member shapes
  and its reasoning. This is the documented hazard in the repository's own instructions, and by its
  own count it had already happened four times.
- **What happens to a user:** nothing, because it was caught. `ConceptRegistryTests` refused the
  two-cell row by name and its message described the exact accident â€” "an editing accident during
  mutation testing truncated exactly this row, and every check went on reporting the registry in
  perfect order". A guard written after a previous occurrence caught the next one.
- **Why it is this way:** the file editor replaces a line when given a fragment of it, and a
  registry or ledger row is thousands of characters long, so quoting one whole is impractical.
- **Repair:** for this session, long-row edits were done by an exact whole-text replacement in a
  script that asserts each fragment matches exactly once, then the file was read back and the
  changed-line count checked. Recorded so the next session does the same rather than rediscovering
  it. **It then happened a second time in the same session**, on the same file, the moment a row
  was added without that method â€” which is the useful part of this finding: knowing the hazard is
  not sufficient, and only the scripted method avoids it.
- **Test cover:** `ConceptRegistryTests` and `InventoryCompletenessTests` between them refuse a
  malformed row in either file. Both occurrences were caught within seconds.
- **Status:** REPAIRED, as of 2026-08-11. Named by ledger rows B4 and B7.

### What closed

- **F-S7-11** â€” continuation references are reconciled rather than discarded. Built, with the
  caveat F-S7-28 adds. REPAIRED in capture as of 2026-08-11.
- **F-S7-15** â€” the old tree's avoidance survived on two undocumented lines with a comment naming
  the wrong reason. The new tree has one file that may build a search, a document saying why, and a
  build failure for anything else. REPAIRED as of 2026-08-11.
- **F-S7-20** â€” "requests are never pipelined" is now a stated constraint with a guard behind it
  rather than an accident of how the passes were written. REPAIRED as of 2026-08-11.

F-S7-4, F-S7-10 and F-S7-12 stay **open as standing constraints**. They are not defects to fix;
they are facts about Active Directory that the design must keep avoiding, and they are now written
into a document a future session will find instead of into a comment it will delete.

### F-S7-32 â€” The serialisation guard forbade more than the constraint required

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** the constraint is *never two requests in flight against one controller*. The guard
  built for it on 2026-08-11 forbade every fan-out shape anywhere in the capture project, which
  also forbids reading several naming contexts at once on **different** controllers â€” a design
  that places one serial client on each of several servers and violates nothing.
- **What happens to a user:** nothing directly. What it costs is that a guard standing in the way
  of a design somebody wants is a guard that gets deleted, and its real content goes with it. The
  owner's stated intention on the same day was to run capture units in parallel.
- **Why it is this way:** the constraint and the mechanism that used to imply it were conflated.
  Serial capture is *one way* to guarantee one request per controller; it is not the requirement.
- **Repair:** narrowed the same day. A file may fan work out, or it may talk to a directory, but
  not both â€” so the dispatcher may run naming contexts at once and the reader may not run anything
  at once. Expressed that way it needs no allowlist, and an allowlist is what stops being true.
- **Test cover:** `SerializedDirectoryAccessGateTests`, mutation-tested in both directions,
  including the direction that proves fan-out in a non-directory file is permitted.
- **Status:** REPAIRED, as of 2026-08-11. Named by ledger row B7.

### F-S7-33 â€” B5's deferral trigger conflates production impact with total run cost

- **Severity:** correctness-risk *of a decision*, not of the product
- **Confidence:** verified
- **Evidence:** the trigger recorded above fires "only if capture wall-clock **dominates**
  derived-analysis wall-clock *and* a single-threaded capture does not finish inside the customer's
  maintenance window", and states that if analysis dominates, "B5 stays deferred permanently".
  Those two clauses measure different things. Per
  [`0008`](../decisions/0008-live-verification-is-removed.md) analysis never touches a directory â€”
  it runs on the bundle, offline. **Only capture consumes the customer's production window.**
- **What happens to a user:** the customer whose capture does not fit their maintenance window is
  told it cannot be helped because *analysis* takes longer than capture, which is true and
  irrelevant. The AND makes a fact about total cost veto a decision about production impact.
- **Why it is this way:** the trigger was written to guard against building machinery for an
  unmeasured benefit, which is the right instinct. It bundled the two questions because one
  measurement answers both, and then required both answers to point the same way.
- **Repair proposed, not applied:** the test becomes capture wall-clock against the customer's
  maintenance window, full stop. Whether analysis dominates stays worth measuring â€” it decides
  where optimisation effort goes â€” but it does not gate B5. Not applied here because B5 is a row of
  its own and re-deciding it in passing is what this ledger exists to prevent.
- **Test cover:** none possible; this is a decision procedure, not code.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B5.

### F-S7-34 â€” Under parallel capture, the configuration and schema partitions need a controller each

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** B4's decision of 2026-08-11 gives the configuration and schema partitions "two
  partitions, one controller between them", which is safe while units are read one at a time.
  Every domain partition lives on its own domain's controllers and so spreads naturally; those two
  live on every controller and were deliberately put on one. Run units concurrently and they
  become two simultaneous paged reads on one server, competing for the single `MaxResultSetSize`
  budget the controller resolves by discarding the oldest intermediate results â€” F-S7-12.
- **What happens to a user:** the same silent truncation as F-S7-4, on the two partitions the
  product cannot do without, and only on the forests big enough for someone to have wanted the
  concurrency.
- **Why it is this way:** the one-controller-between-them decision was made for attribution under
  fail-fast, in a design that read units serially. It was correct then and stops being correct the
  moment units overlap.
- **Options:** under parallel capture, one controller each. There is no scarcity â€” every controller
  in the forest serves both partitions â€” so this costs nothing but has to be decided before
  parallelism rather than discovered after it.
- **Test cover:** none. The guard in `SerializedDirectoryAccessGateTests` cannot see this: whether
  two units share a controller is a property of the plan a run is given, not of the code.
- **Status:** OPEN, as of 2026-08-11. Named by ledger row B5.

### F-S7-35 â€” No capture has ever failed in production, and nothing recorded that

- **Severity:** maintainability
- **Confidence:** **testimony, not measurement** â€” see below
- **Evidence:** the owner, 2026-08-11: "I have done a lot of captures in prod with my old tool and
  it never failed on capture, not once." Also that capture is quick and analysis is the costly
  half. This is the recollection of the person who ran the previous product against production
  forests. It is not instrumented, not counted, and not written down anywhere else.
- **What happens to a user:** nothing. What it changes is what gets built. Retry, a
  controller-selection dialog, a candidate-controller list and a decision hand-off are all
  machinery for an event nobody has observed, and machinery built for unobserved events is how the
  previous product acquired twenty-eight buttons wired to nothing.
- **Why it is recorded:** because it is currently the only real-world evidence anyone has about
  capture reliability, and without it the next session designs for failures from first principles.
  It is labelled testimony deliberately: per
  [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) a
  plausible account is not a measurement, and this one is a recollection of absence, which is the
  weakest form of evidence there is. It is still worth more than nothing, which is what preceded it.
- **How it was acted on:** the retry policy is built, because it is cheap and a stalled request
  costs a whole run under fail-fast. The controller-selection dialog is **not** built. The decision
  point is named in [`S-10`](../next/S-10-politeness.md) and the automatic policy answers it; the dialog
  waits for a failure to justify it.
- **Test cover:** none possible. The measurement that would replace this is B5's, in B6's
  instrumentation, which already counts every `busy`, `timeLimitExceeded` and server-closed
  connection.
- **Status:** OPEN as a standing note, as of 2026-08-11. Named by ledger row B7.

## B6, built 2026-08-12

The capture passes: the loop that issues a search, reads a page, asks for the next and knows when a
partition is finished. Documented at [`S-12`](../next/S-12-the-capture-passes.md), bound by
`CapturePassesDocumentationTests`. This is the first component in the rebuild that does anything to
a directory rather than describing what would be done. Seven findings, three of them about the
checking rather than the product.

### F-S7-38 â€” The request B4 built let a controller decide which parts of a security descriptor to send

- **Severity:** correctness-risk
- **Confidence:** verified
- **Evidence:** the request `CaptureSearchRequestFactory` built carried the paging control and the
  domain-scope control and nothing about security descriptors, while `nTSecurityDescriptor` is in
  the attribute catalogue and is asked for on every object. Without `LDAP_SERVER_SD_FLAGS_OID`
  (`1.2.840.113556.1.4.801`) the server decides what to return, and the SACL is privileged:
  Microsoft lists *"retrieving the SACL from an object's ntSecurityDescriptor attribute when using
  SecurityDescriptorFlags"* among the operations that fail with insufficient access rights for a
  caller without the privilege behind it
  ([ldap_bind_s](https://learn.microsoft.com/windows/win32/api/winldap/nf-winldap-ldap_bind_s#remarks)).
- **What happens to a user:** in the best case nothing, and in the worst case a capture that cannot
  be run without granting an audit tool `SeSecurityPrivilege` on every domain controller in the
  forest â€” which is a thing a customer has to be asked for, and a reason not to run the product.
  The old implementation sent the control and the map records exactly why; the rebuild lost it in
  the gap between B4, which built the request, and B6, which was going to issue it.
- **Why it is this way:** B4's job was the referral policy and the paging, and the security
  descriptor is not either of those. Nobody was wrong; the obligation sat between two rows.
- **How it was acted on:** the control is now on every request the factory builds, asking for owner,
  group and DACL. It is a bound row of [`S-9`](../next/S-9-the-capture-unit.md)'s request table, and the
  binding asserts both the documented value and that the SACL bit is absent, so adding it back is a
  red test rather than a quiet change of what a customer must grant.
- **Test cover:** `CaptureUnitDocumentationTests`, mutation 7 of `S-12`.
- **Status:** **CLOSED**, 2026-08-12, by ledger row B6.

### F-S7-39 â€” Interleaving a range retrieval between two pages of a paged search is reasoned, not observed

- **Severity:** evidence-gap
- **Confidence:** reasoned from documentation
- **Evidence:** B6 finishes an object's oversized attributes before asking for the next page, which
  means a base-scope search is issued on the same connection while a paged search is outstanding on
  it. The argument that this is safe is that a base-scope search of one object carries no paging
  control, so it creates no intermediate results and cannot compete for `MaxResultSetSize` â€” the
  budget F-S7-12 records a controller relieving by **discarding the oldest** entries in it. That is
  a sound reading of the limits documentation. It is not an observation of a controller.
- **What happens to a user:** if a controller does disturb an outstanding paged search when another
  request arrives on the same connection, the visible symptom is the bookmark being rejected, which
  ends the run with a named failure rather than truncating a capture silently. So the risk here is a
  run that stops, not a report that lies â€” which is why it is recorded rather than designed around.
- **Options:** confirm against a real controller in the lab session, on a partition large enough to
  page and containing a group large enough to range-retrieve. If it is wrong, the fallback is to
  collect unfinished attributes and drain them after the last page, at the cost of holding
  part-read objects for the length of a partition.
- **Test cover:** the ordering is covered against the controller model, which by construction does
  not object. The controller's side is not covered at all.
- **Status:** OPEN, as of 2026-08-12. Named by ledger row **B20**, which is where the run driver and
  the lab session's instrumentation land.

### F-S7-40 â€” A controller can throw away a paging bookmark, and the failure table has no entry for what the client then sees

- **Severity:** correctness-risk
- **Confidence:** verified that it happens; **unverified** what code it arrives as
- **Evidence:** a controller holds the state behind a paged search in a cache with administration
  limits, and removes entries from it to make room. *"What happens when such a cookie is deleted on
  the server and the client continues the search with this cookie handle? The LDAP Server doesn't
  find the cookie in the server cookie cache and returns an error for the query"*, reported as
  `00000057: LdapErr: DSID-xxxxxxxx, comment: Error processing control`
  ([How LDAP server cookies are handled](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/how-ldap-server-cookies-are-handled)).
  The same article states the correct response: *"if the server returns an error, the client must
  consider the paged search to be unsuccessful. Retrying the search results in restarting the search
  from the first page."*
- **What happens to a user:** a long capture of a large partition ends with an unrecognised failure
  and the run stops, when reading the naming context again from the start would have worked. That is
  fail-fast doing the safe thing with the wrong information, so nothing is misreported â€” but a
  customer's scheduled overnight capture produces nothing where it could have produced a bundle.
- **Why it is this way:** [`S-10`](../next/S-10-politeness.md)'s retry table was written from the LDAP result
  codes, and this failure's code is not stated in the article â€” only its diagnostic text. Guessing
  which result code carries it would be exactly the plausible-mechanism-without-a-source that
  [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) forbids,
  and a wrong guess would mean retrying something nobody has reasoned about.
- **Options:** observe it in the lab by holding a paged search open past the cache's limit, then add
  a row to the retry table answering it with `RestartTheUnit`, which is what the article prescribes
  and what the policy already knows how to do.
- **Test cover:** none. The catch-all currently ends the run, which is safe and not right.
- **Status:** OPEN, as of 2026-08-12. Named by ledger row **B20**.

### F-S7-41 â€” A mutation run that does not build measures the unmutated assembly

- **Severity:** maintainability
- **Confidence:** verified, by observing it
- **Evidence:** the first mutation of B6's referral-policy check was written to
  `PartitionCapture.cs`, confirmed present in the file, and `dotnet test` was run. All sixteen tests
  passed. Re-run as `dotnet build` followed by `dotnet test --no-build`, the identical mutation
  produced fifteen failures.
- **What happens to a user:** nothing directly, and that is what makes it dangerous. What it
  produces is a mutation table in a document saying a guard did not fire, which reads as evidence
  the guard is unnecessary. Every subsequent decision resting on that table would be resting on a
  run that measured the wrong assembly â€” the same shape as gate 5's original wording and the S-2
  document guard, which is the failure category this repository has committed three times.
- **Why it is this way:** unknown. `dotnet test` builds by default, and it did not on that
  invocation. The cause was not chased because the remedy is cheaper than the diagnosis.
- **How it was acted on:** every mutation recorded in [`S-12`](../next/S-12-the-capture-passes.md) builds
  explicitly and then tests with `--no-build`, and the first run is recorded in the table rather than
  quietly replaced by the second.
- **Test cover:** none possible; it is a property of how a session runs commands.
- **Status:** **CLOSED as practice**, 2026-08-12, by ledger row B6. It is worth carrying into the
  session prompt if it recurs.

### F-S7-43 â€” A refactor blinded a document scanner, and only the floor in its self-test caught it

- **Severity:** correctness-risk, in the checking rather than the product
- **Confidence:** verified, by observing it
- **Evidence:** the endings of a capture pass were first written as direct calls to
  `AuditError.Create(ErrorCategory.Capture, "Reason", â€¦)`, and `CapturePassesDocumentationTests`
  matched exactly that shape. Tidying five of them behind a private `Refuse` helper left the pattern
  matching two call sites instead of seven. Both directions of the document check then compared two
  much smaller sets and found them consistent.
- **What happens to a user:** nothing directly. What it produces is a document that claims to
  describe every way a capture can stop, and a test that claims to hold it to the code, while five
  of the six endings are outside what either covers. That is the category this repository has
  committed three times.
- **Why it is this way:** a scanner keyed to a syntax form is keyed to a decision somebody is free
  to change for unrelated reasons, and the person changing it has no way to know. Reflection would
  not help: an error reason is an argument, not a member.
- **How it was acted on:** the self-test asserts a **floor** on how many endings the scan finds, and
  that floor is what failed. It was written for exactly this reason before the refactor happened,
  which is the argument for every scanner carrying one rather than only asserting that it read some
  files. The pattern now recognises both call shapes and the self-test exercises both.
- **Test cover:** `TheScannerReadsTheLoopAndTheDocumentAndItsPatternMatches`, mutation 6.
- **Status:** **CLOSED**, 2026-08-12, by ledger row B6. Recorded because the general lesson â€”
  a scanner self-test must assert a quantity and not merely that something was read â€” applies to
  every gate in the tree.

### F-S7-44 â€” A cancelled mutation run left the mutation in the source file

- **Severity:** correctness-risk, in the checking rather than the product
- **Confidence:** verified, by observing it
- **Evidence:** mutations were applied and reverted inside a PowerShell `try`/`finally` holding a
  byte-for-byte snapshot, which is what the session rules ask for. One mutation deliberately causes
  the capture loop to spin, so the test run hangs; that command was cancelled from outside, the
  `finally` did not execute, and the mutation stayed in `PartitionCapture.cs`. It was found by
  checking the file immediately after the cancellation rather than by the safety net.
- **What happens to a user:** in this case nothing, because it was caught within a minute. Had it
  not been, the committed product would have contained a deliberately disabled guard against an
  endless paging loop, introduced by the very process meant to prove that guard works.
- **Why it is this way:** `finally` protects against an exception inside the script. It does not
  protect against the process being killed, and a mutation whose whole purpose is to hang is exactly
  the one most likely to be killed.
- **How it was acted on:** a mutation that can hang is now applied and reverted through the file
  editor rather than the shell, its test run is launched as a background command that can be stopped
  without killing the outer session, and the file is checked for the mutation's text after any
  interrupted run. The revert-from-snapshot rule stands; it is necessary and it is not sufficient.
- **Test cover:** none possible; it is a property of how a session runs commands.
- **Status:** **CLOSED as practice**, 2026-08-12, by ledger row B6.

### F-S7-42 â€” Sixteen public types were forecast to reach a running consumer at B6, and B6 is a library

- **Severity:** maintainability
- **Confidence:** verified
- **Evidence:** [`SURFACE-REGISTER.md`](../next/SURFACE-REGISTER.md) named B6 as the first *running* consumer
  of sixteen types, on the stated basis that *"the first thing that runs is the capture module."* B6
  is now built and nothing runs: it has no `Main`, no caller, and no way to be reached, because
  choosing a controller and opening a connection is branch A and writing what it reads to a bundle is
  branch C, and neither is decided. Gate 5b asks what a *running* consumer reaches, and the register
  already records the precedent â€” the schema catalogue's forecast moved from K16 to J33 for exactly
  this reason, because *"a library reading a library does not answer it."*
- **What happens to a user:** nothing yet. What it would cost is the gate: had the entries simply
  been removed when B6 reached Done, sixteen types would have left the register on the strength of a
  consumer that does not run, and gate 5a would be quietly weaker while looking unchanged.
- **Why it is this way:** the forecast was made when B6 was the next row on capture's critical path
  and looked like the thing that would run. It was a reasonable forecast and it was wrong in the same
  way twice, which is the argument for the register naming a basis rather than only a row.
- **How it was acted on:** the sixteen forecasts move to **B20** â€” capture run bookkeeping â€” which is
  where a run driver would land, and gate 5b's trigger moves with them. The register's own words
  apply: *"a wrong forecast that gets revised is doing its job; an entry nobody revisits is not."*
- **Test cover:** `SurfaceRegisterTests` in both directions; the decay check is what would have
  forced the entries off.
- **Status:** OPEN, as of 2026-08-12. Named by ledger row **B20**.

## Open questions for the owner


All four at the top of this document are now answered â€” 1 and 2 on 2026-08-10, 3 and 4 on
2026-08-11. F-S7-1 is a fifth and remains open: it is not urgent this week, but it is one question
with three homes and it gets more expensive as each of the three ships.

## Not reviewed

B13 to B23 â€” password policy, Group Policy capture and its file seam and parsers, the shard schema
and merge, coverage recording, progress emission, run bookkeeping, trust persistence, the database
profiler, and the capture setup UI. They remain `(undecided)` in the ledger. B17 in particular is
downstream of B5's deferral; per F-S7-14 it should be decided on its own merits rather than
inheriting B5's Defer, and Delete is the starting hypothesis.

`docs/review/` was not read. It governs the old codebase.
