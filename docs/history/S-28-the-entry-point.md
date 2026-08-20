# S-28 — The entry point

> **This records session S-28 as of 2026-08-10. Nothing here states current behaviour.**  
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

The slice document for [`S-28`](../next/sessions/S-28-the-entry-point.md). It records what building the
composition root found, which was not what the brief expected.

## What the session was for, and what changed

The brief scoped `A9` as roughly fifty lines of wiring: resolve a run directory, open a connection,
plan the run from the RootDSE, walk the plan. Everything it composes was already built.

That is still the shape of the work. What changed is that wiring the four pieces together and
pointing them at a forest with more than one domain produces a bundle that is wrong, and wrong in
the one direction an audit tool may never be wrong in. The owner asked, before any code was written,
how a nine-domain forest would be captured. It would not have been. That is `F-S28-1` below.

The brief already recorded `ForestDiscovery` as provisional, because it treats every published
naming context that is not configuration or schema as a domain and therefore **over-reads**
application partitions — "the safe direction to be wrong in". That is true and it is a different
defect. The one found here is the same code being wrong in the unsafe direction, and it was not
recorded anywhere.

## Findings

### F-S28-1 — A forest of many domains is read as one domain and reported complete

- **Severity:** correctness — the product would tell a customer something false
- **Confidence:** verified, by reading the code rather than the documents
- **Evidence:** `ForestDiscovery.PlanAsync` asks one domain controller for its `namingContexts` and
  treats everything in the answer that is not the configuration or schema partition as a domain to
  read. An ordinary domain controller publishes only the partitions it holds — its own domain, the
  two forest-wide partitions, and its DNS application partitions — so in a forest of nine domains
  the answer names one. `CapturePlan.For` then computes `NotRead`, the record of what the run
  deliberately left alone, by subtracting the units it planned from `namingContextsPublished` — the
  same list it planned from. That subtraction is empty by construction, so `NotRead` is always
  empty, `IsComplete` is always true, and `CaptureRun` seals the bundle.
- **What happens to a user:** an auditor points the tool at a domain controller in a multi-domain
  forest and receives a sealed bundle. Nothing in the bundle, the coverage record or the run outcome
  says that eight of nine domains were never contacted. The customer makes a security decision about
  their forest on evidence covering a ninth of it, and the artefact carries this product's name.
  Pointed at an empty root domain — the ordinary shape of a large forest — it would report almost
  nothing and look like a clean result.
- **Why it is this way:** `CapturePlan` was built to be handed a domain list, with a comment saying
  that working out which naming contexts are domains is branch A's job. Branch A then supplied the
  list by guessing from what one controller published, because the row that reads the authoritative
  answer — `A7`'s cross-reference read — was not finished. Neither component is individually wrong.
  The completeness claim is produced by the join between them, which nothing owned.
- **What it violates:** [`0017`](../decisions/0017-capture-reads-the-whole-forest.md) — the sealed
  bundle is never scoped, and a part of the directory a run could not reach is a coverage failure
  that is stated rather than omitted. This produces a scoped bundle with nothing saying so.
- **How it was acted on:** fixed in this session. The cross-reference read finishes `A7` and gives
  the run the forest's own account of which naming contexts are domains; `CapturePlan` computes what
  it left unread against that list rather than against the list it planned from. The owner chose
  this over shipping an entry point that could not honestly capture his lab.
- **Status:** **CLOSED** by this session.

### F-S28-2 — The test that should have caught `F-S28-1` passes while measuring nothing

- **Severity:** correctness — a guard that always says yes looks like protection
- **Confidence:** verified
- **Evidence:** `ForestDiscoveryTests.APublishedPartitionIsAccountedFor` is named for the obligation
  that a partition the run does not read is recorded rather than ignored. It asserts
  `plan.IsComplete` is true and `plan.NotRead` is empty. But `ControllerModel.NamingContexts`
  publishes exactly three partitions — the domain, configuration and schema — and all three are
  planned. There is nothing for the run to leave out, so `NotRead` is empty for the trivial reason
  rather than the tested one, and the assertion would hold no matter what the code under it did.
- **What happens to a user:** nothing directly, and that is what makes it dangerous. Everything
  downstream of this test looks verified and is not. `F-S28-1` is precisely the defect this test was
  positioned to catch, and it survived because the model it runs against contains no partition that
  a correct implementation would decline to read.
- **Why it is this way:** the model was built for the paging and retry tests, where one domain is
  all that is needed, and the discovery tests reused it. Nothing said the model had to contain a
  case the assertion could fail on.
- **What it repeats:** this is the third instance in this repository of a check that passes against
  a world containing no failing case — after gate 5's original wording, which held against all
  fourteen public types while nothing in the tree was reachable, and the `S-2` document guard, which
  matched a renamed member by substring so a deliberately broken document did not fail it. The
  pattern is recorded in `docs/next/README.md` § Gates, and it is why every gate carries a scanner
  self-test.
- **How it will be acted on:** the controller model gains an application partition it publishes and
  a cross-reference answer, so `NotRead` has something to be non-empty about, and the assertion is
  rewritten to name the partition it expects to be left unread. Both directions mutation-tested.
- **Status:** **OPEN** — the fix is the remaining work of this session.

