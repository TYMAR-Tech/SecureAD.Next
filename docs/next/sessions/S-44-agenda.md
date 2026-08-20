# S-44 agenda — the questions only the owner can answer

**A draft, and deliberately not a complete list.** This is what the agent can see from the
fifty-seven records, the six written area files, the reference inventory and
[`DOCUMENT-COVERAGE.md`](../DOCUMENT-COVERAGE.md). The trap this session was called to avoid is an
agenda that *looks* exhaustive: twenty questions get answered and the one that mattered was never on
the page. So the first question is the last one in this file — **what is missing?**

Nothing here is decided. Every answer becomes a record in `docs/decisions/`, however short.

**Reading order.** Group A first (blocks work about to start), then group B (cheap now, brutal
later), then group C. Skipping to C is the expensive mistake.

---

## Two corrections before we start

The session brief carries two claims that do not survive contact with the records. Neither changes
what needs deciding; both change which record the answer attaches to.

- **`0049` is superseded by [`0052`](../../decisions/0052-the-domain-is-the-only-unit-of-scope.md).**
  The brief asks what "`0049`'s attestation actually asks for". `0049`'s own status line says its
  decision is carried forward whole into `0052`, with one addition: the falsifiable posture is
  offered only once ledger row `B11` makes it testable. So the question is live, but it is a
  question about `0052`, and the answer amends `0052`.
- **`C27` may already be judged.** The brief lists the low-signal OU recommendation query as the one
  unjudged ledger row, asking whether `0052` removes its premise. `0052` decides the domain is the
  only unit of scope. That does not automatically kill a *recommendation* about OUs — scope and
  reporting are different things — so this still needs a yes or no, but it is a smaller question
  than the brief implies. Question C4 below.

---

## Group A — blocks work that is about to start

These sit in front of step 5 of `S-43`, or in front of the next screen. An answer here unblocks a
file; a deferral here means the file gets written with a hole in it, deliberately.

### A1. Can an operator stop a run in progress, and what is the half-run for?
*Area: running a capture. Blocks: `running-a-capture` is written but its open list names this; the
progress screen cannot be designed without it.*

Three shapes, and they are genuinely different products:

- **No stop.** Simplest, and honest — the run is atomic or it is nothing.
- **Stop and discard.** The operator gets his machine back; nothing is kept.
- **Stop and keep what was read**, marked as a deliberately truncated run.

The third is the one with teeth. A half-run that can be opened is a half-run that can be compared,
reported on, and mistaken for a whole one — and the product's own rule is that *found nothing* and
*could not compute* must never render alike. If we keep it, it needs a run state of its own under
[`0028`](../../decisions/0028-one-run-state-vocabulary.md), and
[`0026`](../../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) needs an outcome for it.

**What did the old app do, and did an operator ever want to stop one?**

### A2. How much of a run is shown while it is running?
*Area: running a capture, how failures are reported. Blocks: the progress screen.*

Nothing until it finishes; a domain-by-domain tick; or a live count of objects read. The middle one
is the only one that lets an operator tell "slow" from "hung" — which, on a fourteen-month-old
memory of real forests, is probably the question he actually had at 2am.

### A3. Does an exclusion carry forward between runs, or is it re-attested each time?
*Area: domains we skip. Amends `0052`.*

Carrying it forward is kinder and is how a scheduled run would have to work. Re-attesting each time
is the control: an attestation nobody is ever asked for again is a liability waiver, which is the
exact failure `0049` quotes the predecessor's own code comment about.

Middle option: **it carries forward as a pre-filled answer that must still be confirmed.**

### A4. May a run with an excluded domain be compared to one without it?
*Area: domains we skip, how compare works. Amends `0026`'s outcome set.*

[`0026`](../../decisions/0026-one-answer-to-whether-runs-may-be-compared.md) decided there is **one**
component answering this and every door calls it — so whatever the answer is, it lands in one place.
What it did not decide is this case.

The risk of "yes, compare them": a domain that was excluded looks exactly like a domain whose
objects were all deleted. The risk of "no": an operator who excludes one domain permanently can
never compare anything again.

**Middle option:** comparable, but the excluded domain is reported as *not compared* rather than as
*unchanged* — which is more work and is the only version that cannot lie.

### A5. What does the attestation ask for, where is it stored, and does it reach the bundle?
*Area: domains we skip. Amends `0052`. Currently has no code, no test and no screen.*

Four sub-questions, and they can be answered separately:

1. **What is the operator asked?** A free-text reason, a pick from a fixed list ("no credentials",
   "out of remit", "known-empty"), or a fixed list plus free text?
2. **Who is named?** The signed-in account automatically, or a typed name?
3. **Does it survive into the bundle**, so an auditor reading the run months later sees the reason?
   (If yes, it is schema, and schema is cheapest to add before the first real bundle exists.)
4. **Is any of it testable against the data** — `0049`'s falsifiable posture, deferred to ledger row
   `B11`? "This domain is empty" can be checked. "I lack credentials" cannot.

### A6. How does a deliberately excluded domain look beside one that simply has no candidates?
*Area: domains we skip and which controller we read — this is the seam between them, raised by both.*

By [`0054`](../../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md) both are
attested exclusions. The question is whether the operator can tell them apart on screen, and whether
he should be able to. One is a choice he made; one is a fact about the network.

---

## Group B — free now, expensive later

Naming, the shape of a public interface, where a thing lands. These are the ones worth patience.

### B1. Is the captured attribute catalogue complete for rules not yet written?
*Area: what we capture. The most expensive question in this file.*

An attribute not captured is a question **no past run can ever answer**. Add one in six months and
every bundle taken before that date is silent on it, permanently. There is no migration path,
because the data was never read.

The agent cannot answer this — it requires knowing which rules are coming, which is product
knowledge. Practical form of the question: **from fourteen months of real forests, what did you ever
want to check that this catalogue could not tell you?**

Cheap insurance if the answer is "I'm not sure": capture a wider set now and decide later what to
judge. Costs capture time and bundle size; buys the ability to ask new questions of old runs.

### B1a. Finding — `0051`'s trust attributes are decided and not captured

**`F-S44-1`. Closed by [`0065`](../../decisions/0065-the-catalogue-recovers-what-the-rebuild-dropped.md)
as a decision; the implementation is still owed. Raised 2026-08-16 while assembling B1.**

[`0051`](../../decisions/0051-trusts-describe-a-boundary-and-never-widen-a-run.md) decides that
`trustedDomain` objects are captured rather than copied, and that **`trustAttributes` is preserved
whole and its bits reported** — naming SID filtering absent on an external trust as a severe finding.

`trustedDomain` is not in `CapturedAttributeCatalog`'s class map, so a trust object receives only the
universal attributes. `git grep` for `trustAttributes`, `trustDirection`, `trustPartner` and
`trustedDomain` across `next/` returns nothing.

This is the B1 problem in miniature: not a bug that can be fixed later, because every run taken
before the attribute is added is permanently silent about its trusts.

### B1b. Finding — a closed loop of tests hid fifteen missing attributes

**`F-S44-2`. Open. Raised 2026-08-16, after the owner asked how `0065`'s attributes were missed
despite the golden tests.**

**Nothing was measuring completeness, and the tests that exist look like they were.**

The attribute catalogue is covered by three sound test suites, and they form a closed loop:

- `CapturedAttributeCatalogTests` checks the **mechanism** — that every object is asked for the whole
  catalogue whatever its class, that an unknown class still gets its descriptor, that every
  multi-valued attribute is range-liable. It never asserts *which* attributes are present.
- `CapturedAttributeCatalogDocumentationTests` checks the catalogue against `S-8`, **both
  directions**.
- `CapturedAttributeDerivationDocumentationTests` checks that every attribute names a rule that
  reads it, and that every rule's needs are met.

The document matches the code, the code matches the rules, the rules match the document. Every check
passes with negative controls, and **the whole circle is anchored to the set of rules already
written**. A rule nobody wrote is an attribute nobody misses. From inside, a loop closed around the
wrong circle is indistinguishable from one closed around the right one.

**This is not the "passes while measuring nothing" failure.** The tests measure real things and
would catch a real regression. They are anchored to the wrong reference for *completeness*, which was
never in their remit.

**Why the catalogue and not the rest.** Security descriptor parsing was **ported**, and
`GoldenAceHashTests` pins it to the predecessor's oracle. The rule cards were **ported** — 62 cards
in `docs/rules/`, 62 rules in the predecessor's `rules.yaml`, identifier sets verified identical in
both directions on 2026-08-16. The attribute catalogue was the one thing **reassembled from first
principles**, with the predecessor's list never consulted, and it is the one thing that lost content.

**Proposed remedy — a reconciliation fixture, not a golden test.** The catalogue is *supposed* to
diverge, so pinning it to the predecessor's would fight `0065`'s own reasoning. Instead: record the
predecessor's attribute list as a fixture, and require every entry to be either present in the new
catalogue or **named in a written list of deliberate omissions with a reason**. Divergence stays
legal; silent divergence does not. This would have caught all fifteen on the day they were dropped,
and costs one file.

**The general lesson, worth more than the fix:** anything *reassembled* rather than *ported* has no
anchor, and internal-consistency tests cannot supply one however thorough they are.

### B2. What is a "finding" called, and what does an operator do to one?
*Area: what we call a finding, accepting a finding. Two unwritten areas, and thirty-four consumers
are ahead of us.*

[`0023`](../../decisions/0023-a-finding-has-a-stable-identity.md) and
[`0024`](../../decisions/0024-a-rule-identifier-is-permanent.md) settle identity and permanence, not
vocabulary or lifecycle. Open:

- Is it a *finding*, an *issue*, a *risk*, a *result*? Whatever it is called, it will be called that
  on every screen, in every report, and in every rule card.
- Can an operator **accept** one — mark it known and expected — and does that acceptance carry
  forward between runs? (Same shape as A3, and the answer should probably match.)
- Does an accepted finding **disappear** from the next report, or appear greyed with its reason?
  Disappearing is what makes acceptance a way to hide things.
- Does acceptance expire?

### B3. What is the unit an operator navigates by on the results screen?
*Area: how results are shown. Unwritten.*

**Deferred to the screens work, deliberately, on 2026-08-16.** The owner's words: *"part of the
rebuild is to rethink through the screens so we will answer this more when we get to it."* This is
the *"I need to see it running first"* answer and it is the right one — the question is about how a
screen reads, and those are expensive to be wrong about in advance.

**Settled here, and recorded in [`0066`](../../decisions/0066-a-finding-is-called-a-finding.md):**
the word is *finding*. The predecessor used *Risk* as a grid column heading for the same number its
rule cards called *severity*.

**What the predecessor actually did**, established from a screenshot on 2026-08-16 and correcting an
earlier reading of the code:

- **Six rail entries**: Home, Dashboard, Assets, Reports, Settings, Help.
- **The organising spine is the directory tree** — forest, domain, OU — inside Assets. The operator
  navigates by *position in the directory*, and the tabs are lenses over the current selection.
- **Five tabs** within Assets: Findings, Escalation Paths, Groups, LAPS Status, Objects. `LAPS
  Status` is one rule of sixty-two with a tab of its own; the owner's provisional view is that it
  could be a query and a report instead.
- **Eight detail windows** exist in the tree (finding, object, trustee, delegation, escalation path,
  control edge, inspector, and a generic one). How many the rebuild should have is undecided.

**Three observations to carry into that work:**

- **"Evidence Level: Graph Reachability"** and *"limited to 5 hops and shown as retained
  representative evidence paths"*. The predecessor stated how well it knew a thing and what it had
  truncated. That character must survive.
- **"Validation: Not Validated"** cannot survive.
  [`0008`](../../decisions/0008-live-verification-is-removed.md) removed live verification, so the
  column has nothing behind it.
- **The status bar's "✓ Verified"** is the telemetry theatre
  [`0057`](../../decisions/0057-starting-an-audit-is-a-modal-act.md) removed.

**Still open, and needing the screens session:** what the operator lands on when a run finishes (the
owner leans to a dashboard); how many kinds of detail screen exist; whether escalation paths and
groups keep dedicated surfaces, both of which the owner flagged as needing deeper discussion.

### B4. What is a report *for*, and who reads it?
*Area: reports and export. Unwritten.*

An auditor's evidence pack, a remediation worklist for an AD team, and a one-page summary for a
manager are three different documents with three different failure modes. Which of them must exist
at v1? And what formats — the answer decides whether we take on a rendering dependency.

### B5. Is there a severity scale, and who sets it?
*Area: what we call a finding.*

Fixed per rule, or adjustable per customer? Adjustable severity is the single most requested feature
in tools like this and the single easiest way for a customer to make a real problem invisible.

### B6. What does the run library show, and how does an operator choose a baseline?
*Area: the run library. Unwritten. [`0025`](../../decisions/0025-the-run-library-is-a-managed-root.md)
decides it is a managed root, not what it looks like or how baselines are chosen.*

`0026` notes the predecessor's baseline eligibility never checked run state, so a failed run could be
made a forest's baseline and then never compared against. What is the rule here — most recent
complete run automatically, or an explicit choice?

---

## Group C — the rest

### C1. Can a run be scheduled, and what runs it when nobody is signed in?
*Area: running a capture.* This is a service, not a feature — it changes the deployment shape of the
whole product. Worth a yes/no now even if the build is far off.

### C2. What happens when two runs start against the same forest at once?
*Area: running a capture, how a run is stored.* Refuse the second, queue it, or allow both.

### C3. How much missing coverage is too much to report on at all?
*Area: what the run covered.* Related: **can an operator accept a coverage gap**, marking a
known-unreadable partition as expected — and what stops that becoming a way to hide one? Same shape
as B2's acceptance question.

### C4. `C27` — the low-signal OU recommendation query. Build, drop, or defer?
*See the correction above: `0052` narrows this question, it does not obviously answer it.*

### C5. What is owed about the ten unenforced session documents?
*Not a product question — a housekeeping one, and the agent has a recommendation.*
`DOCUMENT-COVERAGE.md` argues they can move to `docs/history/` **without being read**, because
nothing enforces them and nothing in the product relies on them. **Recommendation: stamp and move
all ten.** This needs a yes, not a discussion.

### C6. How does an operator pin controllers permanently?
*Area: which controller we read.* Referred to as "the configuration file" in `A2` of the reference
inventory, never designed. Does this need to exist at all, given
[`0055`](../../decisions/0055-the-pdc-emulator-is-established-at-preflight.md)?

### C7. Does preflight run against all domains at once?
*Area: which controller we read.* [`0041`](../../decisions/0041-capture-reads-domains-in-parallel.md)
covers capture, not preflight. Each domain currently costs one connection, taken in turn. Related
open finding `F-S41-4`: every Validate press costs a full discovery pass.

### C8. Is a partial object stored, and how is it told from a whole one?
*Area: what we capture.* An object read, but with one attribute that failed. Also: what happens when
the schema declares an attribute the catalogue does not know?

### C9. How much of a very large forest is expected to fit?
*Area: what we capture, how a run is stored.* And what does the product do when it does not?

---

## Answers we can probably record without discussion

Offered so they can be confirmed in a sentence each rather than debated. If any of these is wrong,
it is worth more than the rest of the file.

- **The ten unbound session documents move to `docs/history/` unread** (C5).
- **An exclusion's reason reaches the bundle** (A5.3) — because a reason an auditor cannot see is a
  reason that does not exist. The *wording* still needs answering.
- **A stopped run, if it is kept at all, gets its own run state and its own comparability outcome**
  (A1) — this follows from `0028` and `0026`, whichever way the product question goes.

---

## The question this file exists to ask

**What is missing?**

Thirteen of nineteen areas are unwritten, and the agent's view of them is assembled from records and
a ledger describing a *different* application. Four whole areas below have no question above them
worth the name, because the agent does not know enough to ask one:

- **Who is who** — identity resolution, `SID` to name, cross-domain.
- **What a permission means** — beyond the classification `S-4` already binds.
- **How privilege escalates** — the chains, and what counts as one.
- **Group Policy** — `0043` and `0044` decide where its permissions are read from; nothing decides
  what is judged about them.

**On each of those, the useful prompt is not a question from me — it is: what did the old app get
right there, and what did it get wrong?**
