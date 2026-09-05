# What SecureAD is

An Active Directory security audit tool. **It reads a forest once, seals that reading as evidence,
and everything it says afterwards it says from that file.**

The product makes two separable claims, and keeping them separable is the whole design:

1. **This is what your directory said, at this moment.** Provable years later, on a machine that
   never saw the forest.
2. **This is what we conclude from it.** Re-runnable under better rules without touching claim 1.

**This is orientation, not authority.** Nothing here states the product's position; only a record in
[`decisions/`](decisions/) with `Status: Accepted` does that. Where this file and a record disagree,
the record wins and this file is wrong.

## The shape of a run

| Stage | What happens | State |
|---|---|---|
| Connect | Find the forest itself; climb an ordered ladder of protection and record which rung each controller answered on | built |
| Preflight | Prove a controller can serve what it will be asked, before the run commits | built |
| Capture | Read objects, permissions, group memberships, schema, extended rights, SYSVOL/GPO files | built |
| Reconcile and seal | Reconcile referrals with authorized scope, record uncertainty, then fingerprint immutable Evidence | built |
| Derive | Compute reusable cross-object facts into a disposable store beside Evidence | built; group expansion, membership cycles and AdminSDHolder products persisted and readable |
| Judge | Stream the bundle once, offer every object to every scheduled rule, write findings to a separate store | built, 17 rules |
| Read back | Run library, directory tree, object detail and findings | built |
| Dashboard | Coverage and inventory: how much of the forest was read, and what it held | built |
| Reports, compare and export | — | not built |

**The counts and states in that table are checked rather than maintained by hand**, by
`next/tools/check-stage-status.ps1`. A status goes false when the code moves and the document sits
still, so it cannot be protected by proof-reading; this file claimed *two rules* for long enough
that twelve more were built underneath it. See `P-135`, and `ROADMAP.md` § *Where we are* for the
per-stage witnesses.

`0008` fixes the boundary: **the only component that touches a domain controller is capture.** A
screen showing a permission is reading a file, not asking the directory.

**The application is the product; the command line runs unattended.** The owner's words, 2026-08-26:
*"this whole app is a GUI, the cli is just to capture overnight."* The GUI is where an operator
works and is what every screen is designed for. The command line exists so a long run can happen
overnight without the application open, and **it is intended to grow judging too** — the owner,
later the same day: *"i will be making it so the user can run the audit and it complete the judging
via CLI, so it can run overnight."* So the command line is not capture-only forever; it is the
unattended path, and the GUI is the worked path.

## How judging works

Decided, built and measured — see [`layers/judgement/`](layers/judgement/).

- **One pass over the bundle, not one per rule.** Every object is streamed once and offered to every
  scheduled rule while it is in hand, so judging forty rules costs the same read as judging one.
- **A rule judges one object and nothing else.** No forest, no sibling lookup, no second pass, so a
  rule cannot quietly acquire an input it never declared.
- **A rule declares the data it reads, or the build fails** (`0083`).
- **Atomic per rule, not per run.** A rule that throws loses only itself; its partial findings are
  discarded, because a partial verdict would read as a complete one.
- **Findings live outside the seal** (`0085`), in a store that is disposable and rebuildable.

**The acknowledged rule-input gap:** rules that depend on cross-object facts need persisted,
Evidence-bound Derivation products and typed missing/degraded input handling. The accepted correction
order is recorded in [`docs/next/WORKFLOW.md`](next/WORKFLOW.md); it is no longer treated as an unbounded
architectural question.

## The five commitments

1. **Evidence is permanent.** Sealed once, never re-sealed. Re-analysis copies the source and seals
   the copy; the original is opened read-only (`0021`).
2. **A gap is a fact about the capture, never about the forest** (`0002`). A domain left out by
   choice never looks like one that could not be reached (`0063`); an unfinished run reports nothing
   at all rather than partially (`0068`).
3. **Say what you know, with its uncertainty — except when claiming completeness** (`0086`). Silence
   is reserved for *this is complete*, where a wrong answer makes someone stop looking.
4. **Severity belongs to the rule and the customer cannot move it** (`0066`, `0082`) — lowering a
   severity is quieter than accepting a finding and leaves nothing behind.
5. **A finding carries typed evidence and a permanent identity** (`0080`, `0023`, `0024`), so an
   acceptance made today still attaches after a rename.

## What it deliberately is not

- **Not a live tool.** No live effective access, inheritance, ACL compare or delegation reporting
  (`0008`).
- **Not a policy compliance checker.** Password policy is captured and shown; nothing grades it.
  Plenty of software measures password strength.
- **Not tunable.** No assessment modes (`0031`), no customer-editable catalogue (`0082`).
- **Not an auditor of audit configuration.** The SACL is never requested (`0036`).
- **Not a reporter of account activity, decided 2026-09-01.** Whether an account is really in use
  cannot be answered from one controller: `lastLogon` is per-controller and never replicated, and the
  replicated `lastLogonTimestamp` is documented by Microsoft as updating only once it is already 9 to
  14 days old, and as capable of holding a future value after a clock skew or a Kerberos S4U2Self
  request. Reporting a stale-account threshold from that would print an estimate as a finding, and it
  would under-report as readily as over-report. Sign-in telemetry — Defender for Identity — answers
  this properly and a directory attribute does not. `P-113` keeps two possibilities open: the
  timestamp shown as *information* on an asset rather than as an indicator of activity, and a
  separately named *rough estimate* rule, for customers without that telemetry, whose own wording
  would have to say it is an estimate.

## Where it departs from the predecessor

There is an old application. It worked, the owner ran it, and it is why this rebuild knows what it
is aiming at. **Its architecture is not this one's, and nothing below is a design to follow.** Its
inventory and component map were archived and are deliberately absent from this repository, so that
nobody treats it as a specification.

**The code, however, is on disk at `C:\Users\ba.admin\source\repos\razamus\SecureAD`, and the owner
has said to read it** — *"treat this as a source not a answer, look at what it did but also consider
if there is a better way"*, 2026-08-26. It is the only place a working findings screen for a real
forest exists. Read it for **how something performed**; never for **what the product permits**,
which the decision records settle and which it frequently contradicts.

Thirty-nine of seventy-nine decision records reference it. The load-bearing differences:

| | Old app | Here |
|---|---|---|
| Live directory | kept a live connection alongside the bundle | removed entirely (`0008`) |
| Sealing | signed at the end over evidence *and* conclusions; re-analysis re-signed in place | evidence sealed alone at capture, never re-sealed (`0030`, `0085`) |
| Analysis | eleven dependent phases writing into the same file | one streaming pass into a separate store |
| Failure | phases fault-tolerant, degraded results still presented | unfinished run reports nothing (`0068`) |
| Severity | overridable by policy file | fixed by rule card (`0066`) |
| Capture scope | two class filters as radio buttons | every class except a shipped noise list (`0034`) |
| Schema partition | not read | read every run (`0014`) — what makes object-specific ACE evaluation possible |
| Vocabulary | *Accept* on screen, *Suppression* in code | one word, **finding**, everywhere (`0066`) |

### Why it took hours, and why that is not inherent

**The owner's measurement, 2026-09-03: capture took 30 to 45 minutes across nine domains, and the
run took three to five hours.** Capture was never the problem. The time went on the graph.

Its own CONTROL-EDGES-AND-PATHS document, under docs/ in the predecessor tree, says how, and it is
costs stacked on each other:

- **`fact_group_membership_closure`** — the full transitive closure of every group, materialised.
  Quadratic in the forest.
- **"Traversal: BFS from each non-high-value principal to discover shortest paths to targets."**
  With a hundred thousand principals that is a hundred thousand traversals of a graph holding
  millions of edges.

**Neither is required by the question being asked.** *Who can reach Tier 0* is answered by walking
**backwards from the targets** — there are perhaps dozens of high-value targets against a hundred
thousand principals, so the same answers cost three or four orders of magnitude less. The old
application even built the reverse graph, as step 3 of that document, and then traversed forward
from every principal anyway.

**So the hours were an algorithmic choice, not the price of the analysis.** This matters now because
escalation paths are unbuilt here and will be asked for eventually. Two things follow:

- The closure is already refused: `what-stage-2a-derives.md` walks membership on demand, because
  *the transitive closure of every group is quadratic in a real forest, while every consumer asks
  about a handful of named principals*. That decision was taken for a different reason and happens
  to remove the first cost entirely.
- **When paths are built, traverse from the targets.** Reverse traversal needs `memberOf` edges,
  which are linear in memberships and already persisted, and never needs the closure.

**One correction to a claim made in this session and left here so it is not repeated.** SYSVOL was
suspected of being a runtime risk on the strength of lab capture rising from 7 to 11 seconds when it
began working. The owner's account is that the old application captured little of SYSVOL and he is
not sure it was ever used in production, so there is no prior measurement to lean on either way.
It is unmeasured at scale rather than known to be slow.

### What its findings grid did, and what of it is worth having

Read 2026-08-26 from `SecureAD.Infrastructure/Paging/`, `Findings/FindingsService.Queries.cs`,
`Storage/DerivedStoreSchema.Views.cs` and `SecureAD.UI/ViewModels/FindingsGridViewModel.cs`.

**Keyset paging, and it is better than the obvious alternative.** `KeysetQueryBuilder` pages by
where the last page ended rather than by `LIMIT`/`OFFSET`. Offset paging makes the database walk and
discard every row before the page, so page 500 of a large forest costs 500 pages of work; keyset
paging costs one. Three details are the actual engineering, and all three are easy to omit and hard
to debug afterwards:

- **Every sort ends in a unique tie-breaker** — `severity, rule_id, target_dn`. Without it, rows
  that sort equal can straddle a page boundary and be shown twice or not at all.
- **The continuation token records the sort and a hash of the filter**, and a token that does not
  match them restarts from the first page rather than silently skipping rows.
- **Identifiers are validated against a strict pattern** before they reach the SQL text.

Its page size was 50, in `GridViewModelBase`.

**Filter values are read from the data**, so a filter cannot be set to something no finding has.

**Its grid resolved names by joining** `dim_principal` and `dim_object`, because findings and objects
were in one file. **They are not here** — findings are in `judgement.db` and evidence in the sealed
`evidence.db` — so what the grid shows is stored on the finding when it is made. That costs nothing
at judging time, because the object is already in hand when a rule fires, and it avoids the
alternative: fifty lookups into the evidence to paint one page, on every page and every re-sort.

**Three things in it are not worth having, and two are positions this product has reversed.**
`context_json` is the schemaless blob the judgement schema's own comments record as having silently
downgraded a finding when a value would not parse. `suppressed`/`suppression_reason` are `0066` and
`0082` reversed. And `v_grid_findings` rewrites a finding's coverage to *complete* inside the view,
by matching a `coverage_reason` string — a judgement made in presentation, where nobody reading the
finding can see it, which is `0002` exactly.

**Reading it found a defect here.** The old app's severity sorts correctly because its view does not
order on the text. This judgement store writes `severity` as the enum name, so `ORDER BY severity`
gives Critical, High, Low, Medium — alphabetical, putting Low above Medium. A rank is stored beside
the name to fix it.

### What its finding detail view showed, and what of it is worth having

Read 2026-09-01 from three screenshots the owner supplied of the predecessor's finding window
(`SEC-014`, `SEC-024`). This is the screen an administrator actually works from, so what it did well
matters more than most of the old code.

**Its blocks, in order:** a header carrying rule identifier, title, category (`Delegation`,
`CredentialTheft`), a MITRE technique link and a severity badge; **What was found**; **Evidence
context**; **Why it matters**; **How to fix**; a strip reading `Coverage: Complete  Suppressed: No
Tags: …`; and the buttons *View evidence*, *Accept risk*, *Copy finding key*.

**Worth having, and settled 2026-09-01:** the category, the MITRE link, **Why it matters**, **How to
fix**, and the coverage signal. The owner's decision on where they belong: **in the product, not only
in an exported report** — *"I can see server admins using this as a working app on what to clean up,
and seeing it on screen in a UI is sometimes easier to consume than a report if done right."* So the
finding view is a working surface, not a preview of a document.

**The one thing to change is duplication, not volume.** Of the eleven rows in *Evidence context*,
seven repeat the panel directly above them — rule id, source SID, subject name, target DN, target
name, control type and classification are all already on screen. Of the remaining four, three
(`Source Is Well Known Admin`, `Source Is Privileged By Membership`, `Source Is Broad Principal`) are
the *working behind* the classification line rather than an answer, and the fourth is an internal
edge identifier. The `Detail` sentence then states the same facts a third time, using a raw SID where
the name is two lines above.

**This is not a matter of taste, and the screenshots prove it.** On the owner's laptop the duplicated
block pushed **Why it matters** and **How to fix** below the fold, so the two things he most needed
were the two he could not see. Removing what is printed twice is what brings them onto the first
screen.

**The agreed shape, 2026-09-01:** four blocks — header, *What was found*, *Why it matters*, *What to
do* — with everything raw (identifiers, GUIDs, ACE hashes, the classification working) behind *View
evidence*, which the predecessor already did well. The rule to apply when deciding where something
goes: **the finding page answers what, how bad, why and what do I do; the evidence view answers prove
it.**

**Not worth having:** `Suppressed`, which [`0066`](decisions/) and [`0082`](decisions/) reversed, and
the *Evidence context* table on the front page.

**What must not creep in.** *How to fix* states an action and what it may break. It must never state
that the action makes the customer safe — that is a claim about every path to the object, which
`AC-15` and `AC-21` require to be proven, and it is stage 8 work. Guidance copy is where that line
gets crossed by accident.

**Content is stage 4; presentation is stage 9.** The guidance is written as each rule is built, while
the Microsoft research behind it is in hand; the screen that displays it is designed later, around
content that already exists.

**Every rule gets an About section, and it is where a limitation is stated, decided 2026-09-02.** The
owner: *"we will have an about section that describes each rule and what its looks for so we will have
the ability to surface the limitations to the user in that capacity."* So a rule has three kinds of
copy, and they answer different questions:

| | Answers | Scope |
|---|---|---|
| A finding | what is true about **this object** | one object |
| Guidance (\`RuleGuidance\`) | why that matters and what to do about it | the rule |
| About | **what this rule looks for, and what it does not** | the rule |

**This is what makes a bounded rule honest.** A rule that reports a subset is not free to let its
silence read as *nothing else is wrong*; About is where the boundary is stated to the operator rather
than only to a reviewer reading the rule document. \`SEC-027\` is the first rule to need it: it reports
SID history containing a **well-known** privileged identifier and cannot rank a custom group from a
domain that no longer exists, and an operator must be able to read that without opening this
repository.

It is content, so it is written as each rule is built, alongside the guidance. Where it is displayed
is stage 9 with the rest of the presentation.

**Built 2026-09-03, and it is required on every rule.** `RuleGuidance.About` is not nullable and
`RuleGuidanceTests` refuses a blank one. Optional was the cheaper choice and was refused for a
reason worth keeping: a field populated for some rules and empty for others is rendered by a screen
as *this rule has no limitations*, which for a bounded rule is the exact false statement the section
exists to prevent. Being obliged to write it is also how an unstated limit gets found — writing the
eleven turned up three nobody had said out loud, including that `SEC-028` reports an account
**exempt** from the password length rule rather than one with no password.

**It is shown on the findings panel, which is half of what it is for.** The operator who most needs
a rule's boundary is the one reading a rule that reported *nothing*, and he never opens a finding.
The rest waits for a screen that lists the rules themselves.

## Build order, and two scope decisions

**The dashboard is built before the remaining rules, decided 2026-09-05.** The owner asked whether
it had to wait until every rule existed; it does not, and it should not. Stage 2 depends on nothing
unbuilt. Building it early puts the wording in front of an administrator, which is the only way to
find out whether it reads correctly to the person who has to act on it. The order the owner set:
**dashboard, then a punch-list session, then stage 6**.

**A correction: this paragraph claimed the product had *no screen that shows findings to anybody*,
and that was false.** Corrected 2026-09-05 against the code. `AssetsPane` has had four working
panes bound to live stores for some time — `Objects` and `Laps` over sealed evidence, `Findings` and
`Rules` over the judgement store — and the findings pane already distinguishes *every rule ran and
matched nothing* from *nobody has judged this bundle*. The claim survived into this document because
it was written from a roadmap row rather than from `AssetsViewModel`. What was genuinely missing was
the answer to *what am I looking at*, which is what stage 2 supplies.

**The dashboard was built 2026-09-05 and the owner settled four things about it.**

1. **Coverage first, counts underneath.** How much of the forest was read is stated before any
   number on the screen, and stated every time — including when nothing was missed, so that its
   absence is never read as reassurance.
2. **Counted per domain, totalled afterwards.** A single forest-wide figure cannot show a hole: a
   run that read two domains of three produces a smaller number, and a smaller number looks exactly
   like a smaller forest. An uncovered domain is a visibly present row carrying no figures.
3. **Where a shortfall can be counted exactly, both numbers are shown.** The owner's wording: *if we
   can show how many were read and how many were not then we show the exact numbers.* This applies
   to Group Policy, the one place a sealed bundle can state an exact shortfall — the policies are
   declared by the directory, which is read all-or-nothing, while their files come from SYSVOL,
   which `0044` allows to fail without failing the run.
4. **The dashboard is the landing screen for an opened run.** A failed, interrupted or damaged run
   never reaches it: the owner's observation, confirmed in the code, is that such a run *never
   finished capture*, so there is no sealed evidence to land in. The library states what became of
   it instead.

**A domain cannot be reported as partly read, and the owner was right to question it.** Asked what
the screen should say for a partly read domain, he asked when that could happen — *wouldn't the run
be discarded?* It would. Capture is fail-fast per `0003`: a domain that cannot be read ends the run
before the seal, `UnreadOutcomeIsUnreachableTests` holds that no production code records a unit as
unread, and `BundleReader.ReadScope` refuses outright to open a bundle claiming otherwise. The
reachable gaps in an openable bundle are a domain excluded by choice, a domain the forest named no
writable controller for, and a SYSVOL read that partly failed.

**A count is never rendered for a domain that was not read, and the type enforces it.**
`DomainInventory` holds its counts behind `TryGetCounts`, which answers false for every outcome but
`Read`, and its factories refuse both contradictions at construction. There is no zero available to
render for an unread domain even if the screen's markup were wrong. See
[`layers/shell/what-a-run-counted.md`](layers/shell/what-a-run-counted.md).

**Tier 1 means what Microsoft says it means, decided 2026-09-05.** Per the
[tier model](https://learn.microsoft.com/windows-server/identity/ad-ds/tier-model), Tier 1 is
*enterprise servers and applications*: member servers and server administrator roles, the solutions
that manage them (backup, monitoring, patching, hypervisors), Microsoft server applications such as
Exchange, SharePoint and SQL Server, third-party server solutions, and line-of-business
applications. Tier 2 is end-user devices and accounts. This settles the wording of `SEC-073` and
`SEC-074`, which were recorded as *gap - Tier1 undefined*.

**It does not settle how the product decides which computers those are, and that is the harder
half.** Tier 0 is derivable from the directory - Microsoft names the groups. **Tier 1 is not.**
Nothing in Active Directory marks a member server as an Exchange server or a line-of-business host;
the tier model is an operational structure an organisation adopts, expressed in OUs and groups it
chose the names of. `operatingSystem` distinguishes a server from a workstation and says nothing
about what it carries. So a Tier 1 rule must either read a customer-supplied definition or infer
one, and **inferring it would be this product asserting a tier boundary the customer never drew**.
Recorded as `F-S45-11`; not blocking the dashboard.

**Group Policy is deferred to the end, decided 2026-09-05.** The owner: *"i may leave until the end
unless it will be harder then but i dont see why it would be."* **It will not be harder later**, and
the reason is worth recording: the five GPO rules are blocked on a capability the product does not
have - reading policy *content* out of files on SYSVOL, rather than reading the policy object in the
directory. That capability is self-contained, it is the same amount of work whenever it is done, and
nothing else in the roadmap depends on it. Deferring it costs nothing but the findings themselves.

---

**A question the owner has already answered is a defect in this repository.** When he answers one,
it belongs here, in the same turn.
