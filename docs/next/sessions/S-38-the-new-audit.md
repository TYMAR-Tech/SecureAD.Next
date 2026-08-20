# S-38 - The New Audit flow

**Status: specification, ready to build.** Written 2026-08-15 after reading the predecessor's
discovery code and reconciling it with what the rebuild has. This is the single document for this
work; it replaces `DESIGN-discovery-rework-impact.md` and `DESIGN-new-audit-flow.md`, both deleted.

Read this first, build from it, and correct it where it turns out to be wrong.

---

## 1. What this session is for

An operator clicks **New Audit** and the tool works out the rest. Today the rebuild has no New Audit
surface at all, and its one entry point demands a typed domain controller hostname.

The predecessor did this properly and it was never carried across. What follows is the predecessor's
behaviour where it was right, the rebuild's where it is better, and the decisions already taken.

---

## 2. What the operator sees

### Click New Audit

No text box. No hostname. Work starts immediately.

### Finding the forest (about a second)

The tool reads the machine's own DNS domain suffix, falling back to the NetBIOS domain name, and
opens a connection **to that domain name rather than to a host**. The Windows DC locator turns a
domain name into a nearby live controller; that is the mechanism which removes the text box, because
a domain name is something the machine already knows and a hostname is not.

From that connection it reads the RootDSE and takes `rootDomainNamingContext`, which is the forest
root as stated by the directory.

**Manual entry survives as a recovery path only** - a machine that is not domain-joined, or an
operator auditing a forest that is not his own.

### Learning the whole topology from one read

Every controller holds a full replica of the configuration partition, so one connection yields the
physical topology of the entire forest without opening a second:

- **`crossRef` objects** give every domain, its naming context and its functional level.
  *Already built - `ForestPartitions`.*
- **`nTDSDSA` objects beneath `CN=Sites`** give every controller in the forest. `msDS-hasMasterNCs`
  states which naming contexts it holds a **writable** replica of, which is the per-domain candidate
  list. Its site comes from the great-grandparent container in its own distinguished name, and
  `dNSHostName` from the `server` object above it.
- **`subnet` objects** give the operator's own site, by matching the machine's addresses and taking
  the longest prefix.

**Discovery contacts nobody.** Sixty controllers are enumerated and ranked with one read.

A read-only controller lists a domain in `msDS-hasFullReplicaNCs` rather than `msDS-hasMasterNCs`,
so filtering on the latter means an **RODC can never enter a candidate list**. There is no
capability probe to forget to run and no second refusal to keep in step with the first.

DNS still does what it is good at: resolving `dNSHostName` to an address. It is never asked which
controllers exist.

### Choosing a controller per domain

Ranked, with no I/O:

1. **Same site as the operator's machine.** A client matching no subnet has no site preference, and
   the run says so rather than guessing a plausible-looking wrong answer.
2. **Holds no FSMO role**, the PDC emulator above all. It is the busiest machine in any domain -
   time sync, password chaining, account lockout, Group Policy edits - and pointing a multi-hour
   forest-wide read at it is the one clearly bad choice available. The forest-level roles come free
   in the configuration read; the PDC emulator sits on each domain's naming context head and costs
   one base read per domain.
3. **Lexical by hostname**, so the same candidate set always produces the same choice and two runs a
   week apart pick the same controller unless the forest changed.

The first is pinned; the rest become that domain's ordered failover list.

### The domain table

One row per domain: candidates found, the pinned controller and its site, an override box, and -
once preflight has run - the connection rung, whether the controller serves the partition, and
whether the Password Settings Container could be read.

An override that is not in the candidate list, or is not eligible, **stops the run and says so**. It
never falls back to an automatic choice: the predecessor fell back silently, so a mistyped hostname
produced a successful run against a controller the operator did not name, with nothing recording the
substitution.

### Preflight

Four questions of each domain's pinned controller: whether a connection can be made and **on which
rung**, whether the credentials bind, whether that controller genuinely serves that partition, and
whether the Password Settings Container can be read. Every domain is asked before any answer is
allowed to stop the run.

**Domains are preflighted in parallel.** The rule that protects a customer is one request in flight
*per controller*; preflight touches N different machines with one request each, so nine domains take
about ten seconds rather than ninety.

*Already built - `Preflight`, `PreflightReport`, `PreflightFile`. It takes a plan as an argument and
does not care where the plan came from, so it needs no change beyond being handed the new one.*

### Leaving a domain out

A domain can be excluded, and **an exclusion cannot exist without a posture**:

- **Attested empty** - nothing in it holds or could hold privilege elsewhere in the forest.
  Falsifiable, and checked after the capture.
- **Attested populated** - there is plenty in there and it is being excluded anyway. Nothing to
  check; the point is conceded.

An included domain needs no attestation. Selecting a domain that failed preflight is refused: fix
it, or exclude it with a posture.

**A domain the forest names no controller for is treated the same way.** Nobody chose to exclude it
- an orphaned cross-reference or a failed demotion - but proceeding silently would seal a bundle
missing an entire domain with no human statement attached. The operator attests to it, and it is
recorded as a finding about the forest as well.

### The remaining steps

What to capture; whether to scan SYSVOL for stored Group Policy passwords; then review and begin,
listing the excluded domains and their postures.

**There is no "how much load can the controllers take" step.** A per-controller queries-per-second
dial moves nothing when only one request is ever in flight against a controller, and a setting that
reads as a lever over production impact and is not one is worse than no setting.

### The run

Before any capture traffic, `preflight.json` records per domain: the candidate list in ranked order,
which controller was pinned, whether the pin came from ranking or from an operator, the connection
rung reached, and whether the Password Settings Container was readable. It exists before the
evidence database does, so a run that dies overnight still explains itself.

Then capture. **Configuration and schema first, complete before any domain starts** - everything
else is interpreted against them. **Then the domains in parallel**, one request per controller,
writes funnelled through the single bundle writer.

A domain's controller is fixed for the whole of one attempt. If an attempt dies, that domain
restarts from the beginning on the next controller in its failover list and everything the failed
attempt wrote is discarded: one domain, read once, whole, from one controller, with no stitching. An
exhausted list ends the run.

### Afterwards - checking the claims

Every group's member list is resolved against what was captured, and each member that does not
resolve is classified: in a domain this run did not capture, in another forest across a trust, a
dead identifier left by a deleted object, or something that should have been readable and was not.

Then every **attested empty** domain is tested: a member belonging to it falsifies the claim. The
run is marked degraded and the bundle names the domain and the exact members that contradict it. The
original statement stays on the record beside what turned out to be true, rather than being
rewritten.

**Attested populated** domains are not tested. The point was already conceded.

---

## 3. What is already decided - do not re-open

Each of these was settled and then re-derived from scratch in a later session. Cite them; do not
re-argue them.

| Subject | Record | What it settles |
| --- | --- | --- |
| Parallel capture | `0041` | Domains read in parallel, one request per controller, config and schema first, writes serialised, no operator switch |
| Candidate list | `0050` | From the configuration partition, not DNS SRV; RODC excluded structurally; ranking same-site then lexical; site from `subnet` objects; a bad override stops the run |
| Scope | `0052` | The domain is the only unit of scope; exclusion carries a posture; a failure is never recorded as a decision |
| Preflight | `0048` | The four questions, all domains answered before any stops the run, `preflight.json` written before capture |
| Connection | `0018` | The ordered ladder, and that a controller nothing answered from has no rung |
| Failure and retry | `0040`, `0003` | A failed domain restarts on the next controller; nothing of a failed attempt survives; an exhausted list ends the run |
| Unmeasured claims | `0002` | Absence is never rendered as a fact about the directory |

**Two things are decided but have no record yet, and one is owed:**

- **Automatic bootstrap.** The tool finds its own forest; a typed hostname is a fallback. Decided by
  the owner 2026-08-15. `0050` assumed a typed name in passing while deciding something else, and
  says plainly that *DNS is used to bootstrap and to resolve, never to enumerate* - automatic
  bootstrap is that sanctioned use, not an exception to it.
- **A domain with no candidates is an attested exclusion.** Decided by the owner 2026-08-15. `0050`
  currently says the run records it and continues; that would seal a bundle missing a domain with
  nothing human attached to it.

---

## 4. Where the code currently contradicts a decision

**Read this before believing the code.** In each case the decision is right and the code is
outstanding work, not design.

- **`SerializedDirectoryAccessGateTests` fails the build on any fan-out shape** anywhere in the
  capture project, with an empty allowlist. `0041` requires parallel domains and says this guard is
  deliberately broader than the rule it holds. **Narrow the guard to code that touches a directory.
  Never exempt a file.**
- **`ServerLimits` describes serialisation as though it were global.** The rule is per controller.
  Its wording needs correcting or a reader concludes sequential capture is the design.
- **`ForestDiscovery` sets each domain's controller to the domain's own DNS name.** There is no
  selection, no site affinity, no candidate list. This is the line `0050` exists to replace.
- **`CaptureSession` takes a hostname** and reads every domain unconditionally. It needs a forest, a
  per-domain selection, and an exclusion set.
- **`CoverageId` does not account for exclusions.** Its own comment now says so. Without it, a run
  carrying an exclusion could be compared against a whole-forest one and the difference read as
  change in the directory.
- **`BundleWriter.ResolveParentGuids` writes `unresolved_reference` rows with the reason hardcoded
  to `DomainNotCaptured`.** Nothing classifies them. Every such row is a claim the product did not
  measure, and the same table is what an attestation is checked against - so a parent-container gap
  could falsely contradict an operator's posture, or falsely confirm one. **Fix this as part of the
  classification work, not after it.**

---

## 5. What exists and is reused unchanged

The connection ladder and its rungs; forest enumeration from cross-references; the whole preflight
pass, its report and its file; capture paging, retry and range handling; SYSVOL capture; the bundle
schema, writer and seal; the run library and run states.

---

## 6. What must be built

Bootstrap from the local machine. The `CN=Sites` read for controllers and subnets. Site
determination by longest-prefix match. Ranking including FSMO avoidance. The per-domain candidate
list and pinned selection. Override handling that fails loudly. Parallel preflight. The New Audit
wizard and domain table. Exclusion with attestation. Coverage identity accounting for exclusions.
Parallel capture and the narrowed guard. Failover between controllers. Group member resolution and
classification. The attestation verifier.

---

## 7. Build order

1. **Discovery and selection** - bootstrap, the `CN=Sites` read, site, ranking, candidate lists,
   override semantics. Closes ledger rows `A3`, `A4`, `A5`, and makes `0040`'s failover list real.
2. **Wire it into capture** - `CaptureSession` takes a forest and a selection; preflight is handed
   the new plan; the CLI's `--controller` becomes an override.
3. **Parallel preflight and capture** - narrow the guard first, then fan out.
4. **The wizard** - ledger row `A10`. The first point at which any of this is visible.
5. **Exclusion and attestation** - the posture type, its storage, coverage identity.
6. **Member classification and the verifier** - ledger row `B11`, and the `ResolveParentGuids` fix.

Steps 1 to 3 are invisible plumbing. If something on screen is wanted sooner, do 1, 2, 4 and defer
parallelism.

---

## 8. Owed

Two decision records: automatic bootstrap, and the no-candidate domain as an attested exclusion.
Both are short, and both amend a sentence of `0050` rather than replacing it.

Ledger rows `A3`, `A4`, `A5`, `A10` and `B11` all move on this work and none currently names a
binding test.

---

## 9. Delete on completion

The preflight entry sequence described in `S-37-preflight.md` - it describes `ValidateAsync`
discovering the forest from a typed hostname, which this replaces. The `CaptureSession` class
comment stating that a command line or window supplies the controller to start from. The
`--controller` help text describing it as the entry point rather than an override.

**A note on searching this repository:** `git grep` does not see untracked files, and decision
records `0048` to `0052` are currently untracked. Searching for them with `git grep` returns nothing
and looks like absence. Read the filesystem directly.
