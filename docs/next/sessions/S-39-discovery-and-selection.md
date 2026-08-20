# S-39 — Discovery and controller selection

**Produces:** `docs/next/S-39-discovery-and-selection.md`.
**Governing records:**
[`0050`](../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md),
[`0053`](../../decisions/0053-the-tool-finds-its-own-forest.md),
[`0054`](../../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md).

This is session 1 of five planned in [`S-38`](S-38-the-new-audit.md) § 7.

## State — run and complete, 2026-08-15

**This session is finished.** Its record is
[`../S-39-discovery-and-selection.md`](../../history/S-39-discovery-and-selection.md), which is the document to
read rather than this section. What follows is a summary and a handoff, and it is discussion rather
than authority: where it disagrees with the code, the code wins.

**Built, and each guard mutation-proved in both directions.**

- The owed decision records `0053` and `0054`, with `0050` corrected in place at the two paragraphs
  they change. A third record was owed and not foreseen:
  [`0055`](../../decisions/0055-the-pdc-emulator-is-established-at-preflight.md).
  `docs/DECISIONS.md` regenerated from 55 records.
- `CaptureSearchRequestFactory.ForSiteTopology`, `.ForSubnets` and `.ForRoleOwner`.
- `ForestTopology` — the `CN=Sites` read, with RODCs excluded structurally.
- `OperatorSite` — the operator's site by longest-prefix match, null where nothing matched.
- `ForestRoles` — operations master roles. `ForestController` gained `DirectoryServiceDn`, without
  which a role holder cannot be matched to a candidate.
- `ControllerSelection` — ranking, pinning, the failover list, and override handling that stops the
  run.
- `ForestBootstrap`, `IMachineDomain`, `MachineDomain` — entry from the machine's own domain name.
- 50 tests across five classes. Whole of `SecureAD.Next.Tests`: **1082 passed, 0 failed**, from 1052.

**What the specification got wrong.** `S-38` says a domain's PDC emulator *"costs one base read per
domain"*. It costs a base read **and a connection** per domain, because a controller does not hold
another domain's naming context head and referral chasing is off. Settled by `0055`: the forest
roles are read at discovery, and the PDC emulator is established during preflight, where a
connection to each domain already exists.

**Carried into session 2, and it is the reason this work exists.** Nothing yet keeps an audit off a
PDC emulator. `ControllerSelection` will pin one whenever the run has not established which
controller that is - at the end of discovery, every domain. It reports this through `IsComplete` and
no consumer acts on the report. The re-pin `0055` requires needs preflight, so it lands in session 2
together with the wiring: `CaptureSession` still takes a host name, and `ForestDiscovery` still sets
each domain's controller to the domain's own DNS name.

**Decisions taken while building, which are not to be re-derived.**

- The discovery types are **public**. The rebuild uses no `InternalsVisibleTo` anywhere, so an
  internal type cannot be tested, and these are peers of the already-public `ForestDiscovery`. All
  are entered in [`../SURFACE-REGISTER.md`](../SURFACE-REGISTER.md).
- The topology and subnet reads are **paged**. An unpaged read is safe from silent truncation
  because `LdapDirectoryChannel` throws on any non-success result code - but that turns a large
  forest into a run that cannot plan itself at all, rather than one that plans itself correctly.
- `OperatorSite` and `ControllerSelection` read nothing. Keeping the arithmetic apart from the
  directory access is what lets every ranking rule be exercised without a directory.
- A bootstrap name that does not answer is **reported, not retried under the other form**. Falling
  through from the DNS name to the NetBIOS name would report the second failure as though it were
  the first attempt.
- Error codes are qualified by category, so an assertion reads `Capture.SiteTopologyCouldNotBeRead`.

**Findings** are recorded as `F-S39-1` to `F-S39-5` in the slice document. `F-S39-1` is open and
outlives this session: `SessionCompletionTests`, which
[`README.md`](README.md) describes as a build-failing guard over this folder, **does not exist
anywhere in the repository** - `git ls-files "*SessionCompletion*"` returns nothing - and
`SessionPromptTests` governs `docs/review/README.md` only. No prompt has ever been machine-checked.

## Scope

**In.** Everything that decides *which controller a domain is read from*, and nothing that reads a
domain.

- Bootstrap from the local machine: the machine's own domain suffix, falling back to its NetBIOS
  domain name, opening the first connection to the **domain name** rather than a host, and taking
  `rootDomainNamingContext` from the RootDSE it answers with. A typed name remains as the fallback.
- The `CN=Sites` read of the configuration partition: every `nTDSDSA` object in the forest, the
  writable naming contexts it declares in `msDS-hasMasterNCs`, its site from the position of the
  object in the tree, and its `dNSHostName` from the `server` object above it.
- The operator's own site, by matching the machine's addresses against the `subnet` objects in the
  same partition and taking the longest prefix. A machine matching nothing has **no site
  preference** and says so.
- FSMO role holders — the forest roles from the configuration partition, and each domain's PDC
  emulator from its naming context head.
- Ranking and selection: same site, then no FSMO role, then lexical by host name. The first is
  pinned; the rest are that domain's ordered failover list.
- Override handling: a named controller that is not an eligible candidate for that domain **stops
  the run and says so**, and never falls back to the automatic choice.

**Out, deliberately.**

- Wiring any of this into `CaptureSession` or `Preflight`, and the CLI plan-preview command. That is
  session 2.
- Parallel preflight, parallel capture, the fan-out guard and `ServerLimits`. Session 3.
- Exclusion, attestation postures and coverage identity. Session 4. `0054` is cited here because it
  governs what a no-candidate domain *means*, but nothing in this session collects an attestation.
- Group member classification and the verifier. Session 5.
- The New Audit wizard. Session 6.

Discovery **contacts nobody** beyond the bootstrap connection and one base read per domain for the
PDC emulator. If the PDC read turns out to cost a connection per domain, that is a finding and the
FSMO rank becomes best-effort rather than required — it is not quietly dropped.

## Read first

- [`S-38-the-new-audit.md`](S-38-the-new-audit.md) — the specification this session builds from,
  §§ 2, 3, 4, 6, 7.
- [`../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md`](../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md)
  — the candidate list, the ranking, RODC exclusion, override semantics. Note the two corrections
  dated 2026-08-15.
- [`../../decisions/0053-the-tool-finds-its-own-forest.md`](../../decisions/0053-the-tool-finds-its-own-forest.md)
  — automatic bootstrap, and that the bootstrap controller is never pinned.
- [`../../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md`](../../decisions/0054-a-domain-with-no-candidates-is-an-attested-exclusion.md)
  — what an empty candidate list means.
- [`../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md`](../../decisions/0040-a-failed-domain-is-read-again-from-another-controller.md)
  — the failover list this session makes real.
- [`../../decisions/0002-absent-view-means-degraded-run.md`](../../decisions/0002-absent-view-means-degraded-run.md)
  — why *no site* is a value and not a default.
- [`../S-2-distinguished-name-manipulation.md`](../S-2-distinguished-name-manipulation.md) — the
  existing distinguished-name helpers, which the site derivation must use rather than add a fourth
  way to ask the same question.
- [`../S-14-the-connection.md`](../S-14-the-connection.md) — the connection ladder the bootstrap
  connection walks.
- [`../README.md`](../README.md) §`Tests`, §`Gates`, §`When a document counts as documentation`.

## Rules

- §`Tests` and §`Gates` of [`../README.md`](../README.md) bind this session, including the scanner
  self-test every gate carries.
- Selection is **pure logic over data already read**. It opens no connection and performs no name
  resolution, so it is testable without a directory. Anything that needs the machine or the network
  sits behind a narrow seam and nothing else acquires an abstraction for the sake of it.
- **Nothing guesses a site.** A machine matching no subnet has no site, and that is carried as a
  value through ranking and into whatever records the run.
- **An RODC is excluded structurally**, by filtering on `msDS-hasMasterNCs`. No capability probe is
  added, and a second refusal is not written.
- New types are `internal` unless a caller outside the assembly needs them, per the least-exposure
  rule.
- `ForestDiscovery`'s existing line — each domain's controller set to the domain's own DNS name —
  is replaced, not wrapped.

## Finish by

- The solution builds and the affected test projects pass.
- Site derivation, subnet matching, ranking, pinning, failover order and both override failure modes
  each have a test that fails when the behaviour is broken, proven in both directions.
- `docs/next/S-39-discovery-and-selection.md` is written, recording what was built, what was found,
  and anything the specification got wrong.
- Any disagreement found between a document and the code is recorded as a finding rather than
  quietly repaired.
