# A — Connect & Discover

**Owns:** everything between "the app is open" and "we know which forest we are pointed at, which DC
we will talk to per domain, and whether those DCs will answer." It ends where capture begins.

## The flow

1. **Startup detection** establishes a home domain and a known-good DC.
2. `ServiceFactory.CreateSession` builds one `InfrastructureSession` — a single connection factory,
   DNS resolver, and DC topology manager shared by everything downstream.
3. `SeedHomeDomain(domainFqdn, dcHostname)` seeds that DC, so nothing pays for DNS discovery yet.
4. `DiscoverFailoverDcsAsync` runs fire-and-forget, so failover DCs become available shortly after.
5. Nothing further happens until the Security Audit dialog opens. Then
   `MainViewModel.DiscoverForestIntoViewModelAsync` calls `IForestDiscoveryService.DiscoverForestAsync`,
   receives a `ForestTopology`, and seeds every discovered domain DC back into the topology manager.
6. `ForestDcPreflightService` validates the selected domain/DC pairs before a long-running capture
   starts.

Step 5 is worth naming explicitly: forest discovery and live DC routing are two separate systems, and
`SeedFromForestTopologyAsync` is the bridge between them. Its own doc comment records the cost of not
bridging — 20–45 s of on-demand DNS per domain.

## Components

### A1 — Connection settings & auth mode
- **Layer:** Core
- **Owns:** the knobs for how the tool binds. LDAPS preference, signing requirement, connect and send
  timeouts, protocol version; and whether authentication is integrated or by explicit credential.
- **Implemented by:** `Core/Configuration/LdapConnectionSettings.cs`,
  `Core/Authentication/SavedCredential.cs`
- **Non-obvious:** the second file contains no `SavedCredential` type. See Naming §6.

### A2 — LDAP connection factory
- **Layer:** Infrastructure
- **Owns:** creating bound `LdapConnection`s, with credential handling, LDAPS-with-fallback, signing,
  and connection-security logging.
- **Depends on:** A1
- **Implemented by:** `Ldap/LdapConnectionManager.cs` (253), `Ldap/ILdapConnectionFactory.cs`,
  `Ldap/ConnectionSecurityLevel.cs`
- **Non-obvious:** the single choke point for all LDAP connections. Its summary states it is "shared
  infrastructure used by Browse, Capture, and Live." Nothing else constructs a connection.

### A3 — DC/GC name resolution
- **Layer:** Infrastructure
- **Owns:** turning a domain FQDN into DC hostnames, and a forest root FQDN into GC hostnames, using
  Windows-native AD locator APIs.
- **Implemented by:** `Ldap/DnsSrvResolver.cs` (227), `Ldap/IDcDnsResolver.cs`, `Ldap/IGcDnsResolver.cs`
- **Non-obvious:** results are cached with a 5-minute TTL, and the cache is load-bearing rather than
  an optimisation — `Domain.GetDomain` plus `FindAllDomainControllers` costs 20–45 s per call.

### A4 — DC selection policy
- **Layer:** Core (pure, no I/O)
- **Owns:** given a set of candidates, choose a primary DC and an ordered failover list.
- **Implemented by:** `Core/Discovery/DcSelectionPolicy.cs` (102), `DcCandidate.cs`, `DcCapability.cs`,
  `DcSelectionResult.cs`
- **Non-obvious:** selection is deterministic — same-site preference, then a capability filter
  (`Reachable | Writable`), then lexical sort. A manual override is honoured but still capability-checked,
  falling back to automatic selection if the named host does not qualify. Determinism here is what
  makes a capture reproducible.

### A5 — DC discovery
- **Layer:** Infrastructure
- **Owns:** resolving candidates, probing each one's capabilities over LDAP, and delegating the choice
  to A4. The I/O half of A4.
- **Depends on:** A2, A3, A4
- **Implemented by:** `Ldap/DcDiscoveryService.cs` (189), `Core/Services/IDcDiscoveryService.cs`

### A6 — DC routing & failover
- **Layer:** Infrastructure
- **Owns:** the session-wide answer to "which DC do I use for domain X right now," with failover.
- **Depends on:** A3
- **Implemented by:** `Ldap/DcTopologyManager.cs` (327)
- **Non-obvious:** re-discovery happens only when every known DC for a domain has failed — explicitly
  never on a timer. It also keeps a negative cache for domains that failed DNS resolution, and a
  per-domain lock so concurrent callers cannot trigger duplicate discovery.

### A7 — Forest topology discovery
- **Layer:** Core types + Infrastructure
- **Owns:** domains from the partitions container and from trust objects, GC servers from DNS SRV,
  trust classification, and forest-wide completeness validation.
- **Depends on:** A2, A3, A6
- **Implemented by:** `Ldap/ForestDiscoveryService.cs` + `.Helpers.cs` + `.Reachability.cs` (600 total),
  `Core/Discovery/{ForestTopology,DomainInfo,TrustInfo,TrustType,TrustDirection,GcServerInfo,ForestValidationResult}.cs`
- **Non-obvious:** all outputs are deterministic — lexically sorted by FQDN — given identical directory
  state. This is the denominator that `RunCoverageResolver` later measures coverage against, so its
  confidence matters well beyond this branch.

### A8 — Preflight validation
- **Layer:** Infrastructure
- **Owns:** proving the selected domain/DC pairs will answer, before hours of capture are committed to
  them.
- **Depends on:** A2
- **Implemented by:** `Ldap/ForestDcPreflightService.cs` (233), `Core/Discovery/ForestDcPreflightResult.cs`,
  `Core/Services/IForestDcPreflightService.cs`
- **Non-obvious:** bounded at 4-way concurrency with a 10 s timeout per pair. It is one of the few
  public types in the `Ldap` folder.

### A9 — Session composition root
- **Layer:** Infrastructure
- **Owns:** building the shared LDAP infrastructure once per session, handing it to every service, and
  bridging forest discovery into DC routing.
- **Implemented by:** `ServiceFactory.cs` (224 — contains both `InfrastructureSession` and the static
  `ServiceFactory`)
- **Non-obvious:** this is the composition root for the whole Infrastructure layer, not just for
  branch A. There is no DI container.

### A10 — Discovery UI
- **Layer:** UI
- **Owns:** the Security Audit dialog's discovery phase and its progress reporting.
- **Depends on:** A7, A9
- **Implemented by:** `ViewModels/ForestAuditViewModel.cs`, `ViewModels/MainViewModel.Audit.cs`
  (discovery portion), `Shell/ToolWindowLauncher.cs`

## Naming & taxonomy

### 1. `DnsSrvResolver` names the fallback, not the mechanism

Its own summary reads: "Uses Windows-native AD locator APIs (**DsGetDcName / DNS SRV fallback**)."
DNS SRV is what it does when the locator API does not work, yet it is the entire name. It also
resolves GC servers, which the name does not mention. The type it returns, `DcSrvRecord`, propagates
the same wrong assumption into every caller — those are locator results, not SRV records.

**Rename:** `DcLocator`, or `DirectoryLocator` given it covers GC as well. `DcSrvRecord` →
`DcCandidateRecord`, or fold it into `DcCandidate`.

**Why it matters:** anyone debugging a resolution failure starts at DNS, because the type told them
to. The actual failure is usually `DsGetDcName`.

### 2. `LdapConnectionManager` implements `ILdapConnectionFactory`

The class and its interface disagree about what it is, and the interface is correct. The interface
has exactly two members, `CreateConnectionAsync` and `CreateConnectionForDomainAsync`. It creates and
hands back; it does not own lifetime, dispose, or pool.

**Rename:** `LdapConnectionFactory`.

**Related defect in the doc comment:** `ILdapConnectionFactory` claims it "encapsulates connection
**pooling**." It does not — every call constructs a fresh connection. That is a stale comment
describing a design that either went away or never landed, and it invites callers to assume
connections are cheap.

### 3. "Topology" carries two unrelated meanings

- `ForestTopology` — domains, trusts, GC servers. A *description of the forest*.
- `DcTopologyManager` — which DC hostname serves domain X right now, with failover. A *routing table*.

The two are adjacent in the code: `SeedFromForestTopologyAsync` takes the first and populates the
second. That method name is currently the only thing signalling they are different concepts.

**Rename:** `ForestTopology` stays. `DcTopologyManager` → **`DcRouter`**. Routing is the entire job,
and the seed method then reads as "seed the router from the forest topology," which is exactly what
it does.

### 4. "Discovery" spans two altitudes without distinguishing them

`ForestDiscoveryService` answers "what domains exist?"; `DcDiscoveryService` answers "which DCs serve
this domain, and are they usable?"; and `DcTopologyManager.DiscoverFailoverDcsAsync` is a third use
of the word again.

**Rename:** `ForestDiscoveryService` stays — it genuinely discovers. `DcDiscoveryService` →
**`DcEnumerator`** (or `DcCandidateProbe`), because what it does is enumerate candidates, probe
capabilities, and delegate the decision to `DcSelectionPolicy`.

Combined with §3, this resolves the A5/A6 confusion at the level of the names themselves:
`DcEnumerator` (find them all) versus `DcRouter` (pick one, fail over) is self-explaining in a way
that `DcDiscoveryService` versus `DcTopologyManager` is not.

### 5. `InfrastructureSession` and `ServiceFactory` are too vague to place

Neither name indicates a layer or a concern, and both live in the same file. `InfrastructureSession`'s
own summary is precise where its name is not: "Shared **LDAP** infrastructure created once per session."

**Rename:** `LdapSession` (or `DirectorySession`), and `InfrastructureServices` or `ServiceComposition`.
Split into two files at the same time.

**Why it matters:** `ServiceFactory` is the composition root of the entire Infrastructure layer. A name
that generic is exactly where unrelated things accumulate, because nothing about it says what does not
belong.

### 6. `SavedCredential.cs` names a type that has never existed

`git grep "SavedCredential" -- src tests` returns zero hits. The file contains one two-member enum,
`AuthenticationMode`. A folder and a filename are named after a credential-persistence feature that
was designed and then not built — correctly, for a tool that never writes to the directory and holds
no secrets.

**Rename:** file → `AuthenticationMode.cs`, moved to `Core/Configuration` beside `LdapConnectionSettings`;
`Core/Authentication/` deleted.

### Watch-list

Recorded here so they are not rediscovered later, but they belong to branch B:

- `LdapAttributeHelper` and `LdapCaptureUtilities` — "Helper" and "Utilities" are the two names that
  reliably produce grab bags. Both need their contents read before renaming.
- `DirectCaptureModule` — "Module" does no work, and "Direct" implies a contrasting indirect capture
  that no longer exists.

## Would-do-differently

### 1. `Core/Discovery` is a grab bag

Four of its eighteen files are not discovery:

- `CapturedAttributeCatalog.cs` (293 lines, the largest file in the folder) defines which LDAP
  attributes are captured per object class. That is **Capture**, branch B.
- `ShardDefinition.cs` and `ShardResult.cs` are capture parallelism.
- `DirectoryTreeNode.cs` is live browsing, and goes away with sequencing item 4 of
  `docs/review/00a-product-identity.md`.
- `DnHelper.cs` (122 lines) is generic DN string manipulation used well beyond discovery.

**Ideal:** Discovery holds topology types only. The attribute catalog moves to Capture; `DnHelper`
moves to a shared directory-primitives location.

### 2. `Infrastructure/Ldap` does three unrelated jobs in one folder

- Connection and topology — A2 through A6, roughly 1,050 lines. This branch.
- Capture — `DirectCaptureModule.*`, roughly 700 lines. Branch B.
- Live diagnostics — `LiveDiagnosticsService.*`, `DirectoryTreeService`, `LiveSidResolutionService`,
  roughly 1,700 lines. Branch H, largely scheduled for deletion.

**Ideal:** three folders — `Ldap` holding connection primitives only, `Capture`, and `Live`.

Also in this folder but belonging to Capture rather than to connection: `DcRateLimiter` (per-DC token
bucket) and `OuFailureTracker`. Both are capture-run concerns.

### 3. Two DC-enumeration paths coexist, and the code knows it

`DcTopologyManager`'s remarks state: "Capture-time full DC enumeration still uses `DnsSrvResolver`
directly." So capture bypasses the routing layer entirely.

The split is defensible — capture wants every DC, routing wants one — but it means "which DC did we
use" has two answers depending on which subsystem is asking, and the distinction is implicit in which
type you happened to call.

**Ideal:** make it explicit in the names (see Naming §3 and §4). `DcEnumerator` and `DcRouter` cannot
be confused for each other; `DnsSrvResolver` and `DcTopologyManager` can.

### 4. Topology seed-back is fire-and-forget

`MainViewModel.Audit.cs:68` calls `SeedFromForestTopologyAsync(...).LogFailures(...)` without awaiting.
If seeding fails, discovery still reports success, and every subsequent cross-domain operation quietly
pays the 20–45 s DNS penalty the seed exists to avoid.

**Ideal:** await it, or surface the failure on the topology result. A performance guarantee that fails
silently is indistinguishable from one that was never made.

### 5. No DI container — a static factory plus a hand-rolled session object

For a WPF application of this size this is a live trade-off rather than an obvious mistake, but it has
a visible consequence: `MainViewModel` holds nullable service fields and guards them at each use
(`if (_forestDiscoveryService is null) throw`), rather than receiving them as constructor
dependencies that cannot be absent.

**Ideal:** make this an explicit decision in a rebuild rather than something inherited. If the answer
is still "no container," the session object should at least hand out non-nullable services.

### 6. Preflight is the right idea and should be load-bearing

Nothing to change — recorded because it is a good decision worth keeping. Validating DC reachability
before committing to a multi-hour capture is cheap (10 s timeout, 4-way concurrency) and prevents the
worst failure mode this tool has: discovering at hour three that a domain was never going to answer.

A rebuild should keep it, and should consider extending the same idea — cheap upfront validation of
expensive commitments — to disk space and to credential validity.
