# 0099 - The Tier 0 control-plane catalogue

Date: 2026-09-06
Status: Accepted.

Settles `P-85`. This is the record [0098](0098-a-control-edge-is-expected-or-unexpected.md)
condition 4 defers to. It settles the catalogue policy; it does not claim that the executable
catalogue or stage 6 is built.

## Context

**Two questions look like one and are not.**

1. Is compromise of this principal capable of compromising Tier 0?
2. Should the permissions this principal holds be treated as routine and hidden by default?

Microsoft's tier model answers the first. `0098` asks only the second. A principal can be
Tier 0-sensitive without every permission it holds being expected, and conflating the two is how a
control-plane catalogue quietly becomes a list of everything anyone ever called privileged.

**The asymmetry, which makes generosity the dangerous direction.** A principal left out produces
edges tagged unexpected, which are visible, countable and correctable. A principal put in produces
edges hidden by default. Being cautious costs noise an operator can see; being generous removes
evidence nobody knows to look for. Microsoft's own anti-pattern list warns that collapsing everything
into Tier 0 dilutes it. **Where the evidence is uncertain, this catalogue favours visibility.**

**What was verified before deciding**, because the two preceding sessions each found a punch-list row
whose premise was false:

- **The `CN=Keys` claim in `P-85` was confirmed, and section 12 of `SPEC-stage-6-control-edges.md`
  was corrected after recording it as not found.** Microsoft's [domain-wide schema
  updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates)
  operation 83 adds Full Control allow ACEs on `CN=Keys` for `domain\Key Admins` and
  `rootdomain\Enterprise Key Admins`, mask `(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Key Admins)`, which
  includes `WD` and `WO` and inherits. **The lab observation the spec proposed is not needed.**
- **At review time, ownership accepted principals this control-plane policy excluded.** Its
  identifier lists and protection fallback accepted Account Operators, Server Operators, Print
  Operators, Backup Operators and Replicator. This was an ownership policy, not an already-built
  control-edge catalogue. The reconciliation became P-140 and was implemented under `0107`;
  schema-scoped ownership followed under `0109`.
- **`BroadPrincipalCatalogue` implements `0098` condition 3** and needs nothing from this record.

## Decision

**The control-plane catalogue is the set of principals whose edges may be tagged `Expected`, and
nothing else. It is versioned, and the version is stored on every edge.**

Every entry declares **both** scopes, and an entry that does not declare an unrestricted capability
scope does not receive one (`AC-S6-14`):

- **Authority scope** - where the principal has recognised administrative authority.
- **Capability scope** - which capabilities are normal within that authority scope.

### Unrestricted capability scope, within the stated authority scope

| Entry | Authority scope |
|---|---|
| Built-in Administrator, RID 500 | its own domain |
| Domain Admins, RID 512 | its own domain |
| `BUILTIN\Administrators`, RID 544 | its own domain |
| Enterprise Admins, RID 519 | the forest |

### Restricted entries

- **Schema Admins, RID 518** - expected only for schema-administration capabilities against the
  schema naming context. **Membership does not make control over domain objects, accounts, groups or
  any other naming context expected.** Microsoft's
  [privileged-group reference](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
  names the forest-root built-in Administrator as its default member; the earlier claim of empty
  default membership was incorrect. Membership should be temporary for schema administration;
  an account improperly left in it must surface rather than be hidden.
- **SYSTEM, `S-1-5-18`** - its initially unspecified capability scope was settled by `0100`.
  It is a descriptor-native platform identity, not an ordinary catalogue administrator: expectation
  follows applicable ACEs naming it and transfers to nobody else. **No blanket forest-wide expectedness.**
- **Enterprise Domain Controllers, `S-1-5-9`** - expected only for the directory and replication
  capabilities a domain controller requires, within the forest. Not unrestricted.

### Not entries, and why

- **CREATOR OWNER, `S-1-3-0`** - never a control-plane entry, and **never resolved to a principal**.
  It is a placeholder describing who a holder will be on objects created later, not a holder. The
  product already decided this and says so in `ObjectPermissions`, `EffectiveAccessCalculator` and
  `WellKnownSidCatalog`, which classifies it with the role `Placeholder` against a Microsoft anchor
  test. An edge whose holder is a placeholder is **`Unknown` with reason
  `UnknownHolderIsPlaceholder`** - never `Expected`, and never `Unexpected`, because there is no
  principal to attribute it to. This is separate from an *owner* recorded as CREATOR OWNER, which
  `ObjectOwnershipReading` treats as a directory artefact rather than a person; that treatment stands.
- **krbtgt, RID 502** - absent deliberately. It grants nothing by membership. Its presence in
  `PrivilegedSidCatalogue` answers a different question, about SID history.

### Explicitly excluded

Account Operators (548), Server Operators (549), Print Operators (550), Backup Operators (551),
Replicator (552), Group Policy Creator Owners (520), Key Admins (526), Enterprise Key Admins (527),
Read-only Domain Controllers (521), Enterprise Read-only Domain Controllers (498), Domain Controllers
(516).

**Exclusion is not a claim of low risk.** Backup Operators and Server Operators remain Tier 0-sensitive
for classification and monitoring. Microsoft names them Tier 0 because obtaining their capabilities
can create a path to the identity control plane - which argues for watching them, and does not
establish that arbitrary DACL control, ownership, membership modification, credential control or
replication control held by them should be hidden as routine.

**Starting narrow is reversible; starting wide is not.** A restricted capability scope can be added
later on evidence. Widening after customers have run against a version that hid something changes
what past runs meant.

### The rules an implementer would otherwise guess at

1. **Control-plane membership is transitive**, consistent with `AC-49`. Distribution-only nesting
   never confers it (`AC-25`, `AC-26`).
2. **`sIDHistory` never confers control-plane membership** (`AC-S6-15`). It confers authorisation in
   Active Directory and `PrivilegedSidHistory` reports it as a finding; making it confer
   expectedness would hide the edges that rule exists to raise.
3. **A domain controller computer account is a Tier 0 asset and is not a control-plane entry.** Its
   edges surface. **Corrected under [0112](0112-shared-tier-0-classification-and-ownership-contracts.md):**
   the earlier sentence excluded the Domain Controllers group as a Tier-0 object, contradicting
   0006. The group remains a core Tier-0 target under 0006; it is not itself a domain-controller
   computer and does not become an expected control-plane entry. Classification and expectedness
   remain separate.
4. **A group whose members are Tier 0 assets does not inherit expectedness from them.** A group of
   domain controllers is not a domain controller.
5. **Broad principals are never expected**, whatever else this catalogue says (`0098` condition 3).
6. **Controlling a Tier 0 object never makes the controller expected.** That is the escalation stage 7
   exists to find.
7. **Every expectedness result records a reason code and the catalogue version.** A changed answer is
   a changed version, not unexplained drift.
8. **Tier 0 asset classification and control-plane membership are separate concepts**, and remain so
   ([0006](0006-tier-0-and-expected-admin-are-separate-sets.md)).

### Key Admins and Enterprise Key Admins

Both are excluded. The `CN=Keys` grant is real, documented and includes altering permissions and
ownership within that container - but **`CN=Keys` holds key credential objects, not accounts**, and
control of it is not administrative authority over a domain. Microsoft themselves reduced it:
operation 89 deletes the Enterprise Key Admins Full Control ACE and replaces it with an
object-specific write on `msDS-KeyCredentialLink`.

So the product surfaces as unexpected: control over `msDS-KeyCredentialLink`, control over `CN=Keys`
and its descendants, and any unrelated capability either group holds elsewhere.

A follow-on rule candidate is filed separately: **the legacy Enterprise Key Admins Full Control ACE
still present on `CN=Keys` where the applicable domain update should have replaced it.** That rule
must read the domain-update state before calling the ACE stale, or it will report a supported
configuration as a defect.

### AD CS and AD FS

**Enterprise certification authorities are classified automatically**, from `pKIEnrollmentService`
objects in the Enrollment Services container of the configuration partition, which capture already
reads in full. The directory evidence, including the CA host recorded on the enrollment service
object, is retained as the classification basis. This is evidence-based classification of an object
the directory names, not inference from a server name.

**AD FS is classified only by explicit declaration.** Nothing in Active Directory reliably marks an
AD FS server, and the product will not infer one from service accounts, naming conventions or service
principal names. Naming a server as AD FS on a guess would be the product telling a customer
something false.

The asymmetry runs the other way here because **this concerns assets, not principals**: an
automatically discovered CA adds a target to watch. It does not make control of that target expected
and it suppresses nothing.

### Customer-declared Tier 0

**Assets may be declared. Principals may not.**

A declared Tier 0 asset is added to the set of targets requiring Tier 0 attention, and may affect
prioritisation, display order and reachability analysis where separately specified. It **does not**
make any principal controlling it expected, does not suppress any edge, and does not expand anyone's
authority or capability scope.

**It does not affect severity.** Severity belongs to the rule and the customer cannot move it
([0066](0066-a-finding-is-called-a-finding.md),
[0082](0082-the-rule-catalogue-is-not-customer-tunable.md)); a declaration that raised severity would
be the same mechanism pointed the other way, and would make two identical directories produce
different findings.

Declaring a principal would make the product's conclusions depend on local configuration rather than
on captured evidence and a versioned catalogue. The legitimate need behind it - *this particular edge
is fine here* - is served by **accepting the finding**, which is specific, attributable, reviewable,
reversible and on the record, one edge at a time.

## Consequences

- **Stage 6 has an accepted policy to implement.** The executable catalogue, its stored version
  and control-edge expectedness remain unbuilt; a decided policy is not a running comparison.
- **Ownership reconciliation is implemented.** `0107` removed the five operators from accepted
  ownership by both identifier and membership; `0109` added the separate schema-only answer.
  CREATOR OWNER and SYSTEM remain accepted owners for their documented platform/placeholder reasons.
- **One versioned catalogue, with each entry declaring which question it answers.** Ownership under
  `0095`, expectedness under `0098` and SID-history privilege are three different questions, and
  `PrivilegedSidCatalogue` deliberately includes principals this record excludes. A single flat list
  serving all three would be a regression; a single catalogue whose entries are scoped per consumer
  makes divergence a test failure instead of a screen-specific behaviour.
- **Exclusions preserve visibility, not a promised count.** Their control-edge impact must be
  measured by P-145 once stage 6 produces output. The separate ad.lab five-operator ownership
  comparison produced no new findings; that neither proves the catalogue policy nor predicts
  another forest's volume.

## Follow-up status

- **SYSTEM's policy is settled by `0100`.** Its stage 6 implementation remains future work.
- **P-145 measures consequences, not whether the lab agrees with the exclusions.** The exclusions
  are a product decision; planted cases and exploratory counts must expose classification and
  presentation failures after control-edge output exists. The lab cannot prove the policy by
  agreeing with labels the policy itself supplied.
- **Ownership now has direct, downstream, persistence and lab coverage.**
  `ObjectOwnershipReadingTests` names the predicate outcomes; `ObjectOwnershipRuleTests` exercises
  both rules. The compatibility test still compares against the repository's written-out `0099`
  set and must be retargeted when the real control-plane catalogue is built. It is not independent
  evidence that either side matches Microsoft.
- **Automatic CA classification and asset declarations remain unbuilt**, on P-142 and P-143.
  The decisions above are requirements for those features, not a claim that the features exist.
