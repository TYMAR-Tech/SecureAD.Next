# 0099 - The Tier 0 control-plane catalogue

Date: 2026-09-06
Status: Accepted.

Settles `P-85`. This is the record [0098](0098-a-control-edge-is-expected-or-unexpected.md)
condition 4 defers to, and the last thing gating stage 6.

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

- **The `CN=Keys` claim in `P-85` is true, and section 12 of `SPEC-stage-6-control-edges.md` is wrong
  to record it as not found.** Microsoft's [domain-wide schema
  updates](https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/domain-wide-updates)
  operation 83 adds Full Control allow ACEs on `CN=Keys` for `domain\Key Admins` and
  `rootdomain\Enterprise Key Admins`, mask `(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Key Admins)`, which
  includes `WD` and `WO` and inherits. **The lab observation the spec proposed is not needed.**
- **The product already ships a control-plane list that disagrees with the working position.**
  `ObjectOwnershipReading.AdministrativeSids` and `AdministrativeRids` decide when an owner is
  administrative and therefore not reported - `0095` in running code - and they include Account
  Operators, Server Operators, Print Operators, Backup Operators and Replicator. The brief's claim
  that *nothing but `P-85` says what the control plane is* was wrong. Reconciling the two is a
  finding this record creates.
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
  any other naming context expected.** Its default membership is empty; an account improperly left in
  it must surface rather than be hidden.
- **SYSTEM, `S-1-5-18`** - expected only where the stored security descriptor names SYSTEM directly
  and the authority context is established. **No blanket forest-wide expectedness.** Its capability
  scope must be written out concretely before stage 6 computes anything - see *What remains open*.
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
   edges surface. This follows the settled 516 ruling, which named the computer account as the Tier 0
   object and the group as not one, and it is stated here so that the first run's replication edges
   are a decision rather than a surprise.
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

- **Stage 6 can compute expectedness.** `UnknownControlPlaneCatalogueIncomplete` now has a version to
  compare against rather than an unanswered question.
- **`ObjectOwnershipReading` must be reconciled**, or the product answers the same question two ways
  on two screens. Account Operators, Server Operators, Print Operators, Backup Operators and
  Replicator come out of its administrative list; CREATOR OWNER and SYSTEM stay, for the stated
  reason that an owner is not a holder.
- **One versioned catalogue, with each entry declaring which question it answers.** Ownership under
  `0095`, expectedness under `0098` and SID-history privilege are three different questions, and
  `PrivilegedSidCatalogue` deliberately includes principals this record excludes. A single flat list
  serving all three would be a regression; a single catalogue whose entries are scoped per consumer
  makes divergence a test failure instead of a screen-specific behaviour.
- **The first runs will show more, not less.** That is the intended direction: removing a principal
  from this catalogue increases visibility and never removes evidence.

## What remains open, and is not settled by this record

- **SYSTEM's capability scope is not yet written out.** `S-1-5-18` appears with full control in the
  default descriptor of very nearly every object in Active Directory. Under `AC-S6-14` an undeclared
  capability scope is not unrestricted, so every one of those becomes unexpected and the default
  screen shows a number in the tens of thousands - the failure `0098` exists to prevent, arriving as
  the conservative choice. This must be concrete before stage 6 computes anything.
- **The anchor for the exclusions.** Microsoft's pages anchor the AD CS discovery; `ad.lab` must
  anchor the operator-group exclusions. A catalogue, tests matching the catalogue and a document
  matching the tests is a closed loop with no external reference - the shape of `F-S44-2`.
- **Whether `ObjectOwnershipReading` is covered at all.** No test in the tree names the
  `OwnerIsAdministrative` outcome directly. The reconciliation must not be scheduled on the
  assumption that the suite will catch a mistake in it.
