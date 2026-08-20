# Design — what makes a finding

**Status: proposed, 2026-08-13. Nothing here is decided and nothing is built.**

This document defines one concept — **expected** — that the product currently expresses nineteen
different ways in code and 286 different ways in prose.

It is derived from [`docs/rules/`](../rules/README.md), not from the previous application's code.
That direction matters: every earlier attempt to describe this product's shape was written by
reading the old database schema, and produced conclusions the code later contradicted. The rule
catalogue is the product's *intent*, held as data by
[`0010`](../decisions/0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md), which makes it the
one place the product's purpose is recorded rather than implemented.

**This describes the spirit of the rules, not what their code currently does.** The cards themselves
already draw that line — several exclusions are marked *"(Implicit, not enforced by code)"* with an
`[IMP-*]` tag against the gap. Where the two disagree, this document follows the card, because the
card is the intent and the code is the approximation. Closing those gaps is separate work, and the
cards already name most of them.

---

## What the product is

Sixty-two rules. **Fifteen of them are the same sentence with a different verb:**

> *Unexpected* Principal can DCSync · Reset Admin Password · Write DACL · Write Owner ·
> Add Members to Admin Group · Configure RBCD · Write SPN · Enroll Certificates · Modify GPO ·
> Create GPO Links · Modify GPO via SYSVOL · Read LAPS Passwords · Control a Container ·
> High-Impact Right on a Tier-0 Target · GenericAll on the Domain

So:

> **Someone who should not be able to do something powerful, can.**

A directory is full of permissions. The audit is not finding permissions — it is finding the
**surprising** ones. Every word of that sentence is mechanical except *should not*, and *should not*
is the whole product.

## The three shapes a rule takes

Read as a set, the catalogue contains three different kinds of statement. They are currently modelled
as one, and they have genuinely different needs.

| Shape | Count | What it asserts | What it needs |
|---|---|---|---|
| **Capability** | ~35 | *this principal can do this to that* | principals, capabilities, expectation |
| **State** | ~19 | *this object is configured dangerously* | object attributes. **No graph at all** |
| **Path** | 8 | *this chain of capabilities reaches a tier* | the graph |

The **state** rules — Kerberoastable, AdminCount without protection, LAPS missing, non-expiring
password, duplicate SPN, disabled privileged account, circular group membership — need no edges, no
paths, and no reachability. About a third of the product can be computed correctly from captured
attributes alone, and should not inherit the failure modes of machinery it does not use.

---

## The primary rule: a finding is a difference

The catalogue states this itself, in the strongest language it uses anywhere. Two cards reject an
exclusion on the grounds that including it would be:

> *"a **tautology** and noise"*

and the reason given is:

> *"Custom accounts that are transitive members of tier-0 groups are equivalent to admins."*

Generalised, that is the rule the whole catalogue is reaching for:

> ### A capability is a finding only when it grants the principal power it does not already hold.

Domain Admins already holds everything, so nothing grants it anything, so it is never a finding —
automatically, with no list to maintain. The same is true of anyone transitively in Domain Admins,
including the custom group a customer created last year that nobody has told the tool about.

**Why this matters more than it looks.** Today this is approximated by lists of well-known relative
identifiers — `500, 502, 512, 516, 518, 519, 520, 521, 526, 527` — repeated across dozens of rules.
A list is a snapshot of who was powerful when someone wrote it. A comparison is true whenever it is
asked. Add a group to Domain Admins and the noise stops on its own.

It also explains a defect found separately. `S-22` records that a customer's own Tier 0 policy never
reaches the escalation search. That is not really a wiring mistake — it is what happens when *who is
powerful* has nineteen owners and someone updates one of them.

---

## The five gates

A candidate finding must pass five tests. They are currently fused into predicates like `IsAdminSid`,
which is why that one function ends up meaning several unrelated things.

Only gates 4 and 5 are about *expectation*. Gates 1 to 3 are about whether the finding is **real**,
and they are the ones most often mistaken for it.

### 1. Live — can this be attacked at all?

A deleted or tombstoned object cannot be used against anyone.

> *"A tombstoned principal cannot be authenticated against and is not a viable misconfiguration."*
> *"Tombstoned targets cannot host an attack; lingering ACE rows would be noise."*

Roughly twenty exclusion rows across the catalogue depend on this.

**This gate has an open question against it**, recorded in `S-22`: the rules suppress deleted objects
by reading a flag that `F-S20-1` says capture never populates. If that holds, these twenty
suppressions never fire and every rule promising to ignore tombstoned objects does not. **Verify
before porting any rule that relies on it.**

### 2. Effective — does the permission actually work?

A permission cancelled by a Deny grants nothing.

> *"Already neutralised at edge-derivation time; firing would be noise."*

Eight exclusions. Nothing to do with expectation: the capability does not exist.

`S-22` records that the old implementation only matches a Deny naming the principal *exactly*, so a
Deny naming a group is invisible. That is this gate failing, and it produces **false alarms** — the
most expensive kind of error this product can make.

### 3. Exploitable — is the attack worth anything?

Distinct from expectation, and easy to confuse with it. A group managed service account is not
*expected* to be Kerberoastable — it simply cannot usefully be Kerberoasted:

> *"gMSA passwords are 240-byte random values rotated by AD."*
> *"machine-account passwords are 120-char random and rotated; Kerberoasting is not economical."*

The judgement is about the economics of the attack, not about anyone's intent. It belongs to the
**capability**, not to the principal — and it changes when Microsoft changes a default, which is
exactly what [`FIRST-PARTY-VERIFICATION.md`](../rules/FIRST-PARTY-VERIFICATION.md) exists to track.

### 4. Trusted — does the principal already hold this power?

The primary rule above. Answered by comparison rather than by a list.

The inputs it needs are: the principal's transitive group memberships, and the power those
memberships already confer. Both are things the product computes anyway.

### 5. Warranted — is this expected for what this thing *is*?

The only gate that genuinely needs a maintained list, because it cannot be derived from anything.

A domain controller is expected to hold unconstrained delegation. That is not because a domain
controller is powerful — it is because that is how Kerberos works.

> *"Domain Controllers are expected to be TRUSTED_FOR_DELEGATION; flagging them is noise."*
> *"DCs always carry TRUSTED_FOR_DELEGATION; without the SERVER_TRUST_ACCOUNT carve-out every DC in
> the forest would generate noise."*

Crucially, a warrant is **per capability**, not per principal. A domain controller is warranted for
unconstrained delegation and for replication. It is not thereby warranted for everything.

---

## The warrant list, drawn from the cards

Everything below is extracted from existing exclusions. It is offered as a starting point to be
tuned, not as a finished catalogue.

| Who | Warranted for | Because |
|---|---|---|
| Domain controllers | unconstrained delegation | Kerberos requires it; `SERVER_TRUST_ACCOUNT` |
| Domain controllers | replication (`GetChanges` + `GetChangesAll`) | it is what replication *is* |
| `krbtgt` (RID 502) | holding an SPN; `adminCount=1`; being disabled | *"intentionally disabled by AD design and would always fire otherwise"* |
| `krbtgt` | cross-realm `krbtgt/REALM` duplicate SPNs | *"expected duplicates across trust topologies"* |
| KDC / Certificate Authority | writing `msDS-KeyCredentialLink` | the enrolment side of NGC |
| `Domain Controllers` (516), `Read-only Domain Controllers` (521) | `adminCount=1` | *"Expected protected identity"* |
| `SYSTEM`, `Local Service`, `Network Service`, `Creator Owner`, `Window Manager Group` | holding privilege | *"hold privileges by design"* |

And, as gate 3 rather than gate 5 — not warranted, but not exploitable:

| What | Not exploitable for | Because |
|---|---|---|
| gMSA, MSA | Kerberoasting | 240-byte random password, rotated by AD |
| Computer accounts | Kerberoasting | 120-char random password, rotated |

---

## What this replaces

Nineteen separately-named predicates currently answer some version of *"is this principal special?"*:

```
IsExpectedPrivilegedOwnerSid  IsBroadPrincipal          IsHighValueSid
IsExpectedServiceSid          IsBroadPrincipalSid       IsHighValueDn
IsPrivilegedPrincipal         IsBroadSidTargetTierZero  IsHighValueObjectClass
IsPrivilegedByMembership      IsBroad                   IsHighValue
IsPrivilegedGroupSid          IsAdminSid                IsTier0
IsPrivileged                  IsAdminCount              IsTier0Action
ExpectedAdminRids
```

```
git grep -oh "IsExpected[A-Za-z]*\|IsPrivileged[A-Za-z]*\|IsBroad[A-Za-z]*\|IsAdmin[A-Za-z]*\
\|IsTier0[A-Za-z]*\|IsHighValue[A-Za-z]*\|ExpectedAdmin[A-Za-z]*\|TransitivelyPrivileged[A-Za-z]*" \
  -- src/ | sort -u          # 19, measured at a2e0627d
```

The last two alternations are load-bearing: without them the command returns 18 and misses
`ExpectedAdminRids`, which is the one that does not begin with `Is`.

They have not all been read, so this document does not claim they disagree — only that the product's
central idea has nineteen owners, which gate 2 of the rebuild exists to prevent.

**One deliberate exception.** *Broad* principals — `Everyone`, `Authenticated Users`, `Anonymous` —
are not the same concept and must not be folded in. The cards are emphatic and consistent:

> *"An Authenticated Users → Tier 0 path is a Critical escalation, not noise — must surface."*

A broad principal is the opposite of expected. It stays its own idea.

---

## One thing this changes about a decision already taken

Two cards exclude inherited permissions, in identical words:

> *"Rule reports explicit, source-of-action grants; inheritance is the propagation of an upstream
> finding and would produce derivative noise."*

That is a product judgement and it is right: the fix is at the source, so reporting five thousand
inherited copies of one grant helps nobody.

The rebuild has separately decided to **store** inherited entries, because the escalation graph needs
them to find routes (`F-S20-14`). **Both are correct, and they are only compatible if kept apart:**

- the **graph** consumes inherited permissions, because a route is real however the permission arrived
- a **finding** reports the source grant, because that is where the fix is

If that distinction is not made deliberately, storing inherited entries will bury the findings in
precisely the derivative noise the cards were written to avoid. This is `F-S20-15`'s obligation
arriving from the product side, and it is sharper here than it was on the schema side: it is not
only *expected grants* that must be suppressed, but *propagated* ones.

---

## What is extracted and what is inferred

Stated plainly, because this document's value depends on it.

**Extracted from the cards** — the five gates, every quotation, the warrant list, the broad-principal
exception, and the inherited-permission judgement.

**Inferred by this document** — three things:

1. **That the five gates are five** rather than one. The cards apply them; they do not name them.
2. **That the primary rule is a comparison**, not a list. The cards say *tautology* twice and
   approximate it with relative identifiers everywhere else. Reading that as *"the list is a
   workaround for the comparison"* is a judgement, and it is the load-bearing one here.
3. **That `Exploitable` is separate from `Warranted`.** The cards treat gMSA exclusions the same way
   as domain-controller exclusions; separating them is this document's proposal, on the grounds that
   they change for different reasons and are maintained by different evidence.

If any of those three inferences is wrong, this document is wrong, and it should be argued with
rather than built on.

---

## Open questions for the owner

1. **Is the comparison the right primary rule, or is the list load-bearing for a reason not visible
   in the cards?** A comparison is self-maintaining but only as good as the membership closure behind
   it. If that closure is ever wrong or incomplete, the comparison silently over-suppresses — and
   over-suppression is invisible, where a stale list is at least inspectable.
2. **Should `Warranted` be customer-editable?** A customer with an unusual but deliberate
   arrangement — a delegated helpdesk tier, a third-party product with legitimately broad rights —
   currently has acceptances, which are per finding. A warrant is per capability and would suppress a
   whole class. That is more useful and more dangerous.
3. **Does `Exploitable` belong in the rules at all**, or is it a property of the capability
   vocabulary? *"A gMSA cannot usefully be Kerberoasted"* is a fact about Kerberos, not about any
   customer's directory, and repeating it per rule is how it drifts.
