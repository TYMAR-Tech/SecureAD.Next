# 0018 - Connection security is an ordered ladder of named rungs, and the bottom rung is declared rather than reached

Date: 2026-08-12
Status: Accepted. Amended 2026-08-16 by the amendment below - a rung that failed is not evidence
that the controller refused.

## Context

Everything this product ever says about a customer's forest crosses a network once, during capture.
Per [`0008`](0008-live-verification-is-removed.md) capture is the only stage that touches a domain
controller, and per [`0009`](0009-greenfield-in-place-with-the-bundle-as-seam.md) the bundle it
produces is the sole evidence anything downstream reads. So the connection is not one component
among many. It is the single point at which a customer's credentials and a customer's evidence are
both exposed, and it happens once per run with nothing afterwards that could detect a problem.

Two facts about the directory shape the answer, and both come from Microsoft rather than from
instinct.

**A simple bind on port 389 has no protection at all.** Not weak protection - none. Microsoft's own
account of LDAP session security is explicit: sessions on port 389 "that don't use TLS/SSL for a
simple bind: There's no security for these sessions. This is because credentials are transmitted in
clear text. Therefore, there's no secure key material to provide protection"
([LDAP session security settings and requirements after ADV190023 is
installed](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023)).
A tool that reads permissions on credential-bearing objects cannot arrive at a customer's domain
controller with the customer's own administrative password in the clear.

**A SASL bind that is signed is genuinely protected, without a certificate.** The same article:
"If LDAP sessions are signed or encrypted by using an SASL logon, the sessions are secure from
Man-In-the-Middle (MITM) attacks. This is because you can obtain the signing keys only if you know
the user password." That matters practically, because LDAPS is not available by default - it
requires a certificate meeting specific requirements installed on each controller
([Configure certificates for LDAP over SSL in Active Directory Domain
Services](https://learn.microsoft.com/windows-server/identity/ad-ds/configure-ldap-signing-certificates)),
and many forests do not have one. A product that insisted on LDAPS would refuse to audit a large
share of the forests that most need auditing.

**And the ground is moving in the right direction.** Windows Server 2025 and later requires LDAP
signing by default on new Active Directory deployments, and sets channel binding to "when
supported" ([LDAP signing for Active Directory Domain
Services](https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing)). On Windows
Server 2019 and earlier it is optional and controllers accept both signed and unsigned binds. So a
controller's answer to "will you accept a protected connection" varies across a real forest, and it
varies in a way that is itself worth reporting.

## Decision

### The rungs are a list, walked from the top until one answers

| Rung | What it is | Port |
|---|---|---|
| 1 | LDAPS - TLS established before anything is sent | 636 |
| 2 | Signed and sealed over Negotiate - integrity and encryption from the SASL layer | 389 |
| 3 | Signed over Negotiate - integrity only | 389 |
| 4 | Unprotected | 389 |

**It is a list and not a chain of branches.** A fourth rung, or a fifth, must be an entry added to a
list rather than an edit to every place that assumed there were two or three. The same reasoning
that makes a rule catalogue data rather than code, in
[`0010`](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md), applies here at a smaller
scale.

### Authentication is Negotiate, and simple binds are not on the ladder at all

There is no rung on which a credential crosses the wire in clear text, because there is no rung
that performs a simple bind. This is not a preference between two acceptable options; per the
citation above, one of them is not an acceptable option for this product.

### The bottom rung is never reached automatically

The ladder descends to an unprotected connection **only where the auditor declared, before the run
started, that this run is permitted to use one.** Where no such declaration was made, a controller
that will accept nothing better is a controller this run does not read, and the run fails saying so.

It is a declared allowance, not a fallback. The difference is the whole point: a fallback is
something that happens to a run, and an allowance is something somebody chose.

**There is no dialog at the moment of failure.** An audit tool gets scheduled. A run that blocks at
03:00 on a prompt nobody sees has done nothing by morning, and the operator arrives to a machine
waiting politely for an answer instead of a bundle. This is the same reasoning that made the retry
policy report rather than ask, recorded at [`S-10`](../next/S-10-politeness.md).

### The declaration is per run and is never remembered

It is not a setting, not a registry value, not a line in a configuration file. It is stated when a
run is started and it dies with the run.

A persisted setting is one somebody turned on once, for a reason that was probably good, and nobody
has thought about since - which is the shape of the container exclusion
[`0017`](0017-capture-reads-the-whole-forest.md) removed, and of the five capture settings with no
consumer that ledger row B1 refuses to carry. This product has already deleted a batch of levers
that were not levers. This one is a real lever, and it is pulled fresh each time.

### The rung that answered is recorded per domain controller, by name

Not a boolean. A boolean has nowhere to put a third state, and this ladder has four; adding a state
to a named list is additive, where splitting a flag is not. The record is per controller because
that is the granularity at which the answer actually varies.

### A controller that will not accept a protected connection is a finding about the customer's forest

Not merely a fact about our run. Microsoft's hardening guidance treats unsigned LDAP as something to
eliminate, and Windows Server 2025 requires signing by default on new deployments. This product is
standing right there when a controller declines, so it says so: *"three of your twelve domain
controllers would not accept a signed connection."*

That also keeps the allowance honest. Ticking the box produces a finding rather than silence, so the
easy path is not the quiet one.

### A run that used an unprotected connection is not presented as though it had not

Evidence gathered over a channel that could have been altered in transit is not the same evidence,
and per [`0002`](0002-absent-view-means-degraded-run.md) a difference of that kind is never rendered
away. Where the disclosure has to appear is the report, which is phase 3, so this decision creates an
obligation rather than a feature: it is registered against the ledger rows that will produce it,
where a future session reads it, rather than left as an intention in a document nobody opens.

## Consequences

**A capture can run against a forest with no LDAPS certificate**, which is most of them, and still
be protected - because rungs 2 and 3 need no certificate and are secure against a man in the middle
per the citation above.

**A customer learns something they did not ask for.** The ladder is a probe: walking it produces, at
no extra cost, a per-controller inventory of what each domain controller will accept. That is a
security finding a customer would otherwise pay for separately.

**An unprotected run is possible and is expensive to choose.** It requires a declaration before the
run, it produces a finding, and it marks the report. None of those can be turned off, and none of
them is a dialog anybody can click past at three in the morning.

**Nothing else in the product may open a connection or decide a security level.** One owner, held by
a build failure, for the same reason the referral policy has one owner: the correctness is invisible
at the point where it is lost, and a second place that opens a connection is a second ladder.

## Amendment, 2026-08-16: a rung that failed is not evidence that the controller refused

The clause above - *a controller that will not accept a protected connection is a finding about the
customer's forest* - is right, and it was being applied to walks that had established no such thing.
Every rung failure was caught as one kind of event, so a walk that failed for **any** reason ended
with the sentence *a controller accepting nothing signed leaves its LDAP traffic open to alteration
in transit*. A run whose password had expired therefore accused a customer's forest of a weakness on
the strength of a stale credential. That is `F-S35-1` reached from a new direction, and
[`0002`](0002-absent-view-means-degraded-run.md) forbids it.

**The finding requires an answer.** The ladder may describe what a controller accepts only where
something came back from that controller. A walk nothing answered reports that nothing answered -
that the name may not resolve, the host may be off, or a firewall may be in the way, and that from
here those look alike - and it makes no claim about the machine at all.

**Rejected credentials are a credential.** The controller answered and declined to authenticate. It
is not a network fault and not a weakness in the forest, and descending the ladder never had a
chance of changing it.

**An unclassified failure is treated as no answer, deliberately, and this is the part to leave
alone.** It is the conservative direction and it will look wrong to somebody later: a code nobody has
mapped will often *in fact* be the controller refusing something, and treating it as silence
understates what we know. That trade is made on purpose. The two mistakes are not equal - saying
less than we measured costs a line in a report, and saying more than we measured puts an accusation
about a customer's security posture in a document they will act on. So the unknown case says less,
and a new code earns its finding by being classified rather than by being assumed.

**What the ladder cannot tell apart.** A name that does not resolve and a host that is switched off
both arrive as the same protocol error. Separating them means resolving the name deliberately, which
is a further act against DNS and would need weighing against
[`0050`](0050-the-candidate-list-comes-from-the-configuration-partition.md), which permits DNS for
bootstrapping and nothing else. Not decided here; the message says the cases look alike rather than
guessing between them.
