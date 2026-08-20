# S-14 — The connection

**Type:** slice
**Inventory row:** A2 — LDAP connection factory
**Lands in:** `SecureAD.Audit`
**Implements:** [`0018 — Connection security is an ordered ladder of named rungs`](../decisions/0018-connection-security-is-an-ordered-ladder.md)
**Date:** 2026-08-12

---

## What this is, in one paragraph

This is the first thing in the rebuilt product that would reach a customer's domain controller. Every
other component either reads a file or was written against a model of one. This opens a socket,
decides how well protected the conversation is going to be, presents an identity, asks the controller
what it can do, and hands back the channel everything above it was built to use. It is the other
half of a seam [`S-12`](S-12-the-capture-passes.md) wrote and deliberately left open.

The code is [`LdapDirectoryChannelFactory`](../../next/src/SecureAD.Audit/Connect/LdapDirectoryChannelFactory.cs)
and [`LdapDirectoryChannel`](../../next/src/SecureAD.Audit/Connect/LdapDirectoryChannel.cs), with
[`ConnectionSecurityLadder`](../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLadder.cs),
[`ConnectionLadderWalk`](../../next/src/SecureAD.Audit/Connect/ConnectionLadderWalk.cs),
[`ConnectionSecurityLog`](../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs),
[`DirectoryConnectionSettings`](../../next/src/SecureAD.Audit/Connect/DirectoryConnectionSettings.cs)
and [`DirectoryCredential`](../../next/src/SecureAD.Audit/Connect/DirectoryCredential.cs) beside
them. `ConnectionDocumentationTests` holds this document to them. Per [`README.md`](README.md)
§When a document counts as documentation, this file is not documentation until that test holds.

## The failure this exists not to have

> **An audit tool that reads a customer's most sensitive permissions over a channel anybody on the
> path could read, or alter, and says nothing about it.**

Both halves of that matter and they fail differently.

**The credential.** Microsoft's account of a simple bind on port 389 is not that it is weak. It is
that there is nothing there: *"There's no security for these sessions. This is because credentials
are transmitted in clear text. Therefore, there's no secure key material to provide protection"*
([LDAP session security settings and requirements after ADV190023 is
installed](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023)).
An account able to read every permission in a forest is worth intercepting, and the tool that would
put it on the wire is one somebody deliberately pointed at their most sensitive systems.

**The evidence.** Everything this product ever says comes out of one bundle, and the bundle is what
one capture read. If that reading could have been altered in transit, so could every finding. That is
not a theoretical objection — an attacker who can alter LDAP responses can remove the entry that
names their own foothold, and the report says nothing is wrong.

So the answer is not a default that happens to be safe. It is a ladder, walked from the top, whose
bottom rung is out of reach unless somebody said otherwise before the run started.

## The ladder

Each row is a rung the code names. The table is held to
[`ConnectionSecurityLadder.Rungs`](../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLadder.cs)
in both directions and in order: a rung with no row fails the build, a row naming no rung fails it
too, and a row that disagrees with the rung about a port or an option fails it as well.

<!-- LADDER:BEGIN -->

| Rung | Port | TLS | Signed | Sealed | Declaration needed |
|---|---|---|---|---|---|
| Ldaps | 636 | yes | no | no | no |
| SignedAndSealed | 389 | no | yes | yes | no |
| Signed | 389 | no | yes | no | no |
| Unprotected | 389 | no | no | no | yes |

<!-- LADDER:END -->

**It is a list and not a chain of branches**, and that is the design decision rather than a detail
of how it happens to be written. The set of acceptable transports is decided by other people:
Windows Server 2025 and later requires LDAP signing by default on new deployments and sets channel
binding to "when supported", while Windows Server 2019 and earlier accepts both signed and unsigned
binds ([LDAP signing for Active Directory Domain
Services](https://learn.microsoft.com/windows-server/identity/ad-ds/ldap-signing)). It has changed
and it will change again. A fourth rung must be an entry added to a list rather than an edit to
every place that assumed there were three.

**LDAPS is first and is not required**, because it cannot be. LDAP over TLS needs a certificate
meeting specific requirements installed on the controller ([Configure certificates for LDAP over SSL
in Active Directory Domain
Services](https://learn.microsoft.com/windows-server/identity/ad-ds/configure-ldap-signing-certificates)),
and a great many forests have none. A product that insisted on it would refuse to audit a large share
of the forests that most need auditing.

**Rungs 2 and 3 need no certificate and are genuinely protected.** That is the load-bearing fact
this whole design rests on, and it is Microsoft's rather than an inference: *"If LDAP sessions are
signed or encrypted by using an SASL logon, the sessions are secure from Man-In-the-Middle (MITM)
attacks. This is because you can obtain the signing keys only if you know the user password."*

**No rung performs a simple bind.** Authentication is Negotiate on all four, so a credential never
crosses the wire in clear text even on the bottom rung. What is unprotected down there is the
evidence, not the password — and `ConnectionSecurityGateTests` fails the build if any authentication
type other than Negotiate appears anywhere in the tree.

**Nothing asks for both TLS and SASL protection.** They protect the same channel by two mechanisms,
and the platform's client rejects a connection that asks for both.

## The bottom rung is declared, not reached

> **A run descends to an unprotected connection only where somebody said, before it started, that
> this run may use one.**

[`UnprotectedConnectionAllowance`](../../next/src/SecureAD.Audit/Connect/UnprotectedConnectionAllowance.cs)
is that statement. It is a required argument of the factory rather than a defaulted one, so a run
that permits nothing has said so at the call site, and it carries the auditor's own words about why
— which travel into the finding it produces.

**There is no dialog at the moment of failure.** An audit tool gets scheduled. A run that blocks at
03:00 on a prompt nobody sees has done nothing by morning, and the operator arrives to a machine
waiting politely instead of a bundle. That is the same reasoning that made the failure policy in
[`S-10`](S-10-politeness.md) report rather than ask.

**It is never persisted.** Not a registry value, not a settings file, not a remembered checkbox. A
persisted allowance is one somebody turned on once, for a reason that was probably good, and nobody
has thought about since. This product has already deleted a batch of settings for being levers that
were not; this one is a real lever and it is pulled fresh each time.

**Declaring it does not buy silence.** A controller that accepts nothing better is a finding either
way, and a run that used the bottom rung says so on its report. The allowance decides whether the run
proceeds, not whether it discloses. Both obligations are registered against the inventory rows that will
carry them out — F-S13-1 on E1 and F-S13-2 on I3 — rather than left as an intention here.

## What comes back out, and why it is a level rather than a flag

[`ConnectionSecurityLog`](../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs) records,
per domain controller, which rung answered and how many better ones it turned down first.

A boolean has nowhere to put a third state and this ladder has four. Worse, the two questions a
boolean would conflate are asked by different readers: *was our evidence protected* is about the run,
and *would this controller accept a signed connection* is about the customer's forest. The second is
a security finding they would otherwise pay for separately, and walking the ladder produces it at no
extra cost, because a capture has to connect to every controller it reads from anyway.

**The log also carries its failures**, and that is not bookkeeping. Without them, a run in which
nothing was unprotected and a run in which nothing was reached both leave the list of unprotected
controllers empty, and a reader cannot tell *"we looked and found nothing wrong"* from *"we never got
to look"* — the distinction [`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids
collapsing. Gate 4 is what made this get written: it fired on the first version of this type, and it
was right.

## The seam survived contact, and that is worth saying

[`S-12`](S-12-the-capture-passes.md) wrote `IDirectoryChannel` from the loop's side, against a
controller model, with nothing real on the other end. This row is the first thing to meet it from the
other direction, and the question of whether it would hold is the cheapest it will ever be to answer:
one consumer, one implementer.

It held, unchanged. Every member maps onto something a live connection actually has:

| What the seam asks for | Where it comes from |
|---|---|
| The referral policy in force | Read back off the live session options, never remembered from what was set |
| Whether the capability list was really read | Whether the RootDSE answered with any advertised control at all |
| The controls the controller advertises | `supportedControl` on the RootDSE |
| A page, in three states | Whether the response carried a paging control, and what was in it |

One thing was added rather than changed. The RootDSE answer also carries `namingContexts`, which is
what confirms a controller actually serves the partition a unit names, so the channel exposes it. It
arrives in the same round trip and costs nothing extra; what asks the question is inventory row A8.

**The request for it is built by the search-request factory**, not here. That is the one-place rule
from [`S-9`](S-9-the-capture-unit.md) applying to a request nobody had needed yet, and it is the
right answer rather than a formality: the RootDSE read happens on the same connection as everything
else, and a second builder would be a second referral policy.

## What is guarded, and what is not

`ConnectionSecurityGateTests` holds four things:

- **One place opens a connection.** A second is a second ladder, and nothing later in a run could
  notice they disagreed.
- **One place decides how protected a channel is.** The level is reported and recorded afterwards,
  never adjusted.
- **Nothing binds with anything but Negotiate**, anywhere, including inside the factory.
- **The rung list and the level enumeration are the same set, in the same order.** A rung added to
  one and not the other would leave the product climbing one ladder and reporting another — and the
  reporting half is what a customer reads.

It was mutation-tested in four directions, each confirmed present in the source before the run was
believed, and each reverted.

| # | Mutation | Expected | Observed |
|---|---|---|---|
| 1 | A connection opened, a transport option set and a non-Negotiate bind added to a file that is not the factory | The three boundary checks fire | All three fired |
| 2 | The bottom rung deleted from the list | The ladder and the enumeration disagree | Both the list check and the scanner self-test fired |
| 3 | The factory stops setting `Sealing` | The self-test's floor on what the factory contains fires | Fired |
| 4 | The factory file renamed, so the exemption matches nothing | The self-test fires rather than the checks passing against an unguarded tree | The self-test fired, and both boundary checks fired with it |

**What no test here reaches is the connection itself.** There is no domain controller in a build
agent, so nothing exercises the bind, the TLS handshake, or a real controller's refusal. That is
stated rather than glossed, and it is the same split [`S-9`](S-9-the-capture-unit.md) records about
the referral policy: what is checked is that the ladder is descended in order and stops where it
should, and that nothing else in the tree does any of this. The rest is a lab obligation on inventory
row B20, alongside the three that row already carries.

## What happens to a customer's credentials

There are two answers and no third: the account the product is already running under, or an account
an operator typed in for this run.

**Nothing is remembered between runs.** The map records a file named `SavedCredential.cs` in the
previous product containing no such type — a folder and a filename left behind by a
credential-persistence feature that was designed and never built. That was the right call and it
stands. A tool that reads a directory and writes nothing to it has no business holding a customer's
administrative password from one week to the next.

**A password is not on this component's public surface.** The way a secret normally escapes is that
something prints the object holding it, so `DirectoryCredential` is deliberately not a record — a
record's compiler-generated `ToString` prints every member it has — its `ToString` names neither the
password nor the account, and no public member hands either back. Both are asserted rather than
intended.

**The account name is withheld too**, which is a slightly stronger position than it needs to be and
is taken on purpose. A user name is not a secret, but it is half of one, and an audit tool's logs
travel: they go into support tickets and get pasted into chat. There is no operational question this
product answers better by naming the account.

## What this document cannot tell you

Whether the ladder is the right ladder. It records four rungs, why each is there, and what Microsoft
says about each; it does not argue that four is the right number, or that a forest requiring channel
binding is adequately served by the second rung. Channel binding in particular is named here and not
built: it is a property of a TLS session, so it applies only to the top rung, and no run has yet met
a controller that required it. That needs a reader and, eventually, a lab.
