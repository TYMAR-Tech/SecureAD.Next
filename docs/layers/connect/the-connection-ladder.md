# The connection ladder

**Layer.** How this product connects to a domain controller, how well protected that connection is,
and what it may and may not conclude when a connection fails.

The code is [`ConnectionSecurityLadder`](../../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLadder.cs),
[`ConnectionLadderWalk`](../../../next/src/SecureAD.Audit/Connect/ConnectionLadderWalk.cs),
[`ConnectionSecurityLog`](../../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs),
[`ConnectionFailureReason`](../../../next/src/SecureAD.Audit/Connect/ConnectionFailureReason.cs) and
[`UnprotectedConnectionAllowance`](../../../next/src/SecureAD.Audit/Connect/UnprotectedConnectionAllowance.cs).

What actually opens the socket at a chosen rung is
[`how-a-connection-is-opened.md`](how-a-connection-is-opened.md).

Governed by [`0018`](../../decisions/0018-connection-security-is-an-ordered-ladder.md), including its
2026-08-16 amendment. Where this page and that record disagree, the record wins and the
disagreement is a finding.

---

## The failure this exists not to have

> **An audit tool that reads a customer's most sensitive permissions over a channel anybody on the
> path could read, or alter, and says nothing about it.**

Both halves matter and they fail differently.

**The credential.** Microsoft's account of a simple bind on port 389 is not that it is weak. It is
that there is nothing there: *"There's no security for these sessions. This is because credentials
are transmitted in clear text. Therefore, there's no secure key material to provide protection"*
([LDAP session security settings and requirements after ADV190023 is
installed](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023)).
An account able to read every permission in a forest is worth intercepting.

**The evidence.** Everything this product says comes out of one bundle, and the bundle is what one
capture read. If that reading could have been altered in transit, so could every finding. An
attacker who can alter LDAP responses can remove the entry naming their own foothold, and the report
says nothing is wrong.

---

## The ladder

Each row is a rung the code names. The table is held to
[`ConnectionSecurityLadder.Rungs`](../../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLadder.cs)
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
and a great many forests have none. A product that insisted on it would refuse to audit a large
share of the forests that most need auditing.

**Rungs 2 and 3 need no certificate and are genuinely protected.** That is the load-bearing fact
this design rests on, and it is Microsoft's rather than an inference: *"If LDAP sessions are signed
or encrypted by using an SASL logon, the sessions are secure from Man-In-the-Middle (MITM) attacks.
This is because you can obtain the signing keys only if you know the user password."*

**No rung performs a simple bind.** Authentication is Negotiate on all four, so a credential never
crosses the wire in clear text even on the bottom rung. What is unprotected down there is the
evidence, not the password.

**Nothing asks for both TLS and SASL protection.** They protect the same channel by two mechanisms,
and the platform's client rejects a connection that asks for both.

### How the descent works

[`ConnectionLadderWalk.Descend`](../../../next/src/SecureAD.Audit/Connect/ConnectionLadderWalk.cs)
tries each permitted rung from the top and stops at the first that answers. It will not re-order the
rungs and it will not carry on past a success.

The filtering of what a run may attempt is
[`ConnectionSecurityLadder.PermittedBy`](../../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLadder.cs)'s,
not a condition inside the loop — **one statement of what a run may do rather than two that could
disagree.** The walk is separated from the thing that opens a socket precisely so the descent can be
tested, because there is no forest in a build agent and the alternative was this rule stated in
prose beside code nothing exercised.

---

## The bottom rung is declared, not reached

> **A run descends to an unprotected connection only where somebody said, before it started, that
> this run may use one.**

[`UnprotectedConnectionAllowance`](../../../next/src/SecureAD.Audit/Connect/UnprotectedConnectionAllowance.cs)
is that statement. It is a required argument rather than a defaulted one, so a run that permits
nothing has said so at the call site, and it carries the auditor's own words about why — which
travel into the finding it produces. `Refused` is a named value, not omission.

**It is a type and not a boolean** for two reasons, the second load-bearing: a boolean at a call
site reads as `true` with nothing beside it saying what was agreed to, and a declaration carries a
reason. A flag has nowhere to put that. `DeclaredFor` rejects an empty reason, because an allowance
with no stated reason is the persisted setting this decision exists to avoid, reached by another
route.

**There is no dialog at the moment of failure.** An audit tool gets scheduled. A run that blocks at
03:00 on a prompt nobody sees has done nothing by morning, and the operator arrives to a machine
waiting politely instead of a bundle. Same reasoning as the failure policy in
[`limits-and-failures`](../audit/limits-and-failures.md).

**It is never persisted**, and **declaring it does not make the run quiet.** A controller that
accepts nothing better is a finding either way. The allowance decides whether the run proceeds, not
whether it discloses.

---

## What a failure is allowed to mean

This is the part of the ladder most likely to be got wrong by a later reader, because the wrong
answer is the intuitive one.

> **The ladder may describe what a controller accepts only where something came back from that
> controller.**

Every rung failure used to be caught as one kind of event, so a walk that failed for **any** reason
ended with *"a controller accepting nothing signed leaves its LDAP traffic open to alteration in
transit."* A run whose password had expired therefore accused a customer's forest of a weakness on
the strength of a stale credential. That is `F-S35-1` reached from a new direction, and
[`0002`](../../decisions/0002-absent-view-means-degraded-run.md) forbids it.

[`ConnectionFailureReason`](../../../next/src/SecureAD.Audit/Connect/ConnectionFailureReason.cs)
classifies by what the directory said:

| The directory said | Reason | Does it prove the controller answered? |
|---|---|---|
| 81 `LDAP_SERVER_DOWN` | `ControllerDidNotAnswer` | no |
| 85 `LDAP_TIMEOUT` | `ControllerDidNotAnswerInTime` | no |
| 91 `LDAP_CONNECT_ERROR` | `ProtectedChannelCouldNotBeEstablished` | **yes — and this is wrong, see below** |
| 49 `LDAP_INVALID_CREDENTIALS` | `CredentialsWereRejected` | yes |
| 8 `LDAP_STRONG_AUTH_REQUIRED` | `ProtectionWasRefused` | yes |
| 13 `LDAP_CONFIDENTIALITY_REQUIRED` | `ProtectionWasRefused` | yes |
| a `DirectoryOperationException` | `ProtectionWasRefused` | yes |
| anything else | `ConnectionRungRefused` | no |

And the walk then ends in one of four places:

| What the walk saw | What it says |
|---|---|
| nothing that proves an answer | `DomainControllerDidNotAnswer` — the name may not resolve, the host may be off, a firewall may be in the way, and from here those look alike |
| all attempts timed out | the same, plus *that is what a firewall dropping packets looks like from here* |
| credentials rejected | `CredentialsWereRejected` — a credential, not a network fault and not a weakness in the forest |
| answered, refused, allowance declared | `DomainControllerAcceptedNoConnection` |
| answered, refused, no allowance | `DomainControllerAcceptedNoProtectedConnection` — **the forest finding** |

**Rejected credentials are a credential.** The controller answered and declined to authenticate.
Descending the ladder never had a chance of changing it.

**An unclassified failure is treated as no answer, deliberately, and this is the part to leave
alone.** It is the conservative direction and it will look wrong to somebody later: a code nobody
has mapped will often *in fact* be the controller refusing something, and treating it as silence
understates what we know. That trade is made on purpose. The two mistakes are not equal — saying
less than we measured costs a line in a report, and saying more than we measured puts an accusation
about a customer's security posture in a document they will act on. **A new code earns its finding
by being classified, not by being assumed.**

### Punch-list `#17` — 91 is not an answer

**Adjudicated during this pass. The finding is real, it is reachable, and the punch-list line that
recorded it was wrong about where it lives.**

The line said the ladder treats 91 as proof of *refused protection*. It does not.
`ConnectionFailureReason.Of` maps 91 to `ProtectedChannelFailed`, which is a distinct reason and a
correct one — an operator whose certificate is broken should be told about a certificate, not about
his network. The fault is one entry further on: **`ProvesTheControllerAnswered` lists
`ProtectedChannelFailed` alongside `CredentialsWereRejected` and `ProtectionWasRefused`**, and that
list is the gate the amendment put in front of the forest finding.

So a 91 on rung 1 plus any failure on rungs 2 and 3 satisfies the gate, and an undeclared run ends
at *"a controller accepting nothing signed leaves its LDAP traffic open to alteration in transit."*
**A broken LDAPS certificate on 636 together with a firewall on 389 reaches it** — a certificate
fault accusing a customer's forest, which is exactly the sentence the amendment exists to prevent.

**Microsoft settles it.** `LDAP_CONNECT_ERROR` (0x5b) is *"Cannot establish the connection"*
([Return Values](https://learn.microsoft.com/previous-versions/windows/desktop/ldap/return-values)).
That is the client reporting its own failure to connect, with nothing in it about the server having
responded. 49 and 8 and 13 are result codes a controller composed and sent; 91 is not a result code
at all.

**How it survived the amendment**, which is the durable lesson. The amendment has three cases and
`ConnectionSecurityTests` has a test for each — the unanswered walk, the rejected credential, the
unclassified code. The fourth entry in the same list was carried over without being re-asked. This
is `P-19` from the other direction: *ask what the check's subject is, not only whether it passes.*

**Not fixed here.** This pass is a documentation rewrite and
[`_DRIFT.md`](../../_DRIFT.md) keeps the branch documentation-only. The remedy is recorded in
[`PUNCH-LIST.md`](../../PUNCH-LIST.md) so the fix pass need not re-derive it: drop
`ProtectedChannelFailed` from `ProvesTheControllerAnswered`, give the no-answer branch a third
message variant naming the certificate rather than the network, and add the missing test.

---

## What comes back out, and why it is a level rather than a flag

[`ConnectionSecurityLog`](../../../next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs) records,
per domain controller, which rung answered and how many better ones it turned down first.

A boolean has nowhere to put a third state and this ladder has four. Worse, the two questions a
boolean would conflate are asked by different readers: *was our evidence protected* is about the
run, and *would this controller accept a signed connection* is about the customer's forest. The
second is a security finding they would otherwise pay for separately, and walking the ladder
produces it at no extra cost.

**It is append-only and never forgets a worse answer.** A controller is recorded once, at the moment
it answered, because the question this answers is what the run actually used.

**Signing is the line, not encryption.** `RefusedIntegrity` is what the finding is made from, and a
controller that accepted signing but not sealing is not a finding — signing is what makes a session
safe from alteration in transit, and it is what Microsoft's hardening guidance and the Windows
Server 2025 default are both about.

**The log also carries its failures**, and that is not bookkeeping. Without them, a run in which
nothing was unprotected and a run in which nothing was reached both leave the list empty, and a
reader cannot tell *"we looked and found nothing wrong"* from *"we never got to look"* — the
distinction [`0002`](../../decisions/0002-absent-view-means-degraded-run.md) forbids collapsing.

---

## What is built

**The test is the evidence; this table is only the index.**

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a controller nothing answered from is not described as refusing protection | `ConnectionLadderWalkTests.AControllerThatNeverAnsweredIsNotDescribedAsRefusingProtection` | |
| read a rejected password as a password, rather than as a weakness in his forest | `ConnectionLadderWalkTests.RejectedCredentialsAreReportedAsCredentialsAndNotAsAWeakness` | |
| still be told when a controller genuinely refuses every protected rung | `ConnectionLadderWalkTests.AControllerThatAnsweredAndRefusedProtectionIsStillAFindingAboutTheForest` | |
| be certain a failure nobody classified is not promoted into a security finding | `ConnectionLadderWalkTests.AFailureNobodyClassifiedIsNotPromotedIntoAFinding` | |
| be certain the ladder is descended in order and stops at the first answer | `ConnectionLadderWalkTests.TheFirstRungThatAnswersIsTheOneUsedAndNothingBelowItIsTried` | |
| see which rung each controller answered on, by name | `ConnectionLadderWalkTests.TheRungThatAnsweredIsRecordedAgainstTheController` | |
| be certain an undeclared run never reaches the bottom rung | `ConnectionLadderWalkTests.AnUndeclaredRunNeverAttemptsTheUnprotectedRung` | |
| be certain a declared run reaches it last, and only last | `ConnectionLadderWalkTests.ADeclaredRunReachesTheUnprotectedRungLast` | |
| tell a controller that refused everything from one that refused only the protected rungs | `ConnectionLadderWalkTests.ADeclaredRunThatStillFailsSaysTheUnprotectedRungWasTriedToo` | |
| be certain an unread controller is not recorded as having answered | `ConnectionLadderWalkTests.AControllerThatAnsweredOnNoRungIsNotRecordedAsHavingOne` | |
| tell "none was unprotected" from "we never got to look" | `ConnectionLadderWalkTests.AControllerThatAnsweredOnNoRungIsRecordedAsAFailure` | |

**No test here reaches the connection itself.** There is no domain controller in a build agent, so
nothing exercises the bind, the TLS handshake, or a real controller's refusal. That is stated rather
than glossed. What is checked is that the ladder is descended in order and stops where it should,
and that nothing else in the tree does any of this. The rest is a lab obligation on inventory row
B20.

---

## What this document cannot tell you

**Whether the ladder is the right ladder.** It records four rungs, why each is there, and what
Microsoft says about each; it does not argue that four is the right number, or that a forest
requiring channel binding is adequately served by the second rung. Channel binding is named here and
not built: it is a property of a TLS session, so it applies only to the top rung, and no run has yet
met a controller that required it.

**Whether a name that does not resolve is told apart from a host that is switched off.** Both arrive
as the same protocol error. Separating them means resolving the name deliberately, which is a
further act against DNS and would need weighing against
[`0050`](../../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md). Not
decided; the message says the cases look alike rather than guessing between them.
