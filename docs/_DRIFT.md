# Drift log

Discrepancies found between documentation and code during the documentation rewrite.

**All eight are fixed**, on `fix/drift`, in five commits grouped by kind. Each was verified against
the code before it was touched, and two had themselves rotted in the meantime: `D-3` had been half
corrected by a later sitting, and `D-2` had lost two of the four sentences it quoted.

The log was written on the premise that `docs/rewrite` stayed documentation-only so it stayed
reviewable, and that is why nothing here was fixed as it was found. **That premise was not true.**
That branch carried thirty-five production files, six of them with real behaviour changes, in two
commits. The deferral was still the right call - these wanted reading together rather than one at a
time - but it was not being held to the rule it cited, and a rule nobody keeps is worth knowing
about.

What this log is for, if it is used again: a discrepancy found while writing a document is recorded
here rather than fixed on the spot, and then worked deliberately on a branch of its own. Nothing
gates this file. If a row is added and never worked, nothing will say so.

Status values: `open` (found, not yet decided), `agreed` (owner decided the fix), `fixed`.

---

## D-1 — `ParsedSecurityDescriptor` names three DACL states, but there are four

| | |
|---|---|
| **Status** | fixed |
| **Found** | Kernel/Security pilot |
| **Where** | `next/src/SecureAD.Kernel/Security/ParsedSecurityDescriptor.cs` |
| **Kind** | Stale XML comment in code |

The parameter documentation reads:

```
<param name="DaclState">Whether the DACL is Present, Null, or Empty.</param>
```

`DaclState` has four members: `Present`, `Null`, `Empty`, and `Unreadable`. `Unreadable` was added by
`docs/decisions/0037-an-unreadable-dacl-says-so.md` and the parameter documentation was not updated
with it.

**Why it matters.** Decision 0037 exists precisely to stop an unreadable DACL being reported as
`Empty` — that is, reporting an object the product could not read as the most locked-down object it
is possible to be. A caller reading only this parameter comment would not know the fourth state
exists, which is the same failure the decision was written to prevent, surviving one layer up in a
comment.

The type's own `<remarks>` section is correct and does discuss completeness and canonicality. Only
the `<param>` line is stale.

**Proposed fix.** One line:

```
<param name="DaclState">Whether the DACL is Present, Null, Empty, or Unreadable.</param>
```

---

## D-2 — Three components say branch A and branch C do not exist

| | |
|---|---|
| **Status** | fixed |
| **Found** | Audit/Capture pass |
| **Where** | `IDirectoryChannel.cs`, `CaptureSearchRequestFactory.cs`, `CaptureUnit.cs` |
| **Kind** | Stale XML comments in code |

`IDirectoryChannelFactory` says *"Opening the connection — choosing the controller, binding, and
applying the referral policy — is branch A's work and is not built."* `IDirectoryChannel` says a
channel *"does not choose a controller or decide what to ask — those are branch A's and are not
built."* `CaptureSearchRequestFactory.ApplyReferralPolicy` says gate 5b unblocks *"once inventory
row B6 gives the rebuild something that runs."* `CaptureUnit.ConfirmServedBy` says *"inventory row
A8 — preflight validation — is where this is invoked, and that row is not yet decided."*

All four are now false. `SecureAD.Audit/Connect/` holds `LdapDirectoryChannelFactory`,
`ForestTopology` and `Preflight`; `CapturePlan.For` calls `ConfirmServedBy` itself; `CaptureRun`
drives the whole thing; `BundleCaptureSink` writes to the bundle.

**Why it matters.** These are the sentences a reader consults to find out what is missing, and they
name work that is finished. More concretely, gate 5b — every public type reachable from something
that runs — is recorded as blocked *on an entry point that now exists*. A gate deferred against a
condition that has already been met is a gate nobody will reinstate.

**Proposed fix.** Rewrite the four comment blocks against what is built, and re-examine whether
gate 5b can now be turned on. The second half is not a comment change and wants its own decision.

**What was done.** Comments only. Two of the four sentences quoted above no longer matched
verbatim by the time this was worked, and the counter-evidence was stronger than recorded here:
`Program.cs` constructs `LdapDirectoryChannelFactory` directly, `CaptureSession` is reached from
both `Program.cs` and the shell's `CaptureLauncher`, and `ConfirmServedBy` is called from
`DomainPreflightRead` and `CapturePlan`. The same false claim was found in
`docs/next/ARCHITECTURE.md`, which said nothing calls the factory, and was corrected too. Gate 5b
is raised as `P-84` rather than attempted: turning it on is its own change with its own fallout.

---

## D-3 — The request factory documents itself as building one request

| | |
|---|---|
| **Status** | fixed |
| **Found** | Audit/Capture pass |
| **Where** | `next/src/SecureAD.Audit/Capture/CaptureSearchRequestFactory.cs`, class summary |
| **Kind** | Stale XML comment in code |

The summary reads *"Builds the one search request capture issues."* It builds nine: `ForUnit`,
`ForNextPage`, `ForAttributeBlock`, `ForRootDse`, `ForCrossReferences`, `ForSiteTopology`,
`ForSubnets`, `ForPasswordSettingsContainer` and `ForRoleOwner`.

**Why it matters.** The sentence is load-bearing in the wrong direction. What makes this class
correct is that it is the *only* place a request is built — not that it builds only one. A reader
who takes the summary literally and finds eight other methods has reason to think the class has
drifted from its own rule, when the rule is intact.

**Proposed fix.** *"Builds every search request capture issues, and holds the referral policy that
makes them safe."*

**What was done.** Half of this had already been applied by a later sitting: the referral-policy
clause was present and *"the one"* was not. Only the first clause was corrected.

---

## D-4 — `ConnectionFailureReason` reads a TLS failure into a code that does not carry one

| | |
|---|---|
| **Status** | fixed |
| **Found** | Audit/Connect pass, while adjudicating `#17` |
| **Where** | `next/src/SecureAD.Audit/Connect/ConnectionFailureReason.cs` |
| **Kind** | XML comment asserting more than the citation supports |

The constant is documented as:

```
/// <summary>The transport could not be established - in practice, TLS.</summary>
private const int ConnectError = 91;
```

Microsoft defines `LDAP_CONNECT_ERROR` (0x5b) as *"Cannot establish the connection"*
([Return Values](https://learn.microsoft.com/previous-versions/windows/desktop/ldap/return-values)),
and says nothing narrowing it to TLS.

**Why it matters.** This is not a cosmetic overstatement — it is load-bearing, and it is the reason
`#17` exists. *In practice, TLS* invites the reader to picture a controller that answered and
negotiated badly, and on that picture it is reasonable to list `ProtectedChannelFailed` among the
reasons that prove the controller answered. On Microsoft's actual wording it is not: a connection
that could not be established is the client reporting its own failure, which is precisely the case
`0018`'s amendment says may not carry a finding. The comment is where the wrong inference is
recorded, and the code below it is where the wrong inference is acted on.

It is also the trap the authority names first — XML comments are argument, not data — with the
unusual feature that here the argument was believed and shipped.

**Proposed fix.** Take the citation's own words and stop there, in the same edit as the `#17` fix:

```
/// <summary>The connection could not be established. Says nothing about the server.</summary>
private const int ConnectError = 91;
```

---

## D-5 — `ConnectionSecurityLog.Controllers` promises an order the type does not keep

| | |
|---|---|
| **Status** | fixed |
| **Found** | Audit/Connect pass |
| **Where** | `next/src/SecureAD.Audit/Connect/ConnectionSecurityLog.cs` |
| **Kind** | XML comment asserting a guarantee the implementation does not give |

The member is documented as *"Every controller this run connected to, in the order it first
connected"* and returns `Dictionary<TKey, TValue>.Values`, which has no documented enumeration
order. It happens to enumerate in insertion order while no entry is removed, and nothing here
removes one — so the comment is true today by implementation accident rather than by contract.

**Why it matters, mildly.** Nothing currently depends on it: `RefusedIntegrity` sorts by host name
explicitly, and that is the member a finding is made from. The exposure is a future reader taking
the comment at its word and rendering this collection directly, at which point a report could order
the same forest differently between runs — the stability `PreflightDispatch` is careful to preserve
for exactly this reason, in the same subsystem.

**Proposed fix.** Either drop the claim, or make it true with an insertion-ordered list beside the
dictionary. Given `PreflightDispatch`'s reasoning about stable ordering, the second is the more
consistent answer.

**What was done.** The second, additively: the dictionary stays as the lookup and the list stands
beside it. Worth recording that **this one cannot be proven by test.** Reverting `Controllers` to
the dictionary's values passes the whole suite, because `Dictionary` does happen to enumerate in
insertion order - which is the accident being removed. Prepending instead of appending fails both
new tests, so they bite on real ordering changes. The value is structural: the type no longer rests
on an undocumented implementation detail.

---

## D-6 — A gate's self-test says four and asserts three

| | |
|---|---|
| **Status** | fixed |
| **Found** | Audit/Connect pass, while checking each gate's subject after the move |
| **Where** | `next/tests/SecureAD.Next.Tests/Architecture/ConnectionSecurityGateTests.cs` |
| **Kind** | Comment contradicting the assertion directly beneath it |

```
// Four transport assignments, because the ladder sets all three options plus the protocol
// version on every attempt; a factory containing fewer has stopped setting one of them.
Assert.Single(RebuildTree.ScanPattern(factories, ConnectionConstruction));
Assert.Equal(3, RebuildTree.ScanPattern(factories, TransportSecurityAssignment).Count);
```

`TransportSecurityAssignment` matches `SecureSocketLayer|Signing|Sealing` — three forms.
`ProtocolVersion` is not in the pattern, so it is not counted and never was. **The assertion is
correct and the comment is wrong.**

**Why it matters more than it looks.** That `3` is a floor in a scanner self-test, and the whole
point of the self-test is that a number nobody can re-derive is a number that rots. A future reader
reconciling the comment with the assertion has two plausible repairs — raise the count to 4, or add
`ProtocolVersion` to the regex — and **the first one turns the gate red for no reason while the
second silently changes what the gate polices.** This is the same shape as `P-19`: a repair made to
restore agreement, without asking what the check's subject is.

**Proposed fix.** Correct the comment to three, and say which three, so the number is re-derivable
from the line above it:

```
// Three transport assignments - SecureSocketLayer, Signing and Sealing, which the ladder sets
// on every attempt. ProtocolVersion is set too and is deliberately not policed: it is not a
// security level. A factory containing fewer than three has stopped setting one of them.
```

---

## D-7 — `RunHash` says the identities appear in folder names; they do not

| | |
|---|---|
| **Status** | fixed |
| **Found** | Evidence pass, second sitting |
| **Where** | `next/src/SecureAD.Evidence/Run/RunHash.cs`, type remarks |
| **Kind** | Stale XML comment in code |

`RunHash`'s remarks justify sharing one hash routine between `ProfileId` and `CoverageId` like this:

```
They appear side by side in folder names and in the run library, and two identities of
different shapes would look like a defect to an operator long before anyone noticed it was one.
```

**Neither identity appears in a folder name.** `RunLibrary.CreateRun` composes
`{Sanitise(forestFqdn)}-{timestamp:yyyyMMdd-HHmmss}` — `ad.lab-20260819-232425` — and its own remarks
say the opposite of what `RunHash` assumes: *"nothing reads meaning back out of it: what a bundle is
evidence of is recorded inside the bundle, and a name is not evidence."*

**Why it matters more than a wrong sentence.** The stated reason for sharing `RunHash` is that the
two values are seen *side by side by an operator*. That reason is false, and the real one is better:
they are compared as opaque strings by code, so a width or alphabet difference between them would be
a defect nobody could see at all. The comment argues from a screen that does not exist, and it argues
for the right conclusion — which is why it survived.

**It was believed and used.** The `F-0079-6` adjudication rested partly on this comment, claiming a
format change would rename directories. It would not. The claim was corrected in the punch list, and
the conclusion held on its other leg, but the reasoning had to be rewritten after the fact.

**Proposed fix.** Replace the folder-name justification with the real one:

```
Internal, and shared by ProfileId and CoverageId so that the width and alphabet of an identity
cannot drift between the two. They are compared as opaque strings - RunScope.Identity groups on
one of them - so a difference in shape would not look like a defect to anybody. It would simply
stop matching.
```


---

## D-8 — The register says the catalogue holds 100 values; it holds 101

| | |
|---|---|
| **Status** | fixed |
| **Found** | Kernel/Schema pass |
| **Where** | `docs/MICROSOFT-VERIFICATION.md` |
| **Kind** | Stale count in a document |

The *Verified* table records `SchemaGuidCatalog` at **100** values, harvested 2026-08-19, and the
defect arithmetic below it reads *12 of 237*. Counted from the source, the shipped table declares
**101** rows over **97** distinct GUIDs, and `SchemaGuidCatalogMicrosoftAnchorTests` carries 101
pinned rows held to the catalogue in both directions. So the anchor test and the code agree with
each other, and the register's prose agrees with neither.

**This is most likely a harvest count read as a component count.**
`DS-Replication-Monitor-Topology` was *added* under its real GUID when the eleven corrections were
made, so a hundred may well be what was harvested on the day. That is a guess, which is why this is
recorded rather than corrected: whether the column means *values checked then* or *values the
component holds now* is the harvester's to say, and the two readings give different totals for
every row in the table.

**Nothing is wrong in the code.** The count that governs is the anchor test's, it is
two-directional, and it passes.

**What was done.** Corrected to 101, and the column sum below it from 237 to 238. The count was
confirmed three independent ways - GUID literals, a breakdown by declaration form summing to 101,
and the anchor test's own 101 rows. The reading was settled by measuring the other four components
rather than by choosing: `AceType` records 10 and holds 10, `UserAccountControlWording` records 22
and holds 22. So the column means *values the component holds now*, and that is now stated in the
document's prose so the ambiguity cannot recur.

---
