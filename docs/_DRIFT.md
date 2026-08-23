# Drift log

Discrepancies found between documentation and code during the documentation rewrite.

**Nothing here is fixed as it is found.** The `docs/rewrite` branch stays documentation-only so it
stays reviewable. Code and code-comment fixes are batched and applied deliberately once the rewrite
is agreed.

Status values: `open` (found, not yet decided), `agreed` (owner decided the fix), `fixed`.

---

## D-1 — `ParsedSecurityDescriptor` names three DACL states, but there are four

| | |
|---|---|
| **Status** | open |
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
| **Status** | open |
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

---

## D-3 — The request factory documents itself as building one request

| | |
|---|---|
| **Status** | open |
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

---

## D-4 — `ConnectionFailureReason` reads a TLS failure into a code that does not carry one

| | |
|---|---|
| **Status** | open |
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

It is also the trap `_HANDOFF.md` names first — XML comments are argument, not data — with the
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
| **Status** | open |
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

---

## D-6 — A gate's self-test says four and asserts three

| | |
|---|---|
| **Status** | open |
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
