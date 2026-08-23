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
