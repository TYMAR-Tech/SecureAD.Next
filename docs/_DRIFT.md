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
