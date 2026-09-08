# 0102 - Group expansion is budgeted, and an incomplete expansion says so

Date: 2026-09-06
Status: Accepted.

Settles `Q6` of `SPEC-stage-6-control-edges.md` - whether there is a size at which the product should
refuse to expand members.

## Context

`0097` counts a group-held permission at the group and expands to its members, so the headline reads
*Helpdesk (400 members) can take over OU=Finance*. The lab is 8,383 objects. A customer forest of
100,000 objects with groups of a few hundred members produces a large stored expansion, and the
question was whether there is a point at which the product should stop.

Microsoft documents very large potential object and membership scales, and its LDAP guidance confirms
that operational limits exist to stop a request adversely affecting a domain controller's
performance, recommending paged behaviour rather than raising result limits. **What Microsoft does not
give is a product-specific safe threshold**, so this specification must not invent a universal
number and present it as one.

## Decision

**Never silently refuse to expand, and never fabricate completeness.** Expansion runs against an
explicit resource budget, keeps everything it found, and marks itself incomplete when a budget is
reached.

1. **Budgets are explicit and configured**: visited nodes, traversed links, elapsed processing, and
   stored expansion records.
2. **Reaching a budget never removes the counted group edge.** The edge at the group is the thing an
   administrator changes (`0097`); the expansion is detail beneath it.
3. **Everything found so far is retained** - resolved members and unresolved nodes alike.
4. **`ExpansionComplete = false`**, and the stop reason is recorded: `NodeBudgetExceeded`,
   `LinkBudgetExceeded`, `StorageBudgetExceeded` or `TimeBudgetExceeded`.
5. **The screen states that the expansion shown is partial.**
6. **A count from an incomplete expansion is never presented as total effective membership.** This is
   commitment 3 exactly: say what you know with its uncertainty, except when claiming completeness.
7. **Traversal order and work-limited results are deterministic** for the same evidence, semantic
   versions and configured node/link/storage budgets. An elapsed-time cutoff can retain a different
   length prefix on a fresh execution, because machine speed and workload vary. The actual partial
   result, processing position, elapsed measurement and stop reason are persisted; reopening that
   stored result is identical and never restarts the walk.
8. **The export carries the configured budget and the stop reason**, so a result read years later
   says what it was allowed to do.

**Accepted timing clarification:** during bounded effective-member preparation, the owner accepted
the distinction in condition 7 and subsequently authorized implementation. It does not permit a
timed partial result to claim completeness, discard discoveries or change holder-edge counts. No
production expansion budget was approved.

## Consequences

- **A large forest produces a partial answer that admits it, rather than a complete-looking answer
  that is not.** The failure mode this forbids is the one an audit tool cannot have.
- **No universal threshold is published**, because none is supportable. The budget is configuration
  with a default, and the default is a starting point to be measured on real forests rather than a
  claim about what is safe.
- **`ExpansionComplete` joins the typed missing-and-degraded input handling** the judging stage
  already owes its rules; an incomplete expansion behind a rule input is an `Unknown`, never a *no*.
