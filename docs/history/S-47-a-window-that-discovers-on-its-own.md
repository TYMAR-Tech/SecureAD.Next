# S-47 - A window that discovers on its own, and a preflight that asks several domains at once

> **This records session S-47 as of 2026-08-16. Nothing here states current behaviour.**
> It is kept for the reasoning it carries, not as documentation. See [`docs/history/README.md`](README.md).

**Status: built and tested, and seen working against the owner's forest.** Everything below is
proven by the test suite. The window was run against the owner's lab and behaved; the parallel pass
has not yet met a forest large enough to stretch it.

This document is discussion, not authority. Where it disagrees with the code, the code wins, and the
disagreement is a finding.

**Governing records:** [`0048`](../decisions/0048-preflight-proves-a-controller-before-a-run-commits.md)
(**amended twice by this session**),
[`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md)
(**amended by this session**),
[`0002`](../decisions/0002-absent-view-means-degraded-run.md),
[`0050`](../decisions/0050-the-candidate-list-comes-from-the-configuration-partition.md),
[`0053`](../decisions/0053-the-tool-finds-its-own-forest.md),
[`0055`](../decisions/0055-the-pdc-emulator-is-established-at-preflight.md),
[`0056`](../decisions/0056-the-visual-language-encodes-three-states.md),
[`0057`](../decisions/0057-starting-an-audit-is-a-modal-act.md).

Ledger rows: `A8`, `J11`.

---

## What this replaces

Opening the New Audit window used to produce an empty table and two buttons - *work out what would
be read*, then *check every domain* - which an operator pressed in order, every time, before he
could see anything. Neither took a decision from him. He cannot choose what the forest contains, and
he cannot answer the preflight questions himself. They asked him to ask for what he had already
asked for by opening a window called New Audit.

Behind them, preflight contacted one controller at a time and waited, because `0048` said to.

---

## What was built

### The per-domain work holds no state, and only then runs together

`Preflight.RunAsync` carried `roles`, `selection` and `units[i]` through its loop and rewrote all
three whenever a domain moved off its PDC emulator. Every domain's answer therefore depended on
which domains were asked before it.

**That was inert, and inert by luck.** `ControllerSelection.Rank` ranks role holders by host name
with no domain attached, so one domain's accumulated PDC emulator could in principle change another
domain's ranking. It never did, because a writable controller holds one domain and so another
domain's role holder never appears in this domain's candidate list. The correctness came from Active
Directory's shape rather than from anything this code enforced.

An assumption that holds by luck stops holding the moment two of these run at once, so the state was
removed before any concurrency was added. `AskOneDomainAsync` reads the plan and writes nothing but
its own return value; the re-pin re-ranks from `plan.Roles` and `plan.Selection`, never from what
another domain left behind. Proven unchanged by the whole `Connect` suite before anything else moved.

### The concurrency, and the guard that would not admit it

Adding `Task.WhenAll` to `Preflight.cs` failed `SerializedDirectoryAccessGateTests` - the guard the
previous session had just widened. **It was not weakened.** Its rule is *a file may fan work out, or
it may talk to a directory, never both*, and `Preflight.cs` counts as talking to one because it
names `IDirectoryChannelFactory` in its signatures.

So the split the guard's own failure message asks for was made once more. There are three files
where there were two:

| File | Fans work out | Talks to a directory |
|---|---|---|
| `Preflight.cs` | no | yes - holds the connections and the plan |
| `PreflightDispatch.cs` | yes | no - opaque subjects and host names |
| `DomainPreflightRead.cs` | no | yes - strictly serial |

**Turns are taken per host, not per domain.** Two domains pinned to one controller is not a shape
Active Directory produces, but `ControllerSelection` has no rule against it and will pin the same
host twice if handed a forest that declares one. The previous session named relying on that
disjointness as the defect to avoid, so the gate does not rely on it.

### The parallelism was fake, and the guard that caught it

`DomainsOnDifferentControllersAreAskedAtTheSameTime` failed on the first implementation, which was
correct in shape and sequential in fact: opening a connection is **synchronous**, and `Task.WhenAll`
enumerates a lazy `Select` on the calling thread, so the first domain ran its whole connection
ladder before the second task started.

Every same-controller assertion passed. The pass would have shipped looking correct and costing the
full ten seconds per controller it exists to remove. **This is the reason both directions are
guarded rather than only the dangerous one:** the safe-looking half of a concurrency rule is exactly
what a broken implementation satisfies.

Both guards were mutation-tested and both directions observed:

| Mutation | What failed |
|---|---|
| per-host turn bypassed | `TwoDomainsOnOneControllerAreNeverAskedAtTheSameTime` |
| the yield removed | `DomainsOnDifferentControllersAreAskedAtTheSameTime` |

Neither guard measures elapsed time. `OverlapWatch` holds each connection open until the expected
company arrives or a short deadline passes, so a serial pass reaches the deadline and reports one at
a time and a parallel pass sees the others arrive. Both answers are reached the same way every run.

`ForestModel.ConnectionsAttempted` was a plain increment and is now `Interlocked`. Under concurrency
it would have lost connections, so `EachDomainCostsOneConnection` would have passed while counting
nothing reliable.

### Checking a typed controller costs one machine - `F-S41-4`

`ValidateOverrideAsync` worked the whole plan out again - a bootstrap connection, the configuration
partition, and the candidate list for every domain - to answer a question about one host. An
operator correcting a typo in a nine-domain forest paid for the whole forest on every press.

`NamedControllerCheck` opens one connection and asks that machine what it serves. **It asks the host
rather than the forest**, which is the predecessor's `ForestDcPreflightService` shape and the
question the operator actually asked: *is this a machine I can read this domain from*. A controller
the forest does not list can still answer it, and one the forest does list can still be switched
off.

Whether the forest also names the host stays a separate fact and is not folded into the refusal: a
host that answers and holds the right partition while the forest does not list it leaves the site
column *not established*, per `0056`. Whether the run may pin it remains `ControllerSelection`'s,
and that refusal is unchanged.

The guard asserts the count of **planning passes** is unchanged, not merely that a check happened. A
check added beside the old pass rather than in place of it would satisfy everything else while
costing exactly what it did before.

### A refusal is put in front of him, and can be got out of

`INewAuditDialog.ShowRefusal` names the host and carries the audit layer's own words. Dismissing it
clears the box, so the domain falls back to the ranked choice; the refusal stays on the row, because
the dialog is gone the moment he closes it and the row is what he looks at next.

**This is not the silent fallback `0048` and its predecessor forbid.** What was wrong with the
predecessor was the silence, not the fallback - an operator who mistyped got a successful run
against a controller he did not name, with nothing recording it. Holding him in a refusal whose only
exit is closing the window would trade one bad outcome for another.
`AnIneligibleControllerIsNotQuietlyReplacedByTheRankedChoice` was rewritten to assert he was told,
and told which host, before the box clears. Remove the dialog and it fails though the fallback still
works.

### The window works itself out on opening, and can be stopped

`OpenAsync` runs both passes and lands on **Domains**, never Review, so opening the window is never
one click from a capture measured in hours. It is started from `NewAuditDialog` on the window's
`Loaded` event, keeping code-behind to `InitializeComponent` per `ShellMvvmGateTests`.

The indicator is indeterminate and says what is happening in a sentence. The audit layer returns one
result at the end of a pass, so a bar claiming to be four domains through nine would be a number the
window invented to look responsive - the same fault as inventing a fact about a forest, in a smaller
place.

**The Cancel is not a judgement call.** The owner settled it as a standing rule: any long-running
action this product starts gives the operator a way to stop it. Opening the window is now a network
act against every domain in the forest, begun without being asked for. A stopped pass keeps what it
reached and leaves the rest reading *not asked yet* - cancelling is not a finding about the
customer's forest - and offers itself again.

---

## What changed that was not in the brief

- **A third file, `PreflightDispatch.cs`.** The brief expected the concurrency to sit in the
  dispatcher. The guard would not have it, and the guard was right.
- **A Cancel, and a second amendment to `0048`.** Question 1 of the brief, answered by the owner
  during the session rather than after watching it.
- **`ForestModel.ConnectionsAttempted` made thread-safe**, without which an existing guard would
  have counted unreliably.

---

## What was built after the lab test

The window was run against the owner's forest and worked. Two questions were then taken further in
the same session.

**Why the forest could not be reached, rather than that it could not.** Every rung failure was
caught as one kind of event and flattened into a message, so a walk that failed for any reason
ended with *a controller accepting nothing signed leaves its LDAP traffic open to alteration in
transit*. A run whose password had expired therefore accused a customer's forest of a weakness on
the strength of a stale credential - `F-S35-1` reached from a new direction. `ConnectionFailureReason`
now classifies what the directory said, and `ConnectionLadderWalk` makes the protection finding only
where something answered. Governed by the amendment to
[`0018`](../decisions/0018-connection-security-is-an-ordered-ladder.md).

**An unclassified failure counts as no answer**, which is the conservative direction and the part
most likely to look wrong later. The reasoning is in `0018` rather than only in a comment, because a
future reader who flips it would quietly reinstate the accusation.

**The window says which stage failed** and offers the pass again, rather than leaving an empty table
with no button to press.

**The table was trimmed**, once there was a filled one to judge. Ten columns to eight, and the four
fixed widths - 920px before anything else was drawn - removed. The sentences became cells with the
sentence kept on hover, so the mark carries the state, the cell carries the fact and the tooltip
carries the reasoning. `Failover` and `Choice` left the table for the line beneath the row, where
they appear only when an operator could act on them: no alternative to fall back to, or a ranking
made without every input. The other two answers of `Choice` needed no telling - *named by you* is
visible in the box on that row, and *chosen on every input* is the ordinary case, which is what a
column repeats until nobody reads it. That is `0055`'s narrowing applied to a column instead of a
prompt.

Two findings closed with it. The rung reads `Signed and sealed` rather than `SignedAndSealed`, in
the rendering only, because the stored value must keep reading the same way in six months. And a row
is headed by the DNS name the forest declared rather than by a naming context above a line using the
other spelling - **paired, never derived**, since turning `DC=ph,DC=ad,DC=lab` into `ph.ad.lab` by
string surgery is true in almost every forest and wrong in the one that renamed a domain.

**The table is still provisional.** The owner has asked to look again once the *Include* column
exists, because a column that decides whether a domain is audited at all changes what the rest of
the table is for.

---

## Owed

- **Run the parallel pass against a larger forest.** The owner's lab is three single-controller
  domains, so the concurrency has been exercised but not stretched.
- **Whether a name that does not resolve is told apart from a host that is switched off.** Both
  arrive as the same protocol error. Separating them means resolving the name deliberately, which
  would need weighing against `0050`. Recorded in
  [`which-controller-we-read`](../areas/which-controller-we-read.md).
- **Whether `SelectionWasInformed` is right for a domain whose PDC emulator was established but is
  not its pinned controller.** Spotted while reading: that domain's emulator is never folded into
  `roles`, so the row reports the choice as not fully informed though the fact was established. Not
  touched, because it is pre-existing and outside this session.
