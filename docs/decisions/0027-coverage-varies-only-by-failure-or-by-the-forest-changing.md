# 0027 - Coverage varies only by failure or by the forest changing, and a failed run is refused

Date: 2026-08-12
Status: Accepted

Replaces the exclusion-based reasoning in [`0025`](0025-the-run-library-is-a-managed-root.md) and
the state table in [`0026`](0026-one-answer-to-whether-runs-may-be-compared.md). Both stand as
written; this states what replaced the parts of them that rested on a mechanism the product no
longer has.

## Context

`0025` and `0026` were both written on top of the **attestation ladder** - the mechanism by which
an operator excluding part of the directory had to state whether the excluded part was populated or
empty, with the second claim tested after capture against what the forest reported.

That mechanism does not exist. `0017`, decided eight days
earlier, removed operator-configurable exclusion entirely, and its consequences name the exclusion
attestation among what goes with it. Ledger row B3 records the same and adds that the attestation
has nothing left to falsify. The rebuild's `CapturePlan` plans a unit for every domain partition it
is handed, and there is nothing an operator can set before a run.

So `0025`'s justification for keying a baseline to the forest alone - *the only way coverage varies
is an excluded domain, and an exclusion is attested* - names a mechanism already gone, and four of
`0026`'s eleven states describe situations no run can reach. Building that table would have
produced a closed set with four permanently dead members and a document bound by a test asserting
states nothing can produce, which is the failure `docs/next/README.md` names first.

The error was one of sequence. Both records were written in a session that read the run library's
predecessor closely and read `0017` not at all, because `0017` is a capture decision and the session
was about the library.

## Decision

**Coverage varies exactly two ways.** A domain could not be fully read, which is a capture failure
nobody chose; or the forest itself changed shape, a domain decommissioned or an acquisition
completed. The predecessor could not tell these apart, because an exclusion looked like both.

**A partially read domain counts as failed.** A domain read in part is not a smaller success. It is
a hole of unknown shape, which is what makes a later comparison understate change while looking
confident.

**A run that failed to read any domain may not be a baseline, and may not be compared.** A baseline
with a hole in it silently understates every future change. Refusing rather than qualifying is the
same judgement one level down: the operator's remedy is to run it again, and saying so is more use
than a hedge he must interpret.

**A run may be nominated as a baseline only if it sealed and read every domain the forest
reported** - the same predicate as a fully comparable verdict, which keeps `0026`'s consolidation
true rather than leaving eligibility as a second opinion beside it.

**The states are evaluated in order and the first match wins.** A run that both failed a domain and
saw a changed forest reports the failure, because that is the one the operator has to fix. In the
other order he gets a qualified comparison quietly resting on incomplete evidence.

| # | Situation | Shape |
|---|---|---|
| 1 | No earlier run exists | No result |
| 2 | The earlier run was deleted | No result |
| 3 | The earlier run never completed | No result |
| 4 | This run failed to read one or more domains | No result |
| 5 | The earlier run failed to read one or more domains | No result |
| 6 | The forest's domain set differs between the two runs | Qualified |
| 7 | Compatible, but graph findings were withheld | Qualified |
| 8 | Compatible, but the runs came from different major versions | Qualified |
| 9 | Fully compatible, nothing changed | Measured |
| 10 | Fully compatible, changes found | Measured |

`0026`'s exclusion states 4 and 5 are replaced by the failure states above. Its states 6 and 7
collapse into one, because the only indefensible cause of a coverage difference was a falsified
attestation, which no longer exists, and the only other cause was a failure, which states 4 and 5
now catch first.

**States 4 and 5 stay distinct**, for the reason `0026` gives for keeping 1 to 3 apart: they share
an outcome and not a cause, and only one of the two is actionable today.

**State 6 remains qualified rather than refused.** A decommissioned domain is a legitimate change to
a forest's shape, and refusing across it forever loses remediation tracking when it is most wanted.
This is the one part of `0026`'s reasoning that survives its mechanism intact.

## Consequences

**`0025`'s conclusion survives; its reasoning is replaced.** Keying the baseline to the forest alone
is better supported now, not worse: the operator cannot vary coverage at all, so there is no second
axis for a baseline to need. The managed root, the absence of a second tier, the refusal to register
outside bundles and the path guards are untouched.

**`0026`'s structure survives entire** - one component, a closed set of outcomes, eligibility folded
in, three card shapes, and no success flag where no comparison occurred. Only the list of situations
changed. That this cost one table and no rework is the property `0026` said it was buying, and this
is the first time it has been tested.

**One flaky controller near the end of a long capture costs the whole run.** That is the price of
the partial-read rule and it will be felt. It is the correct direction: the alternative is a
baseline with a hole in it that nothing downstream can see.

**A capture failure now has consequences it did not have**, so the failure path must record *which*
domains were not fully read rather than merely that something went wrong. That fact is owed by
capture, and a bundle that cannot answer it cannot be judged - the shape of warning `0026` gives
about states needing facts capture never recorded.

**The attestation verifier is not carried across**, and ledger row C8's note, which still instructs
a future session to salvage it, is corrected rather than left to mislead one.
