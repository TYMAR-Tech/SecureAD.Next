# 0067 - An acceptance names one finding and lives beside the evidence

Date: 2026-08-16
Status: Accepted

Sits under [0023](0023-a-finding-has-a-stable-identity.md),
[0019](0019-the-bundle-carries-a-seal.md) and
[0066](0066-a-finding-is-called-a-finding.md). Names a door
[0026](0026-one-answer-to-whether-runs-may-be-compared.md) already anticipated. Answers `B2` of the
[S-44 agenda](../next/sessions/S-44-agenda.md).

## Context

The predecessor carried **two** acceptance designs, and only one was ever used. This was verified in
code on 2026-08-16, after the agent described the wrong one from its type shape and the owner
corrected it.

- **`SuppressionRecord`** is the live one. It is keyed on the finding's own key, so - in its own
  words - *"the same finding in a new run is automatically suppressed without mutating evidence"*. It
  is referenced across eight files, it is what the accept dialog produces, and it lives in a sidecar
  database beside the audit database.
- **`SuppressionEntry`** is not. It is a pattern-based allow list with trustee, account, edge and
  pair scopes and an optional rule constraint, plumbed into the findings service through a setter -
  and `new SuppressionEntry` appears nowhere in the codebase. It was built as a capability and never
  given a producer.

Carrying both across would import a mechanism that has never run, alongside one that has.

## Decision

**An acceptance names exactly one finding.** It is keyed on that finding's identity under
[`0023`](0023-a-finding-has-a-stable-identity.md), which is what lets the same finding in a later run
be recognised as already accepted, without the acceptance ever describing a pattern.

**There is no pattern-based allow list.** An acceptance cannot say *every finding against this
principal*, or *every finding of this rule*. The predecessor's unfed allow list is not carried
across. A mechanism that accepts findings nobody has seen accepts findings nobody has seen, and an
operator cannot judge what he was never shown.

**An acceptance carries a reason, the person accepting it, and the time.** All three are required.
An acceptance with no reason is a click, and a click is the liability waiver this product refuses
elsewhere.

**An accepted finding is still a finding.** It is marked, not deleted and not hidden. The
predecessor got this right and the reason is stated in its own code: acceptance runs after the rules
have run and before anything is stored, so the finding is preserved with a flag. A report can then
say *"eleven findings, three accepted"*, which is a true sentence. *"Eight findings"* is not.

**An acceptance is permanent until it is revoked**, rather than expiring on a date. A forced expiry
manufactures a review nobody asked for and converts a considered decision into a recurring chore;
the owner's position is that a permanent acceptance is the honest default.

**Age is surfaced instead of enforced.** The screen listing accepted findings can be sorted and
filtered by age, so an acceptance made three years ago stands out from one made last week. That puts
the judgement where it belongs - with a person looking at a list - rather than in a date field that
fires whether or not anyone is watching.

**Revocation is explicit and dated.** An acceptance that is withdrawn records when, so the history
of a finding reads as a sequence of decisions rather than a current state.

**An acceptance is stored beside the evidence, never inside it.** The bundle is sealed under
[`0019`](0019-the-bundle-carries-a-seal.md) and opened read-only; the acceptances are a separate,
writable companion. Evidence is what the directory said, and an acceptance is what a person decided
about it. The predecessor drew this line - its read connection *physically cannot* write the
sidecar - and it is the right line.

**An acceptance records which run it came from**, so a reviewer can tell his own decisions from those
inherited with an imported set.

## Consequences

**Acceptance import is a door onto [`0026`](0026-one-answer-to-whether-runs-may-be-compared.md)**,
which already names it as one. Acceptances from a run that may not be compared to this one may not
be applied to it either, and that test is the one component, not a second opinion.

**A finding's identity is now load-bearing for a second reason.** `0023` made it stable so a finding
could be tracked between runs; it is now also what an acceptance points at. An identity that shifts
does not merely lose history - it silently un-accepts, and the finding returns as if new.

**The list of accepted findings is a screen the product owes**, with age visible on it. Without it
the acceptances are permanent and invisible, which is the failure this record's own reasoning warns
about.

**Nothing here decides how a finding's identity is computed.** That is `0023`'s, and this record
depends on it rather than restating it.
