# 0023 - A finding has a stable identity, and an unmatched acceptance is reported rather than dropped

Date: 2026-08-12
Status: Accepted

## Context

A customer accepts a finding once and expects it to stay accepted. A comparison between two runs is
only meaningful if the same finding can be recognised months later, through renames, moves and
reorganisations. Both depend on one thing: what makes a finding *the same finding*.

Get it wrong and everything looks new every month, acceptances evaporate, and a comparison reports
churn instead of change.

## Decision

**A finding is identified by its rule, its subject, and the object it is about.** The object is
identified by `objectGUID`, which is immutable in Active Directory and survives both rename and move.
The subject is a **kind and a key**, not a security identifier, because findings about containers,
policies and other things without a SID must not be wedged into a column that assumes one.

**The rule's version is recorded beside the finding and is not part of its identity.** Tightening a
rule's logic must not orphan every acceptance made against it.

**A finding records whether the evidence behind it was complete.** A finding that has disappeared has
more than one explanation, and they are not interchangeable.

**An acceptance that does not match is never silently dropped and never silently re-applied.** It is
reported, with a reason drawn from a fixed set rather than free text, so that a screen cannot render
two of them the same way:

| Reason | Meaning |
|---|---|
| Resolved | The finding is gone and coverage was complete |
| Subject changed | Same rule, overlapping subject - the thing being described is not quite the thing that was accepted |
| Rule superseded | The rule was replaced |
| Object gone | The object no longer exists |
| Not captured | This run could not read where it lived |

**Consent is not inherited across a rule change.** Where a rule supersedes another, the relationship
is reported and the acceptance is not carried over. A replacement rule may be stricter than the one
it replaces, and agreement to the old one is not agreement to the new.

## Consequences

Rules whose subject is a *set* rather than a single object - group nesting cycles, most obviously -
change identity when the set changes, and the finding returns. This is correct: a cycle that has
gained a privileged group is a different risk. It is handled by **comparison**, which sees the same
rule with an overlapping subject and reports it as *changed* rather than as one resolved and one new.
Solving it there covers rules that do not exist yet.

The "not captured" reason must never be presented as "resolved". Doing so would tell a customer their
problem is fixed when it is merely invisible, and it would reappear next month looking like a
regression.

Acceptances record where they came from, so an auditor can tell one they made from one inherited from
an earlier run. Without that, a fall in outstanding findings cannot be attributed to work rather than
to a wholesale carry-forward.

What was **offered and declined** is recorded as well as what was taken. A run that declined to carry
forward earlier decisions must not look identical to one where none were ever made.
