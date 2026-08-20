# 0025 - The run library is a managed root, and a baseline belongs to a forest

Date: 2026-08-12
Status: Accepted. The reasoning about excluded domains and attestation is superseded by
[`0027`](0027-coverage-varies-only-by-failure-or-by-the-forest-changing.md), which reached the same
conclusion on different grounds; everything else here still binds.

## Context

A run produces a bundle - a directory holding the evidence file, its seal, the customer's
annotations, and, where the run ended badly, a note saying which ending it was. Where those bundles
live had not been decided, and
[`docs/history/DESIGN-the-run-library.md`](../history/DESIGN-the-run-library.md) recorded the three
options: a managed root the tool owns, no catalogue at all with a destination chosen per run, or
both.

The choice is not about file placement. A catalogue is what lets the product answer *what runs
exist*. Without one there is nothing to list, nowhere for a baseline to live, and comparison cannot
offer "runs comparable with this one" because it does not know what there is. Deleting a failed
run safely also needs an answer to *is this directory one of ours*, which only a managed root
provides.

The predecessor hardcoded `%LOCALAPPDATA%\SecureAD\Runs\{session|library}\<runId>\` into two
constructors. A tool that decides for itself where several gigabytes of evidence go is a tool that
fills the wrong disk.

A second question rode on the first: what a baseline is the baseline *of*. The predecessor keyed it
to `ProfileId`, which is a hash of the forest FQDN and nothing else. Whether that is right depends
on how much two runs of one forest can differ, which is what the attestation ladder already governs.

## Decision

**The tool owns a root directory, and the root is configuration.** Runs are created inside it. The
operator chooses where it is; the tool chooses the layout within it. An operator who wants evidence
on a particular volume sets the root, not a path per run.

**There is no second tier.** The session and library split goes, as
[`S-15`](../history/S-15-storage-dispositions.md) already recorded: it was machinery for scoped
capture, which no longer exists, and two trees means two retention rules - which is what already
pruned logs to twenty-five runs while keeping forever the bundles they explained.

**Capture to an arbitrary path is not offered, and neither is registering an outside bundle.**
Option C's flexibility buys a state the other two cannot reach: a catalogue entry pointing at a
bundle that has moved or been deleted. That is a list of runs which are not there, and every reader
of the catalogue then needs a missing case. The predecessor's four candidate database locations,
three of them labelled legacy, are what that state looks like after a few years.

**The path guards come across whole.** Containment normalises both sides, requires a trailing
separator and rejects the root itself; identifier validation rejects rooted paths, both separators,
`.`, `..` and invalid filename characters; every entry point taking a caller-supplied path resolves
it first. This is a real traversal defence, and deletion depends on it.

**A baseline belongs to a forest.** One nominated run per forest, and the forest is the grouping
key.

Splitting the baseline further - by forest and declared coverage - was considered and rejected,
because the attestation ladder already removes the runs that would make it necessary. Every run
declares the whole forest per [`0017`](0017-capture-reads-the-whole-forest.md). The only way
coverage varies is an excluded domain, and an exclusion is attested. A domain excluded as populated
is recorded degraded and costs the run its baseline eligibility. A domain excluded as empty is
tested after capture against the members the forest actually reported, and a falsified claim is
recorded as what it turned out to be rather than as what was claimed - which costs the run its
eligibility too. So the runs that can ever be a baseline are full-forest runs and runs whose only
exclusions were verified genuinely empty, and those are comparable to each other.

A second grouping axis would be a near-duplicate of a mechanism that already works. This repository
has three near-identical ways to ask one question about distinguished names, and that is how it
happened.

## Consequences

The operator has one folder to restrict write access to, which is the recommendation
[`0020`](0020-the-seal-detects-corruption-not-tampering.md) makes and could not previously offer a
way to follow.

A bundle can still arrive in the root by hand - copied from another machine, restored from a
backup. The forest key means it lands in its own group rather than being silently offered as a
comparison partner for a forest it does not belong to. This is not a supported workflow; it is the
cost of the key being zero and the failure it prevents being silent.

Alternate credentials are not offered, so in practice one machine audits one forest and there is
one group. The key is kept anyway, for the paragraph above.

An operator who wants a single run on a different volume cannot have it without moving the root.
That is the price of not having dangling catalogue entries, and it is reversible: option C is
reachable from here, and not from option B.

Failed-run deletion, ruled on 2026-08-12, becomes safe to implement, because *inside the library*
is now a question with an answer.
