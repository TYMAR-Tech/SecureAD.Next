# 0014 - Capture reads the schema partition, and names come with it

Date: 2026-08-10
Status: Accepted

## Context

[`0008`](0008-live-verification-is-removed.md) states that capture "reads the directory, including
the schema partition." It does not, and never did. The only code that reads the schema for GUIDs is
`LiveDiagnosticsService.SchemaTools.cs`, reached from the Inspect view that `0008` removes, and the
survey already records the result: `dim_guid_map` "will be permanently empty" once that view goes.

So a decision record asserted coverage that did not exist, and the row that would have noticed sat
undecided. That is worse than a gap, because the next reader concludes the capability survives.

An access control entry scopes a permission by GUID. Base-schema GUIDs are the same in every
forest, but every forest also carries extensions - vendor products and locally created attributes,
the latter with GUIDs generated at creation and unique to that forest. Without reading the schema,
those are permanently unnameable. Worse, the component that builds the control graph matches nine
GUIDs hardcoded in its own file, so a permission scoped to an unrecognised GUID produces no control
edge at all: not assessed and found safe, never examined.

The friendly names an administrator recognises are in the directory too. "Reset Password" is the
`displayName` of the `User-Force-Change-Password` control access right, and attribute labels come
from the display specifiers. They do not need authoring.

## Decision

Capture reads the schema partition and the extended-rights container, and records what it finds in
the bundle. This is part of capture, by decision rather than by assumption.

Both the GUID and the label are captured. A name shown to a user is sourced from the directory, not
invented.

The catalogue is one lookup over two layers - shipped and captured - and every answer states which
layer supplied it, so evidence can distinguish a published fact from an observed one.

A base-schema GUID captured from a forest that disagrees with the shipped value is a finding.
`schemaIDGUID` is system-only and cannot legitimately differ, so a mismatch is either a defect in
the reader or something wrong in the forest, and neither is resolved by picking a winner.

## Consequences

Capture gains two searches against the Configuration naming context, on the order of a few thousand
objects. The cost is fixed rather than proportional to the forest, is paid once per forest rather
than per domain, and needs no privilege beyond reading the directory.

A bundle becomes self-describing: it can be read years later, on a machine that has never seen the
forest, and still name every permission it contains.

Ledger row D3 owns this. It already owns turning schema and extended-right GUIDs into names a
bundle can be read with; it now owns its own feed, rather than depending on one that was deleted.

Unknown GUIDs become rare rather than routine, but they do not disappear - a deleted schema object
or an uninstalled product can still leave one behind. What the product reports when it cannot name
a GUID remains undecided and is not settled here.
