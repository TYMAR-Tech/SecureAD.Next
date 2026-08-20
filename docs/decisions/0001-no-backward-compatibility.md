# 0001 - The product has never shipped, so nothing is kept backward compatible

Date: 2026-08-02
Status: Accepted

## Context

SecureAD has no installs in the field, no customer data on disk, and no capture bundles that
predate any change made now. Bundles that exist on development machines are disposable and can
be recaptured in minutes.

Absent an explicit statement of this, work was repeatedly scoped as though the opposite were
true. Proposals arrived carrying schema migrations, legacy-format readers, and one-time sweeps
for artefacts accumulated by earlier builds — half of the effort in each case spent defending
against a past that does not exist.

## Decision

No backward compatibility of any kind is maintained:

- **No schema migration.** A schema change is a schema change; bundles written by an older build
  are discarded, not upgraded.
- **No legacy-format readers** and no compatibility shims for previous on-disk layouts.
- **No cleanup path for existing artefacts.** A change does not need an upgrade prompt, a
  version check, or a sweep of what earlier builds left behind.

## Consequences

Breaking changes to the on-disk format cost only the code change. This makes it cheap to fix a
schema that is wrong rather than layering around it, which is the main reason the decision is
worth stating.

It does **not** license churn in working code. The bias toward leaving a tested product alone is
about the risk of breaking it, which this decision does not reduce. What it removes is only the
migration half of a proposal.

It also forbids lenient fallbacks justified as tolerating "old" data. There is no old data, so a
reader that silently accepts a shape this build does not write is not being compatible — it is
hiding a defect.

This decision must be revisited the first time a build is given to anyone outside the project.
