# 0034 - Capture reads every object class except a shipped list of noise, and the operator may only widen it

Date: 2026-08-13
Status: Accepted

## Context

[`0017`](0017-capture-reads-the-whole-forest.md) decided that capture reads the whole forest, and
recorded that the cost of doing so was unmeasured. It is measured now: in one production forest a
single vendor class — an SSO profile object hung beneath each user — accounts for **two thirds of
all objects captured**. Three objects are read, stored and analysed for every real user.

The previous product had a filter for this and got it the wrong way round. It named twelve object
classes to capture and dropped everything else, which is why it never captured Active Directory
Certificate Services: certificate templates and enrollment services are not among the twelve, no
test could notice, and the AD CS rules sat marked as verified while their query matched nothing a
real run had stored. An allowlist fails silently and in the attacker's favour.

The classes at issue are leaves. They hold no members, nothing is created beneath them, and they
are not security principals, so no escalation path can pass through one to reach something that
matters.

## Decision

**Capture reads every object class except a list of noise classes shipped with the product.** The
list is named in the catalogue beside the DNS classes already there. It is not a customer setting
and not a configuration file.

**A class may be on that list only if it can be neither a hop nor a principal** — not a security
principal, and nothing can exist beneath it. A test holds this, so the list cannot later acquire an
organisational unit or a group.

**Excluded objects are never read.** The exclusion is part of the search filter, so the objects
cost no wire, no disk, no analysis, and nothing about them can be answered from the bundle
afterwards. Answering a later question about them requires a fresh capture.

**The operator may ask for a comprehensive run**, which reads everything including the noise. The
switch only ever adds. There is no setting that reads less than the default, so no run can be made
clean by omission.

**A bundle states which it was**, and names the classes it did not read. **Runs made under
different settings are not comparable without saying so**, because an excluded class would
otherwise appear as several million objects created or deleted between two runs.

**Objects that are captured are counted by class**, which costs nothing during a read that is
happening anyway and is how the next noisy class is noticed.

## Consequences

Capture, analysis and bundle size fall by roughly the share the noise occupied — two thirds in the
forest that motivated this. A class nobody has thought of is still captured, so the next schema
extension and the next attack surface arrive covered rather than missing.

A newly noisy class needs a product release to exclude, not a setting. That is the price of the
guard being enforced at build time, and the per-class census means it is seen rather than reported.

Nothing can be asked later about an excluded object. A bundle can say the class was not read and
cannot say how many there were or who could write to them.
