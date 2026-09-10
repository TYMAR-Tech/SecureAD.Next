# 0117 - Naming-context roots are Tier-0 assets

Date: 2026-09-10
Status: Accepted.

The owner approved this on 2026-09-10, together with the principle that a permission's consequence is
partition-specific. It widens the authoritative Tier-0 definition. It does not authorize an AD CS
feature, a UI change, live access or a production budget.

## Why

Decision [0116](0116-discovery-first-assessment-admission.md) made discovery decide which objects
receive detailed control assessment, by following incoming controller and membership relationships
back from the supported Tier-0 seeds. Those seeds are principals: the classifier recognises the
well-known relative identifiers of Domain Admins, Schema Admins, Enterprise Admins and their peers,
plus five BUILTIN groups.

A naming-context root is not a principal. `DC=contoso,DC=com`, `CN=Configuration,...` and
`CN=Schema,CN=Configuration,...` carry no `objectSid`, so none of them can hold a permission, own an
object, or appear as the controller end of any relation. **No route can reach them.** Under 0116 they
would be recorded as not assessed automatically, permanently, in every forest.

That is a false negative on the most consequential object in a partition. The replication rights
`DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` are granted **on the partition
root**, and on a domain root that combination is DCSync: every password hash, key credential and
managed-service-account secret in the domain, read without touching a domain controller's disk. The
previous behaviour of assessing every object found this. Discovery-first, as written, would not.

The gap was found by a test that failed for the right reason during the fixture re-anchoring for
0116, not by review.

## Decision

A captured naming-context root is a Tier-0 asset in its own right, and a supported discovery seed.

This is a third qualifying basis beside the existing two. It rests on what the object *is* - the head
of a directory partition, identified by the capture's own recorded naming contexts - rather than on a
SID the object does not have. A root qualifies only where the capture recorded that naming context
and the root's captured `objectClass` matches the kind recorded for it: `domainDNS` for a domain,
`configuration` for the configuration partition, `dMD` for the schema partition. A mismatch is an
unverified identity, not a seed.

Admitting a root admits, in turn, the principals holding supported incoming permissions on it. It
does not admit everything the partition contains: a root is the head of a partition, not a
transitive claim over its members, and containment is not control.

## Consequence is partition-specific

**Being worth assessing and being equally dangerous are different questions.** All three roots are
seeds. What a permission on one *means* is not the same in each:

| Partition | What replication rights reach |
|---|---|
| Domain | Password hashes, key credentials, LAPS and gMSA secrets. This is DCSync. |
| Configuration | Forest topology, services, certificate templates. No credential material. |
| Schema | Class and attribute definitions. No credentials and no configuration. |

The existing `ReplicationControlDeriver` already makes this distinction and keeps it: it reads the
captured naming-context kind, requires the root's object class to agree with it, and records
`ResourceContextUnverified` for any holder on a non-domain partition, because no servicing or token
context is established for those partitions in the current slice. A configuration or schema grant is
therefore already reported as Unknown rather than as established domain-secret exposure.

**That treatment is retained and must not be flattened.** Admitting these roots must not cause a
schema-partition grant to be reported with the weight of a domain one. An administrator who is sent
to investigate a finding that yields a list of attribute names has been sent on an errand the
evidence never justified.

## What this does not decide

The configuration partition holds `CN=Public Key Services`, and a writable certificate template can
be an escalation path that does not resemble replication at all. Enterprise CA classification is
already declared in [0099](0099-the-tier-0-control-plane-catalogue.md) with implementation deferred
as `P-142`. Nothing here implements it, and a root being a seed is not an AD CS capability.

Whether the shell should let an administrator navigate the configuration and schema partitions as it
does the domains is open, and deliberately not settled here.

## Acceptance

A replication permission granted on any captured naming-context root is assessed automatically once
discovery gates assessment, and the principals holding it are admitted for assessment in turn. The
partition each root belongs to is preserved on the stored result, and a non-domain partition grant
does not claim domain-secret exposure. A root whose captured object class disagrees with its recorded
naming-context kind is an unverified identity rather than a seed, and its coverage says so.

Existing findings, severities and the ordinary rule pass are unchanged. The old all-object control
counts remain history rather than acceptance oracles, per 0116.

## Boundaries

No timed run, measurement harness or benchmark is authorized; the one-shot and both S1 claims remain
consumed. No live forest access, recapture, production budget, host activation, commit, push or reset
follows from this decision. Production-scale acceptance against the recorded nine-domain shape remains
separate and outstanding.
