# 0042 - DNS zones and records are out of scope, and the bundle says so

Date: 2026-08-13
Status: Accepted

Records the DNS scope decision of 2026-08-11, which until now existed only as remarks on
`CapturedAttributeCatalog.UnreadObjectClasses`. Nothing about the decision changed; it acquired the
authority it was being treated as having. Raised as `F-S31-6`.

## Context

Active Directory-integrated DNS stores its zone data in two application directory partitions that
every forest has - `DomainDnsZones` per domain and `ForestDnsZones` per forest - holding `dnsZone`
objects and, beneath them, one `dnsNode` object per record. A large forest holds hundreds of
thousands of them.

The product declines to read them, and has done since 2026-08-11. The decision was enforced in two
independent places and written down in neither:

- `CapturedAttributeCatalog.UnreadObjectClasses` excludes the classes `dnsNode` and `dnsZone`
  wherever they appear, under [`0034`](0034-capture-excludes-a-shipped-noise-list.md)
- `ForestPartitions` classifies the DNS partitions as ones the run does not open at all, so the
  partitions are never searched

Only the first carried any reasoning, and it carried it as a doc comment. Per
[`docs/next/README.md`](../next/README.md) a comment is discussion rather than the product's
position, which left a choice the product makes on every run resting on nothing that states it. The
prompt to write this record was the owner's intention to tell customers, in the product's help,
that DNS zone permissions are not assessed - a customer-facing statement is not something to derive
from a code comment.

**The security content of those partitions was checked against Microsoft's documentation before
this record was written**, rather than assumed from the earlier decision:

- The partitions are not a special case for permissions. *Application Directory Partition Security*:
  "The security and access control model for application directory partitions is the same as that
  for other partitions in Active Directory Domain Services."
- The zones in them are open by default. *DNS zones*: "By default, any authenticated Active
  Directory user can create the A or PTR RRs in any zone." Microsoft's guidance discusses reserving
  names and tightening that ACL, and warns elsewhere that records created without ACLs leave an
  environment vulnerable to name hijacking.
- The group that administers them is a documented target. Microsoft Defender for Identity ships a
  security assessment, *Unsafe permissions on the DnsAdmins group*, describing it as privileged and
  commonly delegated to non-AD administrators.

So the partitions are not empty of security meaning, and a decision to skip them cannot rest on the
claim that they are.

**What settles it is a different property.** *About Application Directory Partitions*: "An
application directory partition can contain instances of any object type **except security
principals**, such as users, computers, or groups." Nothing in a DNS partition can hold a
permission, be a member of anything, or be a step on the way to something else. It can only ever be
a target.

That is the same test [`0034`](0034-capture-excludes-a-shipped-noise-list.md) applies to the shipped
noise list - a class may be excluded only if it can be neither a hop nor a principal - reached
independently and satisfied here.

The remaining question is therefore narrow: are the permissions *on* the zones worth capturing? No
rule in the catalogue evaluates them, and none is proposed. The rule catalogue's own standard is
that a rule must state what it looks for and what the organisation can thereby mitigate; capturing
several hundred thousand objects to populate a table no rule reads meets neither half.

## Decision

**DNS zones and records are out of scope, and are not read.** The classes `dnsNode` and `dnsZone`
are excluded from every search, and the application directory partitions holding them are never
opened. Both mechanisms stay: the class exclusion covers a zone object wherever it is found, the
partition skip stops the product opening a partition it would then read nothing from.

**No escalation path is lost by this, and that is why it is defensible.** Application directory
partitions cannot contain security principals, so no object in one can hold a right, belong to a
group, or be a hop in a path. This is the same admissibility test as `0034`'s, and it is the whole
justification: were it to stop being true, this decision reopens.

**What is given up is stated exactly, and never implied.** The product says: *DNS zone and record
permissions are not assessed. DNS administrative group membership is.* The second half is not a
consolation - `DnsAdmins` is a security principal, it lives in a domain partition, and it is
captured, assessed and reported like any other group.

**The bundle records the partitions it did not read.** One row per declined partition in
`unread_partition`, written before the first read. Without it a reader cannot distinguish a forest
whose DNS partitions were skipped from a forest that has none, which is the inference
[`0002`](0002-absent-view-means-degraded-run.md) forbids being available, about a part of the
directory [`0017`](0017-capture-reads-the-whole-forest.md) requires a run to state it did not reach.
The operator's console already said it; a console is not evidence.

**The product's help states it too**, because a customer deciding whether DNS zone permissions have
been reviewed should not have to read a bundle to find out that they have not.

**This is not an operator setting.** Consistent with `0017` and `0034`: nothing a customer can
switch makes a run read less, and there is no configuration that turns DNS zones on or off. If they
are ever read, it is because this record changed.

## Consequences

Capture avoids hundreds of thousands of objects in a large forest, and the analysis that would
follow them. That is the same saving `0034` measures for noise classes, and it is the reason the
decision was taken.

**A customer with a delegated DNS zone gets no finding about it**, and gets a clear statement that
none was looked for. The remedy is a manual review, and the product says so rather than being
silent. Anyone who reads the report as "DNS is fine" has been told otherwise in two places.

**Nothing about a DNS zone can be answered from a bundle afterwards.** Not the permissions, not the
record count, not who could write to it. Answering such a question requires a different product
decision and a fresh capture - `0034` records the same consequence for excluded classes.

**The decision reopens if a rule needs it.** The natural candidate is over-permissive delegation on
an AD-integrated zone, which is real, is documented by Microsoft, and has no other source. Should
such a rule be written, this record is what it has to overturn - and the argument it must beat is
cost, not relevance, because relevance is conceded above.

**The two enforcement points must not drift.** A future change that reads the DNS partitions while
leaving the class exclusion in place would open partitions and store nothing from them; the reverse
would leave the classes excluded but pay to search partitions that hold nothing else. They are one
decision with two implementations and should be changed together.
