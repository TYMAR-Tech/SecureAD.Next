# 0022 - An object is stored as typed columns, and what was never captured is recorded by reference

Date: 2026-08-12
Status: Accepted

## Context

How an object's attributes are stored decides the shape of everything that reads a bundle - every
grid, every rule, and comparison. Capture collects 45 attributes per object, and the questions asked
of them are direct: which accounts are disabled, which have password-never-expires, which computers
are domain controllers, everything under this container.

The implementation committed on 2026-08-12 stored one row per object per attribute. It was chosen to
preserve a distinction: an attribute that did not come back versus one that is genuinely empty. That
distinction turned out not to exist in the data. Active Directory returns an absent attribute the
same way whether it was never set or withheld, and per Microsoft's own account a **base schema
attribute cannot be marked confidential at all** - which covers the attributes this product
captures. The mechanism preserved a difference the protocol does not provide, at the cost of turning
every query into a reassembly, and of roughly forty rows per object where one would do.

The question the design was reaching for is real. It was simply aimed one level too low: the risk is
not an attribute we could not read, it is **an object we could not see at all**, which is absent from
a search with no row and no error.

## Decision

**An object is one row with typed columns.** Attributes that are single-valued become columns;
multi-valued attributes get their own tables. There is no per-attribute record of what did not
arrive, because it would record nothing.

**An object's identity is its `objectGUID`**, which survives a rename and a move between containers.
Neither the distinguished name nor a row number is an identity, and a comparison joined on either
would report a moved object as one deleted and one created.

**What was never captured is recorded by reference, not by self-report.** The bundle records the
things something pointed at and that were never seen: a group member, a permission trustee, a parent
container, a primary group. Each carries a reason - in a domain that was not captured, in another
forest, an orphaned identifier, or unreadable.

## Correction, 2026-08-13

Recorded per [`0032`](0032-a-decision-record-is-corrected-in-place.md). The `## Context` above is
left exactly as written, because the reasoning that produced an error is worth more than a tidy
record of the conclusion.

**The argument in that section is withdrawn.** It claims that the withheld-versus-unset distinction
*"turned out not to exist in the data"* because *"a base schema attribute cannot be marked
confidential at all — which covers the attributes this product captures."* Both halves fail. The
general claim was challenged on 2026-08-11 as `F-S7-27`. The coverage claim failed on 2026-08-13,
when [`S-23`](../audit/the-attribute-catalogue.md) added `msLAPS-PasswordExpirationTime` and
`ms-Mcs-AdmPwdExpirationTime` — schema extensions rather than base schema, either of which a
customer can mark confidential.

**The decision stands, on a reason this record did not give.** The distinction is not merely
unrecorded, it is **unobservable at the point of capture**. Active Directory omits an attribute the
caller may not see in exactly the way it omits one that was never set: *"a search operation can
succeed, but the search results don't include objects or properties to which the caller doesn't
have access"*
([Access Control and Read Operations](https://learn.microsoft.com/windows/win32/ad/access-control-and-read-operations)).
A per-attribute column recording which of the two had happened would be recording a guess, whatever
the schema flags say. That reason holds for base-schema attributes and extensions alike, and does
not depend on any claim about which is which.

**And the risk this record was reaching for turned out to live somewhere else.** The case where
confidential attributes really do vanish without an error is a *connection* property, not a schema
one: a Windows Server 2025 controller strips them from an unencrypted search and returns no error
to the client. That is `F-S24-1`, it is owed to the connection ladder at row **A2** and to this
schema as a per-controller record, and no per-attribute column would have caught it.

## Consequences

Queries are direct, and indexes work. The shape is the one whose performance has been measured in
production, which is the only performance evidence that exists.

Adding an attribute later is a schema change. That is cheap here because
[`0001`](0001-no-backward-compatibility.md) keeps nothing backward compatible and there are no
bundles in the field: a new capture writes a new bundle, and
[`0021`](0021-re-analysis-produces-a-new-bundle.md) can re-derive from old ones.

The honesty this buys is the kind an administrator can act on. *"417 permissions are granted to
principals this capture never saw, and 300 of them are in a domain you excluded"* leads to re-running
with a different account, adding the domain, or accepting the gap knowingly. *"This attribute did not
arrive"* led nowhere.

It also means an unseen object is visible as a hole rather than as silence. That matters more than
the mechanism it replaces, because an object we cannot read takes its permissions with it, and the
audit would otherwise report the forest as covered.
