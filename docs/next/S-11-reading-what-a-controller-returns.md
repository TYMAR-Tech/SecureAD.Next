# S-11 — Reading what a domain controller returns

**Type:** slice
**Inventory row:** B8 — LDAP attribute extraction
**Lands in:** `SecureAD.Audit`
**Date:** 2026-08-11

---

## What this is, in one paragraph

A search returns entries, and an entry is a bag of named values. This is the component that turns
those values into things the rest of the product can work with — text, whole numbers, GUIDs,
security identifiers — and, before any of that, decides the question everything else rests on:
**are these all the values there are?** For most attributes the answer is trivially yes. For the
ones that can grow — the members of a group, most of all — it is not, and a reader that assumes yes
reports a privileged group as smaller than it is, calmly, with no error anywhere.

The code is [`LdapEntryReader`](../../next/src/SecureAD.Audit/Capture/LdapEntryReader.cs), with
[`AttributeValues`](../../next/src/SecureAD.Audit/Capture/AttributeValues.cs) and
[`AttributeRange`](../../next/src/SecureAD.Audit/Capture/AttributeRange.cs) beside it.
`LdapEntryReaderDocumentationTests` holds this document to it. Per [`README.md`](README.md)
§When a document counts as documentation, this file is not documentation until that test holds.

## The limit that makes this hard

> **A domain controller will not return more than a fixed number of values for one attribute of one
> object, and an administrator cannot lift that limit out of the way.**

The number is `MaxValRange` in the forest's LDAP policy, **1,500 by default**
([LDAP administration limits](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/view-set-ldap-policy-using-ntdsutil)).
Raising it works only up to a point: Windows Server 2008 and later carry **hardcoded ceilings that
override the policy** whenever the policy is set higher, and for this limit the ceiling is **5,000
values**. Microsoft's own worked example is this product's exact use case — a policy set to 25,000,
and a query for the members of a group with more than 5,000 members returning 5,000
([Windows Server 2008 and newer domain controller returns only 5000 values in an LDAP response](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/domain-controller-returns-500-values-ldap-response)).

So this is not a setting a customer can turn up before running an audit. It is a property of every
forest the product will ever be pointed at.

**What it looks like from the client's side.** Microsoft's description is worth quoting exactly,
because it is broader than a single tidy rule: the results *"may appear truncated or incomplete. In
some occasions, you may not get any results."* There is no error, no warning and no count. The one
sentence that is unambiguous is the remedy: where an attribute has more values than the limit,
*"you must use value range controls in LDAP to retrieve values that exceed the MaxValRange value"* —
and for a group larger than a server will serve at once, range retrieval is *"the only way to
enumerate all members"*
([Enumerating groups that contain many members](https://learn.microsoft.com/windows/win32/ad/enumerating-groups-that-contain-many-members)).

## Asking for the rest

Values are asked for a block at a time, by naming the attribute with a range option after it:

```text
member;range=0-999
```

The two numbers are zero-based indexes of the first and last value wanted, and `*` in place of the
second means "and all the remaining ones"
([Attribute Range Retrieval](https://learn.microsoft.com/windows/win32/adsi/attribute-range-retrieval)).

**A block is a thousand values.** Microsoft's guidance is to ask for as many as the server will
serve, to keep the number of round trips down, but that *"to enable an application to work correctly
with all Windows servers, a maximum number of 1000 should be used."* A thousand is therefore the
largest number that is safe everywhere rather than a compromise, and the product uses it.

**How a block says it was the last one.** The controller answers under the ranged name it actually
served, and on the final block it puts `*` in place of the high number instead of echoing what was
asked for. Microsoft states this as a difference between the string requested and the string
returned: ask for `member;range=101-200` on a group of 150 and the name that comes back is
`member;range=101-*`
([Using IDirectorySearch and IDirectoryObject for Range Retrieval](https://learn.microsoft.com/windows/win32/adsi/using-idirectorysearch-and-idirectoryobject-for-range-retrieval)).
That wildcard, and nothing else, is what ends a retrieval. Not an empty block, not a short block,
and not a count that looks about right.

**Nothing else in the product spells a range.** `AttributeRange` owns the specifier, and
`RangeSpecifierGateTests` fails the build if the text appears anywhere else under `next/src/`. A
second speller is a second opinion about where a block ends, and the two do not disagree loudly —
both produce a plausible name, one of them gets fewer values, and nothing says so.

**This component asks for nothing.** It produces the *name to ask for*. Building a request is
[`S-9`](S-9-the-capture-unit.md)'s job and is confined to one place, because a request carries a
referral policy and a second builder is a second policy. A range retrieval is a further request and
inherits everything [`S-10`](S-10-politeness.md) says about one, including what happens when a
controller will not answer.

## Which attributes are range-retrieved

Every multi-valued one, and the question is never asked about an attribute by name.

Whether an attribute can hold many values is recorded on its catalogue entry —
[`S-8`](S-8-captured-attribute-catalogue.md) — and derived from there. A hand-kept list of "the
attributes that need range retrieval" agrees with the catalogue on the day it is written and stops
agreeing the first time somebody adds a multi-valued entry without thinking about this document. The
failure is silent and the symptom is a large group reported small, which is why the rule is derived
rather than listed.

## Three things an entry can say, and why there are three

The three states are `AttributeCompleteness`, carried on every answer this component gives.

<!-- COMPLETENESS:BEGIN -->

| State | What the response looked like | What a caller may conclude |
|---|---|---|
| Complete | The attribute came back under its own name, or a retrieval ran to the block the controller marked with the wildcard | These are all the values. This is the only state that entitles anyone to say "these are the members" |
| MoreToFetch | The attribute came back under a ranged name whose high bound was a number rather than the wildcard | What is here is the beginning of the values and must never be presented as the values. The answer carries the block to ask for next |
| NotReturned | The response did not carry the attribute at all, under its own name or a ranged one | That the attribute did not come back. Not that the object has none — see below |

<!-- COMPLETENESS:END -->

The third state is the one that costs something to keep, and it is kept deliberately.

**An absent attribute is not a fact about the forest.** An attribute is missing from an entry when
it was never set. It is equally missing when the reader was not permitted to see it: an attribute
marked confidential in the schema is withheld from a caller without `CONTROL_ACCESS` on it, and it
is withheld *silently* — the value simply is not there, exactly as though it had never been set
([Mark an attribute as confidential](https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential)).
[`0002`](../decisions/0002-absent-view-means-degraded-run.md) forbids rendering the second as the
first, because a report that says "nobody has this permission" when the truth is "we were not
allowed to look" is the one thing an audit tool must never do.

**Telling the two apart is not this row's job, and this document does not pretend otherwise.** The
obvious rule — that the schema's `searchFlags` marks an attribute confidential and its `systemFlags`
exempts the base-schema ones — was doubted for a while, because at least one published attribute
carries both marks at once. That turned out to be consistent with the documentation rather than
against it: the bit is *ignored* on a base-schema attribute, not forbidden. The rule stands, it was
settled at S-24, and **F-S7-27** is resolved.

What that rule gives is whether an attribute *could* have been withheld — never whether it *was*.
Nothing on the wire says so, and a second cause exists that the flags cannot see at all: a Windows
Server 2025 controller withholds confidential attributes from an unencrypted connection and returns
no error (`F-S24-1`). So this row's contribution is unchanged and still necessary: `NotReturned` is
a distinct state, so no code downstream can reach an empty list of values without having been handed
the fact that the attribute never arrived. Whoever interprets absence has something to attach it to.

## Where a retrieval is allowed to stop

> **There is no limit on the number of blocks, and there is no partial answer.**

A cap on rounds sounds prudent and is the defect this row exists to remove. A cap that is reached
has to do one of two things: return what it has, or fail. Returning what it has is precisely the
behaviour that turns a ten-thousand-member group into a fifteen-hundred-member one, and putting a
large number on it does not change what it is — it changes how rarely it happens, which makes it
harder to find rather than less harmful.

What bounds the loop instead is **progress**. Each block must advance: it must carry the attribute,
and it must carry at least one value. A block that does neither is a failure with a name, and a
failure ends the run, because capture is fail-fast and a partition it cannot read fully produces no
bundle ([`S-10`](S-10-politeness.md)). The loop therefore cannot spin, and it cannot settle for a
prefix. Those are the only two ways it could end badly, and both are closed.

**A partial read cannot describe itself as anything else.** The values and the statement of
completeness are one thing, not a list with a flag beside it that a caller might not look at. There
is no way to obtain the values without also holding the answer to "are these all of them".

## Reading a value once it is in hand

The conversions below each return either the value or a stated failure. None of them substitutes
anything: a value that cannot be read is reported as unreadable, because a substituted value reads
like a fact about the forest.

<!-- CONVERSIONS:BEGIN -->

| Reads a value as | Method | What it refuses |
|---|---|---|
| Text | AsText | Bytes that are not valid UTF-8, rather than replacing them. A distinguished name silently corrupted attributes an object to a container that does not hold it |
| Raw bytes | AsBytes | A value that arrived as text, rather than re-encoding it and hoping |
| A whole number | AsInteger | Text that is not a number. Read at 64 bits, because directory timestamps are 100-nanosecond intervals since 1601 and do not fit in 32 |
| A GUID | AsGuid | Anything that is not exactly sixteen bytes |
| A security identifier | AsSid | Bytes the platform will not accept as a SID. A SID misread by one byte is a permission attributed to the wrong principal |

<!-- CONVERSIONS:END -->

## How this is tested, and what the tests do not reach

There is no forest in CI, and the case that matters is a group with more members than a controller
will send at once. So the tests put a **server model** in front of the reader: an object holding ten
thousand members that behaves the way the documents above say a controller behaves — it will not put
more than `MaxValRange` values in one response, it answers under the ranged name it served, and it
marks the final block with the wildcard. The reader then runs a whole retrieval against it, exactly
as the capture loop will: ask, join, ask again with the block the answer named, until the answer says
it is complete. The test is run at the 1,500 default and again at the 5,000 ceiling, because both
are real configurations and both are smaller than the group.

That exercises the rule end to end — the specifier asked for, the blocks joined, where the values
are declared complete, and the refusal to call a partial read complete.

**What it does not reach is the wire.** Whether a production domain controller spells its ranged
names exactly as this model does is a claim about a server, and no test in this repository can
settle it. It is owed to the lab session, and it is recorded as finding **F-S7-37** rather than
implied by a green test. Stating that plainly is the point: a test that looked like proof of
something it never touched is the failure this repository has committed more than once.

## What this row does not own

- **Issuing anything.** The paging loop, and the second request a range retrieval needs, are inventory
  row B6.
- **Writing anything down.** Typed values are handed on; the bundle is inventory rows B9 and B10.
- **Interpreting an absent attribute.** The state exists and is distinct; what it means in a
  particular forest is D3's, and needs both the schema flags (`F-S7-27`, resolved at S-24) and the
  security of the connection the values arrived over (`F-S24-1`).
