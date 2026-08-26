# What an object holds

**Code:** `next/src/SecureAD.Evidence/ObjectAttributes.cs`
**Layer:** Evidence — one object's attribute values, as the bundle stored them.

[`what-a-bundle-holds.md`](what-a-bundle-holds.md) describes the tables a bundle is made of.
This page is one object read back out of them: the whole catalogue of attributes rather than the
part that arrived, each value still text or still bytes, and a plain statement of what the
connection it was read over could have been served. It is what the object window on screen is
built from.

The door is `BundleReader.ReadObjectAttributes`, which belongs to
[`how-a-bundle-is-read.md`](how-a-bundle-is-read.md); the reader behind it,
`ObjectAttributesReader`, is internal and is described here because its behaviour is the only
thing a caller can observe about it.

Bound by `ObjectAttributesDocumentationTests`. The storage table below is bound **in both
directions** against the shapes the code actually produces — a storage kind the code handles and
this page does not name fails the build, and so does a row here describing a shape the reader
never produces.

---

## What this page owns

<!-- TYPES:BEGIN -->

| Type | What it is |
|---|---|
| `ObjectAttributes` | Every attribute value this bundle holds for one object, and the statement of what the connection could have been served |
| `ObjectAttribute` | One attribute: what the catalogue asked for, and what the bundle holds for it |
| `AttributeValue` | One value of one attribute, still text or still bytes, exactly as the bundle stored it |

<!-- TYPES:END -->

This table is the page's claim of ownership, and it is bound in both directions: a public type of
this component missing from it fails the build, and so does a row naming something that is not one.
Other pages name these types in passing — to say where a boundary is, or what a column holds — and
a mention is not a claim. That distinction is the whole difference between a page describing a type
and a page pointing at one.

## The whole catalogue, not the part that arrived

`ObjectAttributes.Attributes` holds **every attribute the catalogue names**, whether or not a
value came back for it, ordered by name so that two objects are read the same way round.

This is the point of the type. Capture asks every object for every catalogued attribute whatever
its class, so handing back only the attributes that have values would make a section on screen
guess why it has nothing to show — and would leave *we were refused this* looking exactly like
*this build never asked*. An attribute that is present and empty says the first thing. An
attribute that is absent from `ObjectAttributes.Attributes` says the second, and
`ObjectAttributes.Find` returns null for it.

So `ObjectAttribute.HasValue` is a fact about the object, and a null from
`ObjectAttributes.Find` is a fact about this build.

**What an empty attribute does not distinguish.** An attribute with no values may mean the object
holds no value, or may mean the reader was refused it. The directory does not tell those apart,
and [`0022`](../../decisions/0022-objects-are-stored-as-typed-columns.md) rules that the
distinction is unobservable at capture — so nothing here records a per-attribute completeness,
because doing so would record a guess. What *is* recorded is the connection-wide statement below.

## A value is text or it is bytes

`AttributeValue` keeps the two apart all the way out, as `EvidenceValue` keeps them apart on the
way in. `AttributeValue.Text` is null for a byte value and `AttributeValue.Bytes` is null for a
text value; which of the two arrives follows the attribute's `AttributeStorage` in the catalogue,
never a guess about the characters.

**Nothing here is worded.** A `userAccountControl` of `514` arrives as the four characters the
directory sent. Whatever turns that into *Disabled* does so somewhere a reader can see both,
because a wording this build gets wrong is invisible otherwise.

`AttributeValue.Stored` is the one place bytes become characters, and it says so by being
hexadecimal rather than something that could be mistaken for a value the directory holds.

<!-- STORED:BEGIN -->

| Storage | `AttributeValue.Text` | `AttributeValue.Bytes` | `AttributeValue.Stored` |
|---|---|---|---|
| Text | the characters the directory sent | null | the same characters |
| Binary | null | the octets the directory sent | those octets in uppercase hexadecimal |

<!-- STORED:END -->

Reading an octet string back as text produces a mangled string that still looks like data, which
is why the distinction is carried rather than collapsed: `objectSid` is what a trustee is matched
on.

## One value, or many, in the controller's order

`ObjectAttribute.Cardinality` says whether the directory allows the attribute more than one value,
and it comes from the catalogue rather than from how many values happened to arrive. A
single-valued attribute with nothing in it is still `AttributeCardinality.SingleValued`.

`ObjectAttribute.Values` is the values in the order the controller sent them, and
`AttributeValue.Ordinal` carries that position, counting from zero. The order is kept because
losing it would silently reorder a membership list that nobody could then check against the
directory. For a single-valued attribute the ordinal is always zero.

`ObjectAttribute.OnlyValue` is the first value or null, and is defined for a multi-valued
attribute too. A caller that genuinely wants the first of many should say so by reading
`ObjectAttribute.Values`.

## The two the schema stores under a name of its own

`distinguishedName` and `objectGUID` are columns of the object's identity rather than derived
attribute columns, and a caller asking for them by name should not have to know that. Both are
readable as ordinary attributes.

`objectGUID` comes back in its canonical spelling rather than as bytes, because the canonical
spelling is what the bundle stored and what two runs are joined on. Handing back what the bundle
stored is the whole rule.

## What the connection could have been served

`ObjectAttributes.Completeness` says whether the connection this object was read over could have
been served confidential attributes at all. It is an `EvidenceCompleteness`, and it is the same
statement `EvidenceObject.Completeness` makes about the same object on the way in — recovered by
joining the object's coverage row, not recomputed here, so the two cannot drift apart.

**It does not say every attribute is here**, and it is not named as though it does. Nothing read
from a directory can say that. A Windows Server 2025 controller strips confidential attributes
from an unencrypted search and returns no error, so an encrypted connection yields
`EvidenceCompleteness.Complete` and an unencrypted one yields
`EvidenceCompleteness.MayBeMissingConfidentialValues`, whatever the object turned out to hold.

The coverage row is joined in the same query that reads the object rather than fetched separately,
because an object and the rung it was read over are one fact. Two queries would let a caller hold
an object beside somebody else's coverage.

`ObjectAttributes.CapturedUtc` is carried for a related reason: a timestamp is only meaningful
beside the moment it was read. A password last set six days before a capture is a fact about that
forest and stays one, where the same value measured against a reader's own clock says something
different every morning.

## Finding one

`ObjectAttributes.Find` matches case-insensitively, because the directory treats attribute names
that way and a section naming one must not have to spell it however the catalogue happens to. It
matches on `ObjectAttribute.LdapDisplayName`, which is the attribute under the name the catalogue
asked for rather than under any name a controller may have answered with.

`ObjectAttributes.DistinguishedName` is the object as the controller named it.

`ObjectAttributes.ObjectGuid` is which object it is, immutably. It is typed rather than left to be
parsed out of the `objectGUID` attribute, because it is what a finding's identity rests on and what
two bundles are joined on — it survives both a rename and a move, which the distinguished name does
not. Null is possible and meaningful: an object the controller returned without one cannot be
identified across runs at all, so nothing that has to outlive this bundle may be attached to it.

## What is not here

Which attributes the catalogue asks for, and why each is justified, is
[`the-attribute-catalogue.md`](../audit/the-attribute-catalogue.md)'s. The tables these values are
stored in are [`what-a-bundle-holds.md`](what-a-bundle-holds.md)'s. Neither vocabulary is restated
on this page.
