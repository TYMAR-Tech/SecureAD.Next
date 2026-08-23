# Reading a distinguished name

**Code:** `next/src/SecureAD.Kernel/Naming/`
**Layer:** Kernel — pure logic. Touches no directory, no disk and no clock.

Three questions about a distinguished name, and nothing else: what is this object called, what
contains it, and which domain is it in. Plus one index key derived from the same string.

---

## This page and `naming.md` are one word apart and are different subjects

[`naming.md`](naming.md) opens *"Naming what the directory stored"* and is about turning **stored
values** into words — who a SID is, what a right grants, what an account's flags say, what a
timestamp means. It documents `next/src/SecureAD.Kernel/Security/`.

This page documents `next/src/SecureAD.Kernel/Naming/`, which is about the **distinguished name**:
the string a controller uses to address an object. The folder and the other document share the word
*naming* and share nothing else. **They must not be merged.** A reader arriving at either from a
folder listing should be told which one they wanted, which is what these two paragraphs are for.

---

## Why this is a component rather than a `Split`

A distinguished name looks like a delimited list and is not one.

```text
CN=Smith\, John,OU=Users,DC=corp,DC=local
```

That is one person, in one organisational unit, in one domain — four components, not five. The comma
inside `Smith\, John` is part of the value, escaped, per RFC 2253 §2.4. Split on `','` and the parent
becomes ` John,OU=Users,DC=corp,DC=local`, a container that does not exist, and the person's name
becomes `Smith`.

Names containing commas are not exotic. *Surname, Forename* is the default display format in a great
many directories, so the escaped comma is the **common** case in exactly the objects an audit tool
cares most about: people.

Every operation here scans for an *unescaped* comma for that reason. One scanner, in one place, is
the argument for the component: the alternative is the same decision taken separately at every call
site and got wrong in a different way at each.

---

## The component

`DnHelper` is a public static class in namespace `SecureAD.Kernel.Naming`, and it is the whole
folder. There is no state, no interface and nothing to construct.

| Member | Answers | Absent input |
|---|---|---|
| `GetParentDn` | What contains this object | `null` |
| `ExtractFirstRdn` | What this object is called | the input, unchanged |
| `ExtractFirstRdnOrNull` | As above | `null` |
| `ExtractNameFromDn` | As above | `""` |
| `DnToFqdn` | Which domain this object is in | `""`; a `null` DN throws |
| `ReverseDn` | The index key that makes a subtree question a prefix scan | `""`; a `null` DN throws |

**The absence conventions are the point of this table.** Three members answer the leaf-name question
and differ only in what nothing looks like, and the difference is real: a display surface that binds
`null` falls back to another column, while one that binds `""` renders a blank cell claiming the
object has no name. A caller that picks the wrong one produces a screen that is confidently wrong
rather than one that fails.

**Two members refuse a null DN rather than reporting an empty answer.** An empty DN is a caller with
nothing to look up. A null DN is a caller that lost its input, and reporting *no domain* for it turns
a defect into a routine answer nobody investigates.

---

## `ReverseDn` is the odd one out, deliberately

Every other member answers a question about a DN. This one produces a key **no reader should ever
display**.

A DN is written leaf-first, so every object beneath a container shares a common *suffix* — and a
B-tree cannot serve `LIKE '%OU=Sales,DC=corp,DC=com'`, which is a scan of every object in the forest.
Reversed, the shared part is a common prefix and the same question is a range scan. On a
nine-million-object forest that is the difference between a query and a wait.

**It reverses characters rather than components, and that is to be kept.** Reversing the component
order gives the same prefix property but has to parse the DN to do it, and every parse of a DN is a
chance to disagree with the directory about escaping. Reversing characters cannot be wrong about a DN
it never interprets, and the comparison it feeds is exact.

It is **not a normalisation**. It is stored beside the distinguished name the controller gave, never
instead of it; objects are stored under an identity that survives a rename or a move per
[`0022`](../decisions/0022-objects-are-stored-as-typed-columns.md), and the reversed form is an index
key derived from a column, not a second claim about the object.

---

## A single domain component is not a domain

`DnToFqdn` reads only `DC=` components, matched without regard to case, because a DN's attribute
types are case-insensitive — `dc=corp` and `DC=corp` are the same DN.

Fewer than two components produce the empty string rather than a single label. A lone `DC=gov` would
otherwise yield `gov`, which a caller hands to DNS and then waits on until it times out against a
domain that does not exist. **This is not tidiness; it is the difference between an empty answer and
a hang.**

---

## The escaping this understands, and the escaping it does not

The scan asks one question: is the character before this comma a backslash. That is enough for the
form Active Directory returns and is not a reader of RFC 2253. Two limits follow, both known, both
pinned by a test, and neither repaired.

**The quoted form of a value is not understood.** RFC 2253 §2.4 permits a comma inside a value to be
written escaped (`CN=Smith\, John`) or quoted (`CN="Smith, John"`). Only the escaped form is handled,
so a quoted value is cut at the comma inside the quotes: the leaf name comes back as `"Smith` and the
parent as ` John",OU=Users,DC=corp,DC=local`. Active Directory returns the escaped form, which is why
this has not bitten. It would bite on a DN typed by a person, read from a configuration file, or
pasted from a tool that quotes.

**An escaped backslash at the end of a value hides the next separator.** In `DC=corp\\,DC=com` the
character before the comma is a backslash — but that backslash is itself escaped, so it is a literal
backslash in the value and the comma after it really is a separator. The whole remainder of the DN is
swallowed into the first value, and the separator is then unescaped into a comma for good measure.
The correct question is whether the *run* of backslashes is odd.

**The test that pins each of these asserts the wrong answer on purpose.** It exists so the limit is
visible rather than silent, and it is to be **rewritten, not deleted**, when a real escaping reader
is written. Escaped `+` in a multi-valued RDN, hex-pair escapes such as `\2C`, and leading or trailing
space escaping are the same gap, not separate ones: there is no escaping reader here, only a comma
scanner.

---

## What is not here, checked against the code

- **No comparison.** There is no member that decides whether two DNs are the same, and none that
  decides whether one contains another. Callers compare DNs themselves. Ordinal case-insensitive
  comparison is right for two DNs from the same capture and wrong in general, and a containment test
  written as *does the child end with the parent* answers **yes** for a suffix that is not a DN at
  all — `CN=x,OU=Sales,DC=c,DC=l` is reported as contained in `es,DC=c,DC=l`. A containment test that
  can say yes to a non-existent container is how an object is attributed to the wrong organisational
  unit, and attribution is the whole output of an audit tool. Carried as a punch-list item rather
  than designed here.
- **No re-rooting.** Nothing moves a DN from one domain onto another, and nothing in the predecessor
  did either. The phrase describes an intention, not a removed capability.

---

## What depends on it

**Not nothing, which is what the consumed slice document said.** The claim was written when the
folder had no callers and was never re-read. Measured against `next/src`, the component is reached
from all three layers above it:

| Caller | Uses |
|---|---|
| `SecureAD.Audit` — capture and forest topology | `DnToFqdn` to attribute a naming context to a domain; `GetParentDn` walked three levels to find a site; `ExtractNameFromDn` for site and server names |
| `SecureAD.Evidence` — the writer, the tree, listings, permissions | `ReverseDn` and `GetParentDn` as objects are stored; `ExtractFirstRdn` wherever an object is shown |
| `SecureAD.Shell` — asset rows and the object view | `ExtractFirstRdn` for the displayed name |

**The ancestor walk terminates.** Every consumer of `GetParentDn` is a loop over repeated calls, so a
shortening that ever failed to shorten would hang a capture rather than fail it. That is asserted
against the full chain rather than inferred from the code.

The assembly targets `net10.0` with the rest of the tree.

---

## What an operator can do

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** Blank in **Confirmed in lab** means unit-tested but not yet exercised against a real forest.
The same rows stand in [who is who](../areas/who-is-who.md), which keeps its own copy permanently.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| see a readable name taken from a distinguished name | `DnHelperTests.WhenTheDnIsOrdinary_ThenTheFirstRdnValueIsReturnedWithoutItsType` |  |
| be certain a name containing an escaped comma is read correctly rather than split | `DnHelperTests.WhenTheValueContainsAnEscapedComma_ThenItIsUnescapedIntoTheName` |  |
| be certain the container of an object is derived without being fooled by escaping | `DnHelperTests.WhenTheFirstComponentContainsAnEscapedComma_ThenItIsNotTreatedAsASeparator` |  |
| be certain walking up a distinguished name reaches the root and stops | `DnHelperTests.WhenTheParentIsTakenRepeatedly_ThenTheWalkReachesTheRootAndStops` |  |
| read the same account of distinguished-name handling in the document and the code | `DistinguishedNameDocumentationTests` |  |
