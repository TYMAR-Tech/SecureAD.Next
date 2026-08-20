# S-2 — Distinguished-name manipulation

**Type:** slice
**Reviewed at commit:** working tree, session S-2
**Size:** 1 file, 168 lines, plus 1 test file
**Date:** 2026-08-10

## What it does

Reads Active Directory distinguished names. Three questions, and nothing else: what is this object
called, what contains it, and which domain is it in.

`DnHelper` answers all three. It is the whole component.

## Why it is worth a component

A distinguished name looks like a delimited list and is not one.

```text
CN=Smith\, John,OU=Users,DC=corp,DC=local
```

That is one person, in one organisational unit, in one domain — four components, not five. The
comma inside `Smith\, John` is part of the value, escaped, per RFC 2253 §2.4. Split on `','` and
the parent becomes ` John,OU=Users,DC=corp,DC=local`, a container that does not exist, and the
person's name becomes `Smith`.

Names containing commas are not exotic. `Surname, Forename` is the default display format in a
great many directories, so the escaped comma is the *common* case in exactly the objects an audit
tool cares most about: people.

The previous implementation had **34 files** calling into this one — LDAP capture, principal
resolution, escalation paths, storage, the tree and locator services, and 18 view models and grid
row types. That is the argument for the component. Thirty-four separate `Split(',')` calls would be
thirty-four separate chances to get it wrong, and would be wrong in different ways.

## Shape

| Member | Answers | Absent input |
|---|---|---|
| `GetParentDn` | What contains this object | `null` |
| `ExtractFirstRdn` | What is this object called | the input, unchanged |
| `ExtractFirstRdnOrNull` | As above | `null` |
| `ExtractNameFromDn` | As above | `""` |
| `DnToFqdn` | Which domain is this object in | `""`; `null` throws |
| `ReverseDn` | What index key makes a subtree query a prefix scan | `""`; `null` throws |

`ReverseDn` is the odd one out and is meant to be. Every other member here answers a question about
a DN; this one produces a key nobody should ever display. A DN is written leaf-first, so the objects
under a container share a *suffix* — and a B-tree cannot serve `LIKE '%OU=Sales,DC=corp,DC=com'`,
which is a scan of every object in the forest. Reversed, that shared part is a prefix and the same
question is a range scan. It reverses characters rather than components, which is how the
predecessor did it: the prefix property is identical either way, and reversing characters never has
to parse the DN, so it cannot disagree with the directory about escaping. It is stored beside the
distinguished name in `captured_object`, never instead of it.

Three ways to ask for a leaf name is one more than the subject needs. They differ only in what
absence looks like, and the difference is real — a display surface binding `null` falls back to
another column, and one binding `""` renders a blank cell that claims the object has no name — but
two of the three could be one method and a caller-supplied fallback. Recorded as F-S2-3 rather than
changed, because this is a Port row.

## Dependencies

- **Depends on:** nothing. `string`, `ReadOnlySpan<char>` and `List<string>`, which is why it
  targets plain `net8.0` and needs no directory, no database and no Windows.
- **Depended on by:** nothing yet. The register entry names B11 as the row expected to bring the
  first consumer, on the strength of the previous implementation's group-member writer calling
  `DnToFqdn` to attribute a member to its domain.
- **Layering violations:** none.

## Where it lands, and why it moved

It sat at `src/SecureAD.Core/Discovery/DnHelper.cs`, under branch A's folder. **Thirty-three of its
thirty-four consumers were outside discovery.** The folder recorded which feature happened to need
it first, in 2025, and nothing since.

It lands in `SecureAD.Kernel`, namespace `SecureAD.Kernel.Naming`. `next/README.md` already names
distinguished names as part of the kernel's subject, alongside security descriptors and schema
GUIDs, so this is the register catching up with a decision already written down rather than a new
one.

The folder is `Naming/` and not `Directory/`. A namespace segment called `Directory` collides with
`System.IO.Directory` at every use site inside it, and the rebuild has a gate that reads the tree
looking for directory access; a name that invites both a compiler ambiguity and a false positive
from a guard is not worth the tidiness.

## The four edge cases, and which were already covered

The prompt for this session named four things about distinguished names that are knowledge about
Active Directory rather than about this code. Checked against
`tests/SecureAD.Core.Tests/Discovery/DnHelperTests.cs` as it stood:

| Edge case | Covered before? | Now |
|---|---|---|
| **Escaped commas** | **Yes**, four tests — parent, leaf name, several commas in one value, and the display-name overload | Carried, and extended: `DnToFqdn` with an escaped comma in an earlier component, and a terminating walk up an ancestor chain that starts at one |
| **Case-insensitive comparison** | **No.** `DnToFqdn` matched `DC=` with `OrdinalIgnoreCase` and no test ever passed it a lowercase DN | Covered, three cases. A DN's attribute types are case-insensitive, so `dc=` is the same DN |
| **Embedded quotes** | **No**, and unsupported. RFC 2253 §2.4 allows `CN="Smith, John"` as an alternative to escaping, and it is not understood | Pinned as a documented limit, F-S2-1 |
| **Re-rooting across domains** | **No**, and **not implemented at all** | Not added. F-S2-4 |

Two of the four are gaps in the component rather than gaps in the tests, which is why they are
findings below rather than new test cases.

## Comparison and re-rooting are not here

The map's entry for K17 says the component owns *"parsing, comparing, shortening and re-rooting AD
distinguished names."* Two of those four are absent from the code.

- **Comparing.** No comparison member exists. Callers compare DNs themselves, with
  `string.Equals(..., OrdinalIgnoreCase)` written out at each site — four of them in the previous
  implementation, in the compare engine, the tree service, the preflight check and the offline
  tree. That happens to be the right comparison for the ordinary case, but it is the same question
  answered four times, which is the failure gate 2 exists to catch.
- **Re-rooting.** Nothing in the previous product re-roots a DN from one domain onto another. The
  phrase describes an intention.

Neither is added under a Port row. Both are recorded, so that whoever writes the comparison writes
one.

## Verified-safe

- **Nothing here reaches a directory, a disk or a clock.** Every member is a pure function of its
  argument.
- **The ancestor walk terminates.** Every consumer of `GetParentDn` in the previous implementation
  was a loop over repeated calls, so a shortening that ever failed to shorten would hang a capture
  rather than fail it. `WhenTheParentIsTakenRepeatedly_ThenTheWalkReachesTheRootAndStops` asserts
  the full chain and bounds the loop, rather than inferring termination from the code.
- **`DnToFqdn` refuses a null DN rather than reporting no domain.** Asserted directly. An empty DN
  is a caller with nothing to look up; a null DN is a caller that lost its input, and the two must
  not produce the same answer.
- **A single domain component is not a domain.** `DC=gov` yields `""`, not `"gov"`. The previous
  implementation records why in a comment: a TLD-only string is handed to DNS and waits until it
  times out.
- **The two absence conventions agree on a present value.** Asserted, so the pair cannot drift into
  disagreeing about anything except absence.

**The guard that binds this document was mutation-tested in both directions, and the first attempt
failed.** Renaming the `ExtractNameFromDn` entry to ExtractNameFromDnXX in the document was expected
to fail the check and did not: the scan was a plain substring search, so the longer name matched the
shorter one and the check reported nothing missing while the document named nothing that existed.
also have accepted the entry for `ExtractFirstRdnOrNull` as covering `ExtractFirstRdn`. The scan now
requires the backticked form, and both directions were then observed:

| Direction | Mutation | Observed |
|---|---|---|
| Document omits something the code has | the `ExtractNameFromDn` entry renamed in the document | Fails: *"does not describe: ExtractNameFromDn"* |
| Document names something the code lacks | a re-rooting member written into the document, backticked, as though it existed | Fails: *"presents members the component does not have: ReRootDn"* |

Both mutations were reverted. `TheCheckIsNotSatisfiedByANameThatMerelyContainsTheMemberName` holds
the repair, so the substring weakness cannot come back unnoticed.

The limits below are *not* covered by that claim. They are known, tested, and unrepaired.

## Findings

### F-S2-1 — The quoted form of a value is not understood

- **Severity:** minor
- **Status:** OPEN, pinned by test

RFC 2253 §2.4 permits a comma inside a value to be written escaped (`CN=Smith\, John`) or quoted
(`CN="Smith, John"`). Only the escaped form is handled, so the quoted form is cut at the comma
inside the quotes: the leaf name comes back as `"Smith` and the parent as
` John",OU=Users,DC=corp,DC=local`.

Active Directory returns the escaped form, which is why this has not bitten. It would bite on a DN
typed by a person, read from a configuration file, or pasted from a tool that quotes.

`WhenAValueIsQuotedRatherThanEscaped_ThenTheQuotingIsNotUnderstood` asserts the wrong answers on
purpose. **That test pins a defect and is not a specification** — it exists so the limit is visible
and dated rather than silent, and it is expected to be rewritten, not deleted, when the quoted form
is handled.

### F-S2-2 — An escaped backslash at the end of a value hides the next separator

- **Severity:** minor
- **Status:** OPEN, pinned by test

The scan asks whether the character before a comma is a backslash. In `DC=corp\\,DC=com` it is —
but that backslash is itself escaped, so it is a literal backslash in the value and the comma after
it really is a separator. The whole remainder of the DN is swallowed into the first value, and the
separator is then unescaped into a comma for good measure.

Correctly answered by counting the run of backslashes and asking whether it is odd. Not fixed here,
because a Port row moves code and does not change it, and because the fix belongs with F-S2-1 —
both are the same missing piece, a real reader of RFC 2253 escaping.

### F-S2-3 — Three members answer one question

- **Severity:** minor
- **Status:** OPEN

`ExtractFirstRdn`, `ExtractFirstRdnOrNull` and `ExtractNameFromDn` differ only in what absent input
returns. The distinction between `null` and `""` is real, so this is not simply duplication, but
the third could be a caller-supplied fallback rather than a member.

Left alone under a Port row. Worth settling before B11 and the view models adopt whichever they
reach for first, because a naming convention gets much more expensive to change once thirty-four
call sites exist — which is exactly how it got to three in the first place.

### F-S2-4 — DN comparison has no owner

- **Severity:** major
- **Status:** OPEN

There is no `AreSame(dnA, dnB)` and no `IsDescendantOf(child, ancestor)`. Both were written out at
the call site in the previous implementation, four times, each as an `OrdinalIgnoreCase` string
compare.

Ordinal case-insensitive comparison is right for DNs that came from the same directory in the same
capture, and wrong in general: RFC 4518 folds whitespace around separators, `DC=corp` and
`DC = corp` are the same DN, and an escaped and a quoted value can be the same value. More
immediately, `childDn.EndsWith(parentDn, OrdinalIgnoreCase)` — which is how the tree service decides
containment — reports `CN=x,OU=Sales,DC=c,DC=l` as contained in `es,DC=c,DC=l`, a suffix that is not
a DN at all.

This is filed as major because a containment test that can say yes to a non-existent container is
how an object gets attributed to the wrong organisational unit, and an audit tool's whole output is
attribution.

Not fixed here: adding a comparison API is a design, and this is a Port row. It is named so that
gate 2 has something to point at.

## Open questions for the owner

- **Does any consumer need the quoted form?** Answerable by checking whether any DN reaching the
  product comes from anywhere but LDAP. If they all come from the directory, F-S2-1 stays minor
  permanently and can be closed as "will not fix" rather than left open.
- **Which comparison does F-S2-4 want?** Ordinal-ignore-case over the whole string is cheap and
  nearly always right. Component-wise comparison is correct and needs a parse. The choice depends
  on whether DNs are ever compared across two captures, where whitespace and escaping could differ.
- **Is `DnHelper` the name to keep?** It was ported unchanged so the move stays traceable, but
  `Helper` names a shape rather than a subject. Renaming is cheap now, at zero consumers, and not
  cheap later.

## Not reviewed

- **Performance.** Not measured. Every member is a single linear scan with at most one allocation
  per component, and the previous implementation's only performance record covers escalation-path
  traversal, group expansion and the control-edges query, none of which is this. It is called once
  per row in the grid view models, which is the place a measurement would eventually be wanted.
- **DN syntax beyond commas.** Escaped `+` in a multi-valued RDN, hex-pair escapes (`\2C`), and
  leading or trailing space escaping are all part of RFC 2253 and none is handled. They are not
  findings of their own because they are the same finding as F-S2-1: there is no escaping reader
  here, only a comma scanner.
