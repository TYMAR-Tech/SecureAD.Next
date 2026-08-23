# What a policy declares

**Component.** `next/src/SecureAD.Kernel/GroupPolicy/` — the half that reads what a Group Policy
object says about itself in the directory. Five types, all of them reading a single stored string
off a directory attribute.

The other half — what the files behind a policy actually contain — is
[`what-a-policy-file-contains.md`](what-a-policy-file-contains.md). The two are split because the
area file's own opening sentence splits them: *the objects in the directory, the files behind them
in SYSVOL, and what those files contain.* Nothing on this page parses a file; nothing on that page
reads a directory attribute.

The governing area file is [`group-policy.md`](../../areas/group-policy.md).

---

## What this is for

Group Policy is where a permission on one object turns into code running on many machines. Before
any of that can be assessed, two questions have to be answered from the directory alone:

- **Which policies is this container subject to, and in what order do they win?** That is `gPLink`.
- **Does this policy hold settings worth fetching at all?** That is `gPCMachineExtensionNames`.

The second question exists for a practical reason. Fetching every policy's files over SMB for every
policy in a forest is expensive, so capture asks each policy what kinds of settings it carries and
fetches only the ones this product parses.

---

## The types

| Type | What it is |
|---|---|
| `GpoClientSideExtensionCatalog` | The two client-side extensions this product parses, and their GUIDs |
| `GpoClientSideExtensions` | Reads `gPCMachineExtensionNames`, and decides whether a policy is worth fetching |
| `ParsedCseList` | What was read from that attribute, beside what could not be |
| `PolicyLink` | One link out of a container's `gPLink` |
| `PolicyLinkList` | The links on one container, read out of the single string that holds them |

---

## A client-side extension, and why the table is its own type

A client-side extension is the component on a domain-joined machine that applies one kind of policy.
A policy's `gPCMachineExtensionNames` lists the extensions whose settings it contains.

The catalogue holds two, both documented in the ADMX_GroupPolicy policy CSP:

| Extension | GUID | Produces and consumes |
|---|---|---|
| Registry | `35378EAC-683F-11D2-A89A-00C04FBBCFA2` | `Registry.pol` |
| Security | `827D319E-6EAC-11D2-A4EA-00C04F79F83A` | `GptTmpl.inf` |

**The catalogue is a separate type from the parser on purpose, and the reason is a gate.** The
catalogue is a table written out in the source: it reads nothing, opens nothing and cannot fail,
which is the ground on which it is exempt from gate 4. The parsing lives next door, where it *can*
fail and says so. Putting them in one type would have meant exempting the parser along with the
table, because gate 4 exempts a type rather than a member — and the parser is exactly the kind of
thing gate 4 exists to hold.

**These are not Active Directory schema GUIDs.** They have no LDAP name, so `SchemaGuidCatalog`
cannot answer for them. This file is their declared home under `SchemaGuidSingleSourceGateTests`.

---

## Reading the attribute

The value is one Unicode string of repeated bracketed groups:

```
[{CSE-GUID}{tool-GUID}...][{CSE-GUID}{tool-GUID}...]
```

Only the **first** GUID in each group is the client-side extension; the rest are tool GUIDs and are
skipped. The result is deduplicated and kept in the order the extensions appeared.

**An unreadable token is recorded, not skipped.** This is the whole reason `ParsedCseList` carries
an error list rather than being a bare list of GUIDs. The parse does not throw on a token it cannot
read — one malformed entry should not cost the whole attribute — but that leaves a list shorter than
the policy really declared, and a short list is indistinguishable from a policy that genuinely
declares fewer extensions.

## Why the fetch decision is permissive

`HasAnalyzableSettings` returns `true` — meaning *fetch this policy's files* — in three cases:

- the policy declares an extension this product parses;
- the attribute is absent or empty;
- **any part of the attribute could not be read.**

It returns `false` only when the whole attribute was understood and none of the extensions in it are
ones this product parses. Correctness is chosen over the I/O saving.

**The third case is not belt and braces.** Before it existed, a value holding one readable extension
and one unreadable token took the non-empty path. A policy whose unreadable token *was* the Registry
or Security extension was skipped — its files never fetched, and SEC-064, SEC-065, SEC-066 and
SEC-093 silently reporting nothing for it, while it looked exactly like a policy that had been
assessed and found clean.

---

## Order is not precedence

A container's `gPLink` is `[LDAP://<dn>;<options>]`, repeated. Microsoft's own example of a
three-link container is three of those concatenated with **no separator**, which is why an unparsed
`gPLink` on screen is one unreadable line however wide the window is.

**The links are read left to right and applied in reverse.** The last link in the string has the
highest precedence; the first can be overridden by every link after it. So each link carries two
numbers, both counting from one:

| | Means |
|---|---|
| `Order` | Where it sits in the stored string, reading left to right |
| `Precedence` | Where it sits in precedence, where one wins |

A viewer that listed links in stored order and let a reader assume the first one wins would have the
answer exactly backwards — which, on a container with two policies setting the same thing, is the
difference between a setting applying and not.

### The name is split on the last semicolon

A distinguished name contains semicolons. Microsoft's own example writes one as
`cn=policies;cn=system;DC=corp;DC=contoso;DC=com`. Splitting on the first semicolon would take the
options to be `cn=system…` and the policy to be `cn=policies` — a plausible-looking wrong answer
rather than a failure, which is worse.

### The option flags are deliberately not worded

A link can be disabled or enforced, and both matter enormously — an enforced link cannot be blocked
lower down. But Microsoft's page for `gPLink` says only *a sorted list of Group Policy options, each
option is a DWORD* and does not give the values, and this product does not word a bit it has not
seen documented. The number is carried through to the screen as stored.

This is the same refusal that kept `WRITE_OWNER` from being labelled with the file system's word for
it. See [`naming.md`](naming.md).

### A malformed link is not an absent one

A container whose `gPLink` is malformed is not a container with no policies, and the two must not
arrive as the same empty list. A value that is not bracketed at all stops the read and is recorded,
along with the fact that the rest of the value was not read. A good link beside a bad one is still
read.

---

## What is not here, checked against the code

- **Nothing resolves a policy's effect.** Blocked inheritance, enforcement and security filtering are
  not read, and no type here works out which objects a policy actually reaches. `PolicyLinkList`
  reports the link and stops.
- **Nothing reads whether a link is disabled**, because the option bits are not worded — see above.
- **The catalogue does not claim to be every client-side extension that exists.** It is the two whose
  on-disk settings this product parses.

These are open questions rather than a plan, and they are tracked as `P-46` through `P-50` in
[`PUNCH-LIST.md`](../../PUNCH-LIST.md).

---

## What an operator can do

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| see which client-side extensions a policy declares | `GpoClientSideExtensionsTests.WhenSingleRegistryGroup_ThenReturnsRegistryCse` |  |
| be certain a malformed extension list is recorded rather than silently skipped | `GpoClientSideExtensionsTests.WhenMalformedTokens_ThenTheyAreRecordedRatherThanSkippedSilently` |  |
| be certain an absent extension list reports no errors, so an error always means something | `GpoClientSideExtensionsTests.WhenAttributeIsAbsent_ThenNoErrorsAreReported` |  |
| be certain duplicate extension entries are reduced to one | `GpoClientSideExtensionsTests.WhenDuplicateCseGroups_ThenDeduplicated` |  |
| see each policy linked to a container as its own entry | `PolicyLinkListTests.EachBracketedEntryIsALink` |  |
| see which policy object a link names | `PolicyLinkListTests.ALinkCarriesThePolicyItNames` |  |
| read the links in the order the directory stores them | `PolicyLinkListTests.TheLinksAreNumberedInTheOrderTheyAreStored` |  |
| be certain precedence is the reverse of stored order, so the last link is not read as the weakest | `PolicyLinkListTests.ThePrecedenceIsTheReverseOfTheStoredOrder` |  |
| be certain a container's only link has the precedence of one | `PolicyLinkListTests.TheOnlyLinkOnAContainerHasThePrecedenceOfOne` |  |
| be certain the link options are shown as stored rather than given a word the product cannot support | `PolicyLinkListTests.TheOptionsAreCarriedAsStoredAndNotWorded` |  |
| have a policy name containing semicolons read correctly | `PolicyLinkListTests.ANameHoldingSemicolonsIsSplitOnTheLastOne` |  |
| be certain a container with no links reads as none rather than as a fault | `PolicyLinkListTests.AContainerWithNoLinksReadsAsNoneAndNoFault` |  |
| be certain an unbracketed link value is an error rather than silence | `PolicyLinkListTests.AValueThatIsNotBracketedIsAnError` |  |
| be certain a link carrying no options is an error | `PolicyLinkListTests.AnEntryWithNoOptionsIsAnError` |  |
| be certain one malformed link does not cost the readable ones beside it | `PolicyLinkListTests.AGoodLinkBesideABadOneIsStillRead` |  |

The first four rows are copied from the area file's *What is built* table, which keeps them. The
policy-link rows are new: the area file's table has never carried a row for `gPLink`, and the eleven
tests behind it were bound by nothing.

---

## What reads this

`GpoClientSideExtensions.HasAnalyzableSettings` is the smart filter in front of SYSVOL capture.
`PolicyLinkList.Of` reads a value the bundle already holds, so it runs against stored evidence
rather than against a directory.
