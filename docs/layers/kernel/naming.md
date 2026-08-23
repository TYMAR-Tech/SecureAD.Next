# Naming what the directory stored

**Code:** `next/src/SecureAD.Kernel/Security/`
**Layer:** Kernel — pure logic. Reads a schema catalogue; touches no directory.

Turning stored values into words an administrator reads: who a SID is, what a right grants, what an
account's flags say, and what a timestamp means.

---

## What this is for

Active Directory stores almost nothing in a form a person can read. A permission is a mask of bits.
An account's state is a bitfield. A principal is `S-1-5-21-…`. A timestamp is either a 64-bit count
of 100-nanosecond units since 1601 or a string of digits — and both appear on one object.

**This is the one place a stored value becomes a word.** That matters more here than anywhere else
in the product, because a wrong word is the defect nobody sees. It does not throw and it does not
look odd. It renders as a confident *Disabled* beside an account that is enabled, and an operator
has no reason to doubt it.

So every table here is transcribed from Microsoft Learn, carries the identifier Microsoft documents
each value under so a reader can check it against Learn **without reading this code**, and is
asserted value by value against a Microsoft anchor test.

---

## The rule that governs all of it

**A value with no word is carried, never dropped.**

Each of these types can be handed something this build has no word for — a mask bit Microsoft has
not published, a `userAccountControl` bit newer than the build, a GUID the schema catalogue does not
know. Discarding it would let the product report a complete reading of a value it did not completely
read, and hide access an administrator is looking straight at.

So each type carries both the unnamed remainder and a flag saying the reading was partial:

| Type | Carries the remainder in | Says the reading was partial via |
|---|---|---|
| `PermissionWording` | the summary line | `RightsAreComplete` |
| `UserAccountControlWording` | `UnwordedBits` | `FlagsAreComplete` |

**And nothing here is a judgement.** `DONT_REQUIRE_PREAUTH` is worded as what it is, not as a risk.
Whether it matters is the classifier's question, asked separately and on the reader's terms.

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `WellKnownSidRole` | What a well-known SID is, for the purpose of saying who holds a permission |
| `WellKnownSid` | A SID Microsoft publishes, with its role and its name |
| `DomainRelativeSid` | A SID that is meaningful only relative to a domain, by its relative identifier |
| `DomainRelativeScope` | Which domain a relative identifier is counted within |
| `WellKnownSidCatalog` | The table of SIDs and relative identifiers Microsoft publishes |
| `PermissionWording` | One entry said in words, and whether every bit was named |
| `PermissionRight` | One right in words, with the mask bits that produced those words |
| `PermissionWordingWriter` | Turns a mask and its GUIDs into those words |
| `UserAccountControlFlag` | One flag: the bit, Microsoft's identifier for it, and what it means |
| `UserAccountControlWording` | What an account's `userAccountControl` value says, one flag at a time |
| `GroupTypeWording` | Whether a group is security or distribution, and what scope it has |
| `DirectoryTimeFormat` | The two ways the directory stores a moment |
| `DirectoryTimeWording` | What a stored timestamp says, with the caveat a reader needs |
| `DirectoryTime` | Reads the timestamps this product captures, including values that are not times |
<!-- TYPES:END -->

Each type carries its Microsoft anchors in its XML documentation. **That is the reference; this page
is the orientation.**

---

## Who holds a permission

Every trustee used to be resolved the same way — search the captured objects for one whose
`objectSid` matches. That question has an answer for SIDs **that are not principals at all**.

Active Directory keeps real objects under `CN=WellKnown Security Principals` for `CREATOR OWNER` and
`PRINCIPAL SELF`, so the search succeeded, and the screen showed them beside real accounts, with a
domain, formatted identically to a group. In one lab bundle the product credited 1,708 entries to
them as though they were groups. An operator reading that is told something untrue about who holds
the permission.

`WellKnownSidRole` exists to make that impossible. The roles are about **what a reader may
conclude**, not about how Windows implements them:

| Role | Means |
|---|---|
| `Principal` | Something authenticates as it, or is a member of it. A permission naming it is genuinely held |
| `Placeholder` | A template the system replaces when the entry is applied — `CREATOR OWNER` becomes the creator, `PRINCIPAL SELF` becomes the object. Held by nobody until substituted, and by different somebodies on different objects |
| `OwnerRightsQualifier` | `OWNER RIGHTS` (`S-1-3-4`), present to change what the owner implicitly holds. MS-DTYP 2.4.2.4 says the system ignores the implicit `READ_CONTROL` and `WRITE_DAC` for the owner. It says nothing about `WRITE_OWNER`, and neither does this product |
| `LogonContext` | Describes how a caller authenticated — `NETWORK`, `BATCH`, `NTLM AUTHENTICATION`. A real grant, but not one that attributes to a person or a group |

---

## What a right says

`PermissionWording` is a type rather than a string because of `RightsAreComplete`. `PermissionRight`
carries the bits that produced its phrase, so a verdict can attach to **a right rather than to the
entry** — an `ACCESS_MASK` is a set of bits Windows evaluates independently, and the classifier
judges them differently by construction, so an entry granting several rights has several answers and
one mark on the row cannot say which right earned it.

**The bits are not always one bit.** *Full control* is the whole mask said in two words. It is one
grant rather than fifteen, so it is one right carrying every bit.

**One GUID can name two things.** `bf9679c0-0de6-11d0-a285-00aa003049e2` is both the `member`
attribute and the *Self-Membership* validated write — Active Directory gives them the same value. So
`WriteProperty` with that GUID is *Write member*, which lets a principal add anybody to a group,
while `Self` with the same GUID is *Self-Membership*, which lets them add only themselves. Taking
whichever catalogue entry came first named one as the other. Found by a test.

**A GUID the catalogue knows under the wrong kind still gets its name.** A name of the wrong kind is
more use than a raw GUID, and the alternative is hiding what the entry is about. A GUID the catalogue
does not know at all is shown as the GUID rather than dropped.

### The words are Microsoft's, not this product's

They are the labels ADSI Edit and the ACL editor show for the same bits. An administrator comparing
this screen against ADUC must not find two different words for one right.

*Modify owner* was *Take ownership* until it was corrected. **That is the file system's label for
`WRITE_OWNER`; the directory's is *Modify Owner*** — and the two tools sit side by side on the same
administrator's screen.

### Full control is one right, but only for the bits it accounts for

*Full control* is the whole mask said in two words, and it is one grant an administrator removes in
one action rather than fifteen findings, so it earns one verdict.

It applies **only to an unscoped entry**, and it claims **only the bits it actually accounts for**.
Both qualifications are corrections of a real defect. The test used to be a subset test that returned
immediately: any mask *containing* full control's bits was rendered as those two words, whatever else
it carried, and the remainder was dropped while the reading still claimed to be complete. Full
control limited to one object type is not full control over the object, and the shortcut ignored the
GUID entirely.

### One bit is worded as an anomaly, not a grant

`ACCESS_SYSTEM_SECURITY` **must not** be set in an entry that is part of a DACL — a DACL does not
control access to a SACL. Its presence is therefore evidence that something is wrong with the entry,
not a permission somebody holds, so it is worded as what it is:

> Access system security (not valid in a DACL - anomalous)

This is the bit the old subset test concealed. An entry carrying it is malformed or hostile evidence,
and it was being hidden behind the two most reassuring words this product prints.

### An empty mask says so

A mask granting nothing reads *No rights*, because saying so plainly beats an empty cell that looks
like a row which failed to load.

---

## What an account's flags say

Twenty-two documented flags, each carrying the `iads.h` identifier Microsoft publishes it under.
Three traps are worth knowing before reading one:

**Two bits are not current state, and both say so.** `ADS_UF_LOCKOUT` and `ADS_UF_PASSWORD_EXPIRED`
were replaced by `ms-DS-User-Account-Control-Computed`. Reading either out of a stored
`userAccountControl` answers a question the directory stopped keeping the answer to there.

Lockout is the worse of the two, **because the obvious fallback is also wrong**: Learn's
`Lockout-Time` remarks say the value *"may be non zero, yet the account is not locked out"*, and only
`lockoutTime` plus the domain's `Lockout-Duration` decides. So the flag's wording names the attribute
that replaced it and says the duration must be added.

**One flag deliberately follows the newer of two Microsoft pages.** `ADS_UF_SERVER_TRUST_ACCOUNT`
(`0x2000`) is described by adschema and `ADS_USER_FLAG_ENUM` as a computer account for a *backup*
domain controller — Windows NT vocabulary. KB 305144 words the same bit as a computer account for a
domain controller of this domain, which is what a current forest actually holds. **The wording here
follows the newer page on purpose; it should not be "corrected" back.**

**Three bits are deliberately unworded.** `0x4` is absent from Learn's table, and `0x4000` and
`0x8000` are listed as unused. None is given a word, so a value setting one arrives with an unworded
bit rather than silently as nothing.

---

## What a timestamp says

Two syntaxes, both on screen on one object. `pwdLastSet` is an `Interval` — 100-nanosecond units
since 1601 — and `whenCreated` is `String(Generalized-Time)`. Neither is recognisable as a time to
anyone who has not been told which is which, and **a generalized time parses perfectly well as an
interval**: `20260913090000.0Z` reads as a valid interval and lands in the year 1666. So the syntax is
held in a table per attribute and never guessed from the value.

**Several values are not times at all**, and each trap was checked against its own Learn page:

| Attribute | Value | Means |
|---|---|---|
| `accountExpires` | `0` **or** `9223372036854775807` | Never expires — **two** sentinels, not one |
| `pwdLastSet` | `0` | The password must be set at next logon |

`accountExpires` having two never-values is the sharp edge: an account created never-expiring holds
the maximum, and one whose expiry was *removed* holds zero. A reader handling only one of them
renders the other as a date in 1601 or in 30828 — and either reads as a real expiry to an operator.
`pwdLastSet` of zero matters because the accounts it is true of are exactly the ones an auditor is
looking for.

**A value this build cannot read is returned as null, never as a fallback date** — including a value
too large to be a date at all, which is shown as stored rather than clamped to a year that would read
as a real one.

**Caveats are not decoration.** `lastLogonTimestamp` is deliberately imprecise: a controller updates
it only when the value it holds is older than `msDS-LogonTimeSyncInterval`, which defaults to between
9 and 14 days. A stale-account judgement made without knowing that is wrong by up to a fortnight, so
the caveat travels with the value.

**An age is measured against the run, never against today.** A bundle is sealed evidence. A password
last set six days before a capture is a fact about that forest, and it stays that fact however long
the bundle sits on a share. Measuring against the reader's clock would make the same evidence say
something different every morning.

---

## What an operator can do

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** Blank in **Confirmed in lab** means unit-tested but not yet exercised against a real forest.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a well-known SID carries the value Microsoft publishes | `WellKnownSidCatalogMicrosoftAnchorTests.WhenMicrosoftPublishesAWellKnownSid_ThenTheCatalogueCarriesThatValue` |  |
| be certain a SID Microsoft does not publish is not resolved to a guess | `WellKnownSidCatalogMicrosoftAnchorTests.WhenASidIsNotWellKnown_ThenTheCatalogueSaysSoRatherThanGuessing` |  |
| be certain whether a SID names a principal at all follows its documented role | `WellKnownSidCatalogMicrosoftAnchorTests.WhetherASidNamesAPrincipalFollowsItsRole` |  |
| be certain the catalogue names the source it was transcribed from | `WellKnownSidCatalogMicrosoftAnchorTests.TheCatalogueNamesItsSource` |  |
| read a mask granting everything as full control rather than as fifteen separate rights | `PermissionWordingTests.FullControlIsOneRightCarryingTheWholeMask` |  |
| be certain a bit this build has no word for is counted rather than discarded | `PermissionWordingTests.ABitWithNoWordForItIsCountedRatherThanDiscarded` |  |
| see the value of a bit this build cannot name | `PermissionWordingTests.ABitWithNoWordForItIsShownAsItsValue` |  |
| be certain full control carrying an unnameable bit is not reported as fully understood | `PermissionWordingTests.FullControlCarryingAnUnnameableBitIsNotReportedComplete` |  |
| be certain a shorthand full control does not read as a real one | `PermissionWordingTests.AShorthandFullControlIsNotWordedAsARealFullControl` |  |
| be certain a shorthand right says it may not be enforced | `PermissionWordingTests.AShorthandBitIsNamedAndSaysItMayNotBeEnforced` |  |
| read an extended right by name rather than as a GUID | `PermissionWordingTests.AnExtendedRightIsNamedRatherThanShownAsAGuid` |  |
| be certain a GUID the catalogue does not know is shown rather than dropped | `PermissionWordingTests.AGuidTheCatalogueDoesNotKnowIsShownRatherThanDropped` |  |
| be certain one GUID meaning two things is named by the right beside it | `PermissionWordingTests.OneGuidMeaningTwoThingsIsNamedByTheRightBesideIt` |  |
| be certain the words and the danger mark agree on what modifying permissions is | `PermissionWordingTests.TheWordingAndTheClassifierAgreeOnWhatModifyPermissionsIs` |  |
| be certain every account flag is worded under the identifier Microsoft gives it | `UserAccountControlWordingTests.EachDocumentedBitIsWordedUnderTheIdentifierLearnGivesIt` |  |
| be certain a flag bit Microsoft does not define is not given a word | `UserAccountControlWordingTests.ABitLearnDoesNotDefineIsNotWorded` |  |
| be certain an account flag with no word is carried rather than dropped | `UserAccountControlWordingTests.ABitWithNoWordingIsCarriedRatherThanDropped` |  |
| be certain a bit with no word makes the reading say it is incomplete | `UserAccountControlWordingTests.ABitWithNoWordingIsSaidToMakeTheFlagsIncomplete` |  |
| be certain a bit the directory stopped maintaining is not worded as current state | `UserAccountControlWordingTests.NeitherBitTheDirectoryStoppedKeepingIsWordedAsCurrentState` |  |
| be certain the lockout bit names the attribute that replaced it | `UserAccountControlWordingTests.TheLockoutBitNamesTheAttributeThatReplacedIt` |  |
| tell a security group from a distribution group | `GroupTypeWordingTests.ADistributionGroupIsNotASecurityGroup` |  |
| read a group's scope from the negative value the directory stores | `GroupTypeWordingTests.AGlobalSecurityGroupIsReadFromItsNegativeStoredValue` |  |
| be certain a group claiming two scopes is given none rather than a guess | `GroupTypeWordingTests.AGroupClaimingTwoScopesIsGivenNone` |  |
| be certain an age is measured from the run rather than from today | `DirectoryTimeTests.AnAgeIsMeasuredFromTheRunAndNotFromToday` |  |
| be certain the moment is shown beside the age | `DirectoryTimeTests.TheMomentIsShownBesideTheAge` |  |
| be certain every timestamp named is an attribute this product actually captures | `DirectoryTimeTests.EveryTimestampNamedIsAnAttributeThisProductCaptures` |  |

---

## Why it is this way

**The identifier travels with the word.** Each `userAccountControl` flag carries the `iads.h` name
Microsoft documents it under, so the table can be checked against Learn without reading the code.
`PARTIAL_SECRETS_ACCOUNT` has no identifier, because it is published only on KB 305144 and never
reached the `ADS_USER_FLAG_ENUM` enumeration — and saying so is more honest than inventing one.

**Two Microsoft pages were not enough, and that is the most useful lesson here.** adschema and
`ADS_USER_FLAG_ENUM` agree on twenty-one flags, and both descend from `iads.h` — **one lineage read
twice, which reads like corroboration and is not.** KB 305144 is maintained separately and publishes
a twenty-second bit, `0x04000000`, marking a read-only domain controller. Without it, an RODC's
account rendered a raw hexadecimal number where a sentence belongs.

The only thing that caught it was a source outside the family. When verifying a table against
Microsoft, **count independent lineages, not pages.**

**Counting sources is not the same as verifying them.** A test pins a *number*. It cannot judge a
*sentence*. So the anchor tests assert the bits and values, and the wording remains a thing a reader
has to check.

**The mask bit values are deliberately duplicated, not shared.** `PermissionWordingWriter` keeps its
own copy of the bit constants rather than reading the classifier's. One type decides what is
dangerous and the other decides what to call things, and a change to either must not silently alter
the other. `PermissionWordingTests` asserts the two agree on the values they share — so the
duplication is checked rather than trusted, which is the opposite of the six-classifier problem,
where nothing compared them.

**Wording is separate from judgement, in both directions.** These types say what a value is; the
classifier says whether it matters. Merging them would put a risk opinion inside a transcription of
Microsoft's table, and the transcription is the part that has to be checkable.

---

## What reads this

The Shell renders all of it. Related: [security descriptors](security-descriptors.md) for where the
mask and flags come from, and [permission classification](permission-classification.md) for the
judgement laid over these words.
