# What a permission grants: classification, scope and reach

**Code:** `next/src/SecureAD.Kernel/Security/`, namespace `SecureAD.Kernel.Security`
**Layer:** Kernel — pure logic. Reads a schema catalogue; touches no directory.

The product's single answer to *does this access control entry hand somebody control*, and to
*how far does it reach*.

---

## What this is for

An access control entry is a mask of bits and up to two GUIDs. Turning that into a judgement an
auditor can act on takes three separate questions, and they are separate on purpose:

| Question | Answered by | Entry point |
|---|---|---|
| Does this entry hand somebody control? | `DangerousPermissionClassifier` | `Classify` |
| What does this entry govern, and where did it come from? | `PermissionScopeWriter` | `Describe` |
| Does it control the object it is attached to at all? | `EntryReachReader` | `FromPropagationFlags` |

`Classify` returns a `PermissionAssessment`, which carries the `Verdict`, the `Reason` an operator
reads, and the `RightName` the verdict is about — so a caller can attach the answer to one right
rather than to the whole entry.

**One answer, in one place.** The previous product answered the first question in six places and
the six disagreed — a bitmask classifier that never used the extended-rights constant it declared,
so a DCSync grant was not dangerous by it; a per-GUID flag that never saw an access mask; a
user-interface service that unioned the two, which was the right answer computed in the wrong layer;
two effective-access panels that matched on rendered display strings and disagreed with each other
about `gPLink`, `scriptPath` and `userAccountControl` — and those two are the screens a customer is
meant to read side by side. A sixth list lived in the rule SQL.

---

## What it decides, and what it does not

**This classifies one entry.** Whether a principal is dangerous because of the *set* of rights it
holds — the replication pair that makes DCSync — is a different question against different evidence,
and it is not answered here. An entry that is only half of such a pair is recorded as
`DangerousInCombination` rather than given a verdict it is not entitled to.

**It does not compute effective access.** Nothing here claims what a principal *effectively* holds
anywhere. That is a computation over the whole DACL of every object beneath this one, and it is not
what this product has read. These are readings of one entry's declared reach.

---

## The four verdicts

`PermissionVerdict` is an enumeration and not a `bool`, and the reason is a defect in the previous
classifier: an entry whose object-type GUID it did not recognise was **not assessed and found safe**
— it was never examined — and both outcomes came back as `false`. A reader cannot tell those apart,
and one of them is a permission nobody has looked at.

| Verdict | Means |
|---|---|
| `Dangerous` | A takeover of the object, or of the account, policy or credential the named right controls |
| `DangerousInCombination` | Not a takeover alone. Becomes one given evidence a single entry does not carry — which other rights the principal holds, or which container the entry sits on |
| `NotDangerous` | Examined, understood, and not a takeover. A positive statement, returned only when the entry was actually understood |
| `CannotClassify` | Not assessed. The GUID is not in the catalogue, or the mask names no right the classifier understands. **Never rendered as safe** |

---

## The types

<!-- TYPES:BEGIN -->
| Type | What it is |
|---|---|
| `DangerousPermissionClassifier` | The single answer to whether an entry hands somebody control |
| `PermissionVerdict` | What the product is prepared to say about one entry |
| `PermissionAssessment` | A verdict about one entry, with the reason it was reached |
| `PermissionScope` | How far one entry reaches, in words: what it governs, and where it came from |
| `PermissionScopeWriter` | Turns inheritance flags into the words the ACL editor's *Applies to* box uses |
| `EntryReach` | Whether an entry controls the object it is attached to, or only what is beneath it |
| `EntryReachReader` | Reads that off the propagation flags the directory stored |
<!-- TYPES:END -->

Each type carries its reasoning and its Microsoft anchors in its XML documentation. **That is the
reference; this page is the orientation.**

---

## Rules that no single type owns

**An entry living in an object's DACL is not the same as governing that object.**
`INHERIT_ONLY_ACE` means the entry does not control access to the object it is attached to — it sits
there to be copied downward. Getting this wrong over-reports rather than under-reports, which is the
safe direction, but it put two halves of one row in disagreement: a Scope column reading *All
descendant objects* beside a mark claiming a grant here.

**The directory service treats every object as a container.** So `CONTAINER_INHERIT_ACE` is the flag
that carries a permission down, and the file system's folder-versus-file split — which is what
`OBJECT_INHERIT_ACE` is for — does not divide the directory. Wording those two the way the file
system does would print *subfolders* and *files* against a forest.

**No GUID is written down in the classifier.** Names are looked up in the schema catalogue. The
catalogue is a constructor argument and is never defaulted, because the catalogue a forest captured
and the one shipped with the product are different tables, and **which was used is part of what an
audit claims**.

**Where the assertions come from.** Mask bit values are Microsoft's `ADS_RIGHTS_ENUM`. Which rights
count as takeover-class is taken from the rule specifications in `docs/rules/`, which are source of
truth for their own rules — not from the previous implementation.

**Encrypted LAPS attributes are weighted the same as clear-text ones.** Windows LAPS encrypts only
when the domain functional level is 2016 or later and encryption has been turned on; below that,
Microsoft states passwords can be stored only in clear text. The schema is extended either way, so
the presence of the attribute proves nothing about whether what it holds is encrypted. Judging them
as lesser would rest on an assumption this component cannot check, and would be wrong in exactly the
environments least likely to have hardened anything else.

**Reading and writing the same attribute are judged separately.** For most attributes the write is
the attack; for a credential-bearing one, the read is.

---

## How a scoped entry is judged

When an entry names an object type, **the mask bit decides which kind of thing that GUID is being
used as.** Active Directory reuses one GUID across a validated write and the attribute it validates,
and the entry's mask is the only thing that says which is meant. So the lookup is by
`(GUID, mask bit)`, never by GUID alone.

The arms are tried in order: child-class rights, extended rights, validated writes, attribute
writes, property-set writes, attribute reads, property-set reads.

**A GUID absent from the catalogue is `CannotClassify`, never `NotDangerous`** — *"It is not being
reported as safe."*

**A GUID the forest publishes without a readable `validAccesses` is its own answer**, said before
the mask-mismatch answer, because the two are different failures and an operator acts on them
differently.

### Class-scoped child rights are recorded, not answered

A right to create or delete children of **one named class** is `DangerousInCombination`, and the
reasoning is worth stating because it is neither of the obvious answers.

It is not `Dangerous`: Microsoft's words for `ADS_RIGHT_DS_CREATE_CHILD` are that the GUID
*"identifies a type of child object"* and the entry *"controls the trustee's right to create this
type of child object"*. A grant of one class is what a delegation wizard produces, and is not on its
own the takeover of the container that the unscoped rule describes.

It is not `NotDangerous` either, **and that matters more**. `CreateChild` scoped to the `computer`
class is *Critical* on the Domain Controllers OU — it is rogue domain controller injection — and
unremarkable on a departmental OU. This component is handed neither the container's identity nor its
place in the directory. Answering `NotDangerous` would put it against a shipped rule specification
on the same entry, which is the disagreement between six classifiers that it exists to have ended,
re-created inside it.

The shipped rule is in fact wider than that: `SEC-121` lists `CreateChild` **unqualified** on the
Domain Controllers OU, giving the `computer` class as the rationale rather than as a filter. So
`NotDangerous` would contradict it across the whole mask, not merely for one class — and `Dangerous`
is the false positive the review upheld this finding to remove. **No third answer is available to a
method handed neither container nor place.**

### A property set is exactly as dangerous as what the forest put in it

This is derived, not opinionated, and it cannot be answered offline.

**A property set names none of its members.** Each attribute points back at the set through
`attributeSecurityGUID`, so a customer can put their own attribute into a Microsoft-defined set. A
run that did not read the schema **cannot know**, and says so rather than guessing either way.

So the verdict is computed from actual membership in that forest:

| Case | Verdict |
|---|---|
| Schema not read | `CannotClassify` — "what the grant reaches is unknown. It is not being reported as safe" |
| Write, and the set holds an attribute already judged dangerous | `Dangerous`, naming the attributes |
| Write, and it holds none | `NotDangerous`, stating how many attributes the forest puts in it |
| Read, and the set holds a credential attribute | `Dangerous` — "held in clear text, so reading is the whole attack" |
| Read, and it holds none | `NotDangerous` |

**This used to answer `Dangerous` for every property set**, on the reasoning that a set is wider
than it reads. That is true, and it is not the same as a takeover. `Personal-Information` is
addresses, telephone numbers and photographs, and Active Directory grants `SELF` write access to it
on every user and computer out of the box. Marking that as a takeover put the product's loudest
signal on a default entry in every forest, **which is how a mark stops being read at all**.

Because the answer is derived from `DangerousAttributeWrites`, it cannot drift from the per-attribute
judgement. `User-Account-Restrictions` comes out dangerous because it holds `userAccountControl` and
`msDS-AllowedToActOnBehalfOfOtherIdentity`; `Personal-Information` comes out not, because it holds
neither.

**Property-set reads were previously not judged at all** — they fell through to `CannotClassify`, so
an entry granting read of a set holding a local administrator password was never marked. LAPS keeps
its password attributes in a set for exactly the reason that makes this matter: one grant reaches
all of them.

---

## What an operator can do

Each capability names the test that proves it. **The test is the evidence; this table is only the
index.** Blank in **Confirmed in lab** means unit-tested but not yet exercised against a real forest.

| An operator can… | Proven by | Confirmed in lab |
|---|---|---|
| be certain a permission to read a local administrator password is judged dangerous | `DangerousPermissionClassifierTests.ReadingALocalAdministratorPasswordIsDangerous` |  |
| be certain writing a policy link or a logon script is judged dangerous | `DangerousPermissionClassifierTests.WritingAPolicyLinkOrALogonScriptIsDangerous` |  |
| be certain an ordinary attribute read is not reported as dangerous | `DangerousPermissionClassifierTests.ReadingAnOrdinaryAttributeIsNotDangerous` |  |
| be certain an ordinary extended right is not reported as dangerous | `DangerousPermissionClassifierTests.AnOrdinaryExtendedRightIsNotDangerous` |  |
| be certain every verdict the classifier can give is exercised and named | `DangerousPermissionClassifierTests.TheCheckExercisesEveryVerdictAndTheCatalogueKnowsTheNames` |  |
| be certain a right to force a password change is judged dangerous | `DangerousPermissionClassifierTests.ForceChangePasswordIsDangerous` |  |
| be certain a replication right is recorded as dangerous only in combination, rather than alone | `DangerousPermissionClassifierTests.AReplicationRightIsDangerousOnlyInCombination` |  |
| be certain a write to an attribute that decides who an account is is judged dangerous | `DangerousPermissionClassifierTests.WritingADangerousAttributeIsDangerous` |  |
| be certain an unscoped grant of every extended right is judged dangerous | `DangerousPermissionClassifierTests.AnUnscopedGrantOfAllExtendedRightsIsDangerous` |  |
| be certain an unscoped grant of every property write is judged dangerous | `DangerousPermissionClassifierTests.AnUnscopedGrantOfAllPropertyWritesIsDangerous` |  |
| be certain a harmless right inside a dangerous mask is not itself reported as dangerous | `DangerousPermissionClassifierTests.TheHarmlessRightInADangerousMaskIsNotDangerousOnItsOwn` |  |
| be certain reading and writing the same attribute are judged separately | `DangerousPermissionClassifierTests.ReadingAndWritingTheSameAttributeAreJudgedSeparately` |  |
| be certain one GUID serving two purposes is read as the right the mask actually names | `DangerousPermissionClassifierTests.TheSharedGuidIsReadAsTheValidatedWriteUnderSelfAndAsTheAttributeUnderWriteProperty` |  |
| see that an entry with no inheritance flags governs only the object it is written on | `PermissionScopeTests.AnEntryWithNoInheritFlagsGovernsTheObjectItIsOn` |  |
| see that an entry inherited by containers governs the object and everything beneath it | `PermissionScopeTests.AnEntryInheritedByContainersGovernsTheObjectAndEverythingBeneathIt` |  |
| be certain an inherit-only entry does not claim a grant on the object it sits on | `PermissionScopeTests.AnInheritOnlyEntryDoesNotGovernTheObjectItIsOn` |  |
| see that an entry which does not propagate reaches one generation only | `PermissionScopeTests.AnEntryThatDoesNotPropagateReachesOneGenerationOnly` |  |
| see which class of object an entry limited to one class applies to | `PermissionScopeTests.AnEntryLimitedToOneClassNamesThatClass` |  |
| see the GUID when this build cannot name the class an entry is limited to | `PermissionScopeTests.AnEntryLimitedToAClassThisBuildCannotNameShowsTheGuid` |  |
| tell an entry the directory marked inherited from one set on the object | `PermissionScopeTests.AnEntryTheDirectoryMarkedInheritedSaysSo` |  |

---

## What the product treats as takeover-class

These lists are the classifier's answer to *which named rights hand over an account*. Every name is
sourced to the rule specification that detects it, not to the previous implementation, and no GUID
is written down — names are resolved through the schema catalogue.

**Extended rights that hand over an account on their own**

| Right | |
|---|---|
| `User-Force-Change-Password` | resets a password without knowing the old one |

**The replication family — components of a combination, never a takeover alone**

`DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All` and
`DS-Replication-Get-Changes-In-Filtered-Set` each return `DangerousInCombination`. Whether a
principal holds the *pair* that makes DCSync is a question about a set of entries, and this
component sees one entry at a time.

**Validated writes that hand over a group or an account**

`Self-Membership` is the membership vector; `Validated-SPN` is the write that makes an account
Kerberoastable.

**Attribute writes whose value decides who an account is**

`member`, `userAccountControl`, `unicodePwd`, `servicePrincipalName`, `sIDHistory`,
`msDS-KeyCredentialLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `gPLink`, `scriptPath`.

`gPLink` and `scriptPath` were the two the live and stored effective-access panels disagreed about.
They are settled in favour of the wider reading: writing either runs code across everything in
scope, and unlinking a hardening policy through `gPLink` needs no other privilege at all.

**Attribute reads where the value *is* the credential**

`ms-Mcs-AdmPwd` is legacy LAPS; `msLAPS-Password` is its Windows LAPS replacement. The encrypted
variants — `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`,
`msLAPS-EncryptedDSRMPassword`, `msLAPS-EncryptedDSRMPasswordHistory` — carry the same weight,
deliberately. Windows LAPS encrypts only when the domain functional level is 2016 or later *and*
encryption has been turned on; below that Microsoft states passwords can be stored only in clear
text, and the schema is extended either way. Judging them as lesser would rest on an assumption this
component cannot check.

---

## Where this sits, and what it deliberately does not do

The archived design review sets out five questions in order, and this product answers three of them:

| | Question | Answered by |
|---|---|---|
| 1 | What exactly did Active Directory return? | `SecurityDescriptorParser` |
| 2 | What does this individual ACE mean? | `PermissionWordingWriter`, `PermissionScopeWriter` |
| 3 | What capability results from multiple applicable entries? | **not built** |
| 4 | What can a particular principal effectively do? | **not built** |
| 5 | Is that result dangerous? | this subsystem |

Layers 3 and 4 are [planned effective access](../planned/effective-access.md). Until they exist,
**this component must not be asked questions that need them** — most importantly, whether a principal
can read a confidential attribute, which requires two rights that may arrive from different entries.

## A deliberate divergence from the design review

The review says a conditional entry should be reported as unsupported and **kept out of ordinary
grant and risk logic** — *"Unknown is the correct answer here."* This product does not do that, and
the reason should survive.

A conditional entry granting full control is a real takeover to anybody who satisfies the condition.
Answering `CannotClassify` would take its mark off the screen and its row out of the dangerous count
— trading a false positive for a false negative, which is the worse direction for an audit tool. The
requirement is met instead by naming the entry as a callback in the sentence an operator reads, while
the condition bytes are preserved on `ParsedAce` and hashed into canonicalisation so the evidence is
never lost.

**Do not "fix" this back on the strength of the review alone.**

---

## Why it is this way

**The decisions this component stands on.** A later session changing one of these can find what
rests on it here.

| Record | What it settles |
|---|---|
| [`0002`](../decisions/0002-absent-view-means-degraded-run.md) | *found nothing* and *could not compute* are never rendered alike |
| [`0004`](../decisions/0004-unknown-counts-name-the-failed-phase.md) | an unknown answer names the phase that failed rather than showing a zero |
| [`0016`](../decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md) | the filtered-set replication route is a product judgement, so a replication right is recorded rather than answered |

`0002` and `0004` are why `PermissionVerdict` is an enumeration and not a `bool`.

**`gPLink` and `scriptPath` are dangerous attribute writes.** They were dangerous to the live
effective-access panel and not to the stored one. That disagreement was settled in favour of the
wider reading: writing either runs code across everything in scope, and unlinking a hardening policy
through `gPLink` needs no other privilege at all.

**`DangerousInCombination` covers two shapes, not one.** A principal holding half a replication pair,
and an entry whose danger depends on which container it sits on — a right to create children of one
class is what a delegation wizard produces, and is also a Critical rogue domain controller injection
depending only on where it sits. The shape is the same in both cases, which is why it is one member
and not two.

**`EntryReachReader` exists because the bit was already written down twice.** Both
`SecurityDescriptorParser` and `PermissionScopeWriter` kept a private copy of `INHERIT_ONLY_ACE`, and
a third would have been the one that drifted.

**Scope is two values, not one string.** *What it governs* and *where it came from* answer different
questions, and a reader scans them in different columns.

---

## What reads this

The Shell renders these verdicts on screen, where the marking is behind a toggle and the counters
are computed only when asked. Those behaviours belong to the Shell and are documented with it, not
here — this page covers only the judgement, not its presentation.

Related: [security descriptors](security-descriptors.md) for where the mask and flags come from,
and [naming what the directory stored](naming.md) for how a right is put into words.
