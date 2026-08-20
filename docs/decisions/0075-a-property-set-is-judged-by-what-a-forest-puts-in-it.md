# 0075 - A property set is judged by what a forest actually puts in it

Date: 2026-08-18
Status: Accepted

Corrects the classifier's answer for property-set permissions, and adds one it never gave. Follows
[0014](0014-capture-reads-the-schema-partition.md), which made a forest's own schema readable, and
[0074](0074-red-marks-a-takeover-permission-when-the-operator-asks.md), which spends red on a
takeover-class permission and therefore depends on that verdict being right.

## Context

`DangerousPermissionClassifier` answered `Dangerous` for **every** property-set write, with the
reasoning that a set is a group of attributes rather than one, so the grant is wider than it reads.
That reasoning is true and is not the same as a takeover.

The consequence reached a screen. Active Directory grants `SELF` write access to
`Personal-Information` on every user and computer object out of the box, and Microsoft's schema
reference lists that set as addresses, telephone numbers, photographs and certificates. So the
product's loudest signal appeared on a default entry in every forest that has ever existed. `0074`
authorised red on the argument that a takeover-class permission is *the thing an auditor came for*;
a mark that appears on an out-of-the-box ACE everywhere makes it mean nothing.

The behaviour had **no test at all**. Nothing in `DangerousPermissionClassifierTests` covered a
property-set permission, which is how an unexamined blanket answer survived from the day it was
written until an administrator looked at a window.

Reading a property set was worse than wrong: it was not answered. A property-set read fell through
to `CannotClassify`, so an entry granting read access to a set holding a local administrator
password was never marked at all.

## Decision

**A property set is dangerous exactly when it contains an attribute that is dangerous.** Writing a
set is judged by intersecting its members with the attribute-write list; reading one is judged by
intersecting them with the credential list. Both lists are already sourced to `docs/rules/` per
[0010](0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md).

**The answer is derived, not a second opinion.** This is the point. A separate judgement about which
property sets matter would be a seventh place answering "is this dangerous", and six places
disagreeing is the defect this component was built to end. Under this rule
`User-Account-Restrictions` is dangerous because Microsoft puts `userAccountControl` and
`msDS-AllowedToActOnBehalfOfOtherIdentity` in it, and `Personal-Information` is not because it holds
neither - and neither fact is written down here.

**Membership is read from the forest, never shipped.** A property set names none of its members;
each attribute points back at the set through `attributeSecurityGUID`. A customer can therefore put
their own attribute into a Microsoft-defined set, and a shipped list would call that set harmless
while the directory disagreed. The join is documented by Microsoft and the data was already in every
bundle.

**A set whose membership is unknown is `CannotClassify`.** A run that did not read the schema cannot
know what a set grants. It is not reported as safe, which the verdict's own contract requires.

**Reading a property set is now judged**, where nothing judged it before.

## Consequences

**A count going down is not evidence of improvement.** Applying this to one lab computer object took
its dangerous count from 27 to 24, which looked like the false positives being removed. Three of
those had been correct. The Windows LAPS encrypted-password attributes were not on the credential
list, so `ms-LAPS-Encrypted-Password-Attributes` - which had been marked by the blanket rule *by
accident* - went quiet. A false positive had been traded for a false negative, which is the worse
direction, and the number moved the way that looked like progress while it happened.

Correcting the credential list took the same object to 30, above where it started. Both moves were
right. **Neither direction of travel means anything on its own; only the reason does.**

**The credential list now includes the encrypted LAPS attributes**, at the same weight as the clear
text ones. Windows LAPS only encrypts above a 2016 domain functional level with encryption enabled;
Microsoft states that below it, passwords can be stored **only** in clear text. The schema is
extended either way, so the attribute names prove nothing about what they hold. Judging them as a
lesser thing would rest on an assumption about a forest's configuration that this component cannot
check, and would be wrong in exactly the environments least likely to have hardened anything else.

**`SELF` reading its own encrypted password will be marked on every LAPS-managed computer.** That is
Microsoft's recommended configuration, established by `Set-LapsADComputerSelfPermission`, so this is
a constant background rather than a discovery. It is accepted on a per-object screen because the
operator asked the question. **If it becomes noise, the answer belongs to the findings layer**, which
can see that a pattern is universal and say so once. It does not belong here: weakening a credential
verdict because the grant is common is how a product stops reporting the thing it was bought to
report.

**A run without a captured schema now marks fewer property-set permissions, not more.** Before this
record every one was red; now they are unassessed. That is a real reduction in what an offline read
of a bundle can say, and it is honest rather than regrettable - the previous answer was not
knowledge.
