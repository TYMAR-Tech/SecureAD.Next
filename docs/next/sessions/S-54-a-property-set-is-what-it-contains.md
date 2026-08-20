# S-54 — A property set is what it contains

**Status: closed. See *What this session leaves behind*.**

Written 2026-08-18, continuing from [`S-53`](S-53-the-schema-the-run-already-read.md). Read
[`0074`](../../decisions/0074-red-marks-a-takeover-permission-when-the-operator-asks.md) and
[`0075`](../../decisions/0075-a-property-set-is-judged-by-what-a-forest-puts-in-it.md).

**The tree was at `build W`, 1,634 tests green.** Names resolved for the first time, which is what
made the next defect visible.

---

## Why this

Resolving the schema had a second effect nobody planned. GUIDs that previously could not be resolved
were unclassifiable; now they resolved, reached the classifier, and were judged. So the owner's next
screenshot showed `Write Personal-Information, Read Personal-Information` marked **Takeover** on the
`SELF` entry of a computer object.

That entry is created by Active Directory on every user and computer that has ever existed, and
Microsoft's schema reference lists `Personal-Information` as addresses, telephone numbers,
photographs and certificates.

`DangerousPermissionClassifier` was answering `Dangerous` for **every** property-set write, and
**nothing tested it.** No test in `DangerousPermissionClassifierTests` covered a property-set
permission at all, which is how an unexamined blanket answer survived from the day it was written
until somebody looked at a window.

---

## What Learn settled

The owner's instruction was *"I want this to be measured against what Learn says is dangerous"*, and
Learn answers it completely.

| Set | Microsoft's membership | Verdict |
|---|---|---|
| `User-Account-Restrictions` | `userAccountControl`, `msDS-AllowedToActOnBehalfOfOtherIdentity`, `pwdLastSet`, `accountExpires` | **dangerous** — it is the RBCD vector |
| `Personal-Information` | addresses, telephone numbers, photographs, certificates | **not** |

Both of those dangerous attributes were already on the classifier's own list. So the rule is not a
new opinion, and that is the whole point of it:

> **A property set is dangerous exactly when it contains an attribute that is dangerous.**

It is *derived* from a list already sourced to `docs/rules/`. A separate judgement about which sets
matter would be a seventh place answering "is this dangerous", and six places disagreeing is the
defect this component exists to end.

**Membership is the forest's and cannot be shipped.** A property set names none of its members; each
attribute points back through `attributeSecurityGUID`. A customer can put their own attribute into a
Microsoft-defined set. `CapturedAttributeCatalog` already captured the join and described it in
exactly those terms; nothing had ever read it.

---

## The number moved twice, both times for good reasons, in opposite directions

This is the part worth carrying forward.

| | Count on one lab computer | Why |
|---|---|---|
| Before | **27** | every property-set write marked |
| After the set fix | **24** | three false marks removed — *and one true one* |
| After the LAPS fix | **30** | six real detections that had never been reported |

The drop to 24 **looked like progress and contained a regression.** The Windows LAPS encrypted
attributes were not on the credential list, so `ms-LAPS-Encrypted-Password-Attributes` — which the
blanket rule had marked *by accident* — went quiet. A false positive had been traded for a false
negative, which is the worse direction, and it happened while the number moved the way that looks
like success.

The rise to 30 **looked like noise and was detection.** It came from two paths, not one: the
property set on `SELF`, and direct attribute reads of `msLAPS-EncryptedPassword` held by three
delegated groups. Those are grants that hand out a local administrator password.

**Neither direction means anything on its own. Only the reason does.**

---

## What this session leaves behind

**Built:** `attributeSecurityGUID` read into a property-set membership map,
`SchemaGuidCatalog.MembersOfPropertySet`, `ClassifyPropertySetWrite` rewritten against membership, a
`ClassifyPropertySetRead` that never existed, four encrypted LAPS attributes added to the credential
list, and the `ControlAccess` bare-noun wording fixed. **1,653 tests, at `build Z`.**

### Three refusals worth having written down

**Reading an encrypted LAPS password is `Dangerous`, not `DangerousInCombination`.** The tempting
argument is that ciphertext is only a credential to somebody who can also decrypt it, which is what
`DangerousInCombination` exists for. The owner refused it on better grounds: *"not all environments
use encrypted even with the new LAPS."* Windows LAPS only encrypts above a 2016 domain functional
level with encryption enabled, and Microsoft states that below it passwords can be stored **only** in
clear text. The schema is extended either way, so the attribute names prove nothing about what they
hold. The lesser verdict would have rested on an assumption about a forest's configuration that this
component cannot check.

**`SELF` reading its own encrypted password stays marked**, though it is Microsoft's recommended
configuration and will therefore appear on every LAPS-managed computer. If it becomes noise the
answer belongs to the findings layer, which can see that a pattern is universal and say so once.
Weakening a credential verdict because the grant is common is how a product stops reporting the thing
it was bought to report.

**A genuine extended right keeps its bare name.** The `ControlAccess` bit rendered its GUID through
an identity function, so a *property set* named by that bit produced rows reading
`Private-Information, Write Private-Information, Read Private-Information` — a first item that read
as a fragment. The repair words only the mismatched case, as `Control access to X`, because
`PermissionWording` states outright that *the words are Microsoft's, not this product's* and an
administrator comparing this screen against the ACL editor must not find two words for one right.

### A method question the owner raised, and was right about

Asked whether one access control entry commonly carries rights judged differently, a measurement was
run against a lab bundle. The owner then asked:

> *"help me understand why we are measuring in my app. is what we are trying to do not something
> that Learn can explain to us"*

**He was right and the measurement was deleted.** The design defect was derivable from Learn alone:
`ACCESS_MASK` is a set of independent bits, `AccessCheck` evaluates per right and accumulates across
entries, and the classifier judges rights differently by construction — so a row showing N rights and
carrying one mark cannot say which right earned it. That is structural, not statistical, and it does
not become more or less true at 5% or 60%.

Two further hazards were named:

- **One lab forest is weak evidence for a product shipping to many.** Percentages from it were being
  presented as if they characterised the problem generally.
- **Calibrating security judgement to observed frequency is backwards.** A finding that most marked
  rows look partly innocent invites the reading *the marks are noisy, mark less* — which tunes the
  product's opinion to whatever the sample contained. `0010` already says the rule catalogue is
  sourced to specifications rather than observation, for exactly this reason.

Measurement remains legitimate for three things and no others: **volume and ergonomics**, **whether
reality departs from the model**, and **verification that a fix worked**. The row-shape question was
none of them.

### Findings

- **`F-S54-1`** — **The blanket property-set answer had no test, in either direction.** It was
  written, shipped, and reached a screen without one assertion. When it was replaced, **no golden
  test changed** — which is the finding, not a reassurance.
- **`F-S54-2`** — **A fix can trade a false positive for a false negative and look like an
  improvement.** Recorded in `0075` because the shape recurs: any change that narrows a verdict can
  silence a true one, and the count will move the reassuring way while it happens.
- **`F-S54-3`** — **`SecretAttributeReads` was two names when Microsoft publishes six.** The four
  Windows LAPS encrypted attributes were absent from a list written after Windows LAPS existed. A
  list of credential attributes needs a source and a review date, not just entries.

### Agreed and not built

- **Option C — per-right marks inside the row.** Settled in principle and unbuilt. A row stays one
  access control entry, because an ACE is what the directory holds, what canonical order applies to
  and what an administrator removes; but the mark moves to the right that earned it. `0074` and the
  Learn reasoning above are its grounds — **not** the measurement, which was deleted.
- **Saying when a name came from the shipped table only** (`F-S53-*`), still unsurfaced.
- **The base-schema disagreement finding** from `0014`, now reachable.
