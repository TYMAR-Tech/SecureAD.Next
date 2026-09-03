# SEC-092 — LAPS password rotation has stopped

**A computer whose stored LAPS expiration time has passed and stayed passed.** The password should
have rotated by now and did not, so the local administrator password on that machine is a fixed
value that the directory believes is being cycled.

This document is written from Microsoft's Windows LAPS documentation and from the code. It is a
layer document, not a product position: nothing here overrides a record in
[`docs/decisions/`](../../../decisions/).

## For a reviewer

The predecessor card [`docs/rules/SEC-092.md`](../../../rules/SEC-092.md) is **source material, not
an answer**. Three things were taken from it and one was rejected:

| From the card | Taken? |
| --- | --- |
| Fire when the stored expiration is at or before the reference time | **Partly** — the intent, but with a 24-hour grace (§8) and measured from the *newest* lapsed timestamp, which `ad.lab` forced (§11) |
| Sentinel values (null, zero, negative) are *never set*, not *stale* | Yes — §6 |
| Its domain-controller exclusion matched `OU=Domain Controllers` in the DN | **No** — §5 |
| Severity `High` | **No** — Medium, the owner's decision of 2026-09-03, §7 |

## 1. What it finds

A computer account carrying a LAPS password-expiration timestamp that decodes to an instant **more
than 24 hours before the judging's reference time**, where no other timestamp on that object is
still in the future.

Two qualifications are load-bearing and each has its own section, because the plain reading of that
sentence is wrong in a way that produces false or overstated findings:

- **The 24-hour grace** (§8), without which a healthy machine mid-rotation is reported.
- **Where a machine carries both timestamps**, any fresh one clears it, and the overdue span is
  measured from the **newest** lapsed value (§11). The legacy attribute is residue that stops moving
  at migration, so measuring from the oldest overstates the outage — on `ad.lab` by more than
  double.

Microsoft states the mechanism plainly:

> Windows LAPS reads the password expiration time from Windows Server Active Directory during each
> policy processing cycle. If the password is expired, a new password is generated and stored
> immediately.
>
> — [Get started with Windows LAPS and Windows Server Active
> Directory](https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory#rotate-a-password)

and again:

> The device rotates the password automatically when the password expiration time is reached.
>
> — [Key concepts in Windows
> LAPS](https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview#basic-scenario-flow)

So a past-dated expiration is not a normal resting state. In a working deployment the value is
always in the future, because the moment it is not, the next policy cycle replaces it with a new one
`PasswordAgeDays` ahead. **A value that is in the past is a statement that no policy cycle has
completed since it lapsed.**

## 2. Why this is the hole the other two LAPS rules leave

SecureAD already ships two LAPS rules and they divide the estate by *presence*:

| Rule | Fires when |
| --- | --- |
| SEC-091 | The computer carries neither expiration timestamp |
| SEC-094 | A Windows-LAPS-capable computer carries only the legacy timestamp |
| **SEC-092** | **The timestamp is present, is the right one, and has lapsed** |

A machine that was correctly onboarded and has since stopped rotating passes both in silence. Its
timestamp is present, so SEC-091 says nothing. It is the modern timestamp, so SEC-094 says nothing.
The product reports a clean bill on a machine whose local administrator password has become a static
shared secret — which is the exact condition LAPS exists to prevent, and the condition an attacker
who recovers one machine's password relies on to reach the next one.

## 3. Why a stale local administrator password matters

The local administrator account is present on every Windows machine and cannot be deleted. Where its
password is the same on many machines, recovering it from one machine — from memory, from a disk
image, from a backup — yields administrative access to all of them, without any domain credential
being involved and without touching a domain controller. That is the lateral movement LAPS is
deployed to break, by making every machine's password different and short-lived.

A password that has stopped rotating loses the second half of that. It is still unique to the
machine, which is worth something, but it is now permanent: whatever exposure it has had since it
was last set is exposure it keeps. Microsoft's default `PasswordAgeDays` is 30 and its maximum is
365, so an organisation's own policy states how long it considers a local administrator password
acceptable. **A machine past its expiration has exceeded that policy, and the directory does not say
so anywhere an operator would look.**

## 4. What the timestamp is

`msLAPS-PasswordExpirationTime` is, in Microsoft's words:

> a 64-bit integer that specifies the currently scheduled password expiration time in UTC.
>
> — [Windows LAPS schema extensions
> reference](https://learn.microsoft.com/windows-server/identity/laps/laps-technical-reference)

Two facts from that same page matter here:

- **`SearchFlags` is `0`.** Unlike `msLAPS-Password`, whose `SearchFlags` of `904` includes
  `fCONFIDENTIAL`, the expiration time is **not confidential by default**. An ordinary read returns
  it. This rule still consults the schema derivation (§9), because a forest may mark any attribute
  confidential itself, but the ordinary case is that the value is readable.
- **It is `IsMemberOfPartialAttributeSet: False`**, so it is not in the global catalogue. This
  product reads each domain's own partition rather than the global catalogue, so that costs nothing
  here — but it is why a global-catalogue-based tool would see nothing.

`ms-Mcs-AdmPwdExpirationTime` is the legacy Microsoft LAPS equivalent and carries the same FILETIME
in the same way. Both are decoded by
[`LapsTimestamp`](../../../../next/src/SecureAD.Evidence/Findings/LapsTimestamp.cs), which is
already shared with SEC-091, SEC-094 and the LAPS inventory so that no two screens can disagree
about whether a value is present.

## 5. What is excluded, and why

| Excluded | Why | How |
| --- | --- | --- |
| Anything that is not a computer | The rule is about machine local administrator passwords | `LapsAttributes.IsComputer`, on the **most derived** class |
| Group managed service accounts | Their `objectClass` chain runs *through* `computer`; three in `ad.lab` do | Same test — reading the last value, not asking whether `computer` appears |
| Disabled computer accounts | No running machine, so nothing is failing to rotate | `LapsAttributes.IsDisabled`, the owner's decision of 2026-09-03 |
| Domain controllers | They have no conventional local administrator account; LAPS manages the DSRM password separately | `DomainControllerSignals`, **never the distinguished name** |

**The domain-controller exclusion is where this document departs from the predecessor.** That card
excluded controllers with `distinguished_name NOT LIKE '%,OU=Domain Controllers,%'`, having just
replaced a `sAMAccountName` subquery that leaked when the name was null. Both are string matching,
and this product replaced both with `DomainControllerSignals`, which reads the object's own
attributes.

Carry forward the correction recorded in **SEC-091 §5**: `DomainControllerSignals` reads *one*
object, so a machine promoted into a child domain leaves a member-server computer account behind in
the parent domain that carries none of a controller's signals. That account is excluded here anyway
— it is disabled, which is exactly what `ad.lab` showed for `BADC` and `PHDC`.

## 6. Sentinel values are *never set*, not *stale*

A null, zero or negative FILETIME is not a password that expired in 1601. It is a value written
empty. Reporting it as stale would put an absurdity in front of an operator and would also duplicate
SEC-091, which owns the *nothing is managing this machine* case.

**This needs no new code.** `LapsTimestamp.Decode` already refuses `fileTime <= 0` and anything
outside the FILETIME range, returning `null` from `ExpiresUtc`; `LapsTimestamp.Reading` then reports
`Unreadable` rather than `Present`. So the rule fires only on a value that decoded to a real
instant, and every sentinel falls out before any comparison happens. A negative control is owed for
each of null, zero and negative (§10).

## 7. Severity

**Decision: Medium.** The owner's, 2026-09-03.

The predecessor said `High`. That was not inherited, because severity should follow from what this
rule establishes and this rule establishes less than SEC-091 does.

The case for Medium, which is the one accepted: the password is still unique to the machine. LAPS
did run here, and the per-machine randomisation — the part that breaks lateral movement between
machines — is intact. What has lapsed is the freshness. SEC-091 reports a machine with *no* LAPS at
all and ships at Medium, so a machine that is managed but stale must not outrank it.

The case that was heard and not taken, recorded so it is not re-argued: the finding is arguably a
signal that management has failed on this machine — the agent, the policy, or the machine's ability
to reach a controller — with the operator unable to tell how long ago, nor what else on that machine
has stopped receiving policy.

## 8. How far past is stale

**Decision: a 24-hour grace.** The owner's, 2026-09-03. A machine is reported when its expiration is
more than 24 hours before the reference time.

The predecessor fired the instant the expiration was at or before capture time, with no tolerance.
Microsoft's documentation gives two reasons that would produce findings an operator cannot act on:

1. **A forced rotation legitimately sets the expiration to now.** `Set-LapsADPasswordExpirationTime`
   exists to make a machine rotate early, and Microsoft's own example sets the expiration *to the
   current time*. The machine then rotates at its next policy cycle. Between those two moments the
   account is past-due and perfectly healthy.
2. **A policy cycle is not instantaneous.** Group Policy refreshes on a 90-minute interval with up
   to 30 minutes of random offset, so a machine that is switched on and working can sit past-due for
   two hours by design.

A third case is not a defect but is not actionable either: a laptop that is switched off for a
fortnight is past-due for a fortnight and there is nothing wrong with it or its configuration. The
grace does not solve that one; nothing in the directory can, because the directory does not record
whether a machine was switched on.

Twenty-four hours removes every false finding Microsoft's documentation predicts, while delaying a
true finding by a single day — and a machine that has genuinely stopped rotating is still stopped
tomorrow.

**The grace cannot be `PasswordAgeDays`.** That setting lives in policy, not in the directory, and
this product judges sealed evidence — so the rule cannot know a given machine's configured age. The
grace is a fixed span, and the finding states how far past the machine actually is so an operator
can tell one day from one year.

**A future-dated timestamp is out of scope**, decided at the same time. A wildly future-dated
expiration also means a password that will not rotate, but it has a different cause and different
advice, and Microsoft's `PasswordExpirationProtectionEnabled` — on by default — already corrects an
expiration further out than `PasswordAgeDays`. It is recorded on the punch list rather than smuggled
into this rule.

## 9. When it does not answer

Absence of the attribute is not this rule's subject — that is SEC-091. But the rule still consults
the attribute-visibility derivation through `LapsAttributes.Judgeability`, for the reason SEC-094
gives: if this forest has marked the timestamp confidential, the directory withholds it silently and
a rule cannot tell *not managed* from *not shown*. Judging refuses the whole run in that case rather
than reporting per-object silence, per `docs/decisions/0091`.

The rule reads the reference time from `JudgingContext.AsOf`, never from the clock. That value is
the one recorded in the judgement's `evaluation_as_of` column, so re-judging this sealed bundle in a
year reproduces exactly these findings rather than reporting the whole estate as stale.

## 10. Tests owed

Positive:

- A computer whose modern timestamp lapsed beyond the grace is reported.
- A computer whose legacy timestamp lapsed beyond the grace is reported.

Negative controls, one per exclusion and one per boundary:

- A timestamp in the future is not reported.
- A timestamp lapsed by less than 24 hours is not reported.
- A timestamp lapsed by exactly 24 hours is not reported, and one lapsed by a minute more is.
- A null, a zero and a negative FILETIME are each not reported (three separate cases).
- Where both timestamps have lapsed, the age is measured from the **newer** — see §11, which is
  where that was learned.
- An unreadable non-numeric value is not reported.
- A disabled computer with a lapsed timestamp is not reported.
- A domain controller with a lapsed timestamp is not reported.
- A group managed service account with a lapsed timestamp is not reported.
- A user object carrying a lapsed timestamp is not reported.
- Two judgings of the same bundle at different wall-clock times, with the same recorded reference
  time, produce identical findings.

## 11. Verified against `ad.lab`, 2026-09-03 — and it changed the rule

Judging the sealed bundle `ad.lab-20260902-175041` ran all three LAPS rules over 14 computers with
none unjudgeable, and `SEC-092` reported one machine. The exclusions held on the real objects that
prompted them: `BADC` and `PHDC` (both `userAccountControl` 4098) silent, and `PHMS1` silent here
while `SEC-094` reported it — its legacy expiry falls three weeks *after* the run, so nothing about
it is stale.

**But the finding carried a wrong number, and only the forest could have shown it.** `PHWK1` carries
both timestamps:

| Attribute | Raw FILETIME | Decoded | Age at 2026-09-03 |
| --- | --- | --- | --- |
| `msLAPS-PasswordExpirationTime` | 134126598388875149 | 2026-01-12 02:50:38Z | 234 days |
| `ms-Mcs-AdmPwdExpirationTime` | 133894007684390633 | 2025-04-17 21:59:28Z | 503 days |

The rule reported **503 days overdue**, having been written to report the older of two lapsed
timestamps on the reasoning that it was the longer outage. That reasoning was wrong, and it is wrong
for the reason `SEC-094` exists to state: **the legacy attribute is residue.** Microsoft's migration
procedure removes the policy and the software and never clears the value, so `PHWK1`'s legacy
timestamp stopped moving the day the machine migrated to Windows LAPS. The password went on rotating
until January.

**The newest lapsed expiration is the last moment anything was due to rotate this password**, so it
is the only one an overdue span can honestly be measured from. Reporting the oldest overstated the
outage by more than double. An overstated age is not a safe error: an operator triaging by age would
put this machine above genuinely worse ones, and the number would not survive him checking it.

**The tests did not catch this and could not have.** The rule and its test were written from the
same belief, so `AMachineWhereBothTimestampsLapsedIsReportedOnce` asserted 400 days for exactly the
reason the rule produced it. The mutation swapping oldest for newest *did* fail that test, which
made the check look sound while it was measuring only its own premise — `F-S44-2` in
[`.github/copilot-instructions.md`](../../../../.github/copilot-instructions.md), and the reason
step 18 is not optional.

Corrected the same day: the rule now measures from `dates.Max()`, and the test asserts 30 days and
explicitly denies 400.
