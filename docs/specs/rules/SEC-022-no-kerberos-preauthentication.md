# SEC-022 ΓÇö an account that does not require Kerberos pre-authentication

**Status:** built 2026-09-01.
**Severity:** High.
**Rule identifier:** `SEC-022`.
**Implemented by:** `NoKerberosPreauthentication` in `SecureAD.Judgement`.

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory below cites a Microsoft source, and every case is stated in terms of the
directory rather than of this product's code. If a claim cannot be checked against the source beside
it, that is a defect in this document.

**What would be most useful to hear:** whether the decision in [┬º5](#5-what-is-not-excluded-and-why)
to report disabled accounts is right, and whether the severity in [┬º6](#6-severity) is right. Both
are judgement calls made against an absence of Microsoft guidance rather than against a source.

---

## 1. What it finds

Any captured account ΓÇö `user` or `computer` ΓÇö whose `userAccountControl` attribute has the
`ADS_UF_DONT_REQUIRE_PREAUTH` bit set.

In plain terms: *a domain controller will hand out material derived from this account's password to
anybody who asks, without the asker proving anything first.*

## 2. What pre-authentication is, and what turning it off does

Normally, before a key distribution centre will issue anything, the account must prove it already
knows its own password: it encrypts the current time with a key derived from that password and sends
it along with the request. A centre that cannot decrypt the timestamp answers with an error.

With this flag set, that proof is not required. The centre replies to the bare request with a message
containing material encrypted from the account's password ΓÇö and that reply can be attacked offline,
at leisure, with no risk of lockout and nothing logged as a failed logon.

## 3. Why it matters, in Microsoft's words

[Microsoft Defender for Identity, *Suspected AS-REP Roasting attack*](https://learn.microsoft.com/defender-for-identity/alerts-mdi-classic#credential-access-alerts)
(external ID 2412):

> Attackers use tools to detect accounts with their *Kerberos preauthentication* disabled and send
> AS-REQ requests without the encrypted timestamp. In response they receive AS-REP messages with TGT
> data, which may be encrypted with an insecure algorithm such as RC4, and save them for later use in
> an offline password cracking attack (similar to Kerberoasting) and expose plaintext credentials.

The same page gives the prevention step as *"Enable Kerberos preauthentication."*

**What the organisation can therefore mitigate:** the theft of a working domain credential by an
attacker who has none. Every other credential attack in this family needs a foothold first ΓÇö
kerberoasting needs an authenticated account to request a service ticket. This one does not, which is
what makes it the cheapest first move available against a forest.

## 4. The remedy, in Microsoft's words

[Defender for Identity, *Unsecure account attributes*](https://learn.microsoft.com/defender-for-identity/security-assessment-unsecure-account-attributes#unsecure-account-attributes)
lists it as a recommended action:

| Recommended action | Remediation | Reason |
|---|---|---|
| Remove Don't require Kerberos preauthentication | Remove this setting from account properties in Active Directory (AD) | Removing this setting requires a Kerberos pre-authentication for the account resulting in improved security. |

The finding's wording says that and nothing more. It does not promise the change is free: an account
was given this flag for a reason, usually a non-Windows Kerberos client that could not send
pre-authentication data, and clearing it may break whatever that was.

## 5. What is **not** excluded, and why

**Nothing is excluded.** Every account carrying the bit is reported. Two exclusions were considered
and rejected:

| Considered | Rejected because |
|---|---|
| Disabled accounts (`ADS_UF_ACCOUNTDISABLE`) | **No Microsoft source states that a key distribution centre refuses an AS-REQ for a disabled account.** The predecessor excluded them anyway. Excluding on an unevidenced belief risks hiding a real exposure, and re-enabling the account would restore it in full. The disabled state travels in the evidence and is named in the finding's wording instead, so an operator can rank it himself. |
| `krbtgt` | The predecessor special-cased it by relative identifier 502. Doing so needs SID parsing for a case that only arises on a tampered or hand-edited directory, and if it ever *did* arise it is something an administrator should be told about rather than something to hide. |

**A consequence worth stating plainly:** an organisation with a handful of disabled legacy service
accounts will see them here. That is a longer list than the predecessor produced, and every row on it
is true.

## 6. Severity

**High**, where the predecessor rated this Medium.

The reasoning is the one in [┬º3](#3-why-it-matters-in-microsofts-words): the attack needs no
credentials. It is rated the same as the two unconstrained-delegation rules, and above a rule
describing an exposure that requires a foothold first. This is a judgement rather than a Microsoft
position; Microsoft rates the *detection* of an AS-REP roasting attempt High, but that is an alert
about an attack in progress rather than a rating of the posture that permits it.

## 7. The bit

`0x00400000`, decimal 4194304, `ADS_UF_DONT_REQUIRE_PREAUTH` ΓÇö *"this account does not require
Kerberos preauthentication for logon."* Three Microsoft pages carry it and agree:

- [`ADS_USER_FLAG_ENUM` enumeration](https://learn.microsoft.com/windows/win32/api/iads/ne-iads-ads_user_flag_enum#constants)
- [`User-Account-Control` attribute](https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol#remarks)
- [Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#list-of-property-flags), which also gives the decimal

It is carried in the product beside the other flags by `UserAccountControlWording`.

## 8. What the rule reads

| Input | Why |
|---|---|
| `userAccountControl` | The flag. |
| `objectClass` | Reported beside the finding, and decides nothing. |
| `sAMAccountName` | The name shown, falling back to the distinguished name when absent. |

**No derived facts.** `RequiredDerivedFacts` is empty, so this rule is offered no derivation and is
unaffected by the refusal in `docs/decisions/0091`. It can judge a bundle that was never derived.

## 9. When it does not answer

| Case | What happens |
|---|---|
| `userAccountControl` absent | No verdict. The attribute is named in `InputsNotCaptured`, so silence is not reported as "clean". |
| `userAccountControl` present but not a number | No verdict, naming the same attribute. It is not read as zero, which would silently report the account as fine. |
| No object GUID | No finding. A finding must be attributable to an object or it cannot be acted on. |

## 10. What it rests on

`UserAccountControlEvidence`, holding the whole `userAccountControl` value the flag was read
from, stored in `finding_user_account_control`. `IsDisabled` is derived from that value
rather than stored beside it, so there is no second copy to disagree with the first.

## 11. Tests

`NoKerberosPreauthenticationTests`. The negative controls are the point: an ordinary account, and the
two flags either side of this one ΓÇö `0x200000` (`USE_DES_KEY_ONLY`) and `0x800000`
(`PASSWORD_EXPIRED`) ΓÇö which is what would catch a mistyped constant.

**Observed failing on 2026-09-01.** The constant was changed to `0x200000` and four of the nine tests
failed; it was restored and all nine passed. Whole `userAccountControl` values are used throughout
rather than the bare bit, so a rule matching on equality instead of on the bit would fail too.

## 12. Verified against `ad.lab`, 2026-09-01

The rule reported nothing on its first real run, and **reporting nothing was correct**. Establishing
that took three separate readings, because a rule that finds nothing and a rule that is broken look
identical from the outside:

| Question | How it was answered | Answer |
|---|---|---|
| Was the rule scheduled at all? | `run.log`: *Judge started rules=4* | yes |
| Did it reach a verdict, or fall over? | `rule_execution` in the judgement store | `Succeeded`, 2,082 accounts judged, 0 not judged |
| Does the forest contain anything to find? | `count-uac-flag.ps1`, reading the sealed evidence directly | **0 of 2,082 accounts carry the flag** |

**The third reading needed its own control.** A script that reports zero is worthless until it has
been seen reporting something, so it was run again against `0x80000`, the unconstrained-delegation
flag, and returned the four objects the lab is known to hold ΓÇö three domain controllers at 532480
and the planted `lab.unconstrained` at 524802. Only then does the zero mean anything.

**A positive case was owed at this point and is recorded in ┬º13 below.** Until one was observed the
rule was only known *not* to fire, which is the weaker half of what needs proving.
`Set-LabNoPreauthAccount.ps1` plants an account carrying the flag so that it can be repeated.

## 13. The positive case, observed against `ad.lab`, 2026-09-01

`lab.nopreauth` was planted in `ba.ad.lab` ΓÇö `userAccountControl` 4194818 (`0x400202`): the flag, a
normal account, disabled. The forest was captured and judged again, and the rule fired:

| Checked | Result |
|---|---|
| Capture saw the new account | 2,083 accounts carry `userAccountControl`, up from 2,082 |
| Capture recorded the flag | `count-uac-flag.ps1`: 1 account, `CN=lab.nopreauth,CN=Users,DC=ba,DC=ad,DC=lab` |
| The rule reached a verdict | `Succeeded`, 2,083 judged, 0 not judged |
| It fired once, and only once | one `SEC-022` finding, no others |
| Attributed to the right domain | `ba.ad.lab`, not either of the other two |
| Stored evidence matches the directory | `user_account_control` = 4194818, the value the directory holds |
| The disabled state reached the wording | the finding's detail carries the disabled sentence |

**The finding an operator would read:**

> `lab.nopreauth` does not require Kerberos pre-authentication, so anyone on the network can ask a
> domain controller for material encrypted from this account's password and crack it offline,
> without needing any credentials first. Clear "Do not require Kerberos preauthentication" on the
> account. The account is currently disabled, which lowers the urgency but not the need to clear the
> setting, because re-enabling it would restore the exposure.

**The same run confirmed the `P-112` fix on real data.** This bundle holds findings of three
different evidence kinds, which is exactly the case that was corrupted before. Read back through
`JudgementReader.ReadPage` ΓÇö the grid's own path, not the whole-store read ΓÇö every finding came back
with its own evidence type intact and the two `SEC-030` findings carried real security identifiers
(`S-1-5-21-ΓÇª-31608` and `ΓÇª-31612`) rather than the severity rank `"2"` the defect produced.


