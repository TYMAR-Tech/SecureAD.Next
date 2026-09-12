# SEC-028, SEC-029 and SEC-033 ΓÇö account flags that weaken a credential

**Status:** specified 2026-09-02. Not yet built.
**Severity:** see [┬º6](#6-severity).
**Rule identifiers:** `SEC-028`, `SEC-029`, `SEC-033`.
**Implemented by:** `PasswordNotRequired`, `ReversiblePasswordEncryption` and `DesEncryptionOnly` in
`SecureAD.Judgement` (planned).

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory cites a Microsoft source, and every case is stated in terms of the directory
rather than of this product's code.

**One document for three rules, because they are one Microsoft assessment.** All three are rows in
the same table of *Unsecure account attributes*, all three are bits of one attribute, and separating
the prose would mean writing the same background three times and letting it drift.

**None of the three has a predecessor card.** They are the `F-S44-2` situation for the second time:
nothing internal can anchor them. The anchor is Microsoft's assessment for *why*, and the
`UserAccountControl` article for the values ΓÇö and the values are additionally held against Microsoft
inside this product by `UserAccountControlWording`, which `SEC-022` already relies on.

**What would be most useful to hear:** whether the exclusion in [┬º5](#5-what-is-excluded-and-why) is
drawn in the right place, and whether the severities in [┬º6](#6-severity) are right.

---

## 1. What they find

| Rule | Flag | Value | Reports |
|---|---|---|---|
| `SEC-028` | `PASSWD_NOTREQD` | `0x0020` / 32 | an account that may have no password at all |
| `SEC-029` | `ENCRYPTED_TEXT_PWD_ALLOWED` | `0x0080` / 128 | an account whose password is stored so it can be decrypted back to plain text |
| `SEC-033` | `USE_DES_KEY_ONLY` | `0x200000` / 2097152 | an account restricted to DES, a cipher long since broken |

All three values are from
[Use the UserAccountControl flags to manipulate user account properties](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#list-of-property-flags),
which gives hexadecimal and decimal side by side.

## 2. What each flag does

**`PASSWD_NOTREQD` ΓÇö "No password is required."** Microsoft's own description, from the article
above. The account is exempt from the domain's minimum password length, so it may hold an empty
password. Anyone who can reach authentication can then sign in as it with nothing.

**`ENCRYPTED_TEXT_PWD_ALLOWED` ΓÇö "The user can send an encrypted password."** The directory keeps a
reversibly encrypted copy of the password, so a reader with the right access recovers the password
itself rather than a hash. Microsoft's stated reason for removing it: *"Removing this setting
prevents easy decryption of the account's password."*

**`USE_DES_KEY_ONLY` ΓÇö "Restrict this principal to use only Data Encryption Standard (DES)
encryption types for keys."** Microsoft's stated reason for removing it: *"Removing this setting
enables the use of stronger encryption algorithms."*

## 3. Why they matter, in Microsoft's words

All three are rows of one table in
[Defender for Identity, *Unsecure account attributes*](https://learn.microsoft.com/defender-for-identity/security-posture-assessments/accounts#unsecure-account-attributes),
whose description is:

> "Microsoft Defender for Identity continuously monitors your environment to identify accounts with
> attribute values that expose a security riskΓÇª Accounts configured with unsecure attributes are
> windows of opportunity for attackers and can expose risks.
>
> For example, if the **PasswordNotRequired** attribute is enabled, an attacker can easily access the
> account. This is especially risky if the account has privileged access to other resources."

**Microsoft names `PasswordNotRequired` as its worked example**, which is one input to the severity
in ┬º6.

**What the organisation can therefore mitigate:** an account whose credential is weaker than the
domain's policy claims. A password policy is enforced on accounts that are subject to it; each of
these flags is a per-account exemption from part of that protection, and none of them is visible on
the screen an administrator uses to review the policy.

## 4. The remedy, in Microsoft's words

| Rule | Recommended action | Remediation | Reason |
|---|---|---|---|
| `SEC-028` | Remove Password not required | Remove this setting from account properties in AD | Removing this setting requires a password to be used with the account and helps prevent unauthorized access to resources. |
| `SEC-029` | Remove Store password using reversible encryption | Remove this setting from account properties in AD | Removing this setting prevents easy decryption of the account's password. |
| `SEC-033` | Remove Use Kerberos DES encryption types for this account | Remove this setting from account properties in AD | Removing this setting enables the use of stronger encryption algorithms. |

**Each finding's wording says that and no more.** Two of the three carry a cost Microsoft does not
state and this product must:

- **`SEC-029`** ΓÇö clearing the flag does not remove the stored reversible copy. **The password must
  be changed afterwards**, or the recoverable value remains until it is. The guidance says so.
- **`SEC-033`** ΓÇö the flag is usually present because something genuinely could not do better.
  Clearing it without establishing what authenticates as the account will break that thing.

## 5. What is excluded, and why

**`SEC-028` excludes interdomain trust accounts. Nothing else is excluded, by any of the three.**

This reverses the *nothing is excluded* position `SEC-022` took, and it does so because **here there
is a Microsoft source and there it was not.** The
[UserAccountControl article](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties#useraccountcontrol-values)
states it plainly:

> "A Windows trust account is exempt from having a password through PASSWD\_NOTREQD
> UserAccountControl attribute value because trust objects don't use the traditional password policy
> and password attributes in the same way as user and computer objects."

and

> "For this reason the PASSWD\_NOTREQD UserAccountControl attribute is set on
> INTERDOMAIN\_TRUST\_ACCOUNT accounts by default."

**So every trust in the forest would be reported, every one of them would be by design, and every one
would be false.** The test is the object's own `INTERDOMAIN_TRUST_ACCOUNT` bit (`0x0800` / 2048) from
the same table ΓÇö not its name, and not its container.

**Decided by the owner, 2026-09-02**, and it is a product decision rather than an engineering one: it
trades a guaranteed-benign row for a rule that stays quiet about one documented case.

**Two exclusions were considered and rejected**, for both `SEC-028` and the other two:

| Considered | Rejected because |
|---|---|
| Disabled accounts | The same reasoning as `SEC-022` ┬º5. The flag survives re-enabling, so the exposure is dormant rather than absent. The disabled state travels in the evidence and is named in the wording. |
| Computer accounts | A computer account is a credential like any other. No Microsoft source says these flags mean something different on one. |

## 6. Severity

**These are judgements made against an absence of Microsoft severity guidance**, as `SEC-022` ┬º6 was.
Microsoft rates the *assessment*, not the individual attribute.

| Rule | Severity | Reasoning |
|---|---|---|
| `SEC-028` | **High** | The account may have **no password**. This is Microsoft's own worked example of the assessment, and it needs no cracking, no capture and no foothold ΓÇö the same "costs an attacker nothing" argument that put `SEC-022` at High. |
| `SEC-029` | **High** | The stored value returns the **password itself**, not a hash to be attacked. Whoever reaches it gets a working credential with no work in between, and people reuse passwords. |
| `SEC-033` | **Medium** | Real, and weaker than the other two: DES must still be attacked, and the account's exposure depends on what else accepts DES. It is a degraded protection rather than an absent one. |

**The argument against `SEC-029` at High**, stated so it is not lost: reading the reversibly
encrypted value requires directory replication access, which is close to domain administrator
already. The counter is that this is exactly the position `SEC-022` reasoned from ΓÇö a stored
credential that can be turned into a working one is worse than one that must be guessed ΓÇö and that
the flag is almost never set deliberately on a modern forest.

## 7. What the rules read

| Input | Why |
|---|---|
| `userAccountControl` | The flag, and for `SEC-028` the trust-account bit that excludes an object. |
| `objectClass` | Reported beside the finding, and decides nothing. |
| `sAMAccountName` | The name shown, falling back to the distinguished name when absent. |

**No derived facts.** `RequiredDerivedFacts` is empty for all three, so none is offered a derivation
and none is affected by the refusal in `docs/decisions/0091`. They judge a bundle that was never
derived.

## 8. When they do not answer

Identical to `SEC-022` ┬º9, because the reading is identical:

| Case | What happens |
|---|---|
| `userAccountControl` absent | No verdict. The attribute is named in `InputsNotCaptured`, so silence is not reported as "clean". |
| `userAccountControl` present but not a number | No verdict, naming the same attribute. It is not read as zero, which would silently report the account as fine. |
| No object GUID | No finding. A finding must be attributable to an object or it cannot be acted on. |

## 9. What they rest on

`UserAccountControlEvidence`, stored in `finding_user_account_control` ΓÇö **one kind and one table
shared with `SEC-022`**, because all four rules read bits of one integer and all four store the whole
integer.

That sharing is why an operator reading a `SEC-028` finding can see from its evidence that the same
account is also disabled, also DES-only, or also a domain controller. Four tables differing only in
which bit their rule cared about would have hidden that and drifted apart.

## 10. Tests

`PasswordNotRequiredTests`, `ReversiblePasswordEncryptionTests` and `DesEncryptionOnlyTests`.

The negative controls follow `SEC-022` ┬º11, which is the shape that catches the mistake this rule
family is most likely to make:

- **whole `userAccountControl` values throughout, never the bare bit** ΓÇö a rule matching on equality
  rather than on the bit would otherwise pass
- **the flags either side of each one**: `0x10`/`0x40` around `PASSWD_NOTREQD`, `0x40`/`0x100` around
  `ENCRYPTED_TEXT_PWD_ALLOWED`, `0x100000`/`0x400000` around `USE_DES_KEY_ONLY` ΓÇö which is what
  catches a mistyped constant
- **an ordinary account** at `0x200`
- for `SEC-028`, **a trust account carrying the flag**, which must not be reported, and a
  **non-trust account carrying it**, which must

To be reported here when built: each rule mutated in both directions, with the failures observed and
what they said recorded, as `SEC-022` ┬º11 and `SEC-027` ┬º11 do.

**Observed failing on 2026-09-02.** Two mutations, and the second had to be run on its own:

| Mutation | What failed | What it said |
|---|---|---|
| `PASSWD_NOTREQD` changed from `0x20` to `0x40` (`PASSWD_CANT_CHANGE`, the flag next to it) | 5 of 12 | `EachRuleReportsAnAccountCarryingItsFlag`, `ANonTrustAccountCarryingPasswordNotRequiredIsReported`, `TheEvidenceCarriesTheWholeValueΓÇª` and `ADisabledAccountIsReportedΓÇª` all found no finding; `ANeighbouringFlagDoesNotFireARule` found one on `0x40` and printed it |
| The trust-account exclusion forced never to fire | 1 of 2 | `ATrustAccountCarryingPasswordNotRequiredIsNotReported`, showing the finding it should not have made against `CONTOSO$` at `userAccountControl` 2080 |

**The second mutation had to be isolated, and that is worth recording.** Run together with the first,
`ATrustAccountCarryingPasswordNotRequiredIsNotReported` **passed** ΓÇö because the mutated flag no
longer matched the fixture at all, so the exclusion was never reached. A mutation that is masked by
another mutation proves nothing about the test, and two mutations run at once can hide each other's
survivors.

## 11. Verified against `ad.lab`, 2026-09-02

**`SEC-028`'s exclusion is the one that mattered, and a real forest proved it.**
`count-uac-flag.ps1 -Flag 0x20`, reading sealed evidence directly, found **7** accounts carrying
`PASSWD_NOTREQD`. The rule reported **3**.

| Accounts carrying the flag | `userAccountControl` | Reported |
|---|---|---|
| `AD$` ├ù2, `BA$`, `PH$` ΓÇö the four interdomain trust accounts | **2080** (`0x820`) = `INTERDOMAIN_TRUST_ACCOUNT` + `PASSWD_NOTREQD` | no |
| `Guest` in each of the three domains | 66082 = `PASSWD_NOTREQD` + `DONT_EXPIRE_PASSWORD` + `NORMAL_ACCOUNT` + `ACCOUNTDISABLE` | yes |

**`0x820` is precisely the value Microsoft documents a trust account as carrying by default**, and
the directory produced exactly that, four times. **Without the exclusion this rule would have
reported seven accounts and four would have been false** ΓÇö on every forest with a trust, not just
this one. That is [┬º5](#5-what-is-excluded-and-why) proven against a directory rather than a fixture.

**The `Guest` findings are true and worth having.** Each is disabled and the finding says so, which
is the disabled-state wording doing its job on real data.

### `SEC-029` and `SEC-033`

| Question | How it was answered | Answer |
|---|---|---|
| Does the forest hold anything to find? | `count-uac-flag.ps1 -Flag 0x80` and `-Flag 0x200000` | **0 of 2,082** for each ΓÇö the silence is the forest's |
| Is the reading script itself trustworthy? | the same script at `-Flag 0x20` | 7 accounts, named ΓÇö so its zero means something |
| Does each rule fire on a genuine case? | `Set-LabAccountFlags.ps1` planted `lab.reversible` (`0x282`) and `lab.desonly` (`0x200202`) | **1 finding each**, High and Medium |
| On the right object and domain? | `show-findings.ps1` | `CN=lab.reversible` and `CN=lab.desonly`, both `ba.ad.lab` |

**The whole run was headless**, using `securead-cli --library ΓÇª`, which now captures, derives and
judges in one command. The lab was returned to its prior state with
`Set-LabAccountFlags.ps1 -Remove`, confirmed by re-reading the directory.
