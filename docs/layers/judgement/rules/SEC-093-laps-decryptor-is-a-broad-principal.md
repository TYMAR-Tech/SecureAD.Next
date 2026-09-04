# SEC-093 — a broad principal can decrypt LAPS passwords

## For a reviewer

The subject of this rule is a **Group Policy Object**, not a computer. Section 3 explains why, and it
is not a limitation of what is built — it is a limit of what the evidence can support.

## 1. What it finds

A Group Policy Object that configures Windows LAPS password encryption, where the principal
authorized to decrypt those passwords is — or effectively contains, through nested group membership
— a broad principal such as Domain Users, Authenticated Users or Everyone.

## 2. Why this matters

Windows LAPS can encrypt each managed local administrator password before storing it in the
directory. Microsoft describes the mechanism in
[Key concepts in Windows LAPS](https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview#windows-server-active-directory-passwords):

> The Windows LAPS password encryption feature is based on the Cryptography API: Next Generation
> Data Protection API (CNG DPAPI). CNG DPAPI supports multiple encryption modes, but Windows LAPS
> supports encrypting passwords against only a single Windows Server Active Directory security
> principal (user or group).

That single principal is set by the `ADPasswordEncryptionPrincipal` policy setting.

**Decryption is not governed by the access control list.** The same page separates the two:

> When a user is granted permission to query a password from Active Directory that doesn't
> automatically imply that the user has permission to decrypt an encrypted password.

So the directory permissions SEC-090 examines and the decryptor this rule examines are two
independent gates, and an estate can be tight on one and open on the other. If the decryptor is
broad, every member can decrypt every password that policy protects — regardless of who was granted
read access.

**Nested membership is the centre of the rule, not an edge case.** Microsoft's documented answer to
needing more than one decryptor is a wrapper group:

> If you need to grant decryption permissions to multiple security principals, to resolve the
> constraint, you can create a wrapper group that has all the relevant security principals as
> members.

A wrapper group is the supported pattern and is not itself a finding. What makes it one is what
ended up inside it.

## 3. What this rule refuses to claim

**It does not say which machines are affected**, and this is a deliberate refusal rather than
unfinished work.

Two facts prevent it. First, Microsoft states in
[Key concepts](https://learn.microsoft.com/windows-server/identity/laps/laps-concepts-overview#password-encryption):

> The security principal that's authorized to decrypt the password can't be changed after a password
> is encrypted.

A password sitting in the directory was encrypted against whatever the policy named **at the moment
it was written**, and that value is not recorded anywhere the directory can be asked. Second, even
if it were, attributing a policy to a machine needs Group Policy scoping, which
[`0094`](../../../decisions/0094-a-wmi-filter-is-captured-and-named-never-evaluated.md) permits
using to raise a finding but which cannot account for a WMI filter.

Naming machines would therefore state a fact about the past that no evidence establishes. The owner
settled this on 2026-09-03: *"can we even confidently do per machine since we cant really know if
the current decryptors group applies to the machine or not at any point in time."*

**Every finding carries the consequence of the same fact.** Correcting the policy protects passwords
written from then on; passwords already stored stay decryptable by the old principal until each is
rotated. The remediation says so.

## 4. What the setting can hold, and what an invalid value does

[Configure policy settings for Windows LAPS](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings#adpasswordencryptionprincipal)
gives three accepted forms:

> 1. `S-1-5-21-2127521184-1604012920-1887927527-35197`
> 2. `contoso\LAPSAdmins`
> 3. `lapsadmins@contoso.com`

**An unconfigured setting is the safe state and never fires.** The same page:

> If this setting isn't specified, only members of the Domain Admins group in the device's domain
> can decrypt the password.

**An invalid value is not a quiet fallback.** Microsoft's default-values table carries an explicit
exception:

> ADPasswordEncryptionPrincipal is an exception to the misconfigured setting rule. This setting
> defaults to 'Domain Admins' only when the setting isn't configured. When an invalid user or group
> name is specified, a policy processing failure occurs and the managed account's password isn't
> backed up.

**Microsoft's own two pages disagree here**, and the disagreement is recorded rather than resolved
by preference. The [LAPS CSP](https://learn.microsoft.com/windows/client-management/mdm/laps-csp#policies)
page says *"If the specified user or group account is invalid the device will fallback to using the
Domain Admins group in the device's domain."* The lab settled it by measurement on 2026-09-03: a
deliberately unresolvable principal produced event 10035 followed by 10017, and no password was
stored. The Group Policy page and the lab agree, so the rule follows them: an unresolvable value
means no password is being protected at all, which is a different problem and not this finding.

## 5. Where the setting is read from

`ADPasswordEncryptionPrincipal` is delivered by Group Policy and lands in the policy's
`Registry.pol` file under the machine-side LAPS key. Capture already parses that file into
`gpo_registry_setting`; until this rule, nothing read the table back.

**Microsoft gives each LAPS policy mechanism its own registry root**, in
[Configure policy settings for Windows LAPS](https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings#supported-policy-roots),
and states that *"policy settings are never shared or inherited across policy key roots"*:

| Policy mechanism | Registry key root |
|---|---|
| LAPS CSP | `HKLM\Software\Microsoft\Policies\LAPS` |
| **LAPS Group Policy** | **`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS`** |
| LAPS Local Configuration | `HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config` |
| Legacy Microsoft LAPS | `HKLM\Software\Policies\Microsoft Services\AdmPwd` |

The rule reads **the Group Policy root and only that one**, because it judges a
`groupPolicyContainer` by parsing that policy's own `Registry.pol`, which is what Group Policy
writes. The CSP root arrives by device management rather than by a policy object, local
configuration is a machine's own registry, and the legacy root is a different product covered by
`SEC-091`. It matches on the machine scope, that key as a suffix, and the value name
`ADPasswordEncryptionPrincipal`. It does not match the user scope: LAPS is a machine policy.

**This section was wrong until 2026-09-04, and it is worth saying how.** The rule matched
`Policies\Microsoft\Windows\LAPS`, which is none of the four roots above and which no policy editor
produces. It therefore matched nothing, read that as *this policy configures no decryptor*, and
reported silence — so a policy handing decryption to Domain Users would have been passed as clean.
Twenty-five tests agreed with it, because every fixture was built from the same invented constant,
and seven mutations all fired inside that closed loop. **Each check was sound and the whole circle
was anchored to nothing outside itself.** The first capture of a real forest found it in minutes.
The tests now include a `Registry.pol` captured from a real Group Policy Object, parsed by the
product's own parser, so the loop has an external anchor.

## 6. Severity

**Critical, and not adjustable** — [`0066`](../../../decisions/0066-a-finding-is-called-a-finding.md)
and [`0082`](../../../decisions/0082-the-rule-catalogue-is-not-customer-tunable.md). A broad decryptor
hands every member of that principal the local administrator password of every machine the policy
covers, which is the credential-theft path the whole LAPS product exists to close.

## 7. What the rule reads

| Input | Where from |
|---|---|
| The policy's registry settings | `gpo_registry_setting`, via `BundleReader` |
| The policy's display name | `displayName` on the `groupPolicyContainer` |
| Effective membership of the decryptor | `PrincipalExpansion`, declared as a required derived fact |
| Which principals are broad | `BroadPrincipalCatalogue` |

## 8. When it does not answer

A verdict that could not be reached says so rather than staying silent, per
[`0086`](../../../decisions/0086-a-qualified-statement-beats-silence.md):

- **The bundle carries no SYSVOL capture.** Nothing can be said about any policy's settings.
- **The value names a principal the expansion cannot resolve.** Reported as incomplete, naming the
  configured value, because an unresolvable decryptor means passwords are not being stored at all.
- **The expansion hit its budget.** The finding says the membership may be larger than shown.

## 9. Tests

| # | Case | Expected |
|---|---|---|
| P1 | The value is a broad principal's SID | Fires, naming that principal |
| P2 | The value is a scoped group containing a broad principal by nesting | Fires, showing the membership path |
| P3 | The value cannot be resolved | Incomplete finding, naming the value |
| N1 | The value is a scoped group with no broad member | Silent |
| N2 | No LAPS decryptor setting on the policy | Silent |
| N3 | The setting is present in the user scope only | Silent |
| N4 | The setting is under one of Microsoft's other three LAPS roots | Silent |
| A1 | A `Registry.pol` captured from a real policy | Fires, and the key it carries is the documented Group Policy root |

`A1` is the anchor, and the others are worth little without it: every case above once passed
against a rule that could not match a real policy at all.
