# SEC-094 — Windows LAPS expected, but only a legacy timestamp present

**Status:** specified 2026-09-03. Not yet built.
**Severity:** Low. Settled by the owner 2026-09-03. See [§7](#7-severity).
**Rule identifier:** `SEC-094`.
**Implemented by:** `WindowsLapsNotAppliedOnCapableComputer` in `SecureAD.Judgement` (planned).

---

## For a reviewer

**This document is written to be checked by somebody who cannot see this repository.** Every claim
about Active Directory cites a Microsoft source, and every case is stated in terms of the directory
rather than of this product's code.

**It is the sibling of [`SEC-091`](SEC-091-laps-missing-on-a-computer.md)**, and the two were split
deliberately rather than merged into one rule carrying a state. [§3](#3-why-this-is-its-own-rule)
gives the reason, and it is a product reason rather than a tidiness one.

**It has no card.** The predecessor reported this case inside its `SEC-091` under the title *LAPS
Missing on Computer*, which was wrong — the machine may well be managed. It has no rule of its own to
port, so per the *Anchoring* section of `building-a-rule.md` it has **no internal anchor**, and
[§10](#10-tests) names what must be checked outside this repository.

**The thing most worth challenging** is [§4](#4-two-causes-that-look-identical-in-the-directory): this
rule reports a state with two possible causes, one of which is a deliberate and supported
configuration. Whether that is honest reporting or noise is the judgement this rule stands on.

---

## 1. What it finds

A **computer capable of running Windows LAPS** that carries the **legacy** expiration timestamp
`ms-Mcs-AdmPwdExpirationTime` and **not** the modern `msLAPS-PasswordExpirationTime`.

In plain terms: *this machine could be managed by the current version of LAPS, and the directory
shows no sign that it is. What it does show is a timestamp from the old product, which may be live
and may be a leftover.*

## 2. Why the old timestamp proves nothing on its own

**The legacy attribute is never cleared.** Microsoft's migration procedure disables or removes the
legacy *policy*, then removes the legacy *software* — and touches no directory attribute at any
point. There is no step, in either the immediate-transition or the side-by-side approach, that clears
`ms-Mcs-AdmPwdExpirationTime`.

**So the value persists indefinitely as residue.** A legacy timestamp on a modern machine may mean a
legacy deployment is alive and rotating, or it may be a fossil from a policy that stopped applying
years ago. **From the directory alone those are indistinguishable**, and that is exactly why the
presence of the old value cannot be read as reassurance.

**Microsoft's own success signal is the modern attribute appearing.** Asked how to confirm a
migration has worked, Microsoft says:

> "When storing passwords in Active Directory, you can look for the appearance of a new or updated
> `msLAPS-PasswordExpirationTime` attribute on the managed device's AD computer object."

**This rule is that check, run across an estate rather than one machine at a time.** It is not a
recommendation to modernise; it is the absence of the confirmation Microsoft tells an administrator
to look for.

**And modernising is separately Microsoft's position**, which is why the state is worth surfacing at
all:

> "The legacy Microsoft LAPS product is deprecated as of Windows 11 23H2 and later. Installation of
> the legacy Microsoft LAPS Microsoft Installer (MSI) package is blocked on newer OS versions, and
> Microsoft no longer considers code changes for the legacy Microsoft LAPS product."

**What the organisation can therefore mitigate:** a population of machines its administrators believe
are managed, where the belief rests on a value the directory would still show even if management had
stopped.

## 3. Why this is its own rule

**Acceptance is per finding** (`docs/decisions/0080`, `0023`), and suppression in the interface is per
rule. An estate that runs Windows LAPS in legacy emulation mode on purpose — see
[§4](#4-two-causes-that-look-identical-in-the-directory) — needs to silence **this** state without
also silencing *no LAPS at all*, which is a genuine exposure on any estate.

**One rule carrying a state field cannot be silenced selectively.** Hiding the emulation-mode noise
would hide the unmanaged machines with it, and those are the ones that matter.

**This is the same reasoning that kept `SEC-028`, `SEC-029` and `SEC-033` apart.** Microsoft groups
them as rows of one assessment; this product does not, so that an operator can accept *"this legacy
device genuinely needs DES"* without also accepting *"this account has no password."*

**A customer cannot tune the catalogue** (`docs/decisions/0082`), so the split is what makes the
emulation-mode case survivable at all. There is no switch, and there was never going to be one.

## 4. Two causes that look identical in the directory

**This is the rule's central limitation and it belongs in its About text, not only here.**

| Cause | What it is |
|---|---|
| **Policy not applying** | The Windows LAPS policy is not reaching the machine — a Group Policy scoping, filtering or processing problem. The owner's estate is this case |
| **Legacy emulation mode** | Windows LAPS is present and working, deliberately configured to honour the *legacy* Group Policy and write to the *legacy* attributes |
| **The April 2023 update is missing** | Windows LAPS ships in that update. A machine that has not taken it cannot run Windows LAPS whatever the policy says |

**Emulation mode is supported, deliberate, and aimed squarely at organisations mid-migration.**
Microsoft:

> "You might use emulation mode if you migrate an existing deployment of legacy Microsoft LAPS to
> Windows LAPS."

**The evidence that separates these is not in Active Directory.** Emulation mode is identified by the
client-side extension registry value under
`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}`
and by event 10023 in the machine's Windows LAPS log. Both are on the machine. This product reads a
directory and `docs/decisions/0008` fixes that boundary, so it cannot and must not guess.

**Therefore the finding states what was observed and names the candidates. It never asserts a
cause.** Wording that says *"Group Policy is not applying"* would be a confident claim the evidence
does not support, against an estate that may be configured exactly as it intends.

**Even the benign cause is worth surfacing**, which is what keeps this rule honest rather than merely
noisy: emulation mode stores passwords in clear text only and cannot use Windows LAPS password
encryption. Microsoft: *"when you run Windows LAPS in legacy Microsoft LAPS emulation mode, you can't
configure Windows LAPS to do tasks like encrypt passwords or save passwords to Microsoft Entra ID."*
So a machine in emulation mode is genuinely in a weaker state than one managed natively, and an
auditor is entitled to see it.

## 5. What is excluded, and why

| Excluded | Why |
|---|---|
| **Domain controllers** | The owner's decision of 2026-09-02, and the same exclusion `SEC-091` makes. Excluded through `DomainControllerSignals`, never by distinguished name |
| **Disabled computer accounts** | The owner's decision of 2026-09-03, and the same exclusion `SEC-091` makes for the same reason: a disabled account has no running machine, so there is nothing for a Windows LAPS policy to reach and nothing to migrate |
| **Machines carrying the modern timestamp** | The confirmation Microsoft names is present. Whether it is *stale* is `SEC-092` |
| **Machines carrying neither timestamp** | That is `SEC-091`, and it is the more serious finding |
| **Machines not capable of Windows LAPS** | Server 2016 and earlier. Microsoft never backported it, so its absence says nothing about the machine's configuration |
| **Non-computer objects** | LAPS attributes live on the computer class |

**The capability test is the whole exclusion, and it is why `operatingSystemVersion` is captured.**
Reporting a Server 2016 machine here would be reporting it for not running software Microsoft never
shipped for it.

## 6. What is **not** reported, and why

1. **A machine in emulation mode is not distinguished from one with a broken policy.** Stated above,
   and stated in the About text. It is the boundary an operator most needs to know.
2. **Nothing about whether the legacy password is still rotating.** A legacy timestamp far in the
   past is `SEC-092`'s question. This rule reads presence, not freshness.
3. **Passwords backed up to Microsoft Entra ID are invisible.** A machine managed that way carries no
   Active Directory attribute at all — but note it would then carry *neither* timestamp and so fall
   to `SEC-091`, not here.
4. **A Server 2016 machine carrying a modern timestamp is not reported by this rule or by
   `SEC-091`.** Microsoft says that operating system cannot run Windows LAPS, so the combination
   should not occur. It is surfaced as an **`Unexpected` state in the LAPS inventory grid** rather
   than as a finding, because the machine is managed and there is no exposure to report. The owner
   asked for it as information not implying risk on 2026-09-03, and
   [`0081`](../../../decisions/0081-severity-has-four-levels.md) does not carry an `Info` severity —
   it says instead that *"the product has other ways to tell an operator a fact about the forest."*
   The grid is that way.

## 7. Severity

**Low.** Settled by the owner on 2026-09-03: *nothing at all is worse than possibly-stale
management.* `Severity.Low` is documented as *"a minor concern, recorded so it is not lost,"* which
is the right description of this state.

The reasoning, and it holds together in a way that matters:

- **Something may well be managing this password.** Unlike `SEC-091`, this is not a machine with no
  protection; it is a machine whose protection cannot be confirmed from the directory.
- **One of the two causes is a supported configuration.** A rule that fires on a deliberate setup
  cannot carry a severity that demands action.
- **The volume argument resolves cleanly at Low.** This rule fires across a whole migration wave, so
  it is the noisier of the two — and it is the quieter severity. An operator sorting by severity sees
  the unmanaged machines first, which is the correct order of work.

**The argument against Low**, recorded rather than hidden: an administrator who believes an estate is
LAPS-managed on the strength of a residual attribute is in a worse position than one who knows it is
not, because false assurance stops the investigation. The counter is that `SEC-092` reports staleness
directly and is the better instrument for that fear, and that raising this rule would rank a
supported configuration above genuine gaps.

## 8. What the rule reads

| Input | Why |
|---|---|
| `msLAPS-PasswordExpirationTime` | Must be **absent**. Its presence is the confirmation Microsoft names |
| `ms-Mcs-AdmPwdExpirationTime` | Must be **present**. Reported, with its decoded date |
| `operatingSystem` | The OS family — whether the name says *Server* |
| `operatingSystemVersion` | The build number, and with the family the whole capability answer |
| `objectClass` | The most derived class must be `computer` |
| `userAccountControl` | Feeds `DomainControllerSignals` |
| `primaryGroupID` | Feeds `DomainControllerSignals` |
| `distinguishedName` | Feeds `DomainControllerSignals`, and names the object |
| `sAMAccountName` | The name shown, falling back to the distinguished name |

**Derived facts: `AttributeVisibility`**, the same product `SEC-091` declares. This rule cannot judge
an underived bundle, and `docs/decisions/0091` refuses the run rather than reporting per object.

**Why this rule needs the visibility answer too, and needs it more than `SEC-091` does.** If
`msLAPS-PasswordExpirationTime` were confidential in a forest, **every** modern-capable machine
carrying a legacy value would be reported, and every one of those findings would be false. `SEC-091`
degrades to silence in that case; this rule degrades to a wall of wrong answers. The check is the
same and the consequence of skipping it is worse.

## 9. When it does not answer

| Case | What happens |
|---|---|
| No derivation offered | `CouldNotResolve(NotDerived)`. Per `0091` the run is refused first, so it should be unreachable |
| `msLAPS-PasswordExpirationTime` is confidential in this forest | **`CouldNotJudge`**, naming it. Never a finding — see [§8](#8-what-the-rule-reads) |
| The Windows LAPS schema extension is absent from the forest | No finding. No machine in the forest can carry the attribute, so its absence is not evidence about any machine. Stated in the About text |
| `operatingSystemVersion` absent (a bundle sealed before it was captured) | Capability falls back to the `operatingSystem` name, and the finding records that it did so |
| Both attributes absent | Not this rule. `SEC-091` |
| `operatingSystem` and `operatingSystemVersion` both absent | Capability is `Unknown`, and an unknown machine is **not** reported here — it cannot be shown to be capable |

**Note the asymmetry with `SEC-091`, and that it is deliberate.** An unknown operating system does
not stop `SEC-091`, because *no LAPS at all* is worth reporting whatever the machine is. It does stop
this rule, because this rule's entire claim is *this machine could be running Windows LAPS* — and
that cannot be claimed about a machine nobody can identify.

## 10. Tests

`WindowsLapsNotAppliedOnCapableComputerTests`. The negative controls that matter:

- **a modern-capable machine with the modern timestamp** — the healthy state, and the commonest
- **a modern-capable machine with both timestamps** — the migrated state. Microsoft's success signal
  is present, so it must be silent even though the legacy residue is there. **The rule reading the
  legacy value as significant would report every successfully migrated machine in the estate**
- **a Server 2016 machine with only a legacy timestamp** — correct and healthy, must be silent
- **a machine with neither timestamp** — `SEC-091`'s case, must be silent here
- **a domain controller**, including one outside the Domain Controllers container
- **a machine whose forest marks `msLAPS-PasswordExpirationTime` confidential** — `CouldNotJudge`
- **a machine with no operating system information at all** — silent, per [§9](#9-when-it-does-not-answer)

**The external anchor**, since this rule has no card and no predecessor to agree with: the capability
boundary is Microsoft's published platform list and its published build numbers, and a test checks
the classifier's constants against those rather than against another copy of themselves. `SEC-027`
earned this requirement by having every positive test pass while the rule and its tests shared one
mistake.

**The second test in that list is the one to write first.** It is the rule's whole risk: a naive
implementation that fires whenever a legacy timestamp exists reports every machine that migrated
successfully — which is the largest population in exactly the estates this rule is aimed at.

Each mutated in both directions, **one mutation at a time**.

## 11. Verified against `ad.lab`, 2026-09-03

**This rule was right on its first real run, including the case it was most likely to get wrong.**
The prediction below was written before the rule existed and held in every row.

| Question | How it was answered | Answer |
|---|---|---|
| Was the rule scheduled and did it complete? | `rule_execution` in the judgement store | `Succeeded`, 14 objects judged, **0 not judged, 0 unresolved** |
| Did it fire, and on what? | `show-findings.ps1` | **1 finding, Low** — `CN=PHMS1,OU=Servers,OU=PH Lab,DC=ph,DC=ad,DC=lab` |
| Were the two Server 2016 machines excluded? | the same run, and they carry exactly this rule's attribute pattern | **both silent** — the capability test is what held |
| Was the healthy population silent? | the same run | every machine carrying the modern timestamp, silent |
| Did the finding state a cause? | read the finding text | it names all three candidates and asserts none |

**The Server 2016 machines are the result worth having.** `BA2016` and `PH2016` each carry the
legacy timestamp and no modern one — precisely what this rule looks for — and are excluded on
capability alone, because Microsoft never shipped Windows LAPS for that operating system. Reporting
them would have been reporting a machine for not running software that does not exist for it. The
mutation that narrows the capability test to `Unknown` fails exactly one test,
`AServer2016MachineWithOnlyTheLegacyTimestampIsNotReported`, so the control and the forest agree.

**The finding's decoded date came back sensible**, which is worth saying because it is computed from
a raw FILETIME rather than stored: `PHMS1`'s legacy expiry decoded to a date about three weeks after
the run — a live legacy rotation rather than a fossil. The date itself is not quoted here, because a
document stating a date in the future is indistinguishable from a document nobody checked, which is
what `DocumentationDateGateTests` exists to catch. Note that this rule cannot use that fact and does
not try to: whether the rotation is stale is `SEC-092`'s question, and *legacy present, modern
absent* is reported either way.

**One correction came out of the same run, and it belongs to `SEC-091`.** Two disabled leftover
computer accounts were reported by that rule; the owner excluded disabled accounts from **both**
rules on 2026-09-03, and `SEC-094`'s count was unaffected because `PHMS1` is enabled
(`userAccountControl` 4096).

### What this run did **not** establish

**Emulation mode was not present and could not be.** Both causes this rule refuses to choose between
produce the same directory state, and nothing in `ad.lab` distinguishes them — which is the rule's
own point, and why the finding names candidates rather than a cause. What the lab confirms is the
*state*, not which cause produced it.

**The confidential branch was not exercised**, and never will be on a real forest: both expiration
attributes read `searchFlags` 0 here. It is covered by a fixture that sets bit 128, and that check
was observed failing before it was trusted — which matters more for this rule than for `SEC-091`, as
[§8](#8-what-the-rule-reads) explains.

### What was predicted, before the rule existed

**Read on 2026-09-03**, and every row held:

| Domain | `operatingSystem` | Legacy | Modern | Expected |
|---|---|---|---|---|
| `ph.ad.lab` | Windows Server 2022 Datacenter | present | **absent** | **finding, Low** |
| `ph.ad.lab` | Windows Server 2016 Datacenter | present | absent | silent — not capable |
| `ba.ad.lab` | Windows Server 2016 Datacenter | present | absent | silent — not capable |
| `ba.ad.lab` | Windows Server 2022 Datacenter | absent | present | silent — healthy |
| both clients | Windows 11 Enterprise | absent | present | silent — healthy |
| `ad.lab` × 2 | Windows Server 2022 Datacenter | absent | absent | silent — `SEC-091`'s case |

**Exactly one finding expected, on the Server 2022 member server in `ph.ad.lab`.** One was produced,
on that machine.

**The last row is the one that turned out to be wrong about *why*.** Those two `ad.lab` machines are
not member servers: they are disabled accounts left behind by domain promotions, and `SEC-091` §11
records what that cost. This rule was silent about them for the right reason either way — neither
carries a legacy timestamp.
