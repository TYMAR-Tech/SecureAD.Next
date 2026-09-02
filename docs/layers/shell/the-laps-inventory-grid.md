# The LAPS inventory grid

**Status:** specified 2026-09-03. Not built — this is stage 9 work, written now because the evidence
shape it needs is being fixed in stage 4 and would be expensive to change afterwards.

---

## What it is for

**The owner's question, 2026-09-03:** *which machines have legacy LAPS, which have modern LAPS, and
which have none.*

**That is an inventory, not a finding.** It includes the healthy machines, so it **cannot** come from
the findings store — findings by definition contain only the problems. It reads sealed evidence,
which already holds every computer with its operating system and both expiration timestamps.

| | Source | Contains |
|---|---|---|
| The grid | sealed evidence | **every** computer |
| `SEC-091` / `SEC-094` | the judgement store | only the gaps |

**So the grid depends on none of the rule decisions.** It is true whatever severity the rules carry
and whether or not they are suppressed, and it needs no rule, no acceptance and no derivation.

## What the predecessor had, and what it got wrong

`v_grid_laps_status` — a SQL view over every computer with `laps_tier`, `laps_status`,
`laps_expiration` and `expiration_health`, filters on domain, tier, status and health, keyset paging,
and CSV export. **The skeleton is good and is carried forward.** Four things are not.

### 1. It showed only the tier-appropriate timestamp

```sql
-- Modern tier: only Windows LAPS
WHEN (... '%2019%' OR '%2022%' ...) AND dw.details IS NOT NULL THEN DATETIME(...)
-- Legacy tier: only Legacy LAPS
WHEN o.operating_system LIKE '%2016%' AND dl.details IS NOT NULL THEN DATETIME(...)
ELSE NULL
```

A Server 2022 machine carrying **only** a legacy timestamp showed `laps_expiration` as null and
`expiration_health` as *No LAPS* — **hiding the legacy timestamp that was sitting on the object.**

**That is the single most important fix.** The owner's diagnostic depends on seeing both: a machine
with *both* timestamps has demonstrably received the Windows LAPS policy, which is Microsoft's own
migration success signal; a machine with only the legacy one has not. The old grid decided which
column to look at before it looked, so it could not answer the question it existed to answer.

**Both timestamps are always shown. The tier says which one should have been there.**

### 2. It classified by matching the operating system name

`LIKE '%2019%'`, `LIKE '%2016%'` — flagged in its own backlog as `[IMP-OS-CLASSIFIER]`, and wrong
twice in the under-reporting direction:

- **Windows 10 was classed `N/A`.** Microsoft supports Windows LAPS on Windows 10.
- **Server 2012 and 2008 were classed `N/A`.** Legacy LAPS runs on them perfectly well.

Both said *nothing to see here* across a large slice of a real estate. Replaced by `LapsCapability`,
which reads the build number and falls back to the name only when there is no build to read.

### 3. It tested for a domain controller three different ways

In one feature: the UAC bit in the view's `is_domain_controller` column, a `sAMAccountName` list in
the same query's `WHERE`, and a distinguished-name match in the rule evaluator. Its own backlog
flagged the third as brittle under `[IMP-DC-DETECT]`.

**`DomainControllerSignals`, once**, which is the type that exists to end exactly this.

### 4. Its export ignored the filter and was named for a subset it did not contain

`SELECT <columns> FROM v_grid_laps_status ORDER BY computer_name` — no filter — written to
`computers_no_laps.csv` from a dialog titled *Export Computers Without LAPS*, containing every
computer including the healthy ones.

Now governed by [`0093`](../../decisions/0093-an-export-states-what-it-contains.md): the export
honours the filter and states it, with counts.

## The columns

| Column | From |
|---|---|
| Computer | `sAMAccountName`, falling back to the distinguished name |
| Domain | the object's domain |
| Operating system | `operatingSystem` as captured |
| Version | `operatingSystemVersion` as captured |
| Capability | `LapsCapability.Kind` — Windows LAPS capable, legacy only, or unknown |
| Capability from | `LapsCapability.Basis` — the build number, the name, or nothing |
| Legacy expiry | `ms-Mcs-AdmPwdExpirationTime`, decoded, **always shown** |
| Windows expiry | `msLAPS-PasswordExpirationTime`, decoded, **always shown** |
| State | below |

**`Capability from` is shown rather than hidden**, because *capable, decided from a build number* and
*capable, guessed from a name* are not equally good, and a grid showing only the conclusion lets a
reader believe they are. A bundle sealed before catalogue version 6 will show *name* down the whole
column, which is the honest presentation of an older bundle.

## The states

| State | Meaning |
|---|---|
| `Managed` | the capability-appropriate timestamp is present |
| `Migrated` | modern present **and** legacy present — the policy landed, the old value is residue |
| `NotApplied` | capable of Windows LAPS, legacy present, modern absent — **`SEC-094`** |
| `Unmanaged` | neither timestamp — **`SEC-091`** |
| `Unexpected` | a machine **not** capable of Windows LAPS carrying a modern timestamp |
| `Unknown` | no operating system information, and no timestamps |

**`Unexpected` is why this document exists as much as anything.** Microsoft says Windows LAPS was
never shipped for Server 2016 and earlier, so that combination should not occur. The owner asked on
2026-09-03 for it to be surfaced as *information not implying risk*.
[`0081`](../../decisions/0081-severity-has-four-levels.md) carries no `Info` severity and says
instead that *"the product has other ways to tell an operator a fact about the forest."* **This grid
is that way.** The machine is managed, so there is no exposure and no finding — but an auditor is
entitled to see something the vendor says cannot happen.

**`Migrated` is separated from `Managed` deliberately.** They are equally healthy, and an
administrator mid-migration wants to count them separately.

## Filters

Domain, capability, state, and a name search — the predecessor's set with tier and status replaced by
the two columns that supersede them.

Permitted by [`0092`](../../decisions/0092-a-view-filter-is-not-a-change-to-the-catalogue.md), which
exists so a later session does not read `0082` and delete them as customer tuning. Its three
conditions apply here: judgement is unaffected, the filter never travels silently into an export, and
it is view state rather than saved policy.

## What it does not show

1. **Never a password.** Not `ms-Mcs-AdmPwd`, not `msLAPS-Password`, not the encrypted forms — all
   forbidden by `CredentialAttributeGuardTests` and never captured. The grid answers *whether* a
   password is managed, never *what it is*. The owner's boundary, stated 2026-09-03.
2. **Nothing about who may read a LAPS password.** That is `SEC-093` and needs the permission graph.
3. **Machines whose passwords go to Microsoft Entra ID.** They carry no directory attribute at all
   and appear here as `Unmanaged`. **This is the grid's most likely false impression** and must be
   stated on the screen, not only here — the product cannot detect it and the operator can.
4. **Whether a rotation has gone stale.** A timestamp long past still reads as managed. That is
   `SEC-092`.
5. **Legacy emulation mode.** A machine deliberately configured so Windows LAPS writes the *legacy*
   attributes is indistinguishable here from one whose policy is not applying — both show
   `NotApplied`. The evidence that separates them is on the machine, not in the directory.

## Where the data comes from

Sealed evidence, read the way `count-uac-flag.ps1` already reads it. `next/tools/laps-census.ps1`
reads the same census from the live directory and was used on 2026-09-03 to establish what `ad.lab`
contains before either rule existed.

**On `ad.lab` the grid should show 11 rows** — 3 domain controllers excluded leaves 8 — with two
`Unmanaged` in `ad.lab`, one `NotApplied` in `ph.ad.lab`, and the remainder `Managed`.
