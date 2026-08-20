# Group Policy & SYSVOL Capture

SecureAD captures Group Policy from two complementary sources and correlates them: the **directory
side** (the `groupPolicyContainer` objects and their ACLs in LDAP) and the **filesystem side** (the
policy files and folder DACLs under `\\<domain>\SYSVOL`). This lets it detect Group Policy attack
paths that are invisible to a purely directory-based audit — most importantly, a principal who can
modify a GPO's contents through **SYSVOL file write** even without any dangerous LDAP permission on
the GPO object.

SYSVOL capture runs in **Security mode** captures. It is implemented under
`SecureAD.Infrastructure.Sysvol` with parsing logic in `SecureAD.Core.GroupPolicy`.

## What gets captured

| Source (per GPO) | Parsed by | Written to |
|---|---|---|
| GPO root folder security descriptor (DACL) | `SmbSysvolFileReader` | `fact_sysvol_ace` |
| `Machine\Registry.pol`, `User\Registry.pol` | `RegistryPolicyParser` | `dim_gpo_setting` |
| `Machine\...\SecEdit\GptTmpl.inf` (security template) | `SecurityTemplateParser` | `dim_gpo_setting` |
| Group Policy Preferences XML (`cpassword`) | `GroupPolicyPreferenceParser` | `dim_gpo_setting` (presence-only) |

Settings are stored **losslessly** — raw values are preserved verbatim in `dim_gpo_setting` and
interpreted by findings at query time. This mirrors the parser philosophy: parse structure, defer
interpretation.

## The file-access seam

All SYSVOL I/O goes through the `ISysvolFileReader` interface, which has two implementations:

- **`SmbSysvolFileReader`** — production. Reads UNC paths via the Windows redirector. When alternate
  credentials are supplied it establishes an authenticated SMB session (`WNetAddConnection2`) for the
  reader's lifetime; otherwise the process's integrated token is used. Requests only
  `Owner | Group | DACL` on folder security descriptors (never the SACL, which needs
  `SeSecurityPrivilege`). The credential password is held in a `NetworkCredential` and never logged
  or persisted.
- **`InMemorySysvolFileReader`** — test double. Lets `SysvolCaptureModule` be unit-tested with no
  SMB or network access (see `tests/SecureAD.Infrastructure.Tests/Sysvol/`).

## Capture flow (`SysvolCaptureModule`)

For each domain, `GpoCaptureTargetBuilder` produces one `GpoCaptureTarget` per
`groupPolicyContainer`. The module then makes two passes over the targets on a single SQLite
connection (SQLite allows one open transaction at a time, so the settings writer is fully scoped
before the ACE writer opens):

1. **Settings pass** (`SysvolSettingWriter` → `dim_gpo_setting`)
   - **CSE smart-filter:** `Registry.pol` and `GptTmpl.inf` are only read for GPOs whose
     client-side extensions (from `gPCMachineExtensionNames` / `gPCUserExtensionNames`) indicate the
     Registry or Security CSE. This avoids reading files that cannot exist.
   - **GPP `cpassword` scan** is **not** smart-filtered — it runs for *every* GPO, because a
     GPP-only GPO would be skipped by the CSE filter. It is gated by the
     `CaptureGppPasswords` setting (off by default; see below).
2. **DACL pass** (`SysvolAceWriter` → `fact_sysvol_ace`) — the GPO root folder's DACL.

Failures are per-GPO and non-fatal: a GPO that fails either pass is counted once, the first error is
recorded, and capture continues. Results roll up into a `Sysvol` coverage record per domain
(`Complete` / `Partial` depending on the error count).

## GPP cpassword handling (MS14-025)

Group Policy Preferences could store credentials in SYSVOL XML as a `cpassword` attribute encrypted
with a **published** AES key ([MS-GPPREF]) — so any authenticated user who can read SYSVOL can
decrypt it. SecureAD treats the mere presence of a non-empty `cpassword` as an exposure.

The parser is **presence-only and XXE-hardened**:

- It never decrypts the value and never stores or returns it — it reads the attribute only to test
  whether it is non-empty, then discards it. The published decryption key is intentionally absent
  from the codebase.
- XML parsing sets `DtdProcessing = Prohibit` and `XmlResolver = null` (SYSVOL content is
  attacker-influenceable, so DTD/entity-expansion and external-entity resolution are blocked).

Because scanning every GPO's XML adds cost, GPP scanning is **opt-in**: the "Scan for GPP passwords"
toggle in the Forest Audit screen sets `CaptureSettings.CaptureGppPasswords`. Turn it on when
auditing older, acquired, or never-before-checked domains.

## Data model

```
dim_gpo_setting  PK (gpo_guid, source_file, section, setting_key)
  gpo_guid, source_file, section, setting_key, setting_value, value_type, captured_utc

fact_sysvol_ace  PK (gpo_guid, relative_path, ace_hash)
  gpo_guid, relative_path, ace_hash, trustee_sid, access_mask, ace_type,
  is_inherited, inheritance_flags, propagation_flags, captured_utc
```

See [DATA-MODEL.md](DATA-MODEL.md) for the full schema.

## Findings that consume this data

| Rule | Name | Source |
|---|---|---|
| SEC-080 | Unexpected Principal can Modify GPO | LDAP GPO DACL (control edges) |
| SEC-081 | Unexpected Principal can Create GPO Links | LDAP (gPLink-capable containers) |
| SEC-082 | Unexpected Principal can Modify GPO via SYSVOL | `fact_sysvol_ace` (folder write) |
| SEC-083 | Group Policy Preferences Password Exposure | `dim_gpo_setting` (GPP cpassword) |
| SEC-064 | Dangerous User Right Granted via Group Policy | `dim_gpo_setting` (GptTmpl user rights) |
| SEC-065 | Privileged Local Group Membership via Restricted Groups | `dim_gpo_setting` (Restricted Groups) |
| SEC-066 | Weak Directory or SMB Signing Posture | `dim_gpo_setting` (security template) |

SEC-080 and SEC-082 are deliberately unioned: a GPO is "modifiable" if a principal has either a
dangerous LDAP permission on the GPO object **or** filesystem write on its SYSVOL policy folder.
