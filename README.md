# SecureAD

**Active Directory security assessment and delegation auditing tool for Windows.**

SecureAD captures Active Directory objects, ACLs, and group memberships into a local SQLite
database, then derives control edges, escalation paths, and automated security findings. It is a
single .NET 8 WPF desktop application combining live LDAP exploration with offline audit analysis.

## What It Does

- **Security auditing** — capture a forest-wide snapshot into a SQLite bundle, then evaluate 60+
  built-in security rules against it
- **Attack path analysis** — map control edges and multi-hop escalation paths to show how an
  attacker could reach Domain Admin
- **Delegation analysis** — detect both Kerberos delegation misconfigurations and ACE-based
  permission delegation bundles
- **Access review** — "Who Has Access?" scopes what any principal can reach across the environment
- **Live inspection** — browse the directory tree and inspect any object in real time: permissions,
  groups, Kerberos delegation, SPNs, password policy

### Object Inspector

A single inspection surface that works the same way live and offline. Sections marked *offline*
require a captured bundle, because they read derived analysis rather than the directory.

| Section | Description |
|---------|------------|
| Overview | Identity, account status, password hygiene |
| Permissions | Full DACL with trustee resolution, explicit vs inherited |
| Groups | Transitive group membership |
| Kerberos | Delegation type, account flags, LAPS, shadow credentials |
| Delegated Permissions | ACE-based delegation bundles *(offline)* |
| SPNs | Registered Service Principal Names |
| Control Paths | Who can control this object *(offline)* |
| Findings | Security findings from the built-in rules *(offline)* |
| Effective Access | What can a specific trustee do on this object? |
| Inheritance | Trace where each permission comes from |
| ACL Compare | Side-by-side diff of two objects' ACLs |

### Offline analysis

- **60+ built-in security rules** covering privilege escalation, delegation misconfigurations,
  stale accounts, and infrastructure attacks
- **Group Policy / SYSVOL analysis** — captures GPO settings and SYSVOL folder DACLs, parses
  `Registry.pol` and security templates, and flags GPP `cpassword` exposure (MS14-025)
- **Control edge mapping** — Owner, GenericAll, WriteDacl, WriteOwner, WriteMember, WriteRBCD,
  WriteSPN, and more
- **Escalation path detection** — multi-hop chains from any principal to Domain Admin
- **Delegation bundle matching** — named permission patterns such as Password Reset, Group
  Management, OU Administration

## Architecture

```
Live AD (LDAP) --> SQLite capture --> Derived analysis --> WPF UI / Reports / Export
```

- **SQLite is the primary store.** All captured data and derived analysis lives in audit.db.
- **UI reads views.** Grid data comes from v_grid_* SQL views over dimension and fact tables.
- **Determinism is mandatory.** Same inputs produce identical outputs.

## Solution Structure

| Project | Purpose |
|---|---|
| SecureAD.Core | Domain types, enums, contracts, catalogs, and built-in findings rule loading. Minimal external dependency on YamlDotNet. |
| SecureAD.Infrastructure | SQLite storage, LDAP capture, analysis pipelines. Depends on Core. |
| SecureAD.UI | WPF desktop application (MVVM + CommunityToolkit). Depends on Core + Infrastructure. |
| SecureAD.Core.Tests | Unit tests for Core |
| SecureAD.Infrastructure.Tests | Unit tests for Infrastructure |
| SecureAD.UI.Tests | Unit tests for UI |

## Running It

**Requirements**

- Windows 10/11 or Windows Server 2016+
- .NET 8 Desktop Runtime
- Domain-joined machine with LDAP connectivity to a Domain Controller
- A standard domain user account — no administrative privileges are required

**Quick start**

1. Launch SecureAD. It auto-detects the domain and connects to a DC.
2. Click **Live** in the nav rail to browse the directory tree.
3. Select any object and click **Inspect** to open the Object Inspector.
4. For offline analysis, click **New Audit** to capture a forest-wide snapshot.

## Building It

```powershell
dotnet build SecureAD.sln -c Debug
./test.ps1            # runs the full test suite
```

Visual Studio sets `DOTNET_ROOT` to its private runtime folder, which can stop the .NET 8 test
host from starting on the command line. `test.ps1` points `DOTNET_ROOT` at the system install to
work around this. See [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md) for the full contribution
process and the architectural guardrails a change must respect.

## Documentation

[`docs/README.md`](docs/README.md) is the index and explains how the documentation is organised.
The reference documents are:

| Document | What it covers |
|---|---|
| [Architecture](docs/ARCHITECTURE.md) | Projects, layering, service lifetimes, logging, threading |
| [Data Model](docs/DATA-MODEL.md) | Every table, view and metadata key, and what an absent one means |
| [Capture Pipeline](docs/CAPTURE-PIPELINE.md) | Phases, sharding, run state, degraded runs, coverage |
| [Control Edges and Paths](docs/CONTROL-EDGES-AND-PATHS.md) | How control edges and escalation paths are derived |
| [Group Policy and SYSVOL Capture](docs/GROUP-POLICY-CAPTURE.md) | GPO and SYSVOL capture, and the findings it drives |
| [Configuration](docs/CONFIGURATION.md) | Settings, capture profiles, connection options |
