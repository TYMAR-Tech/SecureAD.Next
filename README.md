# SecureAD

**Active Directory security assessment and delegation auditing for Windows.**

SecureAD reads a forest over LDAP, captures what it finds into a sealed evidence bundle on disk,
and lets an operator read that bundle back offline. It runs as a standard domain user; no
administrative privileges are required.

> ### This repository is a rebuild in progress
>
> The product is being rebuilt from scratch under [`next/`](next/). **The capture half works and
> the judgement half does not exist yet** - nothing in this tree produces a security finding, and
> screens bound to findings are deliberately left out rather than stubbed, so a customer is never
> shown an empty result that reads as *nothing is wrong*.
>
> The predecessor is a separate repository and is not here. Documents that mention it are recording
> history.

## What works today

- **Finds its own forest.** Nothing is typed in; the forest is the one this machine is joined to,
  and every domain in it is read.
- **Connects up an ordered ladder of protection** - LDAPS, signed-and-sealed, signed, and an
  unprotected rung a run may only reach where somebody declared it in advance - and records which
  rung each controller answered on.
- **Proves a controller before a run commits**, asking every domain at once and no controller two
  things at once, and tells *was asked and said no* apart from *was never asked*.
- **Captures objects, permissions and Group Policy files** into a bundle that is sealed when the
  run completes, with its coverage and any deliberate exclusion recorded inside it.
- **Reads a bundle back offline** - the run library, a captured directory tree, and one object's
  detail.

## What is not built yet

Findings and rules; effective access evaluation; reports and export; and any judgement about Group
Policy - the parsers exist and read `Registry.pol`, security templates and Group Policy
Preferences, but nothing yet decides what any of it means.

## Projects

| Project | Target | Owns |
|---|---|---|
| `SecureAD.Kernel` | `net10.0` | Security descriptors, ACE canonicalisation, distinguished names, schema GUIDs, and the cross-cutting `Result<T>` and `AuditError` |
| `SecureAD.Evidence` | `net10.0` | The bundle: schema, views, read and write, and what a run covered |
| `SecureAD.Audit` | `net10.0-windows` | Connecting to a controller, planning a run, and capture |
| `SecureAD.Shell` | `net10.0-windows` | The WPF window |
| `SecureAD.Cli` | `net10.0-windows` | The command line |

## Building and testing

```powershell
dotnet build next/SecureAD.Next.sln
dotnet test next/SecureAD.Next.sln
```

Requires the .NET SDK pinned in [`global.json`](global.json), Windows 10/11 or Windows Server
2016+, and a domain-joined machine to capture from. A standard domain user account is enough; no
administrative privileges are required.

## Documentation

**[`docs/next/README.md`](docs/next/README.md) is the authority.** It states what counts as
documentation here, the gates every change is held to, and how to continue the work.

| Where | What it holds |
|---|---|
| [`docs/next/README.md`](docs/next/README.md) | The rules: what a document must do to count, and the gates |
| [`docs/layers/`](docs/layers/) | How the code works, one document per component, each bound to the code by a test |
| [`docs/decisions/`](docs/decisions/) | The product's positions. Only a record with `Status: Accepted` states one |
| [`docs/next/ARCHITECTURE.md`](docs/next/ARCHITECTURE.md) | Projects, layering, and which project may reference which |
| [`docs/next/SURFACE-REGISTER.md`](docs/next/SURFACE-REGISTER.md) | Every public type and the document that governs it |
| [`docs/PUNCH-LIST.md`](docs/PUNCH-LIST.md) | Work that may need doing, and what blocks it |
| [`docs/rules/`](docs/rules/) | Rule cards describing the **predecessor's** findings rules, kept as reference for rebuilding them |

See [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md) for the contribution process.

Nothing outside `docs/decisions/` states the product's position. Everything else - including the
prose in this file - is one person's understanding at one moment.
