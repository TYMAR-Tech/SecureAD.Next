# `next/` — the rebuild

The new implementation is built here, beside the existing one, and per
[`0013`](../docs/decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) the `audit.db`
bundle is no longer a contract between them - this tree writes its own schema and owes the old
application nothing. It sits outside `src/` and builds from its own solution,
`next/SecureAD.Next.sln`, so that the old tree's architecture tests — two of which assert the old
design rather than a product invariant — do not govern code written to a different one.

**The two records that decided where this tree lives were archived on their own terms.** Decisions
0009 and 0012 were removed by *Archive seven decision records whose premise is gone*: the
predecessor is no longer in this repository, so "beside the existing one" and "outside `src/`"
describe a layout rather than a live choice. The layout is still the layout, which is why it is
stated here as fact rather than cited as a decision.

The rules for this tree are in [`docs/next/README.md`](../docs/next/README.md).

## Projects

| Project | Target | Owns |
|---|---|---|
| `SecureAD.Kernel` | `net10.0` | The directory-domain kernel: security descriptors, ACE canonicalisation, distinguished names, schema GUIDs, and the single classification of a dangerous right. Also the cross-cutting contracts — `Result<T>` and `AuditError` |
| `SecureAD.Evidence` | `net10.0` | The bundle: schema, views, read and write. Its data model is written fresh with the project, per [`0013`](../docs/decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md); `docs/DATA-MODEL.md` specifies the **old** bundle and does not govern this |
| `SecureAD.Audit` | `net10.0-windows` | Capture, derived analysis, and the rule catalogue |

`SecureAD.App` (WPF) is not scaffolded yet. It is phase 3, and `0009` requires the cross-cutting
contracts to exist before the code that would otherwise have to adopt them later.

## Why the target frameworks differ

`SecureAD.Kernel` and `SecureAD.Evidence` target plain **`net10.0`**, not `net10.0-windows`.

This is deliberate and load-bearing. The existing `SecureAD.Core` targets `net8.0-windows` for no
reason its contents require — its parser, catalogues and DN helpers use only `BinaryPrimitives`,
`FrozenCollections`, `Cryptography` and `Text`. The loose target is how presentation-shaped types
came to live in the domain project. Targeting `net10.0` turns that from a convention someone has to
remember into a compile error.

`SecureAD.Audit` is `net10.0-windows` because capture uses `System.DirectoryServices.Protocols`. That
is the only reason, and it is a reason about LDAP rather than about presentation.

## What does not go here

No live directory reads outside capture. See
[`0008`](../docs/decisions/0008-live-verification-is-removed.md).

## Conventions

Inherited from the repository root and not restated per project: `Directory.Build.props` (nullable,
implicit usings, version stamp, analyzers), `Directory.Packages.props` (central package versions),
`global.json` (SDK 10.0.302), `.editorconfig`.

The old application's product-invariants document is **not** inherited
here. Because this tree sits outside `src/`, the old whole-product scan does not reach it, so I-1
and I-3 are asserted explicitly by `ProductInvariantTests` in
[`next/tests/SecureAD.Next.Tests/Architecture/`](tests/SecureAD.Next.Tests/Architecture).
