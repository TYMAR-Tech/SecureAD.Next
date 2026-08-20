# `next/` — the rebuild

Per [`0009`](../docs/decisions/0009-greenfield-in-place-with-the-bundle-as-seam.md), the new
implementation is built here, beside the existing one. Per
[`0013`](../docs/decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md) the `audit.db`
bundle is no longer a contract between them - this tree writes its own schema and owes the old
application nothing. Per [`0012`](../docs/decisions/0012-the-rebuild-lives-outside-src-with-its-own-solution.md)
it sits outside `src/` and builds from its own solution, `next/SecureAD.Next.sln`, so that the old
tree's architecture tests — two of which assert the old design rather than a product invariant — do
not govern code written to a different one.

The rules for this tree are in [`docs/next/README.md`](../docs/next/README.md).

## Projects

| Project | Target | Owns |
|---|---|---|
| `SecureAD.Kernel` | `net8.0` | The directory-domain kernel: security descriptors, ACE canonicalisation, distinguished names, schema GUIDs, and the single classification of a dangerous right. Also the cross-cutting contracts — `Result<T>` and `AuditError` |
| `SecureAD.Evidence` | `net8.0` | The bundle: schema, views, read and write. Its data model is written fresh with the project, per [`0013`](../docs/decisions/0013-the-bundle-is-no-longer-a-two-way-contract.md); `docs/DATA-MODEL.md` specifies the **old** bundle and does not govern this |
| `SecureAD.Audit` | `net8.0-windows` | Capture, derived analysis, and the rule catalogue |

`SecureAD.App` (WPF) is not scaffolded yet. It is phase 3, and `0009` requires the cross-cutting
contracts to exist before the code that would otherwise have to adopt them later.

## Why the target frameworks differ

`SecureAD.Kernel` and `SecureAD.Evidence` target plain **`net8.0`**, not `net8.0-windows`.

This is deliberate and load-bearing. The existing `SecureAD.Core` targets `net8.0-windows` for no
reason its contents require — its parser, catalogues and DN helpers use only `BinaryPrimitives`,
`FrozenCollections`, `Cryptography` and `Text`. The loose target is how presentation-shaped types
came to live in the domain project. Targeting `net8.0` turns that from a convention someone has to
remember into a compile error.

`SecureAD.Audit` is `net8.0-windows` because capture uses `System.DirectoryServices.Protocols`. That
is the only reason, and it is a reason about LDAP rather than about presentation.

## What does not go here

No live directory reads outside capture. See
[`0008`](../docs/decisions/0008-live-verification-is-removed.md).

## Conventions

Inherited from the repository root and not restated per project: `Directory.Build.props` (nullable,
implicit usings, version stamp, analyzers), `Directory.Packages.props` (central package versions),
`global.json` (SDK 8.0.418), `.editorconfig`.

The product invariants in [`docs/INVARIANTS.md`](../docs/INVARIANTS.md) are **not** inherited
here. Because this tree sits outside `src/`, the old whole-product scan does not reach it, so I-1
and I-3 are asserted explicitly by `ProductInvariantTests` in
[`next/tests/SecureAD.Next.Tests/Architecture/`](tests/SecureAD.Next.Tests/Architecture).
