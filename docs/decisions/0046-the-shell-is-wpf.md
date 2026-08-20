# 0046 - The shell is WPF, because of the grid and the single executable

Date: 2026-08-14
Status: Accepted

Records the presentation framework decision taken with the owner during `S-34`, the second of two
records that session produced. Governs every presentation row, `J1`-`J46`.

## Context

The shell has to be built (`0045`), and the owner set two constraints before any code was written.

**No third-party dependencies.** Microsoft-published packages are acceptable - the predecessor
already used `CommunityToolkit.Mvvm` - but nothing outside that. This matters more than it first
appears, because the ordinary way to make a WPF application look modern is a third-party theme
library. `WPF-UI`, `MahApps.Metro` and `ModernWpf` are all excluded. That is not a complaint about
the constraint; it is the reason the usual answer to the second requirement is unavailable.

**The product must not look like default WPF.** The owner is explicit that a modern appearance is
required. Building the visual language is deferred to its own session, after a plain shell has been
seen working, but the framework choice had to be made first because a visual language is trivial to
apply to two screens and a rewrite to apply to twenty.

Two Microsoft routes existed: WPF, with a design system built in-house, or WinUI 3 on the Windows
App SDK, which is modern-looking by default. WinUI 3 was examined seriously rather than dismissed,
on the owner's instruction to look at the predecessor and form a view.

Two measurements decided it.

**The product is grid-shaped.** Twenty-one of the predecessor's thirty-six XAML files use
`DataGrid`, and grids have a map document of their own (`J-presentation-grids.md`). This is not
incidental to an audit tool: tables of objects, permissions and findings are what it exists to
present. **WinUI 3 has no first-party `DataGrid`.** It was not carried forward. Choosing WinUI 3
means the single most important control in the product is either a community toolkit control or one
written here.

**The product ships as one file.** The predecessor is published self-contained, and is used that
way. WPF supports `PublishSingleFile` with `--self-contained`: one executable, no .NET
installation, no administrator rights to run it. **WinUI 3 does not support single-file
publishing.** The alternatives are an MSIX package, which requires installation and code-signing,
or an unpackaged self-contained build, which is a directory of files including the Windows App SDK
runtime.

## Decision

**The shell is WPF, targeting `net8.0-windows`, in a new project `SecureAD.Shell`.**

**The single executable is the deciding constraint, and it is an operational one rather than an
aesthetic one.** This product is copied onto an administrative workstation, a jump host or a domain
controller and run. A security tool that arrives as an installer, or as a folder that must be kept
intact, is materially harder to use in the situations it is used in. Trading that for a default
theme - when the visual language is being built by hand regardless, per the owner's sequencing -
is a bad trade.

**The grid is the second constraint and would have been sufficient alone.** Building or importing a
replacement for the central control of a table-shaped product, before the product presents a single
table, is a cost with no return.

**`CommunityToolkit.Mvvm` is used.** Microsoft-published, and already the predecessor's choice. It
removes the hand-written boilerplate that MVVM otherwise generates, which incidentally shrinks the
surface in which logic can be misplaced.

**Modern appearance is achieved by a design system built here**, in control templates and resource
dictionaries, in its own session after the plain shell is working. What is given up is that this is
effort rather than a package reference. What is gained is that it is ours, has no third-party
dependency, and cannot be taken away by an abandoned library.

## Consequences

**The single executable was verified, not assumed, and it needs one switch beyond the obvious.**
Publishing with `--self-contained -p:PublishSingleFile=true` produces the managed code as one file
but leaves six native libraries beside it - `PresentationNative`, `wpfgfx`, `D3DCompiler`,
`PenImc`, `vcruntime140` and `e_sqlite3` - because single-file publishing does not embed native
libraries by default. Adding `-p:IncludeNativeLibrariesForSelfExtract=true` yields one
`SecureAD.exe` of roughly 157 MB and nothing else that is needed to run it. That switch is part
of the deployment story rather than an optimisation, and dropping it silently reintroduces the folder
this decision exists to avoid.

**`win-x64` is declared in the project rather than passed on the command line.** Both executables
set `RuntimeIdentifier` and `PlatformTarget`, so a build produces what a publish produces and a
publish needs no `-r`. `SelfContained` is deliberately left to the publish: setting it in the project
would make every ordinary build carry a runtime.

**The window is `SecureAD.exe`; the command line is `securead-cli.exe`.** The product's executable
name belongs to the window, by the owner's decision. The command line was renamed to clear it:
Windows filenames and assembly resolution are both case-insensitive, so `SecureAD` and `securead`
are one name, and two assemblies sharing it in one folder is a coin toss over which is loaded.
`CommandLineSurfaceGateTests` lost that coin toss once and reported the window's public types as the
command line's exported surface.

**The application is Windows-only and x64.** It already was; nothing is lost.

**The visual language is unbuilt work, and this record is where that debt is acknowledged.** A plain
WPF shell will look plain until that session happens. The owner has accepted seeing it in that state
and should not be surprised by it.

**A future modern-control requirement cannot be met by installing something.** It is met by building
it, or by overturning the third-party constraint, which is the owner's to overturn and not the
engineering's.

**The predecessor's presentation lessons transfer.** Same framework, same control vocabulary, same
publishing model, which is why `J1`-`J20` remain useful as reference even though the new shell is
not a rebuild of them.

**This record reopens if either measurement stops being true.** If WinUI 3 gains a first-party
`DataGrid` and single-file publishing, the argument above is spent and the question is open again.
Neither is expected soon, and neither should be assumed to have happened without checking.
