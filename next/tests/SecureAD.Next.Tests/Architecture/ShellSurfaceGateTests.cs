using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The window's surface is its screens, and it exports no types at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the shell is not in <see cref="RebuildAssemblies"/>.</b> The gates that reflect over the
/// product - the surface register at gate 5a and the vouched-return rule at gate 4 - ask questions
/// about public types, and name for each one the inventory row expected to bring it a consumer. A view
/// model has no such row and never will: nothing outside this project can legitimately consume one,
/// because what a window offers the world is screens. Registering <c>NewAuditViewModel</c> as
/// though something might come to depend on it is bookkeeping about a fiction. This is the same
/// answer <see cref="CommandLineSurfaceGateTests"/> gives for the command line, for the same
/// reason.
/// </para>
/// <para>
/// <b>But an assembly outside the gates is an assembly that escapes them</b>, and this repository
/// has already had a component drop out of gate coverage unnoticed - <c>F-S24-4</c>. So the
/// exemption is held to its terms: the shell may sit outside the reflected set only for as long as
/// it exports nothing. The day it exports a type, this fails and the choice is made again
/// deliberately, rather than the surface widening one type at a time.
/// </para>
/// <para>
/// <b>What this does not do.</b> It cannot tell whether a screen is reachable. The old product's
/// six unreachable grids would satisfy this gate completely, because they were not the problem this
/// check measures. Proving that running code can get to a screen is gate 5b, which needs an entry
/// point to trace from - and the shell is the first thing in the rebuild to have one. See
/// <c>README.md</c> § Gates.
/// </para>
/// </remarks>
public sealed class ShellSurfaceGateTests
{
    /// <summary>
    /// The window's assembly, named by a type inside it rather than by string.
    /// </summary>
    /// <remarks>
    /// A type reference rather than <c>Assembly.Load</c>, which is what
    /// <see cref="CommandLineSurfaceGateTests"/> is forced into because every type there is
    /// internal and invisible to this project. Here the shell opens its internals to the test
    /// project, so the compiler can name the assembly directly and there is no string to go stale
    /// and no chance of loading the wrong file.
    /// </remarks>
    private static Assembly ShellAssembly() =>
        typeof(SecureAD.Shell.ViewModels.ShellViewModel).Assembly;

    /// <summary>
    /// The one type the shell exports, and it is not the shell's.
    /// </summary>
    /// <remarks>
    /// WPF's XAML compiler emits <c>GeneratedInternalTypeHelper</c> into every assembly whose XAML
    /// classes are internal, and emits it public, so that the XAML runtime can construct them. It
    /// appears precisely <i>because</i> the shell was sealed, and it is not surface anyone authored
    /// or can depend on: it exists only in generated code. Exempted by exact name, so a second
    /// generated type would not slip through with it, and held in place by
    /// <see cref="TheGeneratedHelperIsStillTheReasonForTheExemption"/> below.
    /// </remarks>
    private const string GeneratedHelper = "XamlGeneratedNamespace.GeneratedInternalTypeHelper";

    /// <summary>
    /// The shell exports nothing it wrote. Everything it contains is internal to it.
    /// </summary>
    [Fact]
    public void TheShellProjectExportsNothing()
    {
        var exported = ShellAssembly()
            .GetExportedTypes()
            .Where(t => !string.Equals(t.FullName, GeneratedHelper, StringComparison.Ordinal))
            .Select(t => "  " + t.FullName)
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            exported.Count == 0,
            "The shell exports public types. Its surface is meant to be its screens, which is why "
            + "it sits outside the assemblies the architecture gates reflect over. A public type "
            + "here is covered by no gate at all: it is in neither SURFACE-REGISTER.md nor the "
            + "vouched-return rule. Either make it internal - a view's code-behind needs "
            + "x:ClassModifier=\"internal\" in its XAML as well as the modifier in its .cs, because "
            + "WPF generates the other half of the class - or add the assembly to "
            + "RebuildAssemblies and register what it exports:"
            + Environment.NewLine + string.Join(Environment.NewLine, exported));
    }

    /// <summary>
    /// The decay test for the exemption above. An exemption whose reason has gone is an exemption
    /// nobody revisits, and this repository keeps its carve-outs bound to their stated terms.
    /// </summary>
    [Fact]
    public void TheGeneratedHelperIsStillTheReasonForTheExemption()
    {
        var exported = ShellAssembly().GetExportedTypes().Select(t => t.FullName).ToList();

        Assert.True(
            exported.Contains(GeneratedHelper, StringComparer.Ordinal),
            GeneratedHelper + " is no longer exported by the shell, so the exemption carved out "
            + "for it in this gate is protecting nothing. Remove the exemption and let the check "
            + "above require an empty exported surface outright.");
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by finding an empty assembly and
    /// reporting no public types in it, which is the failure this repository has committed before.
    /// </summary>
    [Fact]
    public void TheGateReadsTheRealShellAssembly()
    {
        var assembly = ShellAssembly();

        Assert.Equal("SecureAD", assembly.GetName().Name);

        var declared = assembly.GetTypes();

        Assert.True(
            declared.Length > 0,
            "Read the shell assembly and found no types in it at all, so the check above would "
            + "pass against nothing.");

        // Named individually: one view model, one view's code-behind and one service, so the scan
        // is shown to reach all three kinds of thing the shell holds rather than one corner of it.
        Assert.Contains(declared, t => t.Name == nameof(SecureAD.Shell.ViewModels.NewAuditViewModel));
        Assert.Contains(declared, t => t.Name == "NewAuditView");
        Assert.Contains(declared, t => t.Name == nameof(SecureAD.Shell.Services.CaptureLauncher));
    }

    /// <summary>
    /// The seal is opened for this project and no other. An <c>InternalsVisibleTo</c> naming a
    /// second assembly would widen the shell's surface again without any type becoming public.
    /// </summary>
    [Fact]
    public void TheShellOpensItsInternalsToTheTestProjectAlone()
    {
        var granted = ShellAssembly()
            .GetCustomAttributes<InternalsVisibleToAttribute>()
            .Select(a => a.AssemblyName)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToList();

        Assert.Equal(["SecureAD.Next.Tests"], granted);
    }
}
