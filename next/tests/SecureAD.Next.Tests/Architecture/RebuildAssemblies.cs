using System.Reflection;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The assemblies making up the rebuild's production surface, named once.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> Three architecture gates - <see cref="ConceptRegistryTests"/>,
/// <see cref="SurfaceRegisterTests"/> and <see cref="UnvouchedResultGateTests"/> - each held their
/// own copy of this list, and each named the audit assembly as
/// <c>typeof(SecureAD.Audit.Capture.CapturedAttributeCatalog).Assembly</c>. When S-24 moved that
/// catalogue into the kernel, that expression still compiled and returned the <i>kernel</i>
/// assembly, so all three lists became kernel, evidence, kernel - and <c>SecureAD.Audit</c> was no
/// longer covered by any of them.
/// </para>
/// <para>
/// <b>It was not silent, and the record says so because the first draft of this comment claimed it
/// was.</b> Mutating the reference here fails five checks, three of them the gates themselves: the
/// registers are bound in both directions, so an assembly dropping out of the scan leaves the
/// register naming types that no longer exist, and
/// <c>SurfaceRegisterTests.TheRegisterNamesNoTypeThatDoesNotExist</c> fires. The bidirectional
/// binding did the job it was built for. That is <c>F-S24-4</c>, and it is duplication worth
/// removing rather than a hole - three copies of one list is three places to update and three
/// chances to update two of them.
/// </para>
/// <para>
/// <b>Each assembly is named by a type that cannot leave it.</b> <c>Result</c> is the kernel's own
/// vocabulary, <c>BundleSchema</c> owns the SQLite schema, and <c>LdapEntryReader</c> is bound to
/// <c>System.DirectoryServices.Protocols</c> - which is the only reason <c>SecureAD.Audit</c>
/// targets <c>net8.0-windows</c>, so it cannot move down.
/// </para>
/// </remarks>
public static class RebuildAssemblies
{
    /// <summary>
    /// Every assembly the architecture gates cover. Named explicitly rather than discovered, so a
    /// new project must be added here deliberately rather than escaping every gate by not being
    /// noticed.
    /// </summary>
    public static IReadOnlyList<Assembly> All { get; } =
    [
        typeof(SecureAD.Kernel.Result<int>).Assembly,
        typeof(SecureAD.Evidence.BundleSchema).Assembly,
        typeof(SecureAD.Audit.Capture.LdapEntryReader).Assembly,
    ];
}

/// <summary>
/// The self-tests for <see cref="RebuildAssemblies"/>, which xUnit cannot collect from a static
/// class.
/// </summary>
public sealed class RebuildAssemblyTests
{
    /// <summary>
    /// The names the covered assemblies must have, in order. Held as strings so the check compares
    /// against something a type reference cannot quietly change.
    /// </summary>
    private static readonly string[] ExpectedNames =
        ["SecureAD.Kernel", "SecureAD.Evidence", "SecureAD.Audit"];

    /// <summary>
    /// The gates cover three distinct assemblies, and they are the three the rebuild has.
    /// </summary>
    [Fact]
    public void TheGatesCoverThreeDistinctAndCorrectlyNamedAssemblies()
    {
        var names = RebuildAssemblies.All.Select(a => a.GetName().Name).ToList();

        Assert.Equal(ExpectedNames, names);

        Assert.Equal(
            RebuildAssemblies.All.Count,
            RebuildAssemblies.All.Distinct().Count());
    }

    /// <summary>
    /// And the covered surface is not empty. Three assemblies exporting nothing would satisfy every
    /// gate above by giving each of them nothing to check.
    /// </summary>
    [Fact]
    public void EveryCoveredAssemblyExportsSomething()
    {
        foreach (var assembly in RebuildAssemblies.All)
        {
            Assert.True(
                assembly.GetExportedTypes().Length > 0,
                assembly.GetName().Name + " exports no public types.");
        }
    }
}
