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
/// targets <c>net8.0-windows</c>, so it cannot move down. <c>JudgementSchema</c> owns the judgement
/// store's schema, and that store exists precisely because what a rule concludes is kept out of the
/// sealed evidence, so it cannot move into <c>SecureAD.Evidence</c> without undoing the separation
/// it was built for.
/// </para>
/// <para>
/// <b><c>Stage2aRun</c> is the derive stage</b>, not a part of it: it is the whole of what that
/// project offers a caller, so a rebuild that moved it elsewhere would have moved the stage. The
/// project joined this list once its surface was narrowed from thirty-two public types to twelve -
/// the pass, the graph, the interner, the writer and the three closure derivations are internal,
/// because a register row states that anything may come to depend on a type, and that is the
/// opposite of what is wanted for the derive's workings.
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
        typeof(SecureAD.Judgement.JudgementSchema).Assembly,
        typeof(SecureAD.Derivation.Stage2aRun).Assembly,
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
    [
        "SecureAD.Kernel", "SecureAD.Evidence", "SecureAD.Audit", "SecureAD.Judgement",
        "SecureAD.Derivation",
    ];

    /// <summary>
    /// The gates cover five distinct assemblies, and they are the five the rebuild has.
    /// </summary>
    [Fact]
    public void TheGatesCoverEveryDistinctAndCorrectlyNamedAssembly()
    {
        var names = RebuildAssemblies.All.Select(a => a.GetName().Name).ToList();

        Assert.Equal(ExpectedNames, names);

        Assert.Equal(
            RebuildAssemblies.All.Count,
            RebuildAssemblies.All.Distinct().Count());
    }

    /// <summary>
    /// And the covered surface is not empty. An assembly exporting nothing would satisfy every
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
