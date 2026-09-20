using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Enforces the decisions that apply to the rebuild specifically, as distinct from the product
/// invariants in <see cref="ProductInvariantTests"/>.
/// </summary>
public sealed class GreenfieldGateTests
{
    /// <summary>
    /// Namespaces and types through which a directory read can be issued. Capture legitimately uses
    /// these; nothing else may, per <c>docs/decisions/0008</c>.
    /// </summary>
    private static readonly string[] DirectoryAccessNamespaces =
    [
        "System.DirectoryServices",
        "DirectoryEntry",
        "LdapConnection",
        "SearchRequest",
    ];

    /// <summary>
    /// The only project permitted to read a directory. Capture is the sole reason the product
    /// connects at all.
    /// </summary>
    private const string CaptureProject = "SecureAD.Audit";

    [Fact]
    public void DirectoryReadsAreConfinedToTheCaptureProject()
    {
        var offenders = RebuildTree
            .Scan(RebuildTree.ProductionFiles(), DirectoryAccessNamespaces)
            .Where(o => !o.File.Contains(
                $"{Path.DirectorySeparatorChar}{CaptureProject}{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "The product does not read from a directory except to capture a run "
            + "(docs/decisions/0008). Directory access outside " + CaptureProject + ":"
            + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>
    /// Every <c>.cs</c> file under the rebuild belongs to a project in the rebuild solution.
    ///
    /// <para>
    /// This exists because a stale project folder survived a rename during setup — Visual Studio
    /// recreated it on disk after it had been removed from the solution — and the file guards, which
    /// read the file system rather than the compilation, scanned it. That is usually the behaviour
    /// wanted, since a file omitted from a project is a real way code goes unreviewed. It also means
    /// an orphan lingers invisibly until something trips over it.
    /// </para>
    /// <para>
    /// SDK-style projects compile every <c>.cs</c> beneath them by default, so a file is covered
    /// when some ancestor directory holds a <c>.csproj</c> that the solution lists.
    /// </para>
    /// </summary>
    [Fact]
    public void EverySourceFileBelongsToAProjectInTheSolution()
    {
        var root = RebuildTree.Root();
        var solutionProjects = ProjectDirectoriesInSolution(root);

        var orphans = RebuildTree.AllFiles()
            .Where(f => !solutionProjects.Any(p =>
                f.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)))
            .Select(f => "  " + f)
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            orphans.Count == 0,
            "Source files under the rebuild tree that no project in SecureAD.Next.sln compiles. "
            + "They are invisible to the compiler and to review, but visible to the file-scanning "
            + "guards:" + Environment.NewLine + string.Join(Environment.NewLine, orphans));
    }

    /// <summary>
    /// The orphan check found the projects it needs. Without this it would pass by comparing every
    /// file against an empty set and finding no orphans only because it found no projects either.
    /// </summary>
    [Fact]
    public void TheOrphanCheckFindsTheSolutionsProjects()
    {
        var projects = ProjectDirectoriesInSolution(RebuildTree.Root());

        Assert.True(projects.Count >= 4, $"Expected at least four projects, found {projects.Count}.");
        Assert.Contains(projects, p => p.EndsWith("SecureAD.Kernel", StringComparison.Ordinal));
    }

    /// <summary>
    /// The orphan check still reads real source. The scan skips preserved measurement evidence under
    /// <c>next/artifacts</c>, which is the other way this gate could pass while measuring nothing:
    /// an exclusion that quietly swallowed the tree would leave it comparing an empty set against
    /// the projects and reporting no orphans.
    ///
    /// <para>
    /// So the exclusion is pinned as narrow. The scan must still reach the ordinary source it exists
    /// to police, including this very file, and must reach nothing inside the evidence directory.
    /// </para>
    /// </summary>
    [Fact]
    public void TheOrphanCheckStillReadsRealSource()
    {
        var scanned = RebuildTree.AllFiles().ToList();

        Assert.True(
            scanned.Count > 400,
            $"The scan reached only {scanned.Count} files. An exclusion that swallows the rebuild "
            + "would leave this gate reporting no orphans because it found no source.");

        Assert.Contains(scanned, f => f.EndsWith("GreenfieldGateTests.cs", StringComparison.Ordinal));

        var evidence = RebuildTree.EvidenceRoot() + Path.DirectorySeparatorChar;
        Assert.DoesNotContain(scanned, f => f.StartsWith(evidence, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Directories holding a project that <c>SecureAD.Next.sln</c> lists.
    /// </summary>
    private static List<string> ProjectDirectoriesInSolution(string root)
    {
        var solution = Path.Combine(root, "SecureAD.Next.sln");
        Assert.True(File.Exists(solution), $"Expected the rebuild solution at {solution}.");

        return File.ReadAllLines(solution)
            .Where(line => line.Contains(".csproj", StringComparison.OrdinalIgnoreCase))
            .SelectMany(ExtractProjectPaths)
            .Select(relative => Path.GetDirectoryName(Path.GetFullPath(Path.Combine(root, relative)))!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static IEnumerable<string> ExtractProjectPaths(string line) =>
        line.Split('"')
            .Where(part => part.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase));
}
