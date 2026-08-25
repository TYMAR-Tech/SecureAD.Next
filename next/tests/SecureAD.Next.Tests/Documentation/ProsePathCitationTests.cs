using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Every path into this repository that a document names in prose points at something that exists.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the check that would have caught the rot.</b>
/// <see cref="DocumentPathCitationTests"/> asks the same question of <c>&lt;c&gt;</c> tags inside
/// <c>.cs</c> files, and nothing asked it of the documentation itself. So
/// <c>docs/next/README.md</c> § <i>How to continue this work</i> went on telling every new session
/// to read <c>docs/map/</c> and start from <c>sessions/</c> long after both were deleted, and
/// <c>.github/copilot-instructions.md</c> - the top authority - named four directories that are not
/// there. Nineteen in-repo paths did not resolve when this was written.
/// </para>
/// <para>
/// <b>Why prose and not links.</b> A markdown link is already held by
/// <see cref="Architecture.DocumentationLinkGateTests"/>. The paths that rotted were written in
/// backticks - <c>`docs/map/`</c> - which reads to a person exactly like an instruction and to a
/// link checker like nothing at all.
/// </para>
/// <para>
/// <b>Scoped to <c>docs/</c> and <c>next/</c>, deliberately.</b> 134 backticked paths fail if
/// everything is checked, and the excess is <c>docs/rules/</c> citing the predecessor's tree at
/// <c>src/SecureAD.Core/</c>. Those cards document the old application and their paths are correct
/// against the repository that holds it, which is not this one. A gate that fired on them would be
/// measuring the wrong thing and would be silenced within a week.
/// </para>
/// <para>
/// <b>What to do when it fires.</b> The same as its sibling: if the document moved, repoint the
/// path; if it was deleted, take the backticks off so the sentence reads as history. A decision
/// record naming a document that no longer exists is not wrong - it is recording what was true
/// then - but written as a path it sends a reader looking for a file.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-documentation-rot-gates.ps1</c>, three
/// directions, all killed; three touched files verified byte-identical by hash.</b> A backticked
/// path to a document that does not exist is killed by
/// <see cref="EveryInRepoPathNamedInProseResolves"/>. A broken link in the root README is killed by
/// <c>DocumentationLinkGateTests</c>, which is the direction that proves widening it past
/// <c>docs/</c> did something; a broken link inside <c>docs/</c> is killed by the same, which
/// proves the widening did not lose the original scope.
/// </para>
/// </remarks>
public sealed class ProsePathCitationTests
{
    /// <summary>
    /// A path into this repository, written in backticks: <c>`docs/next/README.md`</c> or
    /// <c>`next/src/SecureAD.Kernel/`</c>.
    /// </summary>
    private static readonly Regex ProsePath =
        new(@"`(?<path>(?:docs|next)/[A-Za-z0-9_\-./]*)`", RegexOptions.Compiled);

    /// <summary>
    /// Extensions that make a backticked string a file rather than a namespace or an identifier.
    /// A trailing slash marks a directory and counts too.
    /// </summary>
    private static readonly string[] FileSuffixes =
        [".md", ".cs", ".ps1", ".xaml", ".csproj", ".sln", ".yaml", ".yml", ".json"];

    /// <summary>
    /// A rule card's filename is written as a placeholder in the template that creates one - the
    /// literal is assembled below rather than spelled here, because a rule card that does not exist
    /// is exactly what <see cref="DocumentPathCitationTests"/> refuses to see cited. It is a
    /// placeholder rather than a citation, and the day it resolves somebody has created a rule
    /// named for the placeholder.
    /// </summary>
    private const string Placeholder = "XXX";

    [Fact]
    public void EveryInRepoPathNamedInProseResolves()
    {
        var broken = Citations()
            .Where(c => !Exists(c.Path))
            .Select(c => $"  {c.Document} line {c.Line} names '{c.Path}', which is not there")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            broken.Count == 0,
            "Documentation names paths into this repository that do not exist. A path written in "
            + "backticks reads as an instruction, and one that resolves to nothing sends a reader - "
            + "or a session - looking for a file that was deleted. If the document moved, repoint "
            + "it; if it was deleted, take the backticks off so the sentence reads as history:"
            + Environment.NewLine + string.Join(Environment.NewLine, broken));
    }

    /// <summary>
    /// The scanner self-test. Without it this passes by reading no documents and no paths, and
    /// reports that nothing in the tree is broken.
    /// </summary>
    /// <remarks>
    /// It asserts no count of citations. A floor would need editing whenever the documentation
    /// grew or shrank, and a threshold edited to make a gate pass is the defect rather than the
    /// fix. What it asserts is that both trees were reached and that the lookup discriminates in
    /// both directions.
    /// </remarks>
    [Fact]
    public void TheCheckReadsTheDocumentsItsPathsAndDiscriminates()
    {
        var documents = Documents();
        var citations = Citations();

        Assert.True(documents.Count > 0, "Found no documents to scan for paths.");
        Assert.True(citations.Count > 0, "Read no in-repo paths out of the documentation.");

        // Both trees are reached, not just whichever one enumerated first.
        Assert.Contains(citations, c => c.Path.StartsWith("docs/", StringComparison.Ordinal));
        Assert.Contains(citations, c => c.Path.StartsWith("next/", StringComparison.Ordinal));

        // The resolver discriminates, in both directions, against paths built here rather than
        // written whole - so this test does not become a citation it would itself judge.
        Assert.True(Exists("docs" + "/next/README.md"));
        Assert.False(Exists("docs" + "/next/NoSuchDocument.md"));
    }

    /// <summary>
    /// The scan reads paths and not every backticked word. A type name is not a path, and a gate
    /// that treated one as a path would fail on the first mention of a namespace.
    /// </summary>
    [Fact]
    public void TheScanIgnoresBacktickedThingsThatAreNotPaths()
    {
        Assert.Empty(PathsIn("The type `ConnectionSecurityLadder` walks `SecureAD.Audit.Connect`."));
        Assert.Empty(PathsIn("A rule card names `src/SecureAD.Core/Findings/Rules/rules.yaml`."));

        var found = PathsIn("The authority is `docs/next/README.md`, built from `next/src/`.");
        Assert.Equal(2, found.Count);
        Assert.Contains("docs/next/README.md", found);
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static bool Exists(string path)
    {
        var full = Path.Combine(
            RepositoryLocation.Root(), path.Replace('/', Path.DirectorySeparatorChar));

        return File.Exists(full) || Directory.Exists(full);
    }

    private static List<string> PathsIn(string text) =>
        [.. ProsePath.Matches(text)
            .Select(m => m.Groups["path"].Value)
            .Where(IsAFile)
            .Where(p => !p.Contains(Placeholder, StringComparison.Ordinal))];

    private static bool IsAFile(string path) =>
        path.EndsWith('/') || FileSuffixes.Any(s => path.EndsWith(s, StringComparison.Ordinal));

    private static List<(string Document, int Line, string Path)> Citations()
    {
        var found = new List<(string, int, string)>();
        var root = RepositoryLocation.Root();

        foreach (var file in Documents())
        {
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                foreach (var path in PathsIn(lines[i]))
                    found.Add((file[(root.Length + 1)..], i + 1, path));
            }
        }

        return found;
    }

    /// <summary>
    /// Every document that instructs: the documentation tree and the instructions beside it.
    /// </summary>
    private static List<string> Documents()
    {
        var root = RepositoryLocation.Root();
        var found = new List<string>();

        foreach (var directory in new[] { "docs", ".github" })
        {
            var path = Path.Combine(root, directory);
            Assert.True(Directory.Exists(path), $"Expected documents at {path}.");

            found.AddRange(Directory.EnumerateFiles(path, "*.md", SearchOption.AllDirectories));
        }

        return found;
    }
}
