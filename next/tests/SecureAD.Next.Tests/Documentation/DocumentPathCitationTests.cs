using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Every document the code cites as live is a document that is there.
/// </summary>
/// <remarks>
/// <para>
/// <b>This gate exists because the tree was already broken and nothing said so.</b> The layer
/// documents moved under a <c>layers/</c> directory, and the move was made by searching for the
/// path split across arguments — the two strings <c>"docs"</c> and <c>"kernel"</c> handed to
/// <c>Path.Combine</c> — while the same path written whole inside a doc comment was missed. Thirty
/// citations in thirty source files went on naming a directory that no longer existed, through six
/// completed passes of a documentation rewrite, with the suite green the whole time.
/// </para>
/// <para>
/// <b>A citation is live when it is wrapped in a code tag.</b> A path in plain prose is history —
/// a document that used to be here, named so a reader can follow the trail in git. That is the same
/// convention <c>PunchListIdentifierTests</c> applies to identifiers, where a deleted test is
/// written without backticks, and it is kept the same on purpose: two conventions for "this is
/// history" would leave a reader guessing which one a given file follows.
/// </para>
/// <para>
/// <b>What this does not do.</b> It cannot tell whether the document says what the sentence citing
/// it claims. That is review. It closes the gap where the document was renamed, moved or deleted
/// and the citation stayed behind — the case where a reader is sent somewhere that is not there,
/// which is the expensive direction to be wrong in, because a path that resolves to nothing reads
/// as though the reader has made the mistake.
/// </para>
/// </remarks>
public sealed class DocumentPathCitationTests
{
    /// <summary>
    /// A documentation path presented as a live citation. Only what a code tag encloses is read, so
    /// prose naming a document that has gone is left alone.
    /// </summary>
    private static readonly Regex LiveCitation =
        new(@"<c>(?<path>docs/[A-Za-z0-9_\-./]+\.md)</c>", RegexOptions.Compiled);

    [Fact]
    public void EveryDocumentPathCitedInCodeResolves()
    {
        var broken = Citations()
            .Where(c => !File.Exists(Path.Combine(RepositoryLocation.Root(), c.Path.Replace('/', Path.DirectorySeparatorChar))))
            .Select(c => $"  {c.File} line {c.Line} cites '{c.Path}', which is not there")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            broken.Count == 0,
            "Code cites documents that do not exist. A citation is the one thing in a doc comment "
            + "a reader can act on, and a path that resolves to nothing sends him to the old "
            + "application or to nothing at all. If the document moved, repoint the citation; if it "
            + "was deleted, take the code tags off so the sentence reads as history:"
            + Environment.NewLine + string.Join(Environment.NewLine, broken));
    }

    /// <summary>
    /// The scanner self-test. Without it this passes by finding no source files and no citations in
    /// them, and reports that nothing in the tree is broken.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheSourceItsCitationsAndDiscriminates()
    {
        var files = SourceFiles();
        var citations = Citations();

        Assert.True(files.Count > 0, "Found no source files to scan for citations.");
        Assert.True(citations.Count > 0, "Read no document citations out of the source.");

        // Both trees are reached, not just whichever one enumerated first.
        Assert.Contains(files, f => f.Contains($"{Path.DirectorySeparatorChar}src{Path.DirectorySeparatorChar}", StringComparison.Ordinal));
        Assert.Contains(files, f => f.Contains($"{Path.DirectorySeparatorChar}tests{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

        // A decision record is cited by the code and does resolve, so the check has something to pass on.
        Assert.Contains(citations, c => c.Path.StartsWith("docs/decisions/", StringComparison.Ordinal));

        // The live/history distinction is genuinely made, in both directions. The paths are built
        // rather than written whole, so this test does not become a citation it would itself judge.
        const string Path1 = "docs" + "/next/README.md";
        Assert.Single(Read("/// <c>" + Path1 + "</c>"));
        Assert.Empty(Read("/// once lived at " + Path1 + " and was deleted"));
    }

    /// <summary>The citations in one piece of text, used by the self-test to prove discrimination.</summary>
    private static List<string> Read(string text) =>
        [.. LiveCitation.Matches(text).Select(m => m.Groups["path"].Value)];

    private static List<(string File, int Line, string Path)> Citations()
    {
        var found = new List<(string, int, string)>();
        var root = RepositoryLocation.Root();

        foreach (var file in SourceFiles())
        {
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                foreach (Match match in LiveCitation.Matches(lines[i]))
                    found.Add((file[(root.Length + 1)..], i + 1, match.Groups["path"].Value));
            }
        }

        return found;
    }

    /// <summary>
    /// The rebuild's source, both the product and its tests. Build output is skipped: a copy of a
    /// generated file would be counted twice and reported at a path nobody edits.
    /// </summary>
    private static List<string> SourceFiles()
    {
        var next = Path.Combine(RepositoryLocation.Root(), "next");
        var found = new List<string>();

        foreach (var directory in new[] { "src", "tests" })
        {
            var path = Path.Combine(next, directory);
            Assert.True(Directory.Exists(path), $"Expected the rebuild's source at {path}.");

            found.AddRange(Directory.EnumerateFiles(path, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
                .OrderBy(f => f, StringComparer.Ordinal));
        }

        return found;
    }
}
