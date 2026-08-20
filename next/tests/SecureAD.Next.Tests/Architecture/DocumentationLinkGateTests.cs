using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every relative link in every document under <c>docs/</c> points at something that exists.
///
/// <para>
/// This gate was written after a documentation move found five broken links that had nothing to do
/// with the move: a decision record citing a session document under a name it never had, two
/// component documents pointing at source files that had moved projects months earlier, and a
/// session brief written one directory level out. None of them had ever failed anything, because
/// nothing had ever looked.
/// </para>
/// <para>
/// A broken citation is not cosmetic here. The rule this repository runs on is that a claim must be
/// traceable to the record or the code that settles it, and a reader who cannot follow the citation
/// falls back on the inventory or the old application — which is the inference that produced the
/// preflight wizard.
/// </para>
/// </summary>
public sealed class DocumentationLinkGateTests
{
    private static readonly Regex Link = new(@"\]\((?<target>[^)\s]+)\)", RegexOptions.Compiled);

    [Fact]
    public void EveryRelativeLinkUnderDocsResolves()
    {
        var broken = Links()
            .Where(l => !File.Exists(l.Resolved) && !Directory.Exists(l.Resolved))
            .Select(l => $"  {l.Document} line {l.Line} links to '{l.Target}', which is not there")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            broken.Count == 0,
            "Documents link to files that do not exist. A citation that cannot be followed sends "
            + "the reader to the inventory or the old application to guess instead:"
            + Environment.NewLine + string.Join(Environment.NewLine, broken));
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by finding no documents and no
    /// links, and reports that nothing is wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheDocumentsAndTheirLinks()
    {
        var links = Links();

        Assert.True(links.Count > 500, $"Read only {links.Count} links under docs/, which is too few to be the whole tree.");

        Assert.Contains(links, l => l.Document.Replace('\\', '/').Contains("docs/decisions/", StringComparison.Ordinal));
        Assert.Contains(links, l => l.Document.Replace('\\', '/').Contains("docs/areas/", StringComparison.Ordinal));
        Assert.Contains(links, l => l.Document.Replace('\\', '/').Contains("docs/next/", StringComparison.Ordinal));

        // The negative control: a link to something absent must be recognised as absent, or the
        // check above is measuring nothing.
        var absent = Path.Combine(DocsRoot(), "a-document-that-does-not-exist.md");
        Assert.False(File.Exists(absent));
    }

    private static string DocsRoot() => Path.Combine(RepositoryLocation.Root(), "docs");

    private static List<(string Document, int Line, string Target, string Resolved)> Links()
    {
        var root = DocsRoot();
        Assert.True(Directory.Exists(root), $"Expected the documentation at {root}.");

        var found = new List<(string, int, string, string)>();

        foreach (var file in Directory.EnumerateFiles(root, "*.md", SearchOption.AllDirectories))
        {
            var directory = Path.GetDirectoryName(file)!;
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                foreach (Match match in Link.Matches(lines[i]))
                {
                    var target = match.Groups["target"].Value;
                    if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase) || target.StartsWith('#'))
                        continue;

                    var anchor = target.IndexOf('#', StringComparison.Ordinal);
                    var relative = anchor < 0 ? target : target[..anchor];
                    if (relative.Length == 0)
                        continue;

                    found.Add((
                        Path.GetRelativePath(RepositoryLocation.Root(), file),
                        i + 1,
                        relative,
                        Path.GetFullPath(Path.Combine(directory, relative))));
                }
            }
        }

        return found;
    }
}
