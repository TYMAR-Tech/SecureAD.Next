using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/READING-ORDER.md</c> to the source tree.
///
/// <para>
/// <b><c>READING-ORDER.md</c> is a list of file paths.</b> That is its whole value - it names the
/// files in the order one object travels through them, so a reader can follow the logic across
/// components instead of alphabetically. A renamed or moved file turns a step of that path into a
/// dead end, and nothing about the document looks wrong when it happens.
/// </para>
/// <para>
/// <b>The expectation is derived, not listed.</b> The check globs <c>next/src</c> and holds the
/// document to what is there, so it catches a file moved tomorrow rather than one moved last week.
/// Three further checks stood here and were deleted on 2026-08-14: two asserted that two
/// <c>DESIGN-</c> notes still contained a particular correction sentence and that the types those
/// corrections mention still exist, and one asserted that every <c>DESIGN-</c> note carried a
/// status line. The first two pinned a repair a person had already made by reading - they could
/// only fail if someone reworded a note, never if a document went stale - and the third policed
/// the shape of prose. None of the three could be broken by a change to the product.
/// </para>
/// </summary>
public sealed class GoverningDocumentTests
{
    [Fact]
    public void EverySourceFileTheReadingOrderNamesExists()
    {
        var source = Directory
            .EnumerateFiles(
                System.IO.Path.Combine(RepositoryLocation.Root(), "next", "src"),
                "*.cs",
                SearchOption.AllDirectories)
            .Where(p => !p.Contains(
                $"{System.IO.Path.DirectorySeparatorChar}obj{System.IO.Path.DirectorySeparatorChar}",
                StringComparison.Ordinal))
            .Select(p => p.Replace('\\', '/'))
            .ToList();

        var missing = Regex
            .Matches(Read("READING-ORDER.md"), @"`(?<path>[A-Za-z0-9_/\.]+\.cs)`")
            .Select(m => m.Groups["path"].Value)
            .Distinct(StringComparer.Ordinal)
            .Where(cited => !source.Any(p => p.EndsWith("/" + cited, StringComparison.Ordinal)))
            .OrderBy(cited => cited, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "READING-ORDER.md names these files and no file matches them under next/src/: "
            + $"{string.Join(", ", missing)}. The document is a path through the code, so a step "
            + "naming a file that is not there sends a reader nowhere and says nothing about why.");
    }

    private static string Read(string document) =>
        File.ReadAllText(System.IO.Path.Combine(
            RepositoryLocation.Root(), "docs", "next", document));
}
