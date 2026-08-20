using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every document listed in the solution is a document that exists.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> The solution lists documentation as solution items, so the docs tree
/// can be browsed in Visual Studio. Nothing kept that list in step with the folder. Archiving
/// documents during the documentation clean left thirty-six entries pointing at files that were
/// no longer there, and the only symptom was an item in Solution Explorer that opened nothing -
/// no build warning, no failing test, nothing in git that read as wrong.
/// </para>
/// <para>
/// The reverse direction is deliberately not checked. A document that exists but is not listed
/// in the solution is merely not browsable from the IDE, which harms nobody; requiring every
/// document to be listed would make adding one a two-step act for no gain.
/// </para>
/// </remarks>
public sealed class SolutionDocumentItemTests
{
    private static string SolutionPath() =>
        Path.Combine(RepositoryLocation.Root(), "next", "SecureAD.Next.sln");

    [Fact]
    public void EveryDocumentListedInTheSolutionIsThere()
    {
        var solutionDirectory = Path.GetDirectoryName(SolutionPath())!;

        var missing = DocumentItems()
            .Where(rel => !File.Exists(Path.Combine(solutionDirectory, rel)))
            .OrderBy(rel => rel, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            missing.Length == 0,
            "The solution lists documents that are not there. An entry that opens nothing is "
            + "invisible outside the IDE, so it is corrected here rather than found by hand. "
            + "next/tools/prune-solution-document-items.ps1 removes them:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by reading no items at all and
    /// reporting that none of them is missing.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheSolutionsDocumentItems()
    {
        var items = DocumentItems();

        Assert.True(
            items.Count > 50,
            $"Read only {items.Count} document items from the solution, which is too few to be "
            + "the whole list.");

        Assert.Contains(items, i => i.Replace('\\', '/').Contains("docs/decisions/", StringComparison.Ordinal));
    }

    private static IReadOnlyList<string> DocumentItems() =>
        [.. File.ReadAllLines(SolutionPath())
            .Select(l => System.Text.RegularExpressions.Regex.Match(l, @"^\s*(\.\.\\[^=]+?\.md)\s*="))
            .Where(m => m.Success)
            .Select(m => m.Groups[1].Value.Trim())];
}
