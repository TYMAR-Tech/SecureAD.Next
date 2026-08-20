using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Inventory;

/// <summary>
/// Every test an inventory row names as its binding exists.
///
/// <para>
/// <c>docs/next/README.md</c> makes an unbound document visible from the outside by giving it no
/// test. That only works while the citation is real. A row reading <c>Done</c> and naming a binding
/// looks exactly like a row that is bound, and a reader checking the inventory has no way to tell the
/// difference without going and looking - which is the labour the inventory exists to remove.
/// </para>
/// <para>
/// Session <c>S-26</c> found two: <c>A1</c> cited <c>DirectoryCredentialTests</c> and <c>C1</c>
/// cited <c>BundleSchemaDocumentationTests</c>, and neither had ever existed under that name. Both
/// rows were otherwise correct and both components genuinely are covered, which is why nobody
/// noticed. It is the cheap end of the same failure as <c>F-S24-2</c>: paperwork that agrees with
/// itself.
/// </para>
/// </summary>
[Collection(nameof(InventoryFileCollection))]
public sealed class InventoryCitationTests
{
    /// <summary>
    /// Anything in backticks ending in <c>Tests</c> is read as a citation of a test class.
    /// </summary>
    private static readonly Regex Citation = new(@"`(?<name>[A-Za-z][A-Za-z0-9]*Tests)`", RegexOptions.Compiled);

    /// <summary>
    /// The predecessor's tests, which the inventory cites deliberately and which do not live in this
    /// project. <c>DataModelDocSyncTests</c> is named as the <i>shape</i> a rebuild binding should
    /// take, and <c>RunModelDocumentationTests</c> is named as the thing that fails if a document
    /// is deleted before the old code is. Neither is a claim that this project contains them.
    /// </summary>
    private static readonly string[] PredecessorTests =
        ["DataModelDocSyncTests", "RunModelDocumentationTests"];

    [Fact]
    public void EveryTestNamedByTheInventoryExists()
    {
        var declared = DeclaredTestClasses();

        var missing = Citation
            .Matches(File.ReadAllText(InventoryPath()))
            .Select(m => m.Groups["name"].Value)
            .Distinct(StringComparer.Ordinal)
            .Where(name => !declared.Contains(name))
            .Where(name => !PredecessorTests.Contains(name, StringComparer.Ordinal))
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "WHAT-THE-OLD-APP-HAD.md names these tests, and no class by that name is declared in the "
            + $"rebuild's test project: {string.Join(", ", missing)}. A row that cites a binding "
            + "which does not exist reads as a bound row, so the one check a reader can make from "
            + "the inventory alone silently stops working.");
    }

    /// <summary>
    /// The same for the slice documents. A row citing a document that is not there sends the next
    /// session to a file it cannot open.
    /// </summary>
    [Fact]
    public void EveryDocumentLinkedByTheInventoryExists()
    {
        var next = System.IO.Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next");

        var missing = Regex
            .Matches(File.ReadAllText(InventoryPath()), @"\]\((?<target>[A-Za-z0-9\-\.]+\.md)\)")
            .Select(m => m.Groups["target"].Value)
            .Distinct(StringComparer.Ordinal)
            .Where(target => !File.Exists(System.IO.Path.Combine(next, target)))
            .OrderBy(target => target, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "WHAT-THE-OLD-APP-HAD.md links to these documents under docs/next/ and they are not there: "
            + $"{string.Join(", ", missing)}.");
    }

    private static HashSet<string> DeclaredTestClasses()
    {
        var root = System.IO.Path.Combine(
            OldAppInventory.RepositoryRoot(), "next", "tests", "SecureAD.Next.Tests");

        var declared = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories))
        {
            if (file.Contains($"{System.IO.Path.DirectorySeparatorChar}obj{System.IO.Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            {
                continue;
            }

            foreach (Match match in Regex.Matches(
                File.ReadAllText(file), @"class (?<name>[A-Za-z][A-Za-z0-9]*Tests)\b"))
            {
                declared.Add(match.Groups["name"].Value);
            }
        }

        return declared;
    }

    private static string InventoryPath() =>
        System.IO.Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", "WHAT-THE-OLD-APP-HAD.md");
}
