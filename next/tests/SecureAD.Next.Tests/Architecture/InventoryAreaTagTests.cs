using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every inventory row names an area that exists, so the inventory cannot claim a subject belongs to a
/// conversation nobody is having.
///
/// <para>
/// The tag says where a subject is <i>discussed</i>. It is not a promise that the subject will be
/// built — that is settled in the area file and its records. The point of the tag is coverage: an
/// untagged row is a row with no home, which is how a row goes on reading as an obligation long
/// after the product decided otherwise.
/// </para>
/// </summary>
[Collection(nameof(InventoryFileCollection))]
public sealed class InventoryAreaTagTests
{
    /// <summary>
    /// Rows nobody has judged yet, written as <c>?</c> in the table. They are permitted, because a
    /// guess would be worse — it would look decided. They are counted rather than tolerated
    /// silently, so the number cannot creep up without somebody choosing to raise it.
    /// </summary>
    private const int UnjudgedRowsAllowed = 1;

    [Fact]
    public void EveryInventoryRowNamesAnAreaThatExists()
    {
        var areas = KnownAreas();

        var unknown = TaggedRows()
            .Where(r => r.Area != "?" && !r.Area.StartsWith("&mdash;", StringComparison.Ordinal))
            .Where(r => !areas.Contains(r.Area))
            .Select(r => $"  {r.Component} (line {r.Line}) is tagged '{r.Area}', which is not an area")
            .ToList();

        Assert.True(
            unknown.Count == 0,
            "Inventory rows tagged with an area that does not exist. The area index in "
            + "docs/areas/README.md lists every area there is:" + Environment.NewLine
            + string.Join(Environment.NewLine, unknown));
    }

    [Fact]
    public void NoInventoryRowIsLeftWithoutAnArea()
    {
        var blank = TaggedRows()
            .Where(r => r.Area.Length == 0)
            .Select(r => $"  {r.Component} (line {r.Line}) has an empty Area cell")
            .ToList();

        Assert.True(
            blank.Count == 0,
            "Inventory rows with no area at all. A row with no home reads as an obligation to whoever "
            + "finds it:" + Environment.NewLine + string.Join(Environment.NewLine, blank));
    }

    /// <summary>
    /// The count of unjudged rows cannot rise without somebody deciding to raise it. Written as an
    /// exact match rather than a ceiling, so that judging one and leaving another unjudged is still
    /// a visible change.
    /// </summary>
    [Fact]
    public void OnlyTheRowsAlreadyKnownToBeUnjudgedAreUnjudged()
    {
        var unjudged = TaggedRows().Where(r => r.Area == "?").Select(r => r.Component).ToList();

        Assert.True(
            unjudged.Count == UnjudgedRowsAllowed,
            $"Expected {UnjudgedRowsAllowed} inventory row(s) marked '?', found {unjudged.Count}: "
            + string.Join(", ", unjudged)
            + ". A '?' is honest, but it is a question owed to the owner, not a resting place.");
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by reading no rows and no areas,
    /// and reports that nothing is wrong with either.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheRowsAndTheAreas()
    {
        var rows = TaggedRows();
        var areas = KnownAreas();

        Assert.True(rows.Count > 200, $"Read only {rows.Count} inventory rows, which is not the whole table.");
        Assert.True(areas.Count > 10, $"Read only {areas.Count} areas from the index.");

        Assert.Contains(areas, a => a == "which-controller-we-read");
        Assert.Contains(rows, r => r.Component == "A1");
        Assert.Contains(rows, r => r.Area.StartsWith("&mdash;", StringComparison.Ordinal));
    }

    /// <summary>
    /// Every area the index names, by the file name it lives in with the extension dropped, which is
    /// how the inventory writes the tag.
    /// </summary>
    private static HashSet<string> KnownAreas()
    {
        var index = Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "areas", "README.md");
        Assert.True(File.Exists(index), $"Expected the area index at {index}.");

        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (System.Text.RegularExpressions.Match match in
                 System.Text.RegularExpressions.Regex.Matches(File.ReadAllText(index), @"[`(]([a-z0-9-]+)\.md[`)]"))
        {
            names.Add(match.Groups[1].Value);
        }

        return names;
    }

    private static List<(string Component, string Area, int Line)> TaggedRows()
    {
        var rows = new List<(string, string, int)>();

        foreach (var (cells, line) in OldAppInventory.InventoryCells())
        {
            if (cells.Count < OldAppInventory.InventoryColumnCount)
                continue;

            var component = cells[0];
            if (component is "Component" || component.All(c => c is '-' or ':'))
                continue;

            rows.Add((component, cells[^1].Replace("*", string.Empty, StringComparison.Ordinal).Trim(), line));
        }

        return rows;
    }
}
