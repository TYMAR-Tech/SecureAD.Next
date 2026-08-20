using System.Text.RegularExpressions;
using SecureAD.Next.Tests.Architecture;

namespace SecureAD.Next.Tests.Inventory;

/// <summary>
/// Reads <c>docs/map/</c> and <c>docs/next/WHAT-THE-OLD-APP-HAD.md</c> for the inventory tests.
///
/// <para>
/// Both are read from source text rather than from a generated artefact, because the point of the
/// inventory is that it is provably complete against the map as the map actually stands. A cached
/// or hand-maintained copy of either side would be the thing most likely to drift.
/// </para>
/// <para>
/// <b>What this reads changed on 2026-08-16.</b> The file used to carry a disposition, a target
/// project, a status and a documentation obligation, and the accessors here exposed them. Those
/// columns are gone: the file is an inventory of the predecessor and states no work owed, so there
/// is no disposition to read and no status to wait on. What remains is the row list and the raw
/// cells, which is what proves a cited row is real and what proves the file is still navigable.
/// </para>
/// </summary>
internal static class OldAppInventory
{
    /// <summary>Matches a map component heading: <c>### A1 - Connection settings</c>.</summary>
    private static readonly Regex ComponentHeading =
        new(@"^### (?<id>[A-K][0-9]+) (?<title>.*)$", RegexOptions.Compiled);

    private const string TableBegin = "<!-- INVENTORY:BEGIN -->";
    private const string TableEnd = "<!-- INVENTORY:END -->";

    /// <summary>The repository root - the parent of the rebuild tree.</summary>
    public static string RepositoryRoot() =>
        Directory.GetParent(RebuildTree.Root())?.FullName
        ?? throw new DirectoryNotFoundException(
            "The rebuild root at " + RebuildTree.Root() + " has no parent directory, so the "
            + "repository root holding docs/ cannot be located.");

    /// <summary>
    /// Every component in the map, keyed by ID, extracted from the branch files' headings. This is
    /// the same extraction as
    /// <c>git grep -h -o -E "^### [A-K][0-9]+ .*" -- docs/map/</c>.
    /// </summary>
    public static IReadOnlyList<(string Id, string Title, string File)> MapComponents()
    {
        var mapDirectory = Path.Combine(RepositoryRoot(), "docs", "map");
        if (!Directory.Exists(mapDirectory))
        {
            throw new DirectoryNotFoundException(
                "Expected the map at " + mapDirectory + ". The inventory tests assert that the inventory "
                + "matches the map; without the map they would pass by comparing two empty sets.");
        }

        var components = new List<(string, string, string)>();

        foreach (var file in Directory.EnumerateFiles(mapDirectory, "*.md").OrderBy(f => f, StringComparer.Ordinal))
        {
            if (string.Equals(Path.GetFileName(file), "README.md", StringComparison.Ordinal))
                continue;

            foreach (var line in File.ReadLines(file))
            {
                var match = ComponentHeading.Match(line);
                if (match.Success)
                {
                    components.Add((
                        match.Groups["id"].Value,
                        match.Groups["title"].Value.Trim(),
                        Path.GetFileName(file)));
                }
            }
        }

        return components;
    }

    /// <summary>
    /// The inventory's rows: the component ID it names, one per table row between the two markers.
    /// Rows outside the markers are not map components and are not policed by these tests.
    /// </summary>
    public static IReadOnlyList<(string Component, int Line)> InventoryRows()
    {
        var lines = File.ReadAllLines(InventoryPath());

        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        if (begin < 0 || end < 0 || end < begin)
        {
            throw new InvalidOperationException(
                "Could not find the " + TableBegin + " / " + TableEnd + " markers around the table "
                + "in " + InventoryPath() + ". The tests parse only what lies between them, so a "
                + "missing marker must fail rather than silently widen or empty the scan.");
        }

        var rows = new List<(string, int)>();

        for (var i = begin + 1; i < end; i++)
        {
            var cells = SplitRow(lines[i]);
            if (cells is null)
                continue;

            if (cells[0] is "Component" || cells[0].All(c => c is '-' or ':'))
                continue;

            rows.Add((cells[0], i + 1));
        }

        return rows;
    }

    /// <summary>
    /// Every component ID the inventory names. Used by the documentation tests that cite a row, for
    /// one purpose only: to prove the row they cite is real.
    ///
    /// <para>
    /// This replaced <c>LedgerStatuses</c> on 2026-08-16. Those callers asked for a dictionary of
    /// statuses and then read nothing but its keys, because a status was the only row list on
    /// offer. Asking the question directly means the answer no longer travels through a column
    /// that has since been deleted.
    /// </para>
    /// </summary>
    public static IReadOnlySet<string> RowIdentifiers() =>
        InventoryRows().Select(r => r.Component).ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The columns the inventory's table declares, in order. Held here so that a row missing one of
    /// them is a failure rather than a shorter row nobody notices.
    /// </summary>
    public static readonly string[] InventoryColumns =
        ["Component", "Map says", "Addresses", "Area"];

    /// <summary>How many cells a well-formed inventory row has.</summary>
    public static int InventoryColumnCount => InventoryColumns.Length;

    /// <summary>
    /// Every row of the inventory table as its raw cells, header and separator included, so a caller
    /// can check the shape of a row rather than only the contents of one cell.
    /// </summary>
    public static IReadOnlyList<(IReadOnlyList<string> Cells, int Line)> InventoryCells()
    {
        var lines = File.ReadAllLines(InventoryPath());

        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        if (begin < 0 || end < 0 || end < begin)
        {
            throw new InvalidOperationException(
                "Could not find the " + TableBegin + " / " + TableEnd + " markers around the table "
                + "in " + InventoryPath() + ".");
        }

        var rows = new List<(IReadOnlyList<string>, int)>();

        for (var i = begin + 1; i < end; i++)
        {
            var cells = SplitRow(lines[i]);
            if (cells is null || cells.All(c => c.All(ch => ch is '-' or ':')))
                continue;

            rows.Add((cells, i + 1));
        }

        return rows;
    }

    /// <summary>The inventory file, which must exist for any of these tests to mean anything.</summary>
    public static string InventoryPath()
    {
        var path = Path.Combine(RepositoryRoot(), "docs", "next", "WHAT-THE-OLD-APP-HAD.md");
        if (!File.Exists(path))
            throw new FileNotFoundException("Expected the inventory at " + path + ".", path);

        return path;
    }

    /// <summary>Splits a markdown table row into trimmed cells, or null when the line is not one.</summary>
    private static string[]? SplitRow(string line)
    {
        var trimmed = line.Trim();
        if (!trimmed.StartsWith('|') || !trimmed.EndsWith('|'))
            return null;

        return trimmed
            .Trim('|')
            .Split('|')
            .Select(c => c.Trim())
            .ToArray();
    }
}
