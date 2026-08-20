using System.Text.RegularExpressions;
using SecureAD.Next.Tests.Architecture;
using Xunit;

namespace SecureAD.Next.Tests.Inventory;

/// <summary>
/// Holds <c>docs/next/WHAT-THE-OLD-APP-HAD.md</c> to <c>docs/map/</c> in both directions, and holds
/// the file itself to a shape.
///
/// <para>
/// The inventory's whole value is that it is provably complete against the map: a component cannot
/// be silently skipped, and a row cannot name a component that does not exist. Neither claim
/// survives on inspection - there are 256 of them - so it is asserted here instead.
/// </para>
/// <para>
/// <see cref="TheExtractorFindsTheMapsComponents"/> is the scanner self-test, following
/// <see cref="ProductInvariantTests"/>. Without it the two direction tests pass by comparing two
/// empty sets, which is the failure mode a completeness check is most prone to.
/// </para>
/// </summary>
[Collection(nameof(InventoryFileCollection))]
public sealed class InventoryCompletenessTests
{
    /// <summary>
    /// The count the map states in its own <c>§The map is complete</c> section. Stated here so a
    /// change to the map is a decision rather than a number quietly moving.
    /// </summary>
    private const int ExpectedComponentCount = 256;

    [Fact]
    public void EveryMapComponentAppearsInTheInventoryExactlyOnce()
    {
        var rowsByComponent = OldAppInventory.InventoryRows()
            .GroupBy(r => r.Component, StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.Ordinal);

        var missing = OldAppInventory.MapComponents()
            .Where(c => !rowsByComponent.ContainsKey(c.Id))
            .Select(c => $"{c.Id} ({c.File})")
            .ToList();

        var duplicated = rowsByComponent
            .Where(p => p.Value > 1)
            .Select(p => $"{p.Key} appears {p.Value} times")
            .ToList();

        Assert.True(
            missing.Count == 0 && duplicated.Count == 0,
            "Every component in docs/map/ must have exactly one row in the inventory."
            + Environment.NewLine + "Missing: " + Describe(missing)
            + Environment.NewLine + "Duplicated: " + Describe(duplicated));
    }

    [Fact]
    public void EveryInventoryRowNamesAComponentThatExistsInTheMap()
    {
        var mapIds = OldAppInventory.MapComponents()
            .Select(c => c.Id)
            .ToHashSet(StringComparer.Ordinal);

        var unknown = OldAppInventory.InventoryRows()
            .Where(r => !mapIds.Contains(r.Component))
            .Select(r => $"line {r.Line}: {r.Component}")
            .ToList();

        Assert.True(
            unknown.Count == 0,
            "Every row in the inventory must name a component that exists in docs/map/. Rows "
            + "naming something else:" + Environment.NewLine + Describe(unknown));
    }

    /// <summary>
    /// Every row is well-formed and navigable: it names a component, links into the map, and
    /// carries an area tag.
    ///
    /// <para>
    /// This replaced <c>EveryLedgerRowDeclaresADisposition</c> on 2026-08-16, when the disposition,
    /// status and documentation columns were dropped and the file became an inventory of the
    /// predecessor rather than a plan. It deliberately says nothing about work being owed, because
    /// the file no longer owes any.
    /// </para>
    /// <para>
    /// <b>Why it exists at all.</b> The file still has one live job: three documentation tests use
    /// its row list to prove a row they cite is real. With nothing holding the file's shape, a row
    /// can become malformed, drop silently out of that list, and fail nothing - and a document
    /// citing it would then be checked against a list that no longer contains it. That is a check
    /// passing while measuring nothing, arriving by neglect rather than by a bad decision. The area
    /// tag is held for the same reason: it is what makes the inventory navigable when a session
    /// picks up a subject, and nothing else enforces that a row keeps one.
    /// </para>
    /// <para>
    /// <b>Mutation-tested in both directions on 2026-08-16</b>, reverting in a <c>finally</c>.
    /// Blanking A1's Component cell failed it; blanking A1's Area cell failed it; replacing A1's
    /// map link with plain text failed it; and the unmutated file passed. See
    /// <see cref="InventoryShapeGuardMutationTests"/>, which performs those mutations against a copy
    /// rather than the real file, so a process dying midway cannot leave the inventory corrupt -
    /// which is how S-43 damaged it.
    /// </para>
    /// </summary>
    [Fact]
    public void EveryRowIsWellFormedAndNavigable()
    {
        var malformed = new List<string>();

        foreach (var (cells, line) in OldAppInventory.InventoryCells())
        {
            if (cells[0] is "Component")
                continue;

            malformed.AddRange(
                ShapeFaults(cells, line).Select(fault => $"line {line}: {fault}"));
        }

        Assert.True(
            malformed.Count == 0,
            "Every row of " + Path.GetFileName(OldAppInventory.InventoryPath()) + " must name a component, "
            + "link into docs/map/, and carry an area tag. This says nothing about work being "
            + "owed - the file records what the predecessor had. It says the file is still "
            + "well-formed and still navigable, because three documentation tests prove a cited "
            + "row is real by looking it up in this table:"
            + Environment.NewLine + Describe(malformed));
    }

    /// <summary>
    /// The faults a single row can carry. Shared with the mutation test so that the thing mutated
    /// is the thing asserted, rather than a re-implementation that could drift from it.
    /// </summary>
    internal static IEnumerable<string> ShapeFaults(IReadOnlyList<string> cells, int line)
    {
        if (cells.Count != OldAppInventory.InventoryColumnCount)
        {
            yield return $"has {cells.Count} cells, expected {OldAppInventory.InventoryColumnCount} "
                         + $"({string.Join(", ", OldAppInventory.InventoryColumns)})";
            yield break;
        }

        if (!ComponentId.IsMatch(cells[0]))
            yield return $"'{cells[0]}' is not a component identifier";

        if (!MapLink.IsMatch(cells[1]))
            yield return $"{cells[0]} does not link into docs/map/";

        if (cells[3].Length == 0)
            yield return $"{cells[0]} has no area tag";
    }

    /// <summary>A map component identifier: a branch letter and a number, as <c>A1</c>.</summary>
    private static readonly Regex ComponentId = new(@"^[A-K][0-9]+$", RegexOptions.Compiled);

    /// <summary>A markdown link whose target is a file in the map.</summary>
    private static readonly Regex MapLink = new(@"\]\(\.\./map/[^)]+\.md\)", RegexOptions.Compiled);

    /// <summary>
    /// The header declares the columns the shape guard counts against, so the two cannot drift
    /// apart and a column added to the table is a decision rather than a silent widening.
    /// </summary>
    [Fact]
    public void TheHeaderDeclaresTheExpectedColumns()
    {
        var header = OldAppInventory.InventoryCells().FirstOrDefault(r => r.Cells[0] == "Component");

        Assert.True(header.Cells is not null, "The inventory table has no header row.");
        Assert.Equal(OldAppInventory.InventoryColumns, header.Cells);
    }

    /// <summary>
    /// The extractor reads the map's real branch files, and the shape guard reads the real table.
    /// Without this, the two direction tests above both pass when the map cannot be found, because
    /// an empty set is a subset of everything - and the shape guard passes by inspecting no rows.
    /// </summary>
    [Fact]
    public void TheExtractorFindsTheMapsComponents()
    {
        var components = OldAppInventory.MapComponents();

        Assert.Equal(ExpectedComponentCount, components.Count);
        Assert.Equal(ExpectedComponentCount, components.Select(c => c.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(components, c => c.Id == "A1");
        Assert.Contains(components, c => c.Id == "K27");

        var rows = OldAppInventory.InventoryRows();
        Assert.Equal(ExpectedComponentCount, rows.Count);

        var scanned = OldAppInventory.InventoryCells().Count(r => r.Cells[0] != "Component");
        Assert.True(
            scanned == ExpectedComponentCount,
            $"The shape guard inspected {scanned} rows, not the whole table of "
            + $"{ExpectedComponentCount}. A guard that passes against rows it never read is the "
            + "failure this repository has hit twice.");
    }

    private static string Describe(IReadOnlyCollection<string> items) =>
        items.Count == 0 ? "  (none)" : string.Join(Environment.NewLine, items.Select(i => "  " + i));
}
