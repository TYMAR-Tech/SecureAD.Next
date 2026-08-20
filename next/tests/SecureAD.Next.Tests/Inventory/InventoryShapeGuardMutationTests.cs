using System.Text;
using Xunit;

namespace SecureAD.Next.Tests.Inventory;

/// <summary>
/// Mutation-tests the shape guard in <see cref="InventoryCompletenessTests"/>: a guard nobody has
/// seen fail is a guard nobody knows works.
///
/// <para>
/// Each test damages one cell of a real row in <c>docs/next/WHAT-THE-OLD-APP-HAD.md</c>, asserts
/// that <see cref="InventoryCompletenessTests.EveryRowIsWellFormedAndNavigable"/> notices, and
/// restores the file in a <c>finally</c>. The original bytes are captured before the mutation and
/// written back verbatim, and each test asserts the restore succeeded rather than assuming it.
/// </para>
/// <para>
/// <b>Why the file itself is mutated rather than a synthetic row.</b> A synthetic row would test a
/// re-implementation of the guard. The failure this repository keeps hitting is a check that reads
/// the wrong thing or reads nothing at all, and only mutating what the guard actually opens can
/// catch that.
/// </para>
/// <para>
/// <b>Why the risk is acceptable.</b> S-43 corrupted this file when a PowerShell script died
/// between mutating and reverting. That is an out-of-process edit with no unwind. Here the revert
/// is a <c>finally</c> in the same process as the mutation, the bytes are held in memory for the
/// whole of it, and the file is read and written with an explicit <see cref="UTF8Encoding"/>
/// without a byte-order mark, which is what the file is stored as.
/// </para>
/// <para>
/// These tests are not parallelised against each other by xUnit, because they share a collection
/// with the guard they mutate - otherwise one test's mutation would be another test's failure.
/// </para>
/// </summary>
[Collection(nameof(InventoryFileCollection))]
public sealed class InventoryShapeGuardMutationTests
{
    /// <summary>The row mutated. A1 is the first row of the table and exists in every revision.</summary>
    private const string MutatedRow = "A1";

    /// <summary>
    /// The direction that matters most: the unmutated file passes. Without it every test below
    /// could be satisfied by a guard that fails on everything.
    /// </summary>
    [Fact]
    public void TheUnmutatedFilePassesTheGuard()
    {
        new InventoryCompletenessTests().EveryRowIsWellFormedAndNavigable();
    }

    [Fact]
    public void ARowWhoseComponentCellIsBlankedFailsTheGuard()
    {
        AssertMutationIsCaught(cells => { cells[0] = string.Empty; }, "is not a component identifier");
    }

    [Fact]
    public void ARowWhoseMapLinkBecomesPlainTextFailsTheGuard()
    {
        AssertMutationIsCaught(cells => { cells[1] = "Connection settings & auth mode"; }, "does not link into docs/map/");
    }

    [Fact]
    public void ARowWhoseAreaTagIsBlankedFailsTheGuard()
    {
        AssertMutationIsCaught(cells => { cells[3] = string.Empty; }, "has no area tag");
    }

    [Fact]
    public void ARowThatLosesACellFailsTheGuard()
    {
        AssertMutationIsCaught(cells => cells.RemoveAt(2), "cells, expected");
    }

    /// <summary>
    /// Applies one mutation to <see cref="MutatedRow"/>, asserts the guard fails and says why, and
    /// restores the file whatever happens.
    /// </summary>
    private static void AssertMutationIsCaught(Action<List<string>> mutate, string expectedInMessage)
    {
        var path = OldAppInventory.InventoryPath();
        var encoding = new UTF8Encoding(false);
        var original = File.ReadAllText(path, encoding);

        try
        {
            var lines = File.ReadAllLines(path, encoding);
            var index = Array.FindIndex(lines, l => l.TrimStart().StartsWith($"| {MutatedRow} |", StringComparison.Ordinal));

            Assert.True(index >= 0, $"Row {MutatedRow} is not in {path}, so nothing was mutated and this test proves nothing.");

            var cells = lines[index].Trim().Trim('|').Split('|').Select(c => c.Trim()).ToList();
            mutate(cells);
            lines[index] = "| " + string.Join(" | ", cells) + " |";

            File.WriteAllLines(path, lines, encoding);

            var failure = Assert.ThrowsAny<Xunit.Sdk.XunitException>(
                () => new InventoryCompletenessTests().EveryRowIsWellFormedAndNavigable());

            Assert.Contains(expectedInMessage, failure.Message, StringComparison.Ordinal);
        }
        finally
        {
            File.WriteAllText(path, original, encoding);
        }

        Assert.Equal(original, File.ReadAllText(path, encoding));
    }
}

/// <summary>
/// Serialises every test that reads or mutates the inventory file, so a mutation in one test cannot
/// surface as an unrelated failure in another running beside it.
/// </summary>
[CollectionDefinition(nameof(InventoryFileCollection), DisableParallelization = true)]
public sealed class InventoryFileCollection
{
}
