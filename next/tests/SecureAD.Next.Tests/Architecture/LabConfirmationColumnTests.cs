using System.Globalization;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The lab confirmation column in every area file's <c>What is built</c> table.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the column exists.</b> A unit test proves the code does what the test says. It says
/// nothing about whether the product works against a real Active Directory - a synthetic security
/// descriptor proves the parser handles those bytes, not that a domain controller sends them.
/// The owner exercises the product on a separate lab machine, and until this column there was
/// nowhere to record what that run confirmed, so it lived in his memory and was periodically
/// redone.
/// </para>
/// <para>
/// <b>Blank is the honest default</b> and means "unit-tested, not yet seen against a real
/// forest". This test does not require any row to be filled in - only that what is filled in is
/// a real date, and that the column has not quietly disappeared from a table.
/// </para>
/// <para>
/// It is deliberately the one column the assistant cannot fill in. Nothing it can do makes a lab
/// run happen, so a date here is evidence of something no test in this suite can manufacture.
/// </para>
/// </remarks>
public sealed class LabConfirmationColumnTests
{
    private const string BuiltHeading = "## What is built";
    private const string ColumnHeader = "Confirmed in lab";

    private static string AreasDirectory() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "areas");

    /// <summary>
    /// A table of capabilities without the column would silently stop asking the question.
    /// </summary>
    [Fact]
    public void EveryBuiltTableCarriesTheLabColumn()
    {
        var missing = AreaFiles()
            .Where(f => BuiltTableRows(f).Any())
            .Where(f => !BuiltTableRows(f).First().Contains(ColumnHeader, StringComparison.Ordinal))
            .Select(f => "  " + Path.GetFileName(f))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            missing.Length == 0,
            $"These area files have capabilities but no '{ColumnHeader}' column, so nothing asks "
            + "whether any of them was ever seen working against a real forest:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// A date, or blank. Anything else - "yes", "done", "tested" - records that somebody felt
    /// good about it, which is not the same as a run on a known day against a known forest.
    /// </summary>
    [Fact]
    public void EveryLabConfirmationIsADate()
    {
        var bad = new List<string>();

        foreach (var file in AreaFiles())
        {
            foreach (var row in BuiltTableRows(file).Skip(2))
            {
                var cells = row.Split('|');
                if (cells.Length < 3) continue;

                var value = cells[^2].Trim();
                if (value.Length == 0) continue;

                if (!DateTime.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out _))
                {
                    bad.Add($"  {Path.GetFileName(file)}: '{value}'");
                }
            }
        }

        Assert.True(
            bad.Count == 0,
            "Lab confirmations must be a date in yyyy-MM-dd form, or blank. A word instead of a "
            + "date cannot be checked against a run bundle later:"
            + Environment.NewLine + string.Join(Environment.NewLine, bad));
    }

    /// <summary>
    /// The scanner self-test. Without it both checks above pass by reading no tables at all.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheBuiltTables()
    {
        var withCapabilities = AreaFiles().Count(f => BuiltTableRows(f).Skip(2).Any());

        Assert.True(
            withCapabilities >= 10,
            $"Read capability tables from only {withCapabilities} area files, which is too few to "
            + "be the whole set.");
    }

    private static IEnumerable<string> AreaFiles() =>
        Directory.EnumerateFiles(AreasDirectory(), "*.md")
            .Where(f => !string.Equals(Path.GetFileName(f), "README.md", StringComparison.Ordinal));

    /// <summary>The rows of the table under <c>## What is built</c>, header row first.</summary>
    private static List<string> BuiltTableRows(string file)
    {
        var rows = new List<string>();
        var inSection = false;

        foreach (var line in File.ReadAllLines(file))
        {
            if (line.StartsWith("##", StringComparison.Ordinal))
                inSection = line.StartsWith(BuiltHeading, StringComparison.Ordinal);
            else if (inSection && line.StartsWith('|'))
                rows.Add(line);
        }

        return rows;
    }
}
