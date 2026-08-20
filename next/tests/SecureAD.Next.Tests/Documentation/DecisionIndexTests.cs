using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/DECISIONS.md</c> to the decision records it is generated from.
///
/// <para>
/// <b>The index is derived, and this is what keeps it derived.</b> Its predecessor was a
/// hand-written summary - <c>POINT-IN-TIME-REVIEW.md</c> - which opened with <i>read this first if
/// you have been away</i> and was, on 2026-08-14, four days and five records behind, claiming
/// sixty-nine files of production code where there were sixty-eight. A summary maintained beside
/// its source is a second copy of that source, and a second copy is a contradiction waiting for
/// the first edit.
/// </para>
/// <para>
/// <b>What is asserted is the content, not the layout.</b> Every record must appear with its own
/// number, date, verdict and subject, and the index must name no record that is absent. Changing
/// how <c>Build-DecisionIndex.ps1</c> formats a row is free; letting the index disagree with a
/// record is not.
/// </para>
/// </summary>
public sealed class DecisionIndexTests
{
    private sealed record Record(string Number, string FileName, string Date, string Verdict, string Subject);

    [Fact]
    public void EveryDecisionRecordAppearsInTheIndex()
    {
        var index = IndexText();

        var missing = new List<string>();

        foreach (var record in Records())
        {
            var row = index
                .Split('\n')
                .FirstOrDefault(l => l.Contains($"[{record.Number}](", StringComparison.Ordinal));

            if (row is null)
            {
                missing.Add($"{record.Number} has no row");
                continue;
            }

            if (!row.Contains(record.FileName, StringComparison.Ordinal))
                missing.Add($"{record.Number} does not link to {record.FileName}");

            if (!row.Contains(record.Date, StringComparison.Ordinal))
                missing.Add($"{record.Number} shows a date other than {record.Date}");

            if (!row.Contains(record.Verdict, StringComparison.Ordinal))
                missing.Add($"{record.Number} shows a status other than '{record.Verdict}'");

            if (!row.Contains(record.Subject, StringComparison.Ordinal))
                missing.Add($"{record.Number} shows a subject other than '{record.Subject}'");
        }

        Assert.True(
            missing.Count == 0,
            "docs/DECISIONS.md disagrees with the records it is generated from: "
            + string.Join("; ", missing)
            + ". Run next/tools/Build-DecisionIndex.ps1 rather than editing the file.");
    }

    /// <summary>
    /// The other direction. An index naming a record that is not there sends a reader to a file
    /// that cannot be opened, and a deleted record would otherwise go on being advertised.
    /// </summary>
    [Fact]
    public void TheIndexNamesNoRecordThatDoesNotExist()
    {
        var known = Records().Select(r => r.Number).ToHashSet(StringComparer.Ordinal);

        var strangers = Regex
            .Matches(IndexText(), @"\| \[(?<number>\d{4})\]\(")
            .Select(m => m.Groups["number"].Value)
            .Where(number => !known.Contains(number))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            strangers.Count == 0,
            $"docs/DECISIONS.md names records that do not exist: {string.Join(", ", strangers)}. "
            + "Run next/tools/Build-DecisionIndex.ps1.");
    }

    /// <summary>
    /// The generator's inputs exist. Every record states a title, a date and a status, because a
    /// record missing one of them cannot be indexed and would otherwise fail obscurely inside a
    /// script rather than here, where the message can say which file and which line.
    /// </summary>
    [Fact]
    public void EveryRecordStatesATitleADateAndAStatus()
    {
        var incomplete = new List<string>();

        foreach (var file in RecordFiles())
        {
            var head = File.ReadLines(file).Take(20).ToList();

            if (!head.Any(l => l.StartsWith("# ", StringComparison.Ordinal)))
                incomplete.Add($"{Path.GetFileName(file)} has no title");

            if (!head.Any(l => l.StartsWith("Date:", StringComparison.Ordinal)))
                incomplete.Add($"{Path.GetFileName(file)} has no Date:");

            if (!head.Any(l => l.StartsWith("Status:", StringComparison.Ordinal)))
                incomplete.Add($"{Path.GetFileName(file)} has no Status:");
        }

        Assert.True(incomplete.Count == 0, string.Join("; ", incomplete));
    }

    /// <summary>
    /// The scanner self-test. Without it the checks above pass by reading nothing and finding
    /// nothing wrong with it, which is a failure this repository has shipped three times.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheIndexAndTheRecords()
    {
        Assert.True(RecordFiles().Count > 20, "Found suspiciously few decision records.");
        Assert.Contains("| # | Date | Status | Decision |", IndexText(), StringComparison.Ordinal);
        Assert.DoesNotContain("| [9999](", IndexText(), StringComparison.Ordinal);
    }

    private static List<Record> Records()
    {
        var records = new List<Record>();

        foreach (var file in RecordFiles())
        {
            var head = File.ReadLines(file).Take(20).ToList();
            var name = Path.GetFileName(file);
            var number = name[..4];

            var title = head.First(l => l.StartsWith("# ", StringComparison.Ordinal))[2..].Trim();
            var date = head.First(l => l.StartsWith("Date:", StringComparison.Ordinal))[5..].Trim();
            var status = head.First(l => l.StartsWith("Status:", StringComparison.Ordinal))[7..].Trim();

            var subject = Regex.Replace(title, $@"^{number}\s*[-\u2013\u2014]\s*", string.Empty).Trim();

            var verdict = Regex.Replace(status, @"\[([^\]]+)\]\([^)]*\)", "$1");
            verdict = verdict.Split(['.', ';', ','], 2)[0].Trim();

            records.Add(new Record(number, name, date, verdict, subject));
        }

        return records;
    }

    private static List<string> RecordFiles() =>
        Directory
            .EnumerateFiles(
                Path.Combine(RepositoryLocation.Root(), "docs", "decisions"), "0*.md")
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();

    private static string IndexText() =>
        File.ReadAllText(Path.Combine(RepositoryLocation.Root(), "docs", "DECISIONS.md"));
}
