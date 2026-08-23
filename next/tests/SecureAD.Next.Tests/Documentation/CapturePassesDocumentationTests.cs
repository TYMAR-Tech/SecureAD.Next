using System.Text.RegularExpressions;
using SecureAD.Next.Tests.Architecture;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/audit/how-a-controller-is-read.md</c> to the ways a capture pass can actually end.
///
/// <para>
/// This is inventory row B6's deliverable. Every ending is a message a customer or an operator will
/// one day read at the moment a capture stopped, so an ending the document does not describe is a
/// failure nobody has explained, and a described ending the code cannot produce is a reassurance
/// about a case that never happens.
/// </para>
/// <para>
/// <b>Why a source scan.</b> The endings are error reasons passed to <c>AuditError.Create</c>, and
/// there is no way to enumerate them by reflection - they are arguments, not members. The old tree
/// scans source for the same reason, and so do the architecture guards in this project.
/// </para>
/// <para>
/// <b>What it cannot check.</b> Whether the explanation beside each ending is a good explanation,
/// whether the ordering decisions in the document are the right ones, or whether the loop has ever
/// been pointed at a directory. The last of those is gate 5b and is stated in the document rather
/// than implied by this test passing.
/// </para>
/// </summary>
public sealed class CapturePassesDocumentationTests
{
    private const string Document = "how-a-controller-is-read.md";
    private const string TableBegin = "<!-- ENDINGS:BEGIN -->";
    private const string TableEnd = "<!-- ENDINGS:END -->";

    /// <summary>The files whose endings this document is answerable for.</summary>
    private static readonly string[] Sources = ["PartitionCapture.cs", "CapturePlan.cs"];

    /// <summary>
    /// An error reason as it is written at a call site. Two shapes, because there are two: an
    /// ending raised directly through <c>AuditError.Create</c>, and one raised through the loop's
    /// own <c>Refuse</c> helper.
    ///
    /// <para>
    /// Both are here because of something that happened while building this row. The endings were
    /// originally written the first way; a later refactor moved five of them behind the helper and
    /// the scan silently stopped seeing them. It failed loudly only because the self-test below
    /// asserts a floor on how many it finds. Without that floor the document would have gone on
    /// claiming to describe endings nobody was checking.
    /// </para>
    /// </summary>
    private static readonly Regex Ending = new(
        @"(?:ErrorCategory\.Capture,|Refuse<[A-Za-z(), ]+>\()\s*""(?<reason>[A-Za-z]+)""",
        RegexOptions.Compiled | RegexOptions.Singleline);

    [Fact]
    public void TheDocumentDescribesEveryWayAPassCanEnd()
    {
        var described = DocumentedEndings();

        var missing = CodeEndings()
            .Where(e => !described.Contains(e))
            .Select(e => "  " + e)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Endings the capture loop produces and " + Document + " does not describe. Each is a "
            + "message somebody reads at the moment a capture stopped, and an undescribed one is a "
            + "failure nobody has explained:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public void TheDocumentDescribesNoEndingThatCannotHappen()
    {
        var real = CodeEndings();

        var phantom = DocumentedEndings()
            .Where(e => !real.Contains(e))
            .Select(e => "  " + e)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes endings the code cannot produce. A reassurance about a case "
            + "that never happens makes the document look more complete than it is:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The scanner self-test. Without it both checks above pass by comparing two empty sets, which
    /// is the failure this repository has committed three times: a check that measures nothing and
    /// makes everything downstream of it look verified.
    ///
    /// <para>
    /// It is not enough to assert that something was found. The pattern must be shown to match the
    /// shape it is looking for and to reject a near miss, the source files must be shown to exist,
    /// and the document's markers must be shown to delimit rows.
    /// </para>
    /// </summary>
    [Fact]
    public void TheScannerReadsTheLoopAndTheDocumentAndItsPatternMatches()
    {
        foreach (var source in Sources)
        {
            Assert.True(
                File.Exists(SourcePath(source)),
                source + " was not found. If it was renamed, this test must be updated rather "
                + "than left scanning nothing.");
        }

        Assert.Matches(
            Ending, "AuditError.Create(\n ErrorCategory.Capture,\n \"PagedSearchWasNotPaged\",");
        Assert.Matches(Ending, "return Refuse<PartitionCoverage>(\n \"PagedSearchWasNotPaged\",");
        Assert.DoesNotMatch(Ending, "AuditError.Create(ErrorCategory.Analysis, \"SomethingElse\",");

        Assert.True(
            CodeEndings().Count >= 6,
            "The scan found fewer endings than the loop is known to have, so the pattern has "
            + "stopped matching how they are written. That has already happened once: a refactor "
            + "moved five endings behind a helper and the scan quietly stopped seeing them.");

        Assert.Contains("Capture.PagedSearchWasNotPaged".Split('.')[1], CodeEndings());
        Assert.True(DocumentedEndings().Count >= 5, "The endings table parsed to almost nothing.");
    }

    private static string SourcePath(string file) =>
        Path.Combine(RebuildTree.Root(), "src", "SecureAD.Audit", "Capture", file);

    private static HashSet<string> CodeEndings()
    {
        var found = new HashSet<string>(StringComparer.Ordinal);

        foreach (var source in Sources)
        {
            foreach (Match match in Ending.Matches(File.ReadAllText(SourcePath(source))))
            {
                found.Add(match.Groups["reason"].Value);
            }
        }

        return found;
    }

    private static HashSet<string> DocumentedEndings()
    {
        var path = Path.Combine(RebuildTree.Root(), "..", "docs", "audit", Document);
        var lines = File.ReadAllLines(path);

        var begin = Array.FindIndex(lines, l => l.Contains(TableBegin, StringComparison.Ordinal));
        var end = Array.FindIndex(lines, l => l.Contains(TableEnd, StringComparison.Ordinal));

        Assert.True(
            begin >= 0 && end > begin,
            "The endings table markers were not found in " + Document + ". A parse that reads "
            + "nothing must fail rather than report every ending described.");

        var endings = new HashSet<string>(StringComparer.Ordinal);

        for (var i = begin + 1; i < end; i++)
        {
            var cells = lines[i].Split('|', StringSplitOptions.TrimEntries);
            if (cells.Length < 4 || cells[1].Length == 0 || cells[1].StartsWith("---")
                || cells[1] == "Ending")
            {
                continue;
            }

            endings.Add(cells[1]);
        }

        return endings;
    }
}
