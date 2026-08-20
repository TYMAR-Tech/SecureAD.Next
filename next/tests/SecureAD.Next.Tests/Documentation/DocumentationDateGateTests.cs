using System.Text.RegularExpressions;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// No document may claim a date that has not happened yet.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this exists to catch, because it already happened.</b> Between 2026-08-02 and
/// 2026-08-18 the documentation drifted onto a calendar of its own. Each session read the previous
/// document, chose a date that made the narrative feel sequential, and wrote it down; nothing ever
/// compared that date to a clock. The fiction began three days <i>behind</i> reality, overtook it
/// around 2026-08-07, and by the end was <b>twenty-seven days ahead</b> - two records committed on
/// the same afternoon claimed dates five days apart. 1,242 dates across 236 files were wrong.
/// </para>
/// <para>
/// <b>It is the same defect this product exists to report.</b> A plausible value, written
/// confidently, that nothing checked - which is what
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids of the product's own output
/// and what a security audit trail can least afford. The dates are evidence of when a judgement was
/// made, and evidence nobody verified is not evidence.
/// </para>
/// <para>
/// <b>Why the clock and not the git history.</b> Comparing each file against the commit that
/// introduced it would be the exact answer, and it needs a git binary, a full clone and a
/// non-shallow history - three things a build agent may not have. A date in the future needs none
/// of them and catches the whole class. The bound is deliberately loose: anything up to tomorrow
/// passes, so a document written across midnight or in another timezone is not a failure.
/// </para>
/// </remarks>
public sealed class DocumentationDateGateTests
{
    /// <summary>
    /// Dates that are quoted from the predecessor product rather than claimed by this one. They
    /// predate this work by months and are not on its calendar.
    /// </summary>
    private static readonly HashSet<string> PredecessorDates = ["2026-03-16", "2026-04-04"];

    private static readonly Regex Dated = new(@"20\d\d-\d\d-\d\d", RegexOptions.Compiled);

    [Fact]
    public void NoDocumentClaimsADateThatHasNotHappened()
    {
        // Tomorrow, not today: a document written near midnight, or by somebody east of here, is
        // not a fabrication.
        var latest = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1));

        var offences = new List<string>();

        foreach (var file in DatedFiles())
        {
            foreach (var line in File.ReadAllLines(file).Index())
            {
                foreach (Match match in Dated.Matches(line.Item))
                {
                    if (PredecessorDates.Contains(match.Value))
                        continue;

                    if (!DateOnly.TryParse(match.Value, out var stated))
                        continue;

                    if (stated > latest)
                        offences.Add($"{Relative(file)}:{line.Index + 1} states {match.Value}");
                }
            }
        }

        Assert.True(
            offences.Count == 0,
            "A document states a date that has not happened. A date is evidence of when a "
            + "judgement was made, and one nobody checked is not evidence. Use the date the work "
            + "is actually being done:"
            + Environment.NewLine + string.Join(Environment.NewLine, offences));
    }

    // -------------------------------------------------------------------------------------------
    // The scanner self-test. A gate that scans nothing passes.
    // -------------------------------------------------------------------------------------------

    [Fact]
    public void TheGateReadsTheRealDocumentsAndFindsRealDates()
    {
        var files = DatedFiles();

        Assert.NotEmpty(files);
        Assert.Contains(files, f => Path.GetFileName(f) == "DECISIONS.md");

        // And it is actually finding dates in them, rather than passing because it matched none.
        var found = files.Sum(f => Dated.Matches(File.ReadAllText(f)).Count);
        Assert.True(found > 100, $"The gate found only {found} dates; it is not reading the corpus.");
    }

    [Fact]
    public void TheGateWouldFailOnADateInTheFuture()
    {
        var future = DateOnly.FromDateTime(DateTime.UtcNow.AddYears(1)).ToString("yyyy-MM-dd");
        var latest = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1));

        var match = Dated.Match($"Written {future}.");

        Assert.True(match.Success);
        Assert.True(DateOnly.Parse(match.Value) > latest);
    }

    [Fact]
    public void TheGateWouldPassTodaysDate()
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow).ToString("yyyy-MM-dd");
        var latest = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1));

        Assert.False(DateOnly.Parse(Dated.Match($"Written {today}.").Value) > latest);
    }

    private static string Relative(string path) =>
        Path.GetRelativePath(OldAppInventory.RepositoryRoot(), path);

    /// <summary>
    /// Every document and every source comment that could carry a date. Source is included
    /// because the drift reached code comments too.
    /// </summary>
    private static IReadOnlyList<string> DatedFiles()
    {
        var root = OldAppInventory.RepositoryRoot();

        var docs = Directory.EnumerateFiles(
            Path.Combine(root, "docs"), "*.md", SearchOption.AllDirectories);

        var source = Directory
            .EnumerateFiles(Path.Combine(root, "next", "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal));

        return [.. docs.Concat(source)];
    }
}
