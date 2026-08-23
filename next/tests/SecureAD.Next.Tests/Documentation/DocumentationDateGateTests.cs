using System.Text.RegularExpressions;
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

    /// <summary>
    /// A year and month with no day: <c>2026-09</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The lookarounds keep this off the front of a full date. <c>2026-08-18</c> contains
    /// <c>2026-08</c>, and matching that would make every dated line an offence the moment the
    /// month turned.
    /// </para>
    /// <para>
    /// <b>Added 2026-08-23, and it was already wrong here.</b> The punch list carried three
    /// adjudications dated <c>2026-09</c>, written in August by a session that reached for a month
    /// rather than a date. <see cref="NoDocumentClaimsADateThatHasNotHappened"/> never saw them,
    /// because its name says <i>a date</i> and its pattern says <i>a full date</i>. That gap then
    /// propagated: the session that found it copied the surrounding convention into its own
    /// entries before checking the convention.
    /// </para>
    /// </remarks>
    private static readonly Regex DatedByMonth =
        new(@"(?<!\d)20\d\d-\d\d(?!-?\d)", RegexOptions.Compiled);

    /// <summary>
    /// A date with a placeholder where a day or month should be: <c>2026-09-XX</c>.
    /// </summary>
    /// <remarks>
    /// <b>Case-insensitive since 2026-08-23.</b> It matched <c>XX</c> only, under
    /// <see cref="StringComparison.Ordinal"/>, and three lab-verification dates had been sitting as
    /// <c>2026-09-xx</c> in lowercase - invisible to this gate for the case and to the future-date
    /// gate for not being a full date. Two checks, blind to the same three lines, each for its own
    /// reason.
    /// </remarks>
    private static readonly Regex Placeholder = new(
        @"20\d\d-(?:\d\d|XX)-(?:\d\d|XX)(?<!\d)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// A placeholder date is not a date, so <see cref="NoDocumentClaimsADateThatHasNotHappened"/>
    /// never sees it.
    /// </summary>
    /// <remarks>
    /// Written 2026-08-20, after four documents were found carrying <c>2026-09-XX</c> - two from
    /// this session and two from earlier ones. The session that wrote them did not know the date
    /// and would not guess, which was right; what was missing was anything to make the placeholder
    /// come due. Had it guessed, it would have been three weeks out and in the future.
    /// <c>next/tools/replace-date-placeholders.ps1</c> fills them in.
    /// </remarks>
    [Fact]
    public void NoDocumentLeavesADatePlaceholderUnfilled()
    {
        var offences = new List<string>();

        foreach (var file in DatedFiles())
        {
            foreach (var line in File.ReadAllLines(file).Index())
            {
                foreach (Match match in Placeholder.Matches(line.Item))
                {
                    if (!match.Value.Contains("XX", StringComparison.OrdinalIgnoreCase)) continue;

                    offences.Add(
                        $"  {Path.GetFileName(file)} line {line.Index + 1}: {match.Value}");
                }
            }
        }

        Assert.True(
            offences.Count == 0,
            "A date placeholder is not a date, so the future-date gate never sees it. Fill it in "
            + "with next/tools/replace-date-placeholders.ps1:"
            + Environment.NewLine + string.Join(Environment.NewLine, offences));
    }

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

    /// <summary>
    /// The same rule for a claim that names only a month. A wrong month is as fabricated as a
    /// wrong day and is easier to write, because a month feels like an approximation rather than
    /// an assertion.
    /// </summary>
    [Fact]
    public void NoDocumentClaimsAMonthThatHasNotHappened()
    {
        var latest = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1));

        var offences = new List<string>();

        foreach (var file in DatedFiles())
        {
            foreach (var line in File.ReadAllLines(file).Index())
            {
                foreach (Match match in DatedByMonth.Matches(line.Item))
                {
                    if (!DateOnly.TryParse(match.Value + "-01", out var stated))
                        continue;

                    if (stated.Year > latest.Year
                        || (stated.Year == latest.Year && stated.Month > latest.Month))
                    {
                        offences.Add($"{Relative(file)}:{line.Index + 1} states {match.Value}");
                    }
                }
            }
        }

        Assert.True(
            offences.Count == 0,
            "A document states a month that has not happened. Reaching for a month rather than a "
            + "date does not make a claim approximate - it makes it unverifiable, which is worse. "
            + "Use the date the work is actually being done:"
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

    /// <summary>
    /// The month pattern must not fire on the front of a full date. Without this the widening
    /// would report every dated line in the repository the moment the month turned, and the
    /// obvious repair would be to delete it again.
    /// </summary>
    [Fact]
    public void TheMonthGateDoesNotMatchThePrefixOfAFullDate()
    {
        Assert.False(DatedByMonth.IsMatch("Written 2026-08-18."));
        Assert.False(DatedByMonth.IsMatch("Between 2026-08-02 and 2026-08-18"));
        Assert.False(DatedByMonth.IsMatch("bundle ad.lab-20260819-232425"));
    }

    /// <summary>
    /// And it does fire on a bare month, which is what it exists for.
    /// </summary>
    [Fact]
    public void TheMonthGateMatchesABareMonthAndWouldFailOnAFutureOne()
    {
        Assert.True(DatedByMonth.IsMatch("adjudicated 2026-09, and the line was right"));

        var future = DateTime.UtcNow.AddYears(1).ToString("yyyy-MM");
        var latest = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1));
        var match = DatedByMonth.Match($"adjudicated {future}.");

        Assert.True(match.Success);

        var stated = DateOnly.Parse(match.Value + "-01");
        Assert.True(stated.Year > latest.Year
            || (stated.Year == latest.Year && stated.Month > latest.Month));
    }

    [Fact]
    public void TheGateWouldPassTodaysDate()
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow).ToString("yyyy-MM-dd");
        var latest = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(1));

        Assert.False(DateOnly.Parse(Dated.Match($"Written {today}.").Value) > latest);
    }

    private static string Relative(string path) =>
        Path.GetRelativePath(RepositoryLocation.Root(), path);

    /// <summary>
    /// Every document and every source comment that could carry a date. Source is included
    /// because the drift reached code comments too.
    /// </summary>
    private static IReadOnlyList<string> DatedFiles()
    {
        var root = RepositoryLocation.Root();

        var docs = Directory.EnumerateFiles(
            Path.Combine(root, "docs"), "*.md", SearchOption.AllDirectories);

        var source = Directory
            .EnumerateFiles(Path.Combine(root, "next", "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal));

        return [.. docs.Concat(source)];
    }
}
