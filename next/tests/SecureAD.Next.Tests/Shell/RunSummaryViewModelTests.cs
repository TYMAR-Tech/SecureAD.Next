using SecureAD.Evidence.Run;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// One run, as a screen shows it.
///
/// <para>
/// These exist for one reason: a screen bound straight to <c>RunListing</c> printed the enum member
/// name, so a stopped run read "Cancelled" and a running one read "InProgress". Those are names
/// chosen to be unambiguous to a compiler. The tests below hold every state to a form of words, and
/// the last one holds the whole enum to having been given one - a state added later with no wording
/// would otherwise reach an operator as "Unknown" with nothing failing.
/// </para>
/// </summary>
public sealed class RunSummaryViewModelTests
{
    [Theory]
    [InlineData(RunState.InProgress, "Still running")]
    [InlineData(RunState.Sealed, "Finished")]
    [InlineData(RunState.Failed, "Failed")]
    [InlineData(RunState.Cancelled, "Stopped")]
    [InlineData(RunState.Interrupted, "Interrupted")]
    [InlineData(RunState.Damaged, "Damaged")]
    public void EachStateIsShownInWords(RunState state, string expected) =>
        Assert.Equal(expected, Summary(state).State);

    /// <summary>
    /// The guard that matters. Without it, a seventh member of <see cref="RunState"/> would reach an
    /// operator as "Unknown" and every test above would still pass.
    /// </summary>
    /// <remarks>
    /// This deliberately does NOT assert that the wording differs from the member name. Three of the
    /// six - Failed, Interrupted, Damaged - are the same word in both vocabularies because that word
    /// is already the plain one, and a check demanding they differ would force a worse wording to
    /// satisfy a test.
    /// </remarks>
    [Fact]
    public void EveryStateHasBeenGivenWordsAndAMeaning()
    {
        foreach (var state in Enum.GetValues<RunState>())
        {
            var summary = Summary(state);

            Assert.NotEqual("Unknown", summary.State);
            Assert.DoesNotContain("not recognised", summary.Meaning, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// The self-test for the guard above: it must fail when a state genuinely has no wording. The
    /// default enum value proves the fallback branches are reachable and say what they claim.
    /// </summary>
    [Fact]
    public void AStateWithNoWordingFallsThroughToUnknown()
    {
        var summary = Summary((RunState)999);

        Assert.Equal("Unknown", summary.State);
        Assert.Contains("not recognised", summary.Meaning, StringComparison.Ordinal);
    }

    [Fact]
    public void OnlyASealedRunIsSaidToHaveFinishedCleanly()
    {
        Assert.True(Summary(RunState.Sealed).FinishedCleanly);
        Assert.False(Summary(RunState.Interrupted).FinishedCleanly);
    }

    /// <summary>
    /// Interrupted and Damaged read alike and their remedies differ, which is the whole reason the
    /// two are separate members. If their meanings ever coincide, the distinction has been lost on
    /// screen whatever the enum still says.
    /// </summary>
    [Fact]
    public void InterruptedAndDamagedDoNotMeanTheSameThing() =>
        Assert.NotEqual(Summary(RunState.Interrupted).Meaning, Summary(RunState.Damaged).Meaning);

    [Fact]
    public void ARunWithNoDetailIsNotSaidToHaveOne() =>
        Assert.False(Summary(RunState.Sealed).HasDetail);

    [Fact]
    public void AWhitespaceDetailIsNotADetail() =>
        Assert.False(Summary(RunState.Failed, "   ").HasDetail);

    [Fact]
    public void ARunWithADetailReportsIt() =>
        Assert.True(Summary(RunState.Failed, "The drive filled up.").HasDetail);

    [Fact]
    public void ACaptureOnlyRunSaysNothingWasAssessed()
    {
        var row = Summary(RunState.Sealed, products: new RunProducts(false, false));

        Assert.Equal("Evidence sealed — not assessed", row.Analysis);
        Assert.True(row.NothingAssessed);
        Assert.False(row.HasResults);
    }

    [Fact]
    public void ACaptureOnlyRunIsOfferedDerivingAndNotJudging()
    {
        var row = Summary(RunState.Sealed, products: new RunProducts(false, false));

        Assert.True(row.MayDerive);
        // Judging rests on derived facts. Offering it here would offer an analysis that would rest
        // on nothing, and the operator would have no way to know that from the button.
        Assert.False(row.MayJudge);
    }

    [Fact]
    public void ADerivedRunIsOfferedJudgingAndNotDerivingAgain()
    {
        var row = Summary(RunState.Sealed, products: new RunProducts(HasDerivedFacts: true, HasJudgement: false));

        Assert.Equal("Facts derived — not judged", row.Analysis);
        Assert.True(row.MayJudge);
        Assert.False(row.MayDerive);
        Assert.False(row.HasResults);
    }

    [Fact]
    public void AJudgedRunIsOfferedNeitherAndHasResults()
    {
        var row = Summary(RunState.Sealed, products: new RunProducts(true, true));

        Assert.Equal("Judged", row.Analysis);
        Assert.False(row.MayDerive);
        Assert.False(row.MayJudge);
        Assert.True(row.HasResults);
    }

    /// <summary>
    /// A run that did not finish is asked what became of the capture, not what was made from it.
    /// </summary>
    /// <remarks>
    /// Saying "not assessed" about a failed run would answer a question about analysis while the
    /// operator needs to know the drive filled up. The products axis is silent here on purpose.
    /// </remarks>
    [Theory]
    [InlineData(RunState.Failed)]
    [InlineData(RunState.Cancelled)]
    [InlineData(RunState.Interrupted)]
    [InlineData(RunState.Damaged)]
    [InlineData(RunState.InProgress)]
    public void ARunThatDidNotFinishSaysNothingAboutAnalysis(RunState state)
    {
        var row = Summary(state, products: new RunProducts(false, false));

        Assert.Null(row.Analysis);
        Assert.False(row.HasAnalysis);
        Assert.False(row.NothingAssessed);
        Assert.False(row.MayDerive);
        Assert.False(row.MayJudge);
    }

    private static RunSummaryViewModel Summary(
        RunState state, string? detail = null, RunAnnotation? annotation = null,
        RunProducts? products = null) =>
        new(new RunListing(
            "forest-20260101-000000",
            @"D:\audits\forest",
            state,
            detail,
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            annotation ?? RunAnnotation.None,
            Scope: null,
            products ?? new RunProducts(HasDerivedFacts: true, HasJudgement: true)));
}
