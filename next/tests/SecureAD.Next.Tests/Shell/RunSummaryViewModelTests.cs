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

    private static RunSummaryViewModel Summary(
        RunState state, string? detail = null, RunAnnotation? annotation = null) =>
        new(new RunListing(
            "forest-20260101-000000",
            @"D:\audits\forest",
            state,
            detail,
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            annotation ?? RunAnnotation.None));
}
