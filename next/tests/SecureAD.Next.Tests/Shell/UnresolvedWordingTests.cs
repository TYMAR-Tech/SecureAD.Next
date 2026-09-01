using SecureAD.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// What an operator is told when a rule could not decide.
/// </summary>
/// <remarks>
/// <b>These hold the one distinction the vocabulary exists for.</b> A missing attribute means
/// capture again; a disputed claim means Microsoft's own pages disagree and capturing again will
/// change nothing. Reporting the second as the first sends an administrator to re-read a forest
/// that was never the problem, which is what <c>docs/decisions/0091</c> required be kept apart.
/// </remarks>
public sealed class UnresolvedWordingTests
{
    /// <summary>
    /// Every reason has words of its own, so none falls back to the token.
    /// </summary>
    /// <remarks>
    /// The negative control for the test below: without this, a reason nobody worded would pass the
    /// unknown-token test by looking exactly like one this build has never seen.
    /// </remarks>
    [Fact]
    public void EveryReasonIsWordedForAnOperator()
    {
        var unworded = Enum.GetValues<UnresolvedReason>()
            .Select(r => $"{DerivedFactKind.ProtectedPrincipals}.{r}")
            .Where(token => UnresolvedWording.For(token).Contains(
                "no plainer way", StringComparison.Ordinal))
            .ToList();

        Assert.True(
            unworded.Count == 0,
            "Reasons with no wording of their own, so an operator would be shown a token: "
            + string.Join(", ", unworded));
    }

    /// <summary>
    /// A dispute says the answer is unavailable rather than sending anyone back to the forest.
    /// </summary>
    [Fact]
    public void ADisputedClaimSaysCapturingAgainWillNotHelp()
    {
        var said = UnresolvedWording.For("ProtectedPrincipals.ClaimDisputed");

        Assert.Contains("will not change it", said, StringComparison.Ordinal);

        // The negative control. This is the instruction that must not appear here.
        Assert.DoesNotContain("was not captured", said, StringComparison.Ordinal);
    }

    /// <summary>
    /// A missing attribute is reported as a capture gap, which is the opposite instruction.
    /// </summary>
    [Fact]
    public void AMissingAttributeIsReportedAsSomethingTheCaptureDidNotBringBack()
    {
        var said = UnresolvedWording.For("userAccountControl");

        Assert.Contains("userAccountControl", said, StringComparison.Ordinal);
        Assert.Contains("was not captured", said, StringComparison.Ordinal);
    }

    /// <summary>
    /// A reason this build has no words for is still shown, rather than quietly dropped.
    /// </summary>
    /// <remarks>
    /// Hiding it would report a judging as more complete than it was - the failure every gate in
    /// this repository is pointed at.
    /// </remarks>
    [Fact]
    public void AnUnrecognisedReasonIsStillShown()
    {
        var said = UnresolvedWording.For("ProtectedPrincipals.SomethingThisBuildHasNoWordFor");

        Assert.Contains("SomethingThisBuildHasNoWordFor", said, StringComparison.Ordinal);
    }
}
