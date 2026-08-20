using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// F3 - the one run state vocabulary, and the persisted names it round-trips through.
///
/// <para>
/// The predecessor had four vocabularies for this question with no two sharing members, and the
/// failure that came out of it is the one asserted hardest here: an unrecognised persisted value
/// was funnelled into <c>InProgress</c>, so renaming a constant made every sealed run vanish from
/// every picker that filtered on sealed, silently. Per <c>0028</c> an unrecognised state is a
/// failure and never a default.
/// </para>
/// </summary>
public sealed class RunStateNamesTests
{
    /// <summary>
    /// Every state must survive being written down and read back. A state with no persisted name
    /// would be one the product can hold in memory and never record, which is three of the
    /// predecessor's seven.
    /// </summary>
    [Fact]
    public void EveryStateRoundTrips()
    {
        foreach (var state in Enum.GetValues<RunState>())
        {
            var read = RunStateNames.Read(RunStateNames.Persist(state));

            Assert.True(read.IsSuccess, $"{state} did not survive a round trip.");
            Assert.Equal(state, read.Value);
        }
    }

    /// <summary>
    /// Two states sharing a persisted name would make one of them unreadable, which is exactly
    /// the predecessor's collapse of <c>Cancelled</c> into <c>Failed</c> on read.
    /// </summary>
    [Fact]
    public void NoTwoStatesShareAPersistedName()
    {
        var names = Enum.GetValues<RunState>().Select(RunStateNames.Persist).ToList();

        Assert.Equal(names.Count, names.Distinct(StringComparer.Ordinal).Count());
    }

    /// <summary>
    /// The load-bearing one. A value this version does not know is most plausibly a bundle written
    /// by a later version, and the honest answer is that this one cannot read it.
    /// </summary>
    [Fact]
    public void AnUnrecognisedStateIsAFailureAndNotADefault()
    {
        var read = RunStateNames.Read("Quiesced");

        Assert.False(read.IsSuccess);
        Assert.Equal(ErrorCategory.Evidence, read.Error.Category);
        Assert.Contains("Quiesced", read.Error.Description, StringComparison.Ordinal);
    }

    /// <summary>
    /// Stated separately from the test above because this is the specific wrong answer the
    /// predecessor gave, and a future change that reintroduced a default would most likely
    /// reintroduce this one.
    /// </summary>
    [Fact]
    public void AnUnrecognisedStateDoesNotBecomeInProgress()
    {
        var read = RunStateNames.Read("Complete");

        Assert.False(
            read.IsSuccess,
            "'Complete' was the predecessor's persisted name for a sealed run. Reading it as "
            + "anything at all would mean this vocabulary had silently inherited that one.");
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ABlankStateIsAFailure(string persisted)
    {
        Assert.False(RunStateNames.Read(persisted).IsSuccess);
    }

    [Fact]
    public void ANullStateIsAFailure()
    {
        Assert.False(RunStateNames.Read(null!).IsSuccess);
    }

    /// <summary>
    /// A persisted name is a stored value, so changing one silently changes what every existing
    /// bundle means. Frozen here so that a rename is a red test naming the state rather than a
    /// discovery made later against real evidence.
    /// </summary>
    [Theory]
    [InlineData(RunState.InProgress, "InProgress")]
    [InlineData(RunState.Sealed, "Sealed")]
    [InlineData(RunState.Failed, "Failed")]
    [InlineData(RunState.Cancelled, "Cancelled")]
    [InlineData(RunState.Interrupted, "Interrupted")]
    [InlineData(RunState.Damaged, "Damaged")]
    public void ThePersistedNamesAreFixed(RunState state, string expected)
    {
        Assert.Equal(expected, RunStateNames.Persist(state));
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above could pass by iterating an empty
    /// vocabulary.
    /// </summary>
    [Fact]
    public void TheVocabularyIsNotEmpty()
    {
        Assert.Equal(6, Enum.GetValues<RunState>().Length);
    }
}
