using SecureAD.Evidence.Run;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// F1 - the run's target identity. A profile answers <i>same forest</i> and nothing else.
///
/// <para>
/// The property everything else leans on is that it is a pure function of the forest name, so a
/// bundle whose metadata was never written can still be placed in the right group by recomputing
/// it. The predecessor recorded why its two-argument factory was deleted: nothing checked that the
/// separate root DN was the FQDN's transform, so two callers could compute different profiles for
/// one forest, and such a run landed in a group of one and was never offered as a compare partner,
/// silently.
/// </para>
/// </summary>
public sealed class ProfileIdTests
{
    [Fact]
    public void TheSameForestAlwaysProducesTheSameProfile()
    {
        Assert.Equal(
            ProfileId.ForForest("contoso.com").Value,
            ProfileId.ForForest("contoso.com").Value);
    }

    [Fact]
    public void TwoForestsProduceDifferentProfiles()
    {
        Assert.NotEqual(
            ProfileId.ForForest("contoso.com").Value,
            ProfileId.ForForest("fabrikam.com").Value);
    }

    /// <summary>
    /// Active Directory does not distinguish forest names by case, so a product that did would
    /// split one forest's history into two groups on nothing but how the operator typed it.
    /// </summary>
    [Theory]
    [InlineData("CONTOSO.COM")]
    [InlineData("Contoso.Com")]
    [InlineData("contoso.COM")]
    public void CaseDoesNotChangeTheProfile(string spelling)
    {
        Assert.Equal(
            ProfileId.ForForest("contoso.com").Value,
            ProfileId.ForForest(spelling).Value);
    }

    [Fact]
    public void TheForestNameIsKeptSoAReaderCanSeeWhatWasHashed()
    {
        Assert.Equal("contoso.com", ProfileId.ForForest("CONTOSO.COM").ForestFqdn);
    }

    /// <summary>
    /// The value is what a folder name, a log line and a comparison all use, so it is fixed at a
    /// width and an alphabet rather than being whatever the hash function of the day returns.
    /// </summary>
    [Fact]
    public void TheValueIsSixteenLowercaseHexCharacters()
    {
        var value = ProfileId.ForForest("contoso.com").Value;

        Assert.Equal(16, value.Length);
        Assert.All(value, c => Assert.True(
            (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
            $"'{c}' is not lowercase hex, and the value is used in file and folder names."));
    }

    /// <summary>
    /// Two profiles carrying the same forest are the same profile. Records give this for free; it
    /// is asserted because grouping a forest's runs depends on it and a later change from record
    /// to class would remove it silently.
    /// </summary>
    [Fact]
    public void TwoProfilesForOneForestAreEqual()
    {
        Assert.Equal(ProfileId.ForForest("contoso.com"), ProfileId.ForForest("contoso.com"));
    }

    /// <summary>
    /// A forest name is not optional and there is no sensible default for one. This is a defect in
    /// the caller rather than an outcome of a run, so it throws rather than returning a
    /// <c>Result</c> - the rule of thumb stated on <c>Result{T}</c>.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnEmptyForestNameIsRefused(string forest)
    {
        Assert.Throws<ArgumentException>(() => ProfileId.ForForest(forest));
    }

    [Fact]
    public void ANullForestNameIsRefused()
    {
        Assert.Throws<ArgumentNullException>(() => ProfileId.ForForest(null!));
    }
}
