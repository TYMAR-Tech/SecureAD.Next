using SecureAD.Kernel.Naming;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Naming;

/// <summary>
/// Parsing and shortening Active Directory distinguished names.
///
/// <para>
/// A distinguished name is not a path with a separator. The comma that divides one relative
/// distinguished name from the next may also appear <i>inside</i> a value, escaped, because
/// <c>CN=Smith\, John</c> is one component and not two. Splitting on <c>','</c> is the single
/// mistake this component exists to stop, and it is the mistake every consumer would otherwise
/// make separately: the previous implementation had thirty-four of them.
/// </para>
/// <para>
/// The cases below are knowledge about Active Directory rather than about this code, so they are
/// carried across a rewrite. The assertions are re-derived from what the behaviour should be, not
/// inherited from what the previous tests happened to check &#8212; see
/// <c>docs/next/README.md</c> &#167;Tests.
/// </para>
/// </summary>
public sealed class DnHelperTests
{
    // --- GetParentDn: shortening a DN by one component ---

    [Fact]
    public void WhenTheDnHasSeveralComponents_ThenTheParentIsEverythingAfterTheFirst()
    {
        Assert.Equal(
            "OU=Users,DC=corp,DC=local",
            DnHelper.GetParentDn("CN=John,OU=Users,DC=corp,DC=local"));
    }

    /// <summary>
    /// The escaped-comma case. <c>CN=Smith\, John</c> is one component; a split on <c>','</c>
    /// would return <c>" John,OU=Users,DC=corp,DC=local"</c>, a DN that does not exist.
    /// </summary>
    [Fact]
    public void WhenTheFirstComponentContainsAnEscapedComma_ThenItIsNotTreatedAsASeparator()
    {
        Assert.Equal(
            "OU=Users,DC=corp,DC=local",
            DnHelper.GetParentDn(@"CN=Smith\, John,OU=Users,DC=corp,DC=local"));
    }

    /// <summary>
    /// The root of a naming context has no parent, and the caller walking upwards needs that
    /// stated rather than inferred from an empty string.
    /// </summary>
    [Fact]
    public void WhenTheDnHasOneComponent_ThenThereIsNoParent()
    {
        Assert.Null(DnHelper.GetParentDn("DC=local"));
    }

    [Fact]
    public void WhenTheDnIsEmpty_ThenThereIsNoParent()
    {
        Assert.Null(DnHelper.GetParentDn(""));
    }

    [Fact]
    public void WhenTheDnIsNull_ThenThereIsNoParent()
    {
        Assert.Null(DnHelper.GetParentDn(null!));
    }

    /// <summary>
    /// Walking to the root terminates. This is asserted directly because every ancestor-chain
    /// consumer in the previous implementation was a <c>for</c> loop over repeated calls, and a
    /// shortening that ever failed to shorten would hang a capture rather than fail it.
    /// </summary>
    [Fact]
    public void WhenTheParentIsTakenRepeatedly_ThenTheWalkReachesTheRootAndStops()
    {
        var visited = new List<string>();

        for (var dn = DnHelper.GetParentDn(@"CN=Smith\, John,OU=Users,DC=corp,DC=local");
             dn is not null;
             dn = DnHelper.GetParentDn(dn))
        {
            visited.Add(dn);
            Assert.True(visited.Count <= 8, "The ancestor walk did not terminate.");
        }

        Assert.Equal(
            ["OU=Users,DC=corp,DC=local", "DC=corp,DC=local", "DC=local"],
            visited);
    }

    // --- ExtractFirstRdn: the leaf name a person reads ---

    [Fact]
    public void WhenTheDnIsOrdinary_ThenTheFirstRdnValueIsReturnedWithoutItsType()
    {
        Assert.Equal(
            "John Smith",
            DnHelper.ExtractFirstRdn("CN=John Smith,OU=Users,DC=corp,DC=local"));
    }

    /// <summary>
    /// The escaped comma is part of the value, so it is unescaped on the way out: the object is
    /// named <c>Smith, John</c> and that is what a reader must see.
    /// </summary>
    [Fact]
    public void WhenTheValueContainsAnEscapedComma_ThenItIsUnescapedIntoTheName()
    {
        Assert.Equal(
            "Smith, John",
            DnHelper.ExtractFirstRdn(@"CN=Smith\, John,OU=Users,DC=corp,DC=local"));
    }

    [Fact]
    public void WhenTheValueContainsSeveralEscapedCommas_ThenAllOfThemAreUnescaped()
    {
        Assert.Equal("A, B, C", DnHelper.ExtractFirstRdn(@"CN=A\, B\, C,OU=Test"));
    }

    [Fact]
    public void WhenTheDnHasNoSeparator_ThenTheWholeRemainderIsTheValue()
    {
        Assert.Equal("SomeValue", DnHelper.ExtractFirstRdn("CN=SomeValue"));
    }

    /// <summary>
    /// Not every string reaching a display property is a DN. A value with no <c>'='</c> is passed
    /// through rather than mangled, because a grid cell showing a truncated fragment is worse than
    /// one showing the raw value.
    /// </summary>
    [Fact]
    public void WhenTheInputHasNoAttributeType_ThenItIsReturnedUnchanged()
    {
        Assert.Equal("plaintext", DnHelper.ExtractFirstRdn("plaintext"));
    }

    [Fact]
    public void WhenTheInputIsEmpty_ThenTheResultIsEmpty()
    {
        Assert.Equal("", DnHelper.ExtractFirstRdn(""));
    }

    /// <summary>
    /// The attribute type is not assumed to be <c>CN</c>. Organisational units, containers and
    /// domain components all reach the same extraction.
    /// </summary>
    [Theory]
    [InlineData("OU=Sales,DC=corp,DC=local", "Sales")]
    [InlineData("CN=Users,DC=corp,DC=local", "Users")]
    [InlineData("DC=corp,DC=local", "corp")]
    public void WhenTheAttributeTypeVaries_ThenTheValueIsStillExtracted(string dn, string expected)
    {
        Assert.Equal(expected, DnHelper.ExtractFirstRdn(dn));
    }

    // --- The two null conventions, which differ on purpose ---

    [Fact]
    public void WhenTheDnIsNull_ThenExtractFirstRdnOrNullReturnsNull()
    {
        Assert.Null(DnHelper.ExtractFirstRdnOrNull(null));
    }

    [Fact]
    public void WhenTheDnIsEmpty_ThenExtractFirstRdnOrNullReturnsNull()
    {
        Assert.Null(DnHelper.ExtractFirstRdnOrNull(""));
    }

    [Fact]
    public void WhenTheDnIsPresent_ThenExtractFirstRdnOrNullReturnsTheName()
    {
        Assert.Equal("John", DnHelper.ExtractFirstRdnOrNull("CN=John,OU=Users"));
    }

    [Fact]
    public void WhenTheDnIsNull_ThenExtractNameFromDnReturnsEmpty()
    {
        Assert.Equal("", DnHelper.ExtractNameFromDn(null));
    }

    [Fact]
    public void WhenTheDnIsEmpty_ThenExtractNameFromDnReturnsEmpty()
    {
        Assert.Equal("", DnHelper.ExtractNameFromDn(""));
    }

    [Fact]
    public void WhenTheDnIsPresent_ThenExtractNameFromDnUnescapesTheSameWay()
    {
        Assert.Equal(
            "Lewis, Jeffrey",
            DnHelper.ExtractNameFromDn(@"CN=Lewis\, Jeffrey,OU=Admins,DC=corp,DC=local"));
    }

    /// <summary>
    /// The two overloads differ only in what absence looks like, and that is the whole reason both
    /// exist. Asserted together so the pair cannot drift into disagreeing about a present value.
    /// </summary>
    [Fact]
    public void WhenTheDnIsPresent_ThenBothNullConventionsAgreeOnTheName()
    {
        const string dn = @"CN=Smith\, John,OU=Users,DC=corp,DC=local";

        Assert.Equal(DnHelper.ExtractFirstRdn(dn), DnHelper.ExtractFirstRdnOrNull(dn));
        Assert.Equal(DnHelper.ExtractFirstRdn(dn), DnHelper.ExtractNameFromDn(dn));
    }

    // --- DnToFqdn: the domain a DN belongs to ---

    [Fact]
    public void WhenTheDnIsADomainRoot_ThenTheDcComponentsJoinIntoAnFqdn()
    {
        Assert.Equal("contoso.com", DnHelper.DnToFqdn("DC=contoso,DC=com"));
    }

    [Fact]
    public void WhenTheDnIsBelowTheRoot_ThenOnlyTheDcComponentsAreUsed()
    {
        Assert.Equal("corp.contoso.com", DnHelper.DnToFqdn("OU=Users,DC=corp,DC=contoso,DC=com"));
    }

    /// <summary>
    /// Attribute types in a DN are case-insensitive, and a directory that returns <c>dc=</c> is
    /// returning the same DN as one that returns <c>DC=</c>. Untested in the previous
    /// implementation despite the comparison being written case-insensitively there.
    /// </summary>
    [Theory]
    [InlineData("dc=contoso,dc=com")]
    [InlineData("Dc=contoso,dC=com")]
    [InlineData("ou=Users,DC=contoso,dc=com")]
    public void WhenTheAttributeTypeIsWrittenInAnyCase_ThenItIsStillADomainComponent(string dn)
    {
        Assert.Equal("contoso.com", DnHelper.DnToFqdn(dn));
    }

    /// <summary>
    /// A single label is not a domain. <c>DC=gov</c> would yield <c>"gov"</c>, which a caller then
    /// hands to DNS; the previous implementation records that as a source of long timeouts against
    /// domains that do not exist. Absence is reported instead.
    /// </summary>
    [Theory]
    [InlineData("DC=gov")]
    [InlineData("OU=Users,DC=local")]
    [InlineData("OU=Test")]
    [InlineData("")]
    public void WhenFewerThanTwoDomainComponentsArePresent_ThenNoFqdnIsProduced(string dn)
    {
        Assert.Equal("", DnHelper.DnToFqdn(dn));
    }

    [Theory]
    [InlineData("OU=Offices,DC=ssa,DC=gov", "ssa.gov")]
    [InlineData("OU=LAN Configs,DC=corp,DC=ssa,DC=gov", "corp.ssa.gov")]
    public void WhenTwoOrMoreDomainComponentsArePresent_ThenTheyJoinInOrder(string dn, string expected)
    {
        Assert.Equal(expected, DnHelper.DnToFqdn(dn));
    }

    /// <summary>
    /// An escaped comma earlier in the DN must not shift the component boundaries, or the domain
    /// read off the end would belong to a different forest than the object does.
    /// </summary>
    [Fact]
    public void WhenAnEarlierComponentContainsAnEscapedComma_ThenTheDomainIsStillReadCorrectly()
    {
        Assert.Equal(
            "corp.contoso.com",
            DnHelper.DnToFqdn(@"CN=Smith\, John,OU=Users,DC=corp,DC=contoso,DC=com"));
    }

    /// <summary>
    /// Null is not empty. An empty DN is a caller with nothing to look up; a null DN is a caller
    /// that lost its input, and swallowing it would report "no domain" for a bug.
    /// </summary>
    [Fact]
    public void WhenTheDnIsNull_ThenDnToFqdnRefusesRatherThanReportingNoDomain()
    {
        Assert.Throws<ArgumentNullException>(() => DnHelper.DnToFqdn(null!));
    }

    // --- Documented limits, not requirements ---

    /// <summary>
    /// <b>This test pins a defect, not a specification.</b> See <c>P-40</c> on the punch list.
    ///
    /// <para>
    /// RFC 2253 &#167;2.4 permits a value containing a comma to be written either escaped
    /// (<c>CN=Smith\, John</c>) or quoted (<c>CN="Smith, John"</c>). Only the escaped form is
    /// understood here, so the quoted form is cut at the comma inside the quotes and both the
    /// leaf name and the parent DN come out wrong.
    /// </para>
    /// <para>
    /// It is asserted rather than left silent so the limit is visible and dated. Active Directory
    /// itself returns the escaped form, which is why this has not bitten; a DN typed by a person
    /// or read from a configuration file is where it would.
    /// </para>
    /// </summary>
    [Fact]
    public void WhenAValueIsQuotedRatherThanEscaped_ThenTheQuotingIsNotUnderstood()
    {
        const string quoted = @"CN=""Smith, John"",OU=Users,DC=corp,DC=local";

        Assert.Equal(@"""Smith", DnHelper.ExtractFirstRdn(quoted));
        Assert.Equal(@" John"",OU=Users,DC=corp,DC=local", DnHelper.GetParentDn(quoted));
    }

    /// <summary>
    /// <b>This test pins a defect, not a specification.</b> See <c>P-41</c> on the punch list.
    ///
    /// <para>
    /// An escaped backslash at the end of a value &#8212; <c>CN=corp\\</c> &#8212; ends with a
    /// literal backslash, so the comma after it <i>is</i> a separator. The scan looks only at the
    /// character before the comma, so it treats the separator as escaped and swallows the rest of
    /// the DN into the value &#8212; and then unescapes the comma it wrongly believed was escaped.
    /// </para>
    /// </summary>
    [Fact]
    public void WhenAValueEndsInAnEscapedBackslash_ThenTheFollowingSeparatorIsMissed()
    {
        Assert.Equal(@"corp\,DC=com", DnHelper.ExtractFirstRdn(@"DC=corp\\,DC=com"));
        Assert.Null(DnHelper.GetParentDn(@"DC=corp\\,DC=com"));
    }
}
