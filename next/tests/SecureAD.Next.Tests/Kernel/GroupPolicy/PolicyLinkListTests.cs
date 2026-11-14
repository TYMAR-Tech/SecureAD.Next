using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

/// <summary>
/// Reading a container's <c>gPLink</c>: which policies are linked, and in what precedence.
/// </summary>
/// <remarks>
/// The format and the precedence rule are both from
/// MS-GPOL 2.2.2 and 3.2.5.1.5: stored ordinary links are prepended to the processing list,
/// leaving the first stored link processed last.
/// </remarks>
public sealed class PolicyLinkListTests
{
    private const string PolicyOne =
        "[LDAP://cn={11110000-0000-1111-22bb-333333cccccc},cn=policies,cn=system,DC=contoso,DC=com;0]";

    private const string PolicyTwo =
        "[LDAP://cn={22220000-0000-1111-22bb-333333cccccc},cn=policies,cn=system,DC=contoso,DC=com;2]";

    [Fact]
    public void EachBracketedEntryIsALink()
    {
        Assert.Equal(2, PolicyLinkList.Of(PolicyOne + PolicyTwo).Links.Count);
    }

    [Fact]
    public void ALinkCarriesThePolicyItNames()
    {
        var links = PolicyLinkList.Of(PolicyOne).Links;

        Assert.Equal(
            "cn={11110000-0000-1111-22bb-333333cccccc},cn=policies,cn=system,DC=contoso,DC=com",
            links[0].DistinguishedName);
    }

    // ---------------------------------------------------------------------------------------
    // Order is not precedence
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void TheLinksAreNumberedInTheOrderTheyAreStored()
    {
        var links = PolicyLinkList.Of(PolicyOne + PolicyTwo).Links;

        Assert.Equal([1, 2], links.Select(l => l.Order));
    }

    /// <summary>
    /// MS-GPOL 3.2.5.1.5 prepends ordinary links to the processing list; the first stored
    /// link is processed last, so its ordinary priority is one.
    /// </summary>
    [Fact]
    public void NormalLinkPriorityFollowsStoredOrderUnderMicrosoftProtocol()
    {
        var links = PolicyLinkList.Of(PolicyOne + PolicyTwo).Links;

        Assert.Equal([1, 2], links.Select(l => l.Precedence));
    }

    [Fact]
    public void TheOnlyLinkOnAContainerHasThePrecedenceOfOne()
    {
        Assert.Equal(1, PolicyLinkList.Of(PolicyOne).Links[0].Precedence);
    }

    // ---------------------------------------------------------------------------------------
    // What this build will not guess at
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The stored reader keeps original option text; computer scope and inheritance are
    /// separate questions from parsing the container's value.
    /// </summary>
    [Fact]
    public void TheOptionsAreCarriedAsStoredAndNotWorded()
    {
        var links = PolicyLinkList.Of(PolicyOne + PolicyTwo).Links;

        Assert.Equal(["0", "2"], links.Select(l => l.Options));
    }

    // ---------------------------------------------------------------------------------------
    // A name with semicolons in it
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Microsoft's own example writes the name with semicolons between its components. Splitting on
    /// the first semicolon takes the policy to be <c>cn=policies</c> and the options to be the rest
    /// of the name - a plausible-looking wrong answer rather than a failure.
    /// </summary>
    [Fact]
    public void ANameHoldingSemicolonsIsSplitOnTheLastOne()
    {
        var links = PolicyLinkList.Of(
            "[LDAP://cn={11110000-0000-1111-22bb-333333cccccc},cn=policies;cn=system;DC=contoso;DC=com;0]").Links;

        Assert.Equal(
            "cn={11110000-0000-1111-22bb-333333cccccc},cn=policies;cn=system;DC=contoso;DC=com",
            links[0].DistinguishedName);
        Assert.Equal("0", links[0].Options);
    }

    // ---------------------------------------------------------------------------------------
    // Nothing, and nonsense
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A container with no policies linked is an ordinary container, and reads as no links and no
    /// errors.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void AContainerWithNoLinksReadsAsNoneAndNoFault(string? stored)
    {
        var list = PolicyLinkList.Of(stored);

        Assert.Empty(list.Links);
        Assert.Empty(list.Errors);
    }

    /// <summary>
    /// A malformed value is not a container with no policies, and the two must not arrive as the
    /// same empty list.
    /// </summary>
    [Fact]
    public void AValueThatIsNotBracketedIsAnError()
    {
        var list = PolicyLinkList.Of("LDAP://cn=policy,DC=contoso,DC=com;0");

        Assert.Empty(list.Links);
        Assert.Single(list.Errors);
    }

    [Fact]
    public void AnEntryWithNoOptionsIsAnError()
    {
        var list = PolicyLinkList.Of("[LDAP://cn=policy,DC=contoso,DC=com]");

        Assert.Empty(list.Links);
        Assert.Single(list.Errors);
    }

    /// <summary>
    /// One malformed entry does not cost the reader the links that were readable.
    /// </summary>
    [Fact]
    public void AGoodLinkBesideABadOneIsStillRead()
    {
        var list = PolicyLinkList.Of(PolicyOne + "[LDAP://;0]");

        Assert.Single(list.Links);
        Assert.Single(list.Errors);
    }

    [Theory]
    [InlineData("prefix", 0)]
    [InlineData("between", 1)]
    [InlineData("suffix", 1)]
    public void UnconsumedLinkContentCannotDisappear(string location, int retained)
    {
        var stored = location switch
        {
            "prefix" => "unread" + PolicyOne,
            "between" => PolicyOne + "unread" + PolicyTwo,
            "suffix" => PolicyOne + "unread",
            _ => throw new ArgumentOutOfRangeException(nameof(location)),
        };
        var reading = PolicyLinkList.Of(stored);
        Assert.Equal(retained, reading.Links.Count);
        Assert.Single(reading.Errors);
    }

    [Fact]
    public void AReadableLinkKeepsItsOriginalSlotAfterAnUnreadableEntry()
    {
        var reading = PolicyLinkList.Of("[LDAP://;0]" + PolicyOne);
        var link = Assert.Single(reading.Links);
        Assert.Single(reading.Errors);
        Assert.Equal(2, link.Order);
        Assert.Equal(2, link.Precedence);
    }
}
