using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.GroupPolicy;

/// <summary>
/// Reading a container's <c>gPLink</c>: which policies are linked, and in what precedence.
/// </summary>
/// <remarks>
/// The format and the precedence rule are both from
/// <c>learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-scope</c>,
/// whose worked example is three links concatenated into one string.
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
    /// Microsoft: the links are read left to right and applied in reverse, so the last one in the
    /// string is applied first and wins. Listing them in stored order and letting a reader assume
    /// the first one wins has the answer exactly backwards.
    /// </summary>
    [Fact]
    public void ThePrecedenceIsTheReverseOfTheStoredOrder()
    {
        var links = PolicyLinkList.Of(PolicyOne + PolicyTwo).Links;

        Assert.Equal([2, 1], links.Select(l => l.Precedence));
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
    /// The options decide whether the link is enabled and whether it is enforced, and both matter -
    /// but Learn's page for the attribute does not give the values, so the number is carried
    /// through unworded rather than being invented.
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
}
