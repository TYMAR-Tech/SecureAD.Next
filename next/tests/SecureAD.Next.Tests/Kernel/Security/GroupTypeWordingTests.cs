using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Kernel.Security;

/// <summary>
/// Reading a group's <c>groupType</c>: its scope, and whether it can hold permissions at all.
/// </summary>
/// <remarks>
/// Asserted against <c>learn.microsoft.com/windows/win32/adschema/a-grouptype</c>. The values are
/// the ones a directory really holds, which is why most of them are negative: the security bit is
/// <c>0x80000000</c> in a signed 32-bit field.
/// </remarks>
public sealed class GroupTypeWordingTests
{
    // ---------------------------------------------------------------------------------------
    // Scope
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("2", "Global")]
    [InlineData("4", "Domain local")]
    [InlineData("8", "Universal")]
    public void EachScopeBitIsWordedAsLearnNamesIt(string stored, string scope)
    {
        Assert.Equal(scope, GroupTypeWording.Of(stored)!.Scope);
    }

    /// <summary>
    /// The value on an ordinary global security group, and the one this reader most has to get
    /// right: stored signed, it is negative.
    /// </summary>
    [Fact]
    public void AGlobalSecurityGroupIsReadFromItsNegativeStoredValue()
    {
        var worded = GroupTypeWording.Of("-2147483646")!;

        Assert.Equal("Global", worded.Scope);
        Assert.True(worded.IsSecurityGroup);
    }

    [Fact]
    public void ADomainLocalSecurityGroupIsRead()
    {
        var worded = GroupTypeWording.Of("-2147483644")!;

        Assert.Equal("Domain local", worded.Scope);
        Assert.True(worded.IsSecurityGroup);
    }

    [Fact]
    public void AUniversalSecurityGroupIsRead()
    {
        var worded = GroupTypeWording.Of("-2147483640")!;

        Assert.Equal("Universal", worded.Scope);
        Assert.True(worded.IsSecurityGroup);
    }

    // ---------------------------------------------------------------------------------------
    // Security or distribution
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A distribution group appears in no access control list. Reading one as a security group
    /// would put a principal in an audit that holds nothing.
    /// </summary>
    [Fact]
    public void ADistributionGroupIsNotASecurityGroup()
    {
        Assert.False(GroupTypeWording.Of("8")!.IsSecurityGroup);
    }

    /// <summary>
    /// Said out loud rather than left to be inferred from the absence of the word security.
    /// </summary>
    [Fact]
    public void ADistributionGroupSaysSoInWords()
    {
        Assert.Equal("Universal distribution group", GroupTypeWording.Of("8")!.Worded);
    }

    [Fact]
    public void ASecurityGroupSaysSoInWords()
    {
        Assert.Equal("Global security group", GroupTypeWording.Of("-2147483646")!.Worded);
    }

    // ---------------------------------------------------------------------------------------
    // The system bit
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Built-in groups carry bit 1. Worth saying, because an operator asking why a group cannot be
    /// deleted is asking about this bit.
    /// </summary>
    [Fact]
    public void AGroupTheDirectoryCreatedSaysSo()
    {
        var worded = GroupTypeWording.Of("-2147483643")!;

        Assert.True(worded.IsSystemGroup);
        Assert.Contains("created by the directory", worded.Worded, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOrdinaryGroupIsNotASystemGroup()
    {
        Assert.False(GroupTypeWording.Of("-2147483646")!.IsSystemGroup);
    }

    // ---------------------------------------------------------------------------------------
    // What this build will not guess at
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A group claiming two scopes is not something Active Directory produces. Picking the first
    /// would hide that the object is malformed.
    /// </summary>
    [Fact]
    public void AGroupClaimingTwoScopesIsGivenNone()
    {
        Assert.Null(GroupTypeWording.Of("6")!.Scope);
    }

    [Fact]
    public void AGroupWithNoScopeBitIsGivenNone()
    {
        Assert.Null(GroupTypeWording.Of("0")!.Scope);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Global")]
    [InlineData(null)]
    public void TextThatIsNotAValueIsNotWorded(string? stored)
    {
        Assert.Null(GroupTypeWording.Of(stored));
    }

    [Fact]
    public void TheValueIsCarriedAsTheDirectoryHoldsIt()
    {
        Assert.Equal(-2147483646, GroupTypeWording.Of("-2147483646")!.Value);
    }
}
