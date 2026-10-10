using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

public sealed class CaptureObjectScopeTests
{
    [Fact]
    public void TheDefaultExcludesOnlyDnsAndTheNamedEnatelMetadataClasses()
    {
        Assert.Equal(
            ["dnsNode", "dnsZone", "enatelSSOAccountParameter", "enatelUserManagedAuth", "enatelSSOStorage", "enatelSSOAccount"],
            CaptureObjectScope.Default.ExcludedClasses);
    }

    [Fact]
    public void IncludingEnatelDoesNotIncludeDns()
    {
        Assert.Equal(["dnsNode", "dnsZone"], CaptureObjectScope.WithEnatelSso.ExcludedClasses);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheScopeRetainsTheExplicitInclusionChoice(bool includeEnatelSso)
    {
        Assert.Equal(includeEnatelSso, CaptureObjectScope.For(includeEnatelSso).IncludeEnatelSso);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnExclusionCannotBeChangedThroughTheReturnedCollection(bool includeEnatelSso)
    {
        var excluded = (IList<string>)CaptureObjectScope.For(includeEnatelSso).ExcludedClasses;

        Assert.Throws<NotSupportedException>(() => excluded[0] = "user");
    }
}
