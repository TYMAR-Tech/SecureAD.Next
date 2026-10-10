using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// The paging behaviour of <see cref="CaptureSearchRequestFactory"/>.
///
/// <para>
/// A paged search is one request per page, each carrying the bookmark the controller returned with
/// the page before. These tests exist because the bookmark is the single point at which an
/// incomplete capture and a complete one become indistinguishable: a loop ends when the cookie
/// comes back empty, and a client that lost its cookie sees an empty one immediately. Everything
/// about the request that guards against that is asserted in
/// <c>CaptureUnitDocumentationTests</c>; this asserts that a second page can be asked for at all.
/// </para>
/// </summary>
public sealed class CaptureSearchRequestFactoryTests
{
    private static CaptureUnit Unit() =>
        CaptureUnit.Create("DC=example,DC=com", NamingContextKind.Domain, "dc01.example.com").Value;

    private static string[] Controls() => [CaptureSearchRequestFactory.DomainScopeControlOid];

    private static PageResultRequestControl PageControl(SearchRequest request) =>
        request.Controls.OfType<PageResultRequestControl>().Single();

    [Fact]
    public void TheDefaultRequestExcludesEnatelMetadataClassesAndDns()
    {
        var request = CaptureSearchRequestFactory.ForUnit(Unit(), Controls());

        Assert.Equal("(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone))"
            + "(!(objectClass=enatelSSOAccountParameter))(!(objectClass=enatelUserManagedAuth))"
            + "(!(objectClass=enatelSSOStorage))(!(objectClass=enatelSSOAccount)))", request.Filter);
    }

    [Theory]
    [InlineData(false, "(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone))(!(objectClass=enatelSSOAccountParameter))(!(objectClass=enatelUserManagedAuth))(!(objectClass=enatelSSOStorage))(!(objectClass=enatelSSOAccount)))")]
    [InlineData(true, "(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone)))")]
    public void TheFirstPageUsesTheExplicitClassScope(bool includeEnatelSso, string expected)
    {
        var request = CaptureSearchRequestFactory.ForUnit(Unit(), Controls(), CaptureObjectScope.For(includeEnatelSso));

        Assert.Equal(expected, request.Filter);
    }

    [Theory]
    [InlineData(false, "(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone))(!(objectClass=enatelSSOAccountParameter))(!(objectClass=enatelUserManagedAuth))(!(objectClass=enatelSSOStorage))(!(objectClass=enatelSSOAccount)))")]
    [InlineData(true, "(&(objectClass=*)(!(objectClass=dnsNode))(!(objectClass=dnsZone)))")]
    public void ALaterPageUsesTheExplicitClassScope(bool includeEnatelSso, string expected)
    {
        var request = CaptureSearchRequestFactory.ForNextPage(Unit(), Controls(), [1], CaptureObjectScope.For(includeEnatelSso));

        Assert.Equal(expected, request.Filter);
    }

    [Fact]
    public void TheFirstPageIsRequestedWithNoBookmark()
    {
        var request = CaptureSearchRequestFactory.ForUnit(Unit(), Controls());

        Assert.Empty(PageControl(request).Cookie);
    }

    [Fact]
    public void ANextPageCarriesTheBookmarkTheControllerReturned()
    {
        byte[] cookie = [4, 8, 15, 16, 23, 42];

        var request = CaptureSearchRequestFactory.ForNextPage(Unit(), Controls(), cookie);

        Assert.Equal(cookie, PageControl(request).Cookie);
    }

    /// <summary>
    /// Everything else about a next page is identical to the first. A page that quietly changed
    /// the filter, the attributes or the scale would produce a partition read under two different
    /// definitions, and only the parts read under the second would be complete.
    /// </summary>
    [Fact]
    public void ANextPageIsTheSameSearchAsTheFirst()
    {
        var first = CaptureSearchRequestFactory.ForUnit(Unit(), Controls());
        var next = CaptureSearchRequestFactory.ForNextPage(Unit(), Controls(), [1]);

        Assert.Equal(first.DistinguishedName, next.DistinguishedName);
        Assert.Equal(first.Filter as string, next.Filter as string);
        Assert.Equal(first.Scope, next.Scope);
        Assert.Equal(first.SizeLimit, next.SizeLimit);
        Assert.Equal(first.TimeLimit, next.TimeLimit);
        Assert.Equal(first.Attributes.Cast<string>(), next.Attributes.Cast<string>());
        Assert.Equal(PageControl(first).PageSize, PageControl(next).PageSize);
        Assert.Equal(
            first.Controls.OfType<DomainScopeControl>().Any(),
            next.Controls.OfType<DomainScopeControl>().Any());
    }

    /// <summary>
    /// An empty cookie means the controller has already sent its last page. Asking for another
    /// restarts the search from the beginning, so the partition would be read twice and every
    /// object in it written twice. Refused rather than tolerated, because the symptom - a capture
    /// that never finishes and a bundle with duplicates in it - looks nothing like the cause.
    /// </summary>
    [Fact]
    public void AskingForANextPageWithNoBookmarkIsRefused()
    {
        Assert.Throws<ArgumentException>(
            () => CaptureSearchRequestFactory.ForNextPage(Unit(), Controls(), []));
    }

    /// <summary>
    /// The RootDSE read asks a controller about itself: an empty base, base scope, and the two
    /// attributes a capture cannot proceed without.
    /// </summary>
    [Fact]
    public void TheRootDseRequestReadsTheEntryEveryServerPublishes()
    {
        var request = CaptureSearchRequestFactory.ForRootDse();

        Assert.Equal(string.Empty, request.DistinguishedName);
        Assert.Equal(SearchScope.Base, request.Scope);
        Assert.Equal(
            [
                "supportedControl",
                "namingContexts",
                "configurationNamingContext",
                "schemaNamingContext",
                "rootDomainNamingContext",
            ],
            request.Attributes.Cast<string>());
    }

    /// <summary>
    /// It carries no paging control, because there is one entry, and no domain-scope control,
    /// because the RootDSE is not in a partition and there is nothing below it to suppress
    /// referrals for.
    /// </summary>
    [Fact]
    public void TheRootDseRequestIsNeitherPagedNorDomainScoped()
    {
        var request = CaptureSearchRequestFactory.ForRootDse();

        Assert.Empty(request.Controls.OfType<PageResultRequestControl>());
        Assert.Empty(request.Controls.OfType<DomainScopeControl>());
    }
}
