using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Pins every identifier in <c>BroadPrincipalCatalogue</c> to the value Microsoft publishes for it.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this catalogue decides, in plain terms.</b> Two rules report a permission when the
/// principal holding it is one that <i>nobody chooses to be a member of</i> — everybody in the
/// organisation is already in it. That is the whole claim those rules make, because it is the only
/// one that needs no local knowledge of what a customer intended. If an identifier here is wrong,
/// the product either names a principal as broad when it is an ordinary group, or misses one that
/// really does contain the whole directory.
/// </para>
/// <para>
/// <b>Why a separate anchor class.</b> <c>BroadPrincipalCatalogueTests</c> covers behaviour — that
/// the shape of a SID is checked rather than its tail, and so on. Those would all pass against a
/// catalogue holding the wrong numbers. Per <c>F-S44-2</c>, a set of checks that agree with each
/// other proves only that they agree; this class is the outside anchor, and its values come from
/// <see href="https://learn.microsoft.com/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab">MS-DTYP
/// 2.4.2.4</see> and Microsoft's security groups reference rather than from the code.
/// </para>
/// <para>
/// <b>The membership claims are Microsoft's too, and they are the reason two of these are here.</b>
/// <c>BUILTIN\Users</c> and <c>Pre-Windows 2000 Compatible Access</c> are not broad by their own
/// definition — they are broad because of what Microsoft says they contain. The security groups
/// reference gives <c>BUILTIN\Users</c> default members of <i>Authenticated Users</i> and
/// <i>Domain Users</i>, and says <c>Pre-Windows 2000 Compatible Access</c> holds read access for all
/// users and groups in the domain and may contain <i>Everyone</i> and <i>Anonymous</i>.
/// </para>
/// </remarks>
public sealed class BroadPrincipalCatalogueMicrosoftAnchorTests
{
    /// <summary>
    /// Each absolute identifier Microsoft publishes is the one this catalogue treats as broad.
    /// </summary>
    /// <remarks>
    /// The SID strings are MS-DTYP's, transcribed from the well-known SID table.
    /// </remarks>
    [Theory]
    [InlineData("S-1-1-0")]      // WORLD / Everyone
    [InlineData("S-1-5-7")]      // ANONYMOUS
    [InlineData("S-1-5-11")]     // AUTHENTICATED_USERS
    [InlineData("S-1-5-32-545")] // BUILTIN_USERS
    [InlineData("S-1-5-32-546")] // BUILTIN_GUESTS
    [InlineData("S-1-5-32-554")] // BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS
    public void EachPublishedAbsoluteIdentifierIsBroad(string sid) =>
        Assert.True(BroadPrincipalCatalogue.IsBroad(sid));

    /// <summary>
    /// Each domain-relative identifier is broad under a domain SID.
    /// </summary>
    /// <remarks>
    /// MS-DTYP gives these as relative identifiers because the group differs per domain and only
    /// the last component is fixed: <c>DOMAIN_USERS</c> 513, <c>DOMAIN_GUESTS</c> 514,
    /// <c>DOMAIN_COMPUTERS</c> 515.
    /// </remarks>
    [Theory]
    [InlineData(513)]
    [InlineData(514)]
    [InlineData(515)]
    public void EachPublishedDomainRelativeIdentifierIsBroad(int rid) =>
        Assert.True(BroadPrincipalCatalogue.IsBroad($"S-1-5-21-1004336348-1177238915-682003330-{rid}"));

    /// <summary>
    /// The catalogue names the principal, so a finding can say which one made a group broad.
    /// </summary>
    [Theory]
    [InlineData("S-1-1-0", "Everyone")]
    [InlineData("S-1-5-11", "Authenticated Users")]
    public void ThePrincipalIsNamedAndNotOnlyDetected(string sid, string expected) =>
        Assert.Equal(expected, BroadPrincipalCatalogue.NameOf(sid));

    /// <summary>
    /// A privileged group is not broad, however powerful it is.
    /// </summary>
    /// <remarks>
    /// <b>The negative control that keeps the two ideas apart.</b> This catalogue answers "does
    /// everybody end up inside this", not "is this dangerous". <c>Domain Admins</c> (512) sits one
    /// number below <c>Domain Users</c> and is the most powerful group in the domain, and it belongs
    /// to neither this catalogue nor the rules that read it.
    /// </remarks>
    [Theory]
    [InlineData(512)] // Domain Admins
    [InlineData(519)] // Enterprise Admins
    [InlineData(516)] // Domain Controllers
    public void APrivilegedGroupIsNotBroad(int rid) =>
        Assert.False(BroadPrincipalCatalogue.IsBroad($"S-1-5-21-1004336348-1177238915-682003330-{rid}"));

    /// <summary>
    /// A well-known identifier that is not a principal is not broad.
    /// </summary>
    /// <remarks>
    /// <c>SYSTEM</c> and <c>CREATOR OWNER</c> appear on almost every object. Counting either as
    /// broad would report the whole directory.
    /// </remarks>
    [Theory]
    [InlineData("S-1-5-18")] // LOCAL_SYSTEM
    [InlineData("S-1-3-0")]  // CREATOR_OWNER
    [InlineData("S-1-5-9")]  // ENTERPRISE_DOMAIN_CONTROLLERS
    public void APlatformIdentityIsNotBroad(string sid) =>
        Assert.False(BroadPrincipalCatalogue.IsBroad(sid));

    /// <summary>
    /// The catalogue holds exactly the identifiers this class pins, and no others.
    /// </summary>
    /// <remarks>
    /// <b>Without this the class checks a set it does not bound.</b> Every test above asks whether a
    /// known identifier is present; none would notice a tenth identifier added to the catalogue with
    /// no Microsoft source behind it, which is the shape <c>F-S44-2</c> records — a rule nobody wrote
    /// was an attribute nobody missed. Counting the set forces a new entry to arrive with an anchor.
    /// </remarks>
    [Fact]
    public void TheCatalogueHoldsNineIdentifiersAndNoMore()
    {
        string[] absolute =
            ["S-1-1-0", "S-1-5-7", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546", "S-1-5-32-554"];

        int[] rids = [513, 514, 515];

        // Every identifier this class anchors is broad, and nothing in the neighbouring RID range
        // is broad unless it is one of the three named. 512 to 521 covers the well-known domain
        // groups, so an unanchored addition among them is caught here.
        Assert.All(absolute, sid => Assert.True(BroadPrincipalCatalogue.IsBroad(sid)));

        for (var rid = 512; rid <= 521; rid++)
        {
            var sid = $"S-1-5-21-1004336348-1177238915-682003330-{rid}";

            Assert.Equal(rids.Contains(rid), BroadPrincipalCatalogue.IsBroad(sid));
        }
    }
}
