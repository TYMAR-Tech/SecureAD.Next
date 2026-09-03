using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

/// <summary>
/// Which principals count as too broad to hold a sensitive right.
/// </summary>
/// <remarks>
/// <para>
/// <b>The values are anchored to Microsoft's security groups reference, not to our own reading of
/// what looks broad.</b> That page gives each group's well-known SID, and the two that matter most
/// here are the ones whose names do not sound broad at all: the built-in <c>Users</c> group, whose
/// default members are <i>Authenticated Users</i> and <i>Domain Users</i>, and
/// <c>Pre-Windows 2000 Compatible Access</c>, which Microsoft says has read access for all users
/// and groups in the domain and may contain <i>Everyone</i> and <i>Anonymous</i>.
/// </para>
/// <para>
/// <b>The negative controls carry as much weight as the positives.</b> A catalogue that answered
/// true too often would report every delegation in an estate, and the rule resting on it would be
/// switched off within a day.
/// </para>
/// </remarks>
public sealed class BroadPrincipalCatalogueTests
{
    /// <summary>Everyone, by its absolute SID.</summary>
    [Fact]
    public void Everyone_IsBroad() => Assert.True(BroadPrincipalCatalogue.IsBroad("S-1-1-0"));

    /// <summary>Authenticated Users, which includes every computer account as well as every person.</summary>
    [Fact]
    public void AuthenticatedUsers_IsBroad() => Assert.True(BroadPrincipalCatalogue.IsBroad("S-1-5-11"));

    /// <summary>Anonymous, which is reachable without authenticating at all.</summary>
    [Fact]
    public void Anonymous_IsBroad() => Assert.True(BroadPrincipalCatalogue.IsBroad("S-1-5-7"));

    /// <summary>
    /// The built-in Users group, whose name gives no hint of what is in it.
    /// </summary>
    /// <remarks>
    /// Microsoft lists its default members as Authenticated Users and Domain Users. A delegation to
    /// it is a delegation to everyone who can authenticate, and nothing about the name says so.
    /// </remarks>
    [Fact]
    public void BuiltinUsers_IsBroad() => Assert.True(BroadPrincipalCatalogue.IsBroad("S-1-5-32-545"));

    /// <summary>
    /// Pre-Windows 2000 Compatible Access, which Microsoft says holds read access for all users and
    /// groups in the domain.
    /// </summary>
    [Fact]
    public void PreWindows2000CompatibleAccess_IsBroad() =>
        Assert.True(BroadPrincipalCatalogue.IsBroad("S-1-5-32-554"));

    /// <summary>Domain Users, reached by its relative identifier under any domain.</summary>
    [Theory]
    [InlineData("S-1-5-21-1004336348-1177238915-682003330-513")]
    [InlineData("S-1-5-21-9-9-9-513")]
    public void DomainUsers_IsBroadUnderAnyDomain(string sid) =>
        Assert.True(BroadPrincipalCatalogue.IsBroad(sid));

    /// <summary>Domain Computers, for the same reason, and it is easy to forget.</summary>
    [Fact]
    public void DomainComputers_IsBroad() =>
        Assert.True(BroadPrincipalCatalogue.IsBroad("S-1-5-21-9-9-9-515"));

    /// <summary>
    /// Domain Admins is not broad, and reporting it would make the rule useless.
    /// </summary>
    /// <remarks>
    /// <b>This is the control that matters most.</b> Microsoft's own default for the LAPS decryptor
    /// is Domain Admins, so a catalogue that called it broad would report the correct configuration
    /// on every machine in every estate.
    /// </remarks>
    [Fact]
    public void DomainAdmins_IsNotBroad() =>
        Assert.False(BroadPrincipalCatalogue.IsBroad("S-1-5-21-9-9-9-512"));

    /// <summary>An ordinary delegated group is not broad, however many members it has.</summary>
    /// <remarks>
    /// The owner's decision of 2026-09-03, recorded as <c>P-123</c>: the product cannot know which
    /// principals an organisation intended, so it reports only what is broad everywhere.
    /// </remarks>
    [Fact]
    public void AnOrdinaryGroup_IsNotBroad() =>
        Assert.False(BroadPrincipalCatalogue.IsBroad("S-1-5-21-9-9-9-1174"));

    /// <summary>
    /// A domain whose own identifier ends in a broad relative identifier is not itself broad.
    /// </summary>
    /// <remarks>
    /// <b>This is why the relative identifier is read off the end rather than matched as text.</b>
    /// A substring test for "513" would match this SID, and the finding would name a whole domain
    /// as a broad principal.
    /// </remarks>
    [Fact]
    public void ADomainSidEndingInABroadRid_IsNotItselfBroad() =>
        Assert.False(BroadPrincipalCatalogue.IsBroad("S-1-5-21-513-513-513"));

    /// <summary>Nothing is not broad, and asking does not throw.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-sid")]
    public void AnAbsentOrUnreadableSid_IsNotBroad(string? sid) =>
        Assert.False(BroadPrincipalCatalogue.IsBroad(sid));

    /// <summary>
    /// A broad principal can name itself, so a finding need not make the operator look it up.
    /// </summary>
    [Fact]
    public void ABroadPrincipalCanNameItself()
    {
        Assert.Equal("Everyone", BroadPrincipalCatalogue.NameOf("S-1-1-0"));
        Assert.Equal("Domain Users", BroadPrincipalCatalogue.NameOf("S-1-5-21-9-9-9-513"));
    }

    /// <summary>Something that is not broad has no broad name to give.</summary>
    [Fact]
    public void SomethingThatIsNotBroadHasNoName() =>
        Assert.Null(BroadPrincipalCatalogue.NameOf("S-1-5-21-9-9-9-512"));
}
