using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class AdminSdHolderCatalogueSemanticTests
{
    [Theory]
    [InlineData(498, 2, 3)]
    [InlineData(516, 0, 3)]
    [InlineData(521, 0, 3)]
    [InlineData(526, 0, 3)]
    [InlineData(527, 0, 3)]
    [InlineData(520, 1, 1)]
    [InlineData(500, 0, 4)]
    [InlineData(502, 0, 4)]
    public void PrincipalProtectionAndMemberPropagationAreIndependentClaims(
        int rid,
        int expectedPrincipal,
        int expectedPropagation)
    {
        var entry = Entry(rid);

        Assert.Equal((CatalogueClaimStatus)expectedPrincipal, entry.PrincipalProtection.Status);
        Assert.Equal((CatalogueClaimStatus)expectedPropagation, entry.MemberPropagation.Status);
    }

    [Fact]
    public void EveryClaimRecordsProvenanceAndAStableSource()
    {
        foreach (var entry in ProtectedGroupCatalogue.Default.Entries)
        {
            Assert.NotEqual(default, entry.PrincipalProtection.Provenance);
            Assert.False(string.IsNullOrWhiteSpace(entry.PrincipalProtection.SourceId));
            Assert.NotEqual(default, entry.MemberPropagation.Provenance);
            Assert.False(string.IsNullOrWhiteSpace(entry.MemberPropagation.SourceId));
        }
    }

    [Theory]
    [InlineData(500, 0)]
    [InlineData(512, 0)]
    [InlineData(518, 1)]
    [InlineData(519, 1)]
    [InlineData(527, 1)]
    [InlineData(544, 2)]
    [InlineData(548, 2)]
    public void EveryEntryStatesTheScopeNeededToResolveItsSid(
        int rid,
        int expectedScope)
    {
        Assert.Equal((CataloguePrincipalScope)expectedScope, Entry(rid).Scope);
    }

    [Fact]
    public void CatalogueVersionTwoMeansDecision0089Semantics()
    {
        Assert.Equal(2, ProtectedGroupCatalogue.Default.Version);
    }

    [Fact]
    public void ACompleteMaskDisablesOnlyEffectiveMemberPropagation()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(WithMask('1'));
        var accountOperators = catalogue.Entries.Single(e => e.Rid == 548);

        Assert.Equal(CatalogueClaimStatus.Established, accountOperators.PrincipalProtection.Status);
        Assert.Equal(CatalogueClaimStatus.Established, accountOperators.MemberPropagation.Status);
        Assert.Equal(
            CatalogueClaimStatus.EstablishedNo,
            catalogue.EffectiveMemberPropagation(accountOperators).Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("000000000100000z")]
    public void AnUnreadOrMalformedMaskMakesAnExcludableRootUnverified(string? dsHeuristics)
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(dsHeuristics);
        var accountOperators = catalogue.Entries.Single(e => e.Rid == 548);

        Assert.Equal(
            CatalogueClaimStatus.Unverified,
            catalogue.EffectiveMemberPropagation(accountOperators).Status);
        Assert.Equal(CatalogueClaimStatus.Established, accountOperators.PrincipalProtection.Status);
    }

    [Fact]
    public void ACompleteMaskCannotChangeANonExcludableRoot()
    {
        var catalogue = ProtectedGroupCatalogue.NarrowedBy(WithMask('f'));
        var administrators = catalogue.Entries.Single(e => e.Rid == 544);

        Assert.Equal(
            CatalogueClaimStatus.Established,
            catalogue.EffectiveMemberPropagation(administrators).Status);
    }

    [Fact]
    public void SwappingTheTwoClaimsWouldFailForAnUnverifiedPropagationEntry()
    {
        var domainControllers = Entry(516);

        Assert.NotEqual(domainControllers.PrincipalProtection, domainControllers.MemberPropagation);
        Assert.Equal(CatalogueClaimStatus.Established, domainControllers.PrincipalProtection.Status);
        Assert.Equal(CatalogueClaimStatus.Unverified, domainControllers.MemberPropagation.Status);
    }

    private static AdminSdHolderCatalogueEntry Entry(int rid) =>
        ProtectedGroupCatalogue.Default.Entries.Single(e => e.Rid == rid);

    private static string WithMask(char mask) => "000000000" + "1" + "00000" + mask;
}
