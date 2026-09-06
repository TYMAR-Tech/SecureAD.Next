using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class PrincipalClassificationRegistryTests
{
    [Theory]
    [InlineData(548)]
    [InlineData(549)]
    [InlineData(550)]
    [InlineData(551)]
    [InlineData(552)]
    public void OperatorsRemainSensitiveWithoutBecomingAcceptedControllersOrOwners(int rid)
    {
        var answer = PrincipalClassificationRegistry.For("S-1-5-32-" + rid);
        Assert.True(answer.IsSensitiveSidHistory);
        Assert.Equal(PrincipalAuthorityScope.None, answer.ControlPlaneScope);
        Assert.Equal(PrincipalAuthorityScope.None, answer.OwnerScope);
        Assert.Equal(rid is 549 or 551 ? true : (bool?)null, answer.IsTier0Asset);
        Assert.Equal(PrincipalClassificationRegistry.Version, answer.CatalogueVersion);
    }

    [Fact]
    public void PlatformOwnerAndExpectedControllerAreDifferentQuestions()
    {
        var creator = PrincipalClassificationRegistry.For("S-1-3-0");
        Assert.Equal(PrincipalAuthorityScope.Descriptor, creator.OwnerScope);
        Assert.Equal(PrincipalAuthorityScope.None, creator.ControlPlaneScope);
        var system = PrincipalClassificationRegistry.For("S-1-5-18");
        Assert.Equal(PrincipalAuthorityScope.Descriptor, system.ControlPlaneScope);
        Assert.Equal("ApplicableSystemAceOnly", system.CapabilityScope);
        var edc = PrincipalClassificationRegistry.For("S-1-5-9");
        Assert.Equal(PrincipalAuthorityScope.RequiredDomainControllerOperations, edc.ControlPlaneScope);
    }

    [Fact]
    public void SchemaAuthorityIsNotUnrestrictedAndDcGroupsAreNotDcAssets()
    {
        var schema = PrincipalClassificationRegistry.For("S-1-5-21-1-2-3-518");
        Assert.Equal(PrincipalAuthorityScope.Schema, schema.OwnerScope);
        Assert.Equal(PrincipalAuthorityScope.Schema, schema.ControlPlaneScope);
        Assert.False(PrincipalClassificationRegistry.AcceptedOwnerRootRids.Contains(518));
        var controllers = PrincipalClassificationRegistry.For("S-1-5-21-1-2-3-516");
        Assert.Equal(false, controllers.IsTier0Asset);
        Assert.Equal(PrincipalAuthorityScope.None, controllers.ControlPlaneScope);
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-513", true)]
    [InlineData("S-1-1-0", true)]
    [InlineData("S-1-5-21-513-513-513", false)]
    [InlineData("S-1-5-32-513", false)]
    [InlineData("S-1-5-21-1-2-3-544", false)]
    public void IdentifierAuthorityAndShapeMatter(string sid, bool broad)
    {
        var answer = PrincipalClassificationRegistry.For(sid);
        Assert.Equal(broad, answer.IsBroad);
        Assert.Equal(PrincipalAuthorityScope.None, answer.ControlPlaneScope);
    }
}
