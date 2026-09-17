using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class Tier0ClassifierTests
{
    [Fact]
    public void DomainAdminsIsEstablishedFromItsCapturedIdentity()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("RenamedGroup", "S-1-5-21-1-2-3-512");
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null);
        Assert.Equal(Tier0State.Established, result.State);
    }

    // The expected population is anchored to decision 0006, not enumerated from the implementation.
    [Theory]
    [InlineData("S-1-5-21-1-2-3-498", "group")]
    [InlineData("S-1-5-21-1-2-3-500", "user")]
    [InlineData("S-1-5-21-1-2-3-502", "user")]
    [InlineData("S-1-5-21-1-2-3-512", "group")]
    [InlineData("S-1-5-21-1-2-3-516", "group")]
    [InlineData("S-1-5-21-1-2-3-517", "group")]
    [InlineData("S-1-5-21-1-2-3-518", "group")]
    [InlineData("S-1-5-21-1-2-3-519", "group")]
    [InlineData("S-1-5-21-1-2-3-520", "group")]
    [InlineData("S-1-5-21-1-2-3-521", "group")]
    [InlineData("S-1-5-21-1-2-3-526", "group")]
    [InlineData("S-1-5-21-1-2-3-527", "group")]
    [InlineData("S-1-5-32-544", "group")]
    [InlineData("S-1-5-32-548", "group")]
    [InlineData("S-1-5-32-549", "group")]
    [InlineData("S-1-5-32-550", "group")]
    [InlineData("S-1-5-32-551", "group")]
    public void EveryPolicyIdentityHasACapturedCoreWitness(string sid, string objectClass)
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("LocalName", sid, objectClass);
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null);
        Assert.Equal(Tier0Basis.Core, Assert.Single(result.Supports).Basis);
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-513")]
    [InlineData("S-1-5-21-1-2-3-544")]
    [InlineData("S-1-5-32-512")]
    [InlineData("S-1-5-32-552")]
    public void NamesAndLookalikeIdentifiersCannotCreateCoreClassification(string sid)
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("Domain Admins", sid);
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null);
        Assert.Equal(Tier0State.Unknown, result.State);
    }

    [Theory]
    [InlineData(498)] [InlineData(518)] [InlineData(519)] [InlineData(527)]
    public void ForestRootIdentitiesCannotBeEstablishedAgainstAnotherRoot(int rid)
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("RootGroup", "S-1-5-21-1-2-3-" + rid);
        var binding = evidence.Binding with { ForestRootNamingContext = "DC=another,DC=com" };
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(binding, evidence.Target(subject), evidence.Input(subject), routes: null).State);
    }

    [Fact]
    public void DomainSidMismatchCannotEstablishACoreIdentity()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("WrongDomain", "S-1-5-21-9-8-7-512");
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null).State);
    }

    [Fact]
    public void BuiltinInConfigurationDoesNotBorrowTheCapturingDomainsAuthority()
    {
        var evidence = new Tier0TestEvidence();
        var nc = "CN=Configuration," + evidence.Domain.DistinguishedName;
        var subject = evidence.Principal("Administrators", "S-1-5-32-544") with { DistinguishedName = "CN=Administrators,CN=Builtin," + nc };
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(evidence.Binding, Tier0Target.From(subject, nc), evidence.Input(subject), routes: null).State);
    }

    [Fact]
    public void AComputerUsingAGroupIdentifierIsNotAConfirmedCoreGroup()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("Computer", "S-1-5-21-1-2-3-516", "computer");
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null).State);
    }

    [Fact]
    public void DuplicateSidIdentityIsNotResolvedByPickingTheRequestedDn()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("One", "S-1-5-21-1-2-3-512");
        var other = evidence.Principal("Two", "S-1-5-21-1-2-3-512");
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject, other), routes: null).State);
    }

    [Fact]
    public void MixedDerivationInputRetainsAnExplicitLimitation()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("Group", "S-1-5-21-1-2-3-512");
        var input = evidence.Input(subject) with { DerivationGenerationId = Guid.NewGuid() };
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), input, routes: null);
        Assert.True(result.Coverage.Limitations.HasFlag(Tier0Limitations.SourceMismatch));
    }

    [Fact]
    public void APositiveWitnessDoesNotClaimCompleteTier0Coverage()
    {
        var evidence = new Tier0TestEvidence();
        var subject = evidence.Principal("Group", "S-1-5-21-1-2-3-512");
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null);
        Assert.Equal((Tier0State.Established, false), (result.State, result.Coverage.IsComplete));
    }

    [Fact]
    public void BinarySidEvidenceRetainsItsOriginalValue()
    {
        var evidence = new Tier0TestEvidence();
        var bytes = Sid.ToBytes("S-1-5-21-1-2-3-512") ?? throw new InvalidOperationException();
        var subject = evidence.Principal("Group", "unused") with
        {
            Attributes = [new("objectSid", AttributeCardinality.SingleValued, [new(7, null, bytes)]), Tier0TestEvidence.Attribute("objectClass", "group")],
        };
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(subject), evidence.Input(subject), routes: null);
        var witness = result.Supports[0].Evidence.First(item => item.Object == result.Target && item.Attribute == "objectSid");
        Assert.Equal((7, Convert.ToHexString(bytes)), (witness.Ordinal, witness.Value));
    }

    [Fact]
    public void RawSecurityMembershipCanEstablishANonProtectedPolicyRoot()
    {
        var (evidence, member, root) = MembershipFixture(520);
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), evidence.Input(member, root), evidence.Routes(member, root));
        Assert.Equal(Tier0Basis.EffectiveMembership, Assert.Single(result.Supports).Basis);
    }

    [Fact]
    public void ASummaryWithoutItsOriginalMembershipWitnessDoesNotEstablishAuthority()
    {
        var (evidence, member, root) = MembershipFixture();
        root = root with { Attributes = root.Attributes.Where(item => item.LdapDisplayName != "member").ToArray() };
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), evidence.Input(member, root), evidence.Routes(member, root));
        Assert.Equal(Tier0State.Unknown, result.State);
    }

    [Fact]
    public void DistributionMembershipCannotBePromotedByASummaryFlag()
    {
        var (evidence, member, root) = MembershipFixture();
        root = root with { Attributes = root.Attributes.Where(item => item.LdapDisplayName != "groupType")
            .Append(Tier0TestEvidence.Attribute("groupType", "2")).ToArray() };
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member),
            evidence.Input(member, root), evidence.Routes(member, root)).State);
    }

    [Fact]
    public void MissingRoutesAreUnknownRatherThanNotEstablished()
    {
        var (evidence, member, root) = MembershipFixture();
        Assert.Equal(Tier0State.Unknown, Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), evidence.Input(member, root), routes: null).State);
    }

    [Fact]
    public void IndependentMembershipSupportsAreNotOverwritten()
    {
        var (evidence, member, first) = MembershipFixture();
        var second = evidence.Principal("Second", "S-1-5-21-1-2-3-520", "group",
            Tier0TestEvidence.Attribute("groupType", "-2147483646"), Tier0TestEvidence.Attribute("member", member.DistinguishedName));
        var routes = evidence.Routes(member, first) with
        { Memberships = [.. evidence.Routes(member, first).Memberships, .. evidence.Routes(member, second).Memberships] };
        var result = Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), evidence.Input(member, first, second), routes);
        Assert.Equal(new[] { first.DistinguishedName, second.DistinguishedName }, result.Supports.Select(support => support.Root.DistinguishedName));
    }

    [Fact]
    public void RepeatedWitnessesDoNotMultiplySupports()
    {
        var (evidence, member, root) = MembershipFixture();
        var routes = evidence.Routes(member, root);
        routes = routes with { Memberships = [.. routes.Memberships, .. routes.Memberships] };
        Assert.Single(Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), evidence.Input(member, root), routes).Supports);
    }

    [Fact]
    public void PrimaryGroupMembershipRequiresTheCapturedRid()
    {
        var (evidence, member, root) = MembershipFixture();
        member = member with { Attributes = [.. member.Attributes, Tier0TestEvidence.Attribute("primaryGroupID", "512")] };
        root = root with { Attributes = root.Attributes.Where(item => item.LdapDisplayName != "member").ToArray() };
        var routes = evidence.Routes(member, root);
        var route = routes.Memberships[0].Routes[0];
        routes = routes with { Memberships = [routes.Memberships[0] with
        { Routes = [route with { Steps = [route.Steps[0], route.Steps[1] with { IsPrimaryGroup = true }] }] }] };
        Assert.Equal(Tier0State.Established, Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member), evidence.Input(member, root), routes).State);
    }

    [Fact]
    public void CancellationStopsTheAdapterRatherThanProducingANegative()
    {
        var (evidence, member, root) = MembershipFixture();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => Tier0Classifier.Qualify(evidence.Binding, evidence.Target(member),
            evidence.Input(member, root), routes: null, cancellationToken: cancellation.Token));
    }

    [Fact]
    public void UnsupportedPolicyVersionCannotProduceACurrentClassification()
    {
        var (evidence, member, root) = MembershipFixture();
        Assert.Throws<ArgumentException>(() => Tier0Classifier.Qualify(evidence.Binding with { PolicyVersion = 1 },
            evidence.Target(member), evidence.Input(member, root), routes: null));
    }

    private static (Tier0TestEvidence Evidence, ObjectAttributes Member, ObjectAttributes Root) MembershipFixture(int rid = 512)
    {
        var evidence = new Tier0TestEvidence();
        var member = evidence.Principal("Member", "S-1-5-21-1-2-3-1200", "user");
        var root = evidence.Principal("Root", "S-1-5-21-1-2-3-" + rid, "group",
            Tier0TestEvidence.Attribute("groupType", "-2147483646"), Tier0TestEvidence.Attribute("member", member.DistinguishedName));
        return (evidence, member, root);
    }
}

internal sealed class Tier0TestEvidence
{
    internal Guid Generation { get; } = Guid.NewGuid();
    internal ObjectAttributes Domain { get; } = new("DC=contoso,DC=com", Guid.NewGuid(), DateTimeOffset.UnixEpoch, default,
        [Attribute("objectSid", "S-1-5-21-1-2-3"), Attribute("objectClass", "top", "domain", "domainDNS")], "contoso.com");
    internal Tier0InputBinding Binding => new(new string('A', 64), Generation, new string('B', 64),
        PrincipalClassificationRegistry.Version, PolicyVersion: 2, ContractVersion: 2,
        ForestRootNamingContext: Domain.DistinguishedName, ConfigurationNamingContext: null);
    internal Tier0Target Target(ObjectAttributes subject) => Tier0Target.From(subject, Domain.DistinguishedName);
    internal CapturedMembershipInput Input(params ObjectAttributes[] subjects) => new(Generation, true, [Domain, .. subjects]);
    internal ObjectAttributes Principal(string name, string sid, string objectClass = "group", params ObjectAttribute[] extras) =>
        new($"CN={name},{Domain.DistinguishedName}", Guid.NewGuid(), DateTimeOffset.UnixEpoch, default,
            [Attribute("objectSid", sid), Attribute("objectClass", "top", objectClass), .. extras], "contoso.com");
    internal MembershipRouteSummary Routes(params ObjectAttributes[] chain) => new(
        [new(PrincipalIdentity(chain[1]), [new(0, "NameDoesNotDefineImportance", MembershipRouteAuthorization.SecurityEnabled,
            false, chain.Select(item => new MembershipRouteStep(PrincipalIdentity(item), false)).ToArray())], MembershipRouteIncompleteReason.None)],
        MembershipRouteIncompleteReason.None);
    internal static MembershipRoutePrincipal PrincipalIdentity(ObjectAttributes item)
    {
        var sid = item.Find("objectSid")?.OnlyValue?.Text ?? "";
        return new(sid, Sid.IsBuiltinDomain(sid) ? item.DomainFqdn : null, item.DistinguishedName);
    }
    internal static ObjectAttribute Attribute(string name, params string[] values) => new(name, AttributeCardinality.MultiValued,
        values.Select((value, index) => new AttributeValue(index, value, null)).ToArray());
}
