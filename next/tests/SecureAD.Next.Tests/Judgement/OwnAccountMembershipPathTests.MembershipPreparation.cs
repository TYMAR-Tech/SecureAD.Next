using SecureAD.Judgement;
using SecureAD.Next.Tests.Derivation;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void RepeatedGroupWitnessValidationPreparesEachSourceAndFingerprintOnce()
    {
        using var reader = Open(ObtainedPrepared("ordinals"));
        var combined = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null,
            CancellationToken.None).Questions).Membership!;
        var dacl = combined.Dacl!;
        var membership = Assert.Single(dacl.Evidence).ObtainedGroupMembership!;
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        var context = RequesterMembershipContext.Create(sources, identities, reader.ReadPathInputs(), CancellationToken.None)!;
        using var counts = new CapturedMembershipPreparationTests.Counts(reader.Description.DerivationGenerationId!.Value);
        for (var use = 0; use < 64; use++)
            context.RequireGroupSources(membership, combined.Membership!.Target!, dacl.Target!, HolderSid, CancellationToken.None);
        Assert.Equal((4L, 3L), (counts.For("membership.attribute_preparations"), counts.For("membership.source_fingerprints")));
    }

    [Theory]
    [InlineData("fingerprint")]
    [InlineData("ordinal")]
    [InlineData("captured")]
    [InlineData("type")]
    [InlineData("resource")]
    [InlineData("trustee")]
    public void ReusedGroupSourcesStillRefuseEveryChangedWitnessOrResource(string changed)
    {
        using var reader = Open(ObtainedPrepared("ordinals"));
        var combined = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null,
            CancellationToken.None).Questions).Membership!;
        var dacl = combined.Dacl!;
        var membership = Assert.Single(dacl.Evidence).ObtainedGroupMembership!;
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        var context = RequesterMembershipContext.Create(sources, identities, reader.ReadPathInputs(), CancellationToken.None)!;
        var resource = dacl.Target!;
        var trustee = HolderSid;
        context.RequireGroupSources(membership, combined.Membership!.Target!, resource, trustee, CancellationToken.None);
        var first = membership.Links[0];
        if (changed == "resource") resource = resource with { DomainFqdn = "uncaptured.example" };
        else if (changed == "trustee") trustee = "S-1-5-21-1-2-3-1999";
        else
        {
            var links = membership.Links.ToArray();
            links[0] = changed switch
            {
                "fingerprint" => first with { SourceFingerprint = new string('f', 64) },
                "ordinal" => first with { Witness = first.Witness with { Ordinal = first.Witness.Ordinal + 100 } },
                "captured" => first with { CapturedUtc = first.CapturedUtc.AddTicks(1) },
                _ => first with { GroupType = first.GroupType + 1 },
            };
            membership = membership with { Links = links };
        }
        Assert.Throws<InvalidDataException>(() => context.RequireGroupSources(membership, combined.Membership!.Target!,
            resource, trustee, CancellationToken.None));
    }
}
