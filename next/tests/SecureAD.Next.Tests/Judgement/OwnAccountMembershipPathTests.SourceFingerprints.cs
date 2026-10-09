using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("both-permissions")]
    [InlineData("deny-before")]
    [InlineData("allow-before-deny")]
    [InlineData("disabled")]
    [InlineData("existing-membership")]
    [InlineData("missing-schema")]
    [InlineData("missing-account-status")]
    [InlineData("unsupported-group")]
    [InlineData("no-membership-continuation")]
    public void ComponentSourceProofsKeepFormat52SecurityAnswersWhileChangingOnlyTheirSourceBinding(string variant)
    {
        using var fixture = PrerequisiteFixtureFor(variant);
        OwnAccountMembershipRequest[] requests = [new(UserDn, TargetDn),
            new(UserDn, TargetDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers }];
        MembershipDaclRequest[] combined = [new(UserDn, TargetDn, CoreDn),
            new(UserDn, TargetDn, CoreDn) { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers }];
        var oldOwn = MembershipPrerequisiteReference.OwnAccounts(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, requests, CancellationToken.None);
        var oldCombined = MembershipPrerequisiteReference.Combined(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, combined, CancellationToken.None, fixture.Memberships);

        var currentOwn = fixture.Prerequisites.Create(fixture.Nodes, requests);
        var currentCombined = fixture.Combined(combined);

        Assert.Equal(oldOwn.Count, currentOwn.Count);
        Assert.Equal(oldCombined.Count, currentCombined.Count);
        for (var index = 0; index < oldOwn.Count; index++)
        {
            Assert.Equal(JsonSerializer.Serialize(oldOwn[index].Assessment, ProofSerialization.Options),
                JsonSerializer.Serialize(currentOwn[index].Assessment, ProofSerialization.Options));
            Assert.Equal(oldOwn[index].Steps, currentOwn[index].Steps);
            Assert.NotEqual(oldOwn[index].SourceFingerprint, currentOwn[index].SourceFingerprint);
            Assert.Equal(JsonSerializer.Serialize(oldCombined[index].Assessment, ProofSerialization.Options),
                JsonSerializer.Serialize(currentCombined[index].Assessment, ProofSerialization.Options));
            Assert.NotEqual(oldCombined[index].SourceFingerprint, currentCombined[index].SourceFingerprint);
        }
    }

    [Theory]
    [InlineData(2)]
    [InlineData(16)]
    public void ProductionSourceFingerprintWorkFollowsSharedInputsRatherThanQuestionCount(int accounts)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", accounts);
        using var counts = new PathSourceFingerprintTests.Counts(fixture.Description.GenerationId);
        var ownRequests = Enumerable.Range(0, accounts).SelectMany(index => new[] { TargetDn, OtherGroupDn }
            .SelectMany(group => Enum.GetValues<OwnAccountMembershipPermissionKind>().Select(kind =>
                new OwnAccountMembershipRequest(PrerequisiteUser(index), group) { PermissionKind = kind }))).ToArray();
        var own = fixture.Prerequisites.Create(fixture.Nodes, ownRequests, membershipContinuation: false);
        Assert.Equal(accounts * 4, own.Count);
        Assert.Equal((1L, 2L, accounts * 2L, accounts * 4L),
            (counts.Read(PathSourceFamily.OwnAccountMembership, "shared"), counts.Read(PathSourceFamily.OwnAccountMembership, "target"),
                counts.Read(PathSourceFamily.OwnAccountMembership, "requester"), counts.Read(PathSourceFamily.OwnAccountMembership, "question")));

        var direct = Enumerable.Range(0, accounts).SelectMany(index => new[] { CoreDn, "DC=contoso,DC=com" }
            .Select(target => new RequesterDaclProofs.Question(new(PrerequisiteUser(index), target), null))).ToArray();
        var directProofs = RequesterBatchEvaluation.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, direct, CancellationToken.None, fixture.Memberships);
        Assert.Equal(accounts * 2, directProofs.Count);
        Assert.Equal((1L, 2L, accounts * 2L, accounts * 2L),
            (counts.Read(PathSourceFamily.RequesterDacl, "shared"), counts.Read(PathSourceFamily.RequesterDacl, "target"),
                counts.Read(PathSourceFamily.RequesterDacl, "requester"), counts.Read(PathSourceFamily.RequesterDacl, "question")));

        var combined = fixture.Combined(Enumerable.Range(0, accounts).SelectMany(index => new[] { CoreDn, "DC=contoso,DC=com" }
            .Select(target => new MembershipDaclRequest(PrerequisiteUser(index), TargetDn, target))).ToArray());
        Assert.Equal(accounts * 2, combined.Count);
        Assert.Equal(accounts, counts.Read(PathSourceFamily.RequesterDacl, "obtained-membership"));
        Assert.Equal((2L, 4L, accounts * 4L),
            (counts.Read(PathSourceFamily.RequesterDacl, "shared"), counts.Read(PathSourceFamily.RequesterDacl, "target"),
                counts.Read(PathSourceFamily.RequesterDacl, "question")));
        Assert.Equal(1, counts.Read(PathSourceFamily.OwnAccountMembership, "shared"));
        Assert.Equal(2, counts.Read(PathSourceFamily.OwnAccountMembership, "target"));
    }

    [Fact]
    public void ObtainedMembershipSourceIsFingerprintedOnceAcrossDifferentPermissionTargets()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var own = Assert.Single(fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)], membershipContinuation: false)).Assessment;
        var schema = new RequesterReuseTests.CountingList<ObjectAttributes>(own.SchemaEvidence);
        own = own with { SchemaEvidence = schema };
        var source = fixture.Sources.Bundle;
        var requester = source.ReadObjectAttributes(UserDn);
        var target = source.ReadObjectAttributes(CoreDn);
        var permissions = source.ReadPermissions(CoreDn);
        var assessment = Assert.Single(TargetPermissionReference.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, [new(UserDn, CoreDn)], CancellationToken.None, own, fixture.Memberships)).Assessment;
        var before = schema.Visits;
        using var counts = new PathSourceFingerprintTests.Counts(fixture.Description.GenerationId);
        var builder = new PathSourceFingerprints(PathSourceFamily.RequesterDacl, fixture.Description, fixture.Inputs, new { }, CancellationToken.None);
        var first = builder.PrepareTarget(target, permissions, []);
        var second = builder.PrepareTarget(source.ReadObjectAttributes("DC=contoso,DC=com"), source.ReadPermissions("DC=contoso,DC=com"), []);

        var firstFingerprint = first.RequesterDacl(requester, own, assessment);
        var secondFingerprint = second.RequesterDacl(requester, own, assessment);

        Assert.NotEqual(firstFingerprint, secondFingerprint);
        Assert.Equal(own.SchemaEvidence.Count, schema.Visits - before);
        Assert.Equal(1, counts.Read(PathSourceFamily.RequesterDacl, "obtained-membership"));
        Assert.Equal(2, counts.Read(PathSourceFamily.RequesterDacl, "target"));
    }

    [Theory]
    [InlineData("obtained")]
    [InlineData("captured-membership")]
    [InlineData("obtained-group-membership")]
    [InlineData("resource-context")]
    public void RequesterSourceFingerprintRetainsEveryQuestionSpecificContext(string changed)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var own = Assert.Single(fixture.Prerequisites.Create(fixture.Nodes, [new(UserDn, TargetDn)], membershipContinuation: false)).Assessment;
        var source = fixture.Sources.Bundle;
        var requester = source.ReadObjectAttributes(UserDn);
        var target = new PathSourceFingerprints(PathSourceFamily.RequesterDacl, fixture.Description, fixture.Inputs, new { }, CancellationToken.None)
            .PrepareTarget(source.ReadObjectAttributes(CoreDn), source.ReadPermissions(CoreDn), []);
        var assessment = Assert.Single(TargetPermissionReference.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, [new(UserDn, CoreDn)], CancellationToken.None, own, fixture.Memberships)).Assessment;
        Assert.NotEmpty(assessment.Evidence);
        var original = target.RequesterDacl(requester, own, assessment);
        var membership = new RequesterMembershipEvidence(default, new string('f', 64), [], []);
        if (changed == "obtained") own = own with { OperationEvidence = [] };
        else if (changed == "resource-context")
            assessment = assessment with { ResourceContext = new(fixture.Identities["DC=contoso,DC=com"], ["contoso.com"], new string('a', 64)) };
        else
            assessment = assessment with
            {
                Evidence = [assessment.Evidence[0] with
                {
                    Membership = changed == "captured-membership" ? membership : assessment.Evidence[0].Membership,
                    ObtainedGroupMembership = changed == "obtained-group-membership" ? membership : assessment.Evidence[0].ObtainedGroupMembership,
                }, .. assessment.Evidence.Skip(1)],
            };

        Assert.NotEqual(original, target.RequesterDacl(requester, own, assessment));
    }
}
