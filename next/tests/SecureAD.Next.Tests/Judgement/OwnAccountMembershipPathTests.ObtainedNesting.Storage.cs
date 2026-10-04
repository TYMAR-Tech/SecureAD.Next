using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("$.Dacl.ObtainedMembership.TargetDn", "'CN=Wrong,DC=contoso,DC=com'")]
    [InlineData("$.Dacl.DerivationGenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.Dacl.EvidenceSeal", "'changed'")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.Links[0].Member.DistinguishedName", "'CN=Wrong,DC=contoso,DC=com'")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.Links[0].Witness.Ordinal", "-1")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.Links[1].Group.NamingContext", "'DC=elsewhere'")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.Links[0].GroupType", "2")]
    [InlineData("$.Dacl.Evidence[0].ObtainedGroupMembership.SourceFingerprint", "'bad'")]
    [InlineData("$.Dacl.Steps[0].PermissionId", "987654321")]
    [InlineData("$.Steps[1].MembershipWitness.Ordinal", "99")]
    [InlineData("$.Request.PermissionKind", "'WriteMembers'")]
    public void ObtainedNestingSelectedReadRejectsChangedOperationOrNestedProof(string path, string value)
    {
        var directory = ObtainedPrepared("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.MembershipDacls[0].Assessment" + path[1..], value);
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None));
    }

    [Theory]
    [InlineData("$.Links[0].Witness.Ordinal", "55")]
    [InlineData("$.Links[0].SourceFingerprint", "'" + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" + "'")]
    [InlineData("$.Links[0].CapturedUtc", "'2000-01-01T00:00:00+00:00'")]
    [InlineData("$.Links[0].GroupType", "2")]
    public void ObtainedNestingAdmissionSourcesMustMatchTheOriginalCapture(string path, string value)
    {
        var directory = ObtainedPrepared("nested");
        using (var reader = Open(directory)) PathProofVerification.ReadInputs(reader);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE ownership_relation SET witness_membership=json_set(witness_membership,$path," + value
                + ") WHERE controller_target=$group AND witness_membership IS NOT NULL";
            command.Parameters.AddWithValue("$path", path);
            command.Parameters.AddWithValue("$group", TargetDn);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var changed = Open(directory);
        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadInputs(changed));
    }

    [Fact]
    public void ObtainedNestingDoesNotAdmitAdditionalGroupsForGenericMasks()
    {
        using var reader = Open(ObtainedPrepared("nested", descriptor: $"O:SYG:SYD:(A;;0x10000000;;;{HolderSid})"));
        Assert.DoesNotContain(reader.ReadPathInputs().AdmissionRelationships, relation => relation.Witness?.GroupMembership is not null);
        Assert.Empty(reader.ReadTier0Path(UserDn).MembershipDaclAssessments);
    }

    [Fact]
    public void ObtainedNestingDisabledSelectionDoesNotAddTheNewAdmissionWork()
    {
        var directory = ObtainedCapture("nested", OwnAccountMembershipPermissionKind.SelfMembership);
        Derive(directory);
        var result = JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);
        Assert.DoesNotContain(reader.ReadPathInputs().AdmissionRelationships, relation => relation.Witness?.GroupMembership is not null);
        Assert.Empty(reader.ReadTier0Path(UserDn).MembershipDaclAssessments);
    }

    [Fact]
    public void ObtainedNestingRetainsTheExistingTerminalHolderCountAcrossActivation()
    {
        var directory = ObtainedCapture("nested", OwnAccountMembershipPermissionKind.SelfMembership);
        Derive(directory);
        var result = JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var before = Open(directory);
        var holders = before.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Select(value => (value.HolderSid, value.Capability, value.IsCounted)).ToArray();
        JudgeCoverage(directory);
        using var after = Open(directory);
        Assert.Equal(ControlEvaluationState.Established, Combined(after).Authorization);
        Assert.Equal(holders, after.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Select(value => (value.HolderSid, value.Capability, value.IsCounted)));
    }

    [Fact]
    public void ObtainedNestingReusesSourceContextAndGroupRoutesAcrossPhases()
    {
        using var reader = Open(ObtainedPrepared("nested"));
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(value => value.Identity.DistinguishedName,
            value => value.Identity, StringComparer.OrdinalIgnoreCase);
        var input = reader.ReadPathInputs();
        var first = RequesterMembershipContext.Create(sources, identities, input, CancellationToken.None)!;
        var routes = first.Groups(HolderDn);
        var actual = Assert.Single(routes, route => route.GroupDn == TargetDn).Evidence;
        var next = RequesterMembershipContext.Create(sources, identities, input, CancellationToken.None)!;
        Assert.Same(first, next);
        Assert.Same(routes, next.Groups(HolderDn));
        Assert.Same(actual, next.Read(TargetDn, HolderDn));
        Assert.Equal(2, actual.Links.Count);
        Assert.Throws<InvalidDataException>(() => sources.RequesterMemberships(input.Input! with { DerivationGenerationId = Guid.NewGuid() },
            identities, CancellationToken.None));
    }

    [Fact]
    public void ObtainedNestingCancellationDoesNotReplaceThePublishedGeneration()
    {
        var directory = ObtainedPrepared("nested");
        using var before = Open(directory);
        var generation = before.Description.GenerationId;
        using var stopping = new CancellationTokenSource();
        var failure = Record.Exception(() => JudgeCoverage(directory,
            new StopCoveragePhase(PathRequesterWorkPhase.WritingProofs, stopping.Cancel), stopping.Token));
        Assert.IsAssignableFrom<OperationCanceledException>(failure);
        using var after = Open(directory);
        Assert.Equal(generation, after.Description.GenerationId);
        Assert.Equal(ControlEvaluationState.Established, Combined(after).Authorization);
    }

    [Fact]
    public void ObtainedNestingReadbackUsesSavedResultsRatherThanAnalysisReplay()
    {
        var directory = ObtainedPrepared("nested");
        PathProofVerification.AlterRequesterProof(directory, "$.MembershipDacls[0].SourceFingerprint",
            "'" + new string('f', 64) + "'");
        using var reader = Open(directory);
        var question = Assert.Single(reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None).Questions);
        Assert.Equal(new string('f', 64), question.SourceFingerprint);
        Assert.Equal(4, question.Steps.Count);
    }

    [Theory]
    [InlineData("origin")]
    [InlineData("requester")]
    public void ObtainedNestingKeepsSidHistoryOutsideTheAuthorizationModel(string subject)
    {
        using var reader = Open(ObtainedPrepared("nested"));
        var membership = Combined(reader).Membership;
        Assert.Equal(ControlEvaluationState.Established, membership.Obtainability);
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(value => value.Identity.DistinguishedName,
            value => value.Identity, StringComparer.OrdinalIgnoreCase);
        ObjectAttributes? Read(string dn)
        {
            var value = sources.Bundle.ReadObjectAttributes(dn);
            if (value is null || dn != (subject == "origin" ? TargetDn : UserDn)) return value;
            return value with { Attributes = [.. value.Attributes.Where(attribute => attribute.LdapDisplayName != "sIDHistory"),
                new("sIDHistory", AttributeCardinality.MultiValued, [new(0, null, Sid.ToBytes(HolderSid)!)])] };
        }
        var inputs = reader.ReadPathInputs();
        var contexts = sources.ReadNamingContexts().Value;
        var nested = new RequesterMembershipContext(sources.OpenDerivation().Value, inputs.Input!, Read, identities, contexts, CancellationToken.None);
        var result = RequesterDaclEvaluator.Assess(new(UserDn, CoreDn), inputs, reader.Description, identities, Read,
            sources.Bundle.ReadPermissions(CoreDn), contexts, reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges,
            sources.Bundle.Description.ForestFqdn, CancellationToken.None, membership, nested);
        Assert.Equal(ControlEvaluationState.Unknown, result.Authorization);
        Assert.Empty(result.Steps);
    }

    [Fact]
    public void ObtainedNestingPreChangeChecksReuseTheIdentityIndexRatherThanScanningTheForest()
    {
        using var reader = Open(ObtainedPrepared("nested"));
        var original = Combined(reader).Membership;
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var sources = ControlProofVerification.OpenSources(reader);
        var identities = new ObtainedIdentityVisits(OwnershipAuditStorage.Targets(connection).ToDictionary(value => value.Identity.DistinguishedName,
            value => value.Identity, StringComparer.OrdinalIgnoreCase));
        var input = reader.ReadPathInputs();
        RequesterMembershipContext.Create(sources, identities, input, CancellationToken.None);
        identities.Reset();
        var assessments = OwnAccountMembershipProofs.Create(connection, reader.Description, sources, identities, input,
            new Dictionary<string, Tier0PathNode>(), Enumerable.Repeat(original.Request, 8).ToArray(),
            CancellationToken.None, membershipContinuation: false);
        Assert.Equal(8, assessments.Count);
        Assert.All(assessments, value => Assert.Equal(Tier0PathCalculation.Fingerprint(original), Tier0PathCalculation.Fingerprint(value.Assessment)));
        // The batch visits identities once to select captured schema, never once per identity check.
        Assert.Equal(1, identities.ValuesRead);
    }

    private sealed class ObtainedIdentityVisits(Dictionary<string, Tier0Target> values)
        : Dictionary<string, Tier0Target>(values, StringComparer.OrdinalIgnoreCase), IReadOnlyDictionary<string, Tier0Target>
    {
        internal int ValuesRead { get; private set; }
        IEnumerable<Tier0Target> IReadOnlyDictionary<string, Tier0Target>.Values
        {
            get { ValuesRead++; return Values; }
        }
        internal void Reset() => ValuesRead = 0;
    }
}
