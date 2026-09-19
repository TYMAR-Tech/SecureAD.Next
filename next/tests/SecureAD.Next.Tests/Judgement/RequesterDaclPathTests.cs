using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class RequesterDaclPathTests(ITestOutputHelper output)
{
    private const string RootDn = "DC=contoso,DC=com";
    private const string ConfigurationDn = "CN=Configuration,DC=contoso,DC=com";
    private const string OtherDn = "CN=Other,DC=contoso,DC=com";
    private const string OtherSid = "S-1-5-21-1-2-3-1300";

    [Fact]
    public void ARequesterCheckConnectsTheExistingGroupGrantWithoutAnExistingPath()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(2, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void TheDirectRequesterAnswerIsStoredSeparatelyFromTheExistingHolderRoute()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Established, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void TheGroupStepKeepsTheOriginalMemberOrdinal()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: [OtherDn, UserDn]);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal((UserDn, TargetDn, "member", 1, UserDn), reader.ReadTier0Path(UserDn).Steps
            .Where(step => step.Kind == Tier0PathStepKind.Membership)
            .Select(step => (step.From.DistinguishedName, step.To.DistinguishedName, step.MembershipWitness!.Attribute,
                step.MembershipWitness.Ordinal, step.MembershipWitness.Value)).Single());
    }

    [Fact]
    public void ThePermissionStepReferencesTheUnchangedGroupHeldEdge()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);
        var edge = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges.Single(value => value.Capability == ControlCapability.CanWriteDacl);

        Assert.Equal((TargetDn, CoreDn, (long?)edge.Id, new RequesterDaclRequest(UserDn, CoreDn)), reader.ReadTier0Path(UserDn).Steps
            .Where(step => step.Kind == Tier0PathStepKind.WriteDacl)
            .Select(step => (step.From.DistinguishedName, step.To.DistinguishedName, step.PermissionId, step.RequesterRequest)).Single());
    }

    [Theory]
    [InlineData("O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1100)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("O:SYG:SYD:(A;;WD;;;S-1-5-21-1-2-3-1200)(D;;WD;;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.Established)]
    [InlineData("O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1200)(A;;WD;;;S-1-5-21-1-2-3-1100)", ControlEvaluationState.NotEstablished)]
    [InlineData("O:SYG:SYD:(D;;WD;;;AU)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.NotEstablished)]
    [InlineData("O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1300)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Established)]
    [InlineData("O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1999)(A;;WD;;;S-1-5-21-1-2-3-1200)", ControlEvaluationState.Unknown)]
    [InlineData("O:SYG:SYD:(A;;WD;;;S-1-5-21-1-2-3-1200)(D;;WD;;;S-1-5-21-1-2-3-1999)", ControlEvaluationState.Established)]
    public void AllApplicableTrusteesAreCheckedInCapturedOrder(string descriptor, ControlEvaluationState expected)
    {
        var directory = Capture(descriptor);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(expected, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Theory]
    [InlineData("WO")]
    [InlineData("WP")]
    [InlineData("SW")]
    [InlineData("CR")]
    public void OtherOperationsDoNotBecomeRequesterDaclPermission(string right)
    {
        var directory = Capture($"O:SYG:SYD:(A;;{right};;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Theory]
    [InlineData(null, ControlEvaluationState.Unknown)]
    [InlineData(-2147483644L, ControlEvaluationState.Unknown)]
    [InlineData(-2147483640L, ControlEvaluationState.Unknown)]
    [InlineData(2L, ControlEvaluationState.NotEstablished)]
    public void UnsupportedOrDistributionGroupsDoNotAuthorizeTheRequester(long? groupType, ControlEvaluationState expected)
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", groupType: groupType);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(expected, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void MissingDirectMembershipIsNotProofOfNonMembership()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: []);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void PrimaryGroupEvidenceDoesNotExpandTheRequesterModel()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", members: [], userAttributes: [Text("primaryGroupID", "1200")]);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Theory]
    [InlineData("computer")]
    [InlineData("foreignSecurityPrincipal")]
    public void ComputerAndForeignIdentitiesAreNotPromotedToUserRequesters(string kind)
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", userClasses: ["top", "user", kind]);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Theory]
    [InlineData(null, RequesterDaclIssue.DescriptorUnreadable)]
    [InlineData("O:SYG:SYD:NO_ACCESS_CONTROL", RequesterDaclIssue.GrantRouteUnsupported)]
    [InlineData("O:SYG:SYD:(A;;WD;;;AU)", RequesterDaclIssue.GrantRouteUnsupported)]
    [InlineData("O:SYG:SYD:(OA;;WD;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-3-1200)", RequesterDaclIssue.ScopeUnsupported)]
    public void MissingEvidenceAndUnsupportedAnalysisKeepDifferentReasons(string? descriptor, RequesterDaclIssue expected)
    {
        var directory = Capture(descriptor);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(expected, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Issues);
    }

    [Fact]
    public void InheritOnlyEntriesDoNotGrantOnTheTarget()
    {
        var directory = Capture($"O:SYG:SYD:(A;CIIO;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(ControlEvaluationState.NotEstablished, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Authorization);
    }

    [Fact]
    public void AnUncapturedRequesterGetsAnExplicitUnknownAnswer()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new("CN=Missing," + RootDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.RequesterMissing,
            Assert.Single(reader.ReadTier0Path("CN=Missing," + RootDn).RequesterAssessments).Issues);
    }

    [Fact]
    public void OnlyFixedTargetsCanTerminateANewRequesterRoute()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.TargetNotFixed, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Issues);
    }

    [Fact]
    public void AForestWidePartitionDoesNotBorrowTheCapturedDomainLabel()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", configurationTarget: true);
        Derive(directory);
        Judge(directory, [new(UserDn, ConfigurationDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.ResourceContextUnsupported, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).Issues);
    }

    [Fact]
    public void CrossDomainRequestersRemainOutsideTheSupportedResourceContext()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})", otherDomainRequester: true);
        Derive(directory);
        Judge(directory, [new("CN=CrossDomain,DC=child,DC=contoso,DC=com", CoreDn)]);
        using var reader = Open(directory);

        Assert.Contains(RequesterDaclIssue.ResourceContextUnsupported,
            Assert.Single(reader.ReadTier0Path("CN=CrossDomain,DC=child,DC=contoso,DC=com").RequesterAssessments).Issues);
    }

    [Fact]
    public void ARefusedRequesterOperationDoesNotEraseAnExistingMembershipRoute()
    {
        var directory = Capture($"O:SYG:SYD:(D;;WD;;;{UserSid})(A;;WD;;;{TargetSid})", existingMembership: true);
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal((Tier0Reachability.Reachable, (int?)1),
            (reader.ReadTier0Path(UserDn).Reachability, reader.ReadTier0Path(UserDn).ShortestProvenDistance));
    }

    [Fact]
    public void ARequesterRefusalIsNotANotReachableConclusion()
    {
        var directory = Capture($"O:SYG:SYD:(D;;WD;;;{UserSid})(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void RequesterProofsDoNotChangeNamedHolderStatesOrCounts()
    {
        var directory = Capture($"O:SYG:SYD:(D;;WD;;;{OtherSid})(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, []);
        using var before = Open(directory);
        var expected = before.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Select(edge => (edge.HolderSid, edge.Capability, edge.EvaluationState, edge.IsCounted)).ToArray();
        Judge(directory, [new(UserDn, CoreDn)]);
        using var after = Open(directory);

        Assert.Equal(expected, after.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Select(edge => (edge.HolderSid, edge.Capability, edge.EvaluationState, edge.IsCounted)).ToArray());
    }

    [Fact]
    public void NormalJudgingStillDoesNotScheduleRequesterDaclQuestions()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        using var reader = Open(directory);

        Assert.Empty(reader.ReadTier0Path(UserDn).RequesterAssessments);
    }

    [Fact]
    public void RequesterProofsRemainBoundToTheEvidenceAndBothAnalysisGenerations()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);
        var assessment = Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments);

        Assert.Equal((reader.Description.EvidenceSeal, reader.Description.GenerationId, reader.Description.DerivationGenerationId),
            (assessment.EvidenceSeal, assessment.GenerationId, assessment.DerivationGenerationId));
    }

    [Theory]
    [InlineData("$.Requesters[0].SourceFingerprint", "'different'")]
    [InlineData("$.Requesters[0].Assessment.Authorization", "'Unknown'")]
    [InlineData("$.Requesters[0].Assessment.GenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.Requesters[0].Assessment.DerivationGenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.Requesters[0].Assessment.EvidenceSeal", "'different'")]
    [InlineData("$.Requesters[0].Assessment.Evidence[0].Entry.AccessMask", "8")]
    [InlineData("$.Requesters[0].Assessment.Permissions[0].Id", "999999")]
    [InlineData("$.Requesters[0].Assessment.Permissions[0].Fingerprint", "'different'")]
    [InlineData("$.Requesters[0].Assessment.Steps[0].To.DistinguishedName", "'CN=Other,DC=contoso,DC=com'")]
    public void SourceContradictionsAreRejectedEvenAfterRefreshingTheStoredChecksum(string path, string value)
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        Mutate(directory, $"UPDATE tier0_path_calculation SET proof=json_set(proof,'{path}',{value})");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void OmittingTheProvenRequesterRouteIsRejected()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        Mutate(directory, "UPDATE tier0_path_node SET proof=json_set(proof,'$.RequesterRoute',NULL),outcome='Unknown' WHERE target LIKE 'CN=Alice,%'");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void AnOpenReaderRefusesRequesterProofFromAChangedDerivation()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        Derive(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void RequesterReadbackIsPassive()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        var before = Snapshot(directory);

        reader.ReadTier0Path(UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void CancelledRequesterJudgingDoesNotReplaceThePreviousPublishedGeneration()
    {
        var directory = Capture($"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory, [new(UserDn, CoreDn)]);
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], [new(UserDn, CoreDn)], Started, Started,
            new CancelBeforePublication(stopping), RunLog.Discarded, selfMembershipDiscoveryBudget: null, cancellationToken: stopping.Token));
        using var reader = Open(directory);

        Assert.Equal(previous, Assert.Single(reader.ReadTier0Path(UserDn).RequesterAssessments).GenerationId);
    }

    private sealed class CancelBeforePublication(CancellationTokenSource stopping) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.PublishingJudgement) stopping.Cancel();
        }
    }

    private static string[] Snapshot(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    private static void Mutate(string directory, string sql) => SelfMembershipCoverageTests.Mutate(directory, connection =>
    {
        using var change = connection.CreateCommand();
        change.CommandText = sql;
        change.ExecuteNonQuery();
        foreach (var table in new[] { "tier0_path_calculation", "tier0_path_node" })
        {
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT rowid,proof FROM " + table;
            var proofs = new List<(long Id, string Proof)>();
            using (var read = query.ExecuteReader()) while (read.Read()) proofs.Add((read.GetInt64(0), read.GetString(1)));
            foreach (var proof in proofs)
            {
                using var update = connection.CreateCommand();
                update.CommandText = "UPDATE " + table + " SET fingerprint=$hash WHERE rowid=$id";
                update.Parameters.AddWithValue("$hash", SHA256.HashData(Encoding.UTF8.GetBytes(proof.Proof)));
                update.Parameters.AddWithValue("$id", proof.Id);
                update.ExecuteNonQuery();
            }
        }
    });

    private string Capture(string? descriptor, long? groupType = -2147483646, string[]? members = null,
        string[]? userClasses = null, EvidenceAttribute[]? userAttributes = null, bool existingMembership = false,
        bool configurationTarget = false, bool otherDomainRequester = false)
    {
        var directory = Bundle(users: 0, groupType: groupType, members: members ?? [UserDn], sddl: "O:SYG:SYD:",
            writeAdditional: (writer, coverage) =>
            {
                Write(writer, coverage, UserDn, userClasses ?? ["top", "user"], UserSid,
                    userAttributes ?? [Text("userAccountControl", "512")], "O:SYG:SYD:");
                Write(writer, coverage, OtherDn, ["top", "user"], OtherSid, [], "O:SYG:SYD:");
                Write(writer, coverage, CoreDn, ["top", "group"], "S-1-5-21-1-2-3-512",
                    [Text("groupType", "-2147483646"), Values("member", existingMembership ? [UserDn] : [])], descriptor);
                if (configurationTarget)
                {
                    var partition = new PartitionCoverage(ConfigurationDn, NamingContextKind.Configuration, "dc01.contoso.com",
                        ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                    writer.WriteCoverage(partition);
                    Write(writer, partition, ConfigurationDn, ["top", "configuration"], null, [], descriptor);
                }
                if (otherDomainRequester)
                {
                    var partition = new PartitionCoverage("DC=child,DC=contoso,DC=com", NamingContextKind.Domain, "dc01.child.contoso.com",
                        ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                    writer.WriteCoverage(partition);
                    Write(writer, partition, "CN=CrossDomain,DC=child,DC=contoso,DC=com", ["top", "user"],
                        "S-1-5-21-4-5-6-1100", [], "O:SYG:SYD:");
                }
            });
        output.WriteLine(directory);
        return directory;
    }

    private static EvidenceAttribute Text(string name, string value) => Values(name, [value]);
    private static EvidenceAttribute Values(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string[] classes, string? sid,
        EvidenceAttribute[] extra, string? descriptor)
    {
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(coverage, dn, guid,
            [Values("objectClass", classes), .. sid is null ? Array.Empty<EvidenceAttribute>()
                : new[] { new EvidenceAttribute("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]) }, .. extra], Started));
        if (descriptor is null) return;
        var raw = new RawSecurityDescriptor(descriptor);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static void Judge(string directory, IReadOnlyList<RequesterDaclRequest> requests)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], requests, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, selfMembershipDiscoveryBudget: null, cancellationToken: CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
