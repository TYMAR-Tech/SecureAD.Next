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

public sealed partial class Tier0PathTests(ITestOutputHelper output)
{
    private const string RootDn = "DC=contoso,DC=com";
    private const string ConfigurationDn = "CN=Configuration,DC=contoso,DC=com";

    [Fact]
    public void DisabledRequesterPolicyStillPersistsBaselineMembershipPath()
    {
        var directory = Captured(depth: 2);
        Derive(directory);
        var result = JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled, Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Equal(new[] { (UserDn, GroupDn(1)), (GroupDn(1), CoreDn) },
            reader.ReadTier0Path(UserDn).Steps.Select(step => (step.From.DistinguishedName, step.To.DistinguishedName)));
    }

    [Fact]
    public void EmptyRequesterBatchesKeepThePhaseNotifications()
    {
        var directory = Captured(depth: 1);
        Derive(directory);
        var progress = new PathPhases();
        var result = JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled, Started, Started,
            progress, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);

        Assert.Equal(new[] { PathRequesterWorkPhase.PreparingPaths, PathRequesterWorkPhase.OwnAccountMembership,
            PathRequesterWorkPhase.RequesterDacl, PathRequesterWorkPhase.MembershipDacl,
            PathRequesterWorkPhase.WritingProofs }, progress.Values);
    }

    private sealed class PathPhases : IProgress<JudgingRun.JudgingProgress>
    {
        internal List<PathRequesterWorkPhase> Values { get; } = [];
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.RequesterPhase is { } phase) Values.Add(phase);
        }
    }

    [Theory]
    [InlineData(CoreDn)]
    [InlineData(RootDn)]
    public void AFixedTargetHasZeroDistance(string target)
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(0, reader.ReadTier0Path(target).ShortestProvenDistance);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(12)]
    public void MembershipDistanceCountsActualLinks(int depth)
    {
        var directory = Captured(depth: depth);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(depth, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void MembershipStepsPointFromMemberTowardTheFixedTarget()
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(new[] { (UserDn, GroupDn(1)), (GroupDn(1), GroupDn(2)), (GroupDn(2), CoreDn) },
            reader.ReadTier0Path(UserDn).Steps.Select(step => (step.From.DistinguishedName, step.To.DistinguishedName)));
    }

    [Fact]
    public void PrimaryGroupMembershipRetainsItsAttributeWitness()
    {
        var directory = Captured(primary: true);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal("primaryGroupID", Assert.Single(reader.ReadTier0Path(UserDn).Steps).MembershipWitness?.Attribute);
    }

    [Fact]
    public void MembershipCyclesDoNotChangeTheShortestSimpleRoute()
    {
        var directory = Captured(depth: 4, cycle: true);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(4, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void AShorterIndependentMembershipRouteWins()
    {
        var directory = Captured(depth: 4, shortcut: true);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(1, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void DirectDaclControlRetainsTheOriginalPermissionReference()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var permission = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges.Single(edge => edge.Capability == ControlCapability.CanWriteDacl);

        Assert.Equal((Tier0PathStepKind.WriteDacl, (long?)permission.Id),
            reader.ReadTier0Path(UserDn).Steps.Select(step => (step.Kind, step.PermissionId)).Single());
    }

    [Fact]
    public void AnEstablishedCurrentOwnerOperationCanTerminateAtTheFixedTarget()
    {
        var directory = Captured(descriptor: $"O:{UserSid}G:SYD:", forestHeuristics: true);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges,
            edge => edge.Capability == ControlCapability.IsOwnerAndCanRewriteDacl && edge.EvaluationState == ControlEvaluationState.Established);

        Assert.Equal(Tier0PathStepKind.CurrentOwnerDacl, Assert.Single(reader.ReadTier0Path(UserDn).Steps).Kind);
    }

    [Fact]
    public void TerminalAuthorityIsNotTransferredAlongMembership()
    {
        var directory = Captured(depth: 3, descriptor: "O:SYG:SYD:(A;;WD;;;S-1-5-21-1-2-3-2001)");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Equal(1, reader.ReadTier0Path(GroupDn(1)).ShortestProvenDistance);

        Assert.Equal(3, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void PermissionOverAMemberDoesNotTransferItsAccountIdentity()
    {
        var directory = Captured(depth: 1, userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadControlEdges(UserDn, null, null, true, 0).Edges,
            edge => edge.Capability == ControlCapability.CanWriteDacl && edge.EvaluationState == ControlEvaluationState.Established);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(TargetDn).Reachability);
    }

    [Theory]
    [InlineData("WO", false, ControlCapability.CanSetOwner)]
    [InlineData("WP", false, ControlCapability.CanModifyGroupMembership)]
    [InlineData("CR", true, ControlCapability.CanResetPassword)]
    [InlineData("WP", true, ControlCapability.CanWriteKeyCredentialLink)]
    public void OtherEstablishedPermissionsAreNotCompletedPaths(string right, bool account, ControlCapability capability)
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;{right};;;{UserSid})", coreAccount: account);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges,
            edge => edge.Capability == capability && edge.EvaluationState == ControlEvaluationState.Established);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void ReplicationPermissionIsNotACompletedPath()
    {
        var directory = Captured(rootDescriptor: $"O:SYG:SYD:(A;;CR;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadControlEdges(RootDn, null, null, true, 0).Edges,
            edge => edge.Capability == ControlCapability.CanReplicateSecretDomainData && edge.EvaluationState == ControlEvaluationState.Established);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void AnUnresolvedDenyPreventsATerminalStep()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(D;;WD;;;{TargetSid})(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges,
            edge => edge.Capability == ControlCapability.CanWriteDacl && edge.EvaluationState == ControlEvaluationState.Unknown);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void ADistributionGroupIsNotAnActingSecurityHolder()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", holderGroupType: 2);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(TargetDn).Reachability);
    }

    [Fact]
    public void AForeignPrincipalStubIsNotAnActingAccount()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})", userClass: "foreignSecurityPrincipal");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void ALocalGroupCanHoldTerminalControlInsideItsOwnDomain()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", holderGroupType: -2147483644);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Reachable, reader.ReadTier0Path(TargetDn).Reachability);
    }

    [Fact]
    public void ALocalGroupDoesNotBorrowAResourceDomainForAForestPartition()
    {
        var directory = Captured(configurationDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})", holderGroupType: -2147483644);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadPathInputs().FixedTargets, target => target.DistinguishedName == ConfigurationDn);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(TargetDn).Reachability);
    }

    [Fact]
    public void SelfMembershipPermissionDoesNotBecomeARequesterPath()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;SW;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Contains(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges,
            edge => edge.Capability == ControlCapability.CanAddSelfToGroup);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public async Task CliJudgingSavesThePathWithoutCapturingAsync()
    {
        var directory = Captured(depth: 2);
        Derive(directory);
        var command = Assert.IsType<SecureAD.Cli.CommandLine>(SecureAD.Cli.CommandLine.Parse(["--judge", directory]));

        Assert.Equal(0, await SecureAD.Cli.Program.RunAsync(command, CancellationToken.None, discoveryBudget: null,
            capture: _ => throw new InvalidOperationException("Offline judging must not capture.")));
        using var reader = Open(directory);

        Assert.Equal(2, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public async Task GuiJudgingSavesTheSameBoundedPathAsync()
    {
        var directory = Captured(depth: 2);
        Derive(directory);

        var result = await new SecureAD.Shell.Services.JudgingLauncher(discoveryBudget: null).RunAsync(directory,
            JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Equal(2, reader.ReadTier0Path(UserDn).ShortestProvenDistance);
    }

    [Fact]
    public void AProvenRouteSurvivesMissingDescriptorEvidence()
    {
        var directory = Captured(depth: 1, descriptor: null);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal((Tier0Reachability.Reachable, false),
            (reader.ReadTier0Path(UserDn).Reachability, reader.ReadTier0Path(UserDn).Coverage.IsComplete));
    }

    [Fact]
    public void UnknownTrusteesKeepTheirSymbolicSourceGap()
    {
        var directory = Captured(descriptor: "O:SYG:SYD:(A;;WD;;;WD)");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Contains(reader.ReadTier0Path(UserDn).Inputs.UncertaintyRegions,
            region => region.Source.TargetDn == CoreDn && region.Cause == PathUncertaintyCause.BroadPrincipalNotExpanded);
    }

    [Fact]
    public void NoDefiniteRouteIsUnknownRatherThanNotReachable()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(Tier0Reachability.Unknown, reader.ReadTier0Path(UserDn).Reachability);
    }

    [Fact]
    public void MissingDerivationIsNotAnEmptyCalculatedResult()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(PathInputAvailability.RequiredInputsUnavailable, reader.ReadTier0Path(UserDn).Inputs.Availability);
    }

    [Fact]
    public void AnUnscopedRunDoesNotClaimACalculation()
    {
        var directory = Captured();
        Derive(directory);
        Assert.True(JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None).IsSuccess);
        using var reader = Open(directory);

        Assert.Equal(PathInputAvailability.NotProduced, reader.ReadTier0Path(UserDn).Inputs.Availability);
    }

    [Fact]
    public void AnUncapturedSubjectIsNotDeclaredSafe()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal((Tier0Reachability.Unknown, (Tier0Target?)null),
            (reader.ReadTier0Path("CN=NotCaptured," + RootDn).Reachability, reader.ReadTier0Path("CN=NotCaptured," + RootDn).Subject));
    }

    [Fact]
    public void AProvenLengthDoesNotClaimTheMinimumAcrossUnsupportedAlternatives()
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.False(reader.ReadTier0Path(UserDn).IsMinimumEstablished);
    }

    [Theory]
    [InlineData("tier0_path_calculation", "$.Version", "999")]
    [InlineData("tier0_path_calculation", "$.Generation", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("tier0_path_calculation", "$.InputFingerprint", "'different'")]
    [InlineData("tier0_path_calculation", "$.NodeCount", "(SELECT COUNT(*) FROM tier0_path_node)")]
    [InlineData("tier0_path_node", "$.MembershipDistance", "0")]
    [InlineData("tier0_path_node", "$.MembershipDistance", "9")]
    [InlineData("tier0_path_node", "$.MembershipNext.MembershipSupport", "999")]
    [InlineData("tier0_path_node", "$.MembershipNext.To.DistinguishedName", "'CN=Target,DC=contoso,DC=com'")]
    public void ContradictorySavedPathsAreRefusedEvenWithRefreshedHashes(string table, string path, string value)
    {
        var directory = Captured(depth: 2);
        Derive(directory);
        Judge(directory);
        if (path == "$.NodeCount") Mutate(directory, "DELETE FROM tier0_path_node WHERE target LIKE 'CN=Alice,%'");
        PathProofVerification.ChangeJson(directory, table, path, value,
            table == "tier0_path_node" ? "WHERE target LIKE 'CN=Alice,%'" : "");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void TerminalProofCannotBeSubstituted()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        PathProofVerification.ChangeJson(directory, "tier0_path_node", "$.PermissionFingerprint", "'different'", "WHERE target LIKE 'CN=Alice,%'");
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadPath(reader, UserDn));
    }

    [Fact]
    public void AnOpenReaderRefusesAChangedSourceGeneration()
    {
        var directory = Captured(depth: 1);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        Derive(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadTier0Path(UserDn));
    }

    [Fact]
    public void PassiveReadbackDoesNotWriteOrPublish()
    {
        var directory = Captured(depth: 2);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        reader.ReadTier0Path(UserDn);
        var before = Snapshot(directory);

        reader.ReadTier0Path(UserDn);

        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void CancellationBeforePublicationKeepsThePreviousCalculatedResult()
    {
        var directory = Captured(depth: 2);
        Derive(directory);
        Judge(directory);
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            new CancelBeforePublication(stopping), RunLog.Discarded, stopping.Token, selfMembershipDiscoveryBudget: null));
        using var reader = Open(directory);

        Assert.Equal(generation, reader.ReadTier0Path(UserDn).Inputs.JudgementGenerationId);
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
    });

    private string Captured(int depth = 0, bool primary = false, bool cycle = false, bool shortcut = false,
        string? descriptor = "O:SYG:SYD:", string userDescriptor = "O:SYG:SYD:", long holderGroupType = -2147483646,
        bool coreAccount = false, string? rootDescriptor = null, string userClass = "user", bool forestHeuristics = false,
        string? configurationDescriptor = null)
    {
        var directory = Bundle(users: 0, members: [UserDn], groupType: holderGroupType, sddl: "O:SYG:SYD:", rootDescriptor: rootDescriptor,
            writeAdditional: (writer, coverage) =>
            {
                if (forestHeuristics)
                    writer.WriteObject(new(coverage, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com",
                        Guid.NewGuid(), [Text("objectClass", "nTDSService"), Text("dSHeuristics", "0000000")], Started));
                if (configurationDescriptor is not null)
                {
                    var configuration = new PartitionCoverage(ConfigurationDn, NamingContextKind.Configuration, "dc01.contoso.com",
                        ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                    writer.WriteCoverage(configuration);
                    Write(writer, configuration, ConfigurationDn, "configuration", null, [], configurationDescriptor);
                }
                Write(writer, coverage, UserDn, userClass, UserSid,
                    primary ? [Text("primaryGroupID", "512")] : [], userDescriptor);
                for (var index = 1; index < depth; index++)
                    Write(writer, coverage, GroupDn(index), "group", $"S-1-5-21-1-2-3-{2000 + index}",
                        [Text("groupType", "-2147483646"), Values("member", [index == 1 ? UserDn : GroupDn(index - 1),
                            .. cycle && index == 1 && depth > 2 ? new[] { GroupDn(depth - 1) } : Array.Empty<string>()])], "O:SYG:SYD:");
                Write(writer, coverage, CoreDn, coreAccount ? "user" : "group", coreAccount ? "S-1-5-21-1-2-3-500" : "S-1-5-21-1-2-3-512",
                    [Text("groupType", "-2147483646"), Values("member", [.. depth > 0 ? new[] { depth == 1 ? UserDn : GroupDn(depth - 1) } : Array.Empty<string>(),
                        .. shortcut && depth > 1 ? new[] { UserDn } : Array.Empty<string>()])], descriptor);
            });
        output.WriteLine(directory);
        return directory;
    }

    private static string GroupDn(int index) => $"CN=PathGroup{index},DC=contoso,DC=com";
    private static EvidenceAttribute Text(string name, string value) => Values(name, [value]);
    private static EvidenceAttribute Values(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string objectClass, string? sid,
        EvidenceAttribute[] extra, string? descriptor)
    {
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(coverage, dn, guid,
            [Values("objectClass", ["top", objectClass]), .. sid is null ? Array.Empty<EvidenceAttribute>()
                : new[] { new EvidenceAttribute("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]) }, .. extra], Started));
        if (descriptor is null) return;
        var raw = new RawSecurityDescriptor(descriptor);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static void Judge(string directory)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
