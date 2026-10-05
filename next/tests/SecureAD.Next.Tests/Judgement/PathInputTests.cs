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

public sealed partial class PathInputTests(ITestOutputHelper output)
{
    private const string RootDn = "DC=contoso,DC=com";

    [Theory]
    [InlineData(null, Tier0DiscoveryReason.DescriptorUnavailable, PathSubjectScope.UnknownWithinForest, PathUncertaintyCause.CapturedEvidenceIncomplete)]
    [InlineData("O:SYG:SY", Tier0DiscoveryReason.NullDacl, PathSubjectScope.UnknownWithinForest, PathUncertaintyCause.BroadPrincipalNotExpanded)]
    [InlineData("O:SYG:SYD:(A;;WD;;;WD)", Tier0DiscoveryReason.BroadTrustee, PathSubjectScope.RecordedTrustee, PathUncertaintyCause.BroadPrincipalNotExpanded)]
    [InlineData("G:SYD:(A;;WD;;;S-1-5-21-9-9-9-1100)", Tier0DiscoveryReason.UnresolvedTrustee, PathSubjectScope.RecordedTrustee, PathUncertaintyCause.IdentityUnresolved)]
    [InlineData("O:SYG:SYD:(A;;WD;;;S-1-3-0)", Tier0DiscoveryReason.UnsupportedRoute, PathSubjectScope.RecordedTrustee, PathUncertaintyCause.AnalysisUnsupported)]
    public void ADiscoveryGapKeepsItsSourceAndSymbolicScope(string? descriptor, Tier0DiscoveryReason reason,
        PathSubjectScope subjects, PathUncertaintyCause cause)
    {
        var directory = Captured(descriptor);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var region = reader.ReadPathInputs().UncertaintyRegions.Single(item => item.Source.TargetDn == CoreDn && item.Source.Reason == reason);

        Assert.Equal((subjects, PathTargetScope.Object, cause, RootDn, true),
            (region.Subjects, region.Targets, region.Cause, region.RecordedResource?.NamingContext, region.AllCapabilityKinds));
    }

    [Fact]
    public void FixedTargetsComeFromTheSharedClassifier()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(new[] { CoreDn, RootDn }, reader.ReadPathInputs().FixedTargets.Select(item => item.DistinguishedName));
    }

    [Fact]
    public void AnEffectiveMemberIsRetainedButIsNotAFixedTarget()
    {
        var directory = Captured(member: true);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var inputs = reader.ReadPathInputs();

        Assert.Equal((true, false),
            (inputs.Classifications.Any(item => item.Target.DistinguishedName == UserDn
                && item.Supports.Any(support => support.Basis == Tier0Basis.EffectiveMembership)),
             inputs.FixedTargets.Any(item => item.DistinguishedName == UserDn)));
    }

    [Theory]
    [InlineData("UPDATE path_input SET proof=json_set(proof,'$.Version',999)")]
    [InlineData("UPDATE path_input SET proof=json_set(proof,'$.Generation','11111111-1111-1111-1111-111111111111')")]
    [InlineData("UPDATE path_input SET proof=json_set(proof,'$.EvidenceSeal',printf('%064d',0))")]
    [InlineData("UPDATE path_input SET proof=json_set(proof,'$.DerivationGeneration','11111111-1111-1111-1111-111111111111')")]
    [InlineData("UPDATE path_input SET proof=json_set(proof,'$.Input.PolicyVersion',999)")]
    [InlineData("UPDATE path_input SET proof=json_set(proof,'$.Input.DerivationSeal',printf('%064d',0))")]
    [InlineData("DELETE FROM path_anchor WHERE target LIKE 'CN=%'; UPDATE path_input SET proof=json_set(proof,'$.AnchorCount',1)")]
    [InlineData("INSERT INTO path_anchor SELECT target FROM ownership_seed WHERE target NOT IN (SELECT target FROM path_anchor); UPDATE path_input SET proof=json_set(proof,'$.AnchorCount',(SELECT COUNT(*) FROM path_anchor))")]
    [InlineData("DELETE FROM path_uncertainty")]
    [InlineData("UPDATE path_uncertainty SET proof=json_set(proof,'$.Subjects','RecordedTrustee') WHERE json_extract(proof,'$.Source.Reason')='DescriptorUnavailable'")]
    [InlineData("UPDATE path_uncertainty SET proof=json_set(proof,'$.RecordedResource.DomainFqdn','other.example') WHERE json_extract(proof,'$.Source.Reason')='DescriptorUnavailable'")]
    [InlineData("UPDATE path_uncertainty SET proof=json_set(proof,'$.Source.Reason','NullDacl','$.Cause','BroadPrincipalNotExpanded') WHERE json_extract(proof,'$.Source.Reason')='DescriptorUnavailable'")]
    public void ContradictoryInputsAreRefusedEvenWithNewFingerprints(string sql)
    {
        var directory = Captured(coreDescriptor: null, member: true);
        Derive(directory);
        Judge(directory);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var change = connection.CreateCommand();
            change.CommandText = sql;
            change.ExecuteNonQuery();
            RefreshProofHashes(connection, "path_input");
            RefreshProofHashes(connection, "path_uncertainty");
        });
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => PathProofVerification.ReadInputs(reader));
    }

    private static void RefreshProofHashes(SqliteConnection connection, string table)
    {
        using var select = connection.CreateCommand();
        select.CommandText = "SELECT id,proof FROM " + table;
        var rows = new List<(long Id, string Proof)>();
        using (var read = select.ExecuteReader()) while (read.Read()) rows.Add((read.GetInt64(0), read.GetString(1)));
        foreach (var row in rows)
        {
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE " + table + " SET fingerprint=$hash WHERE id=$id";
            update.Parameters.AddWithValue("$hash", SHA256.HashData(Encoding.UTF8.GetBytes(row.Proof)));
            update.Parameters.AddWithValue("$id", row.Id);
            update.ExecuteNonQuery();
        }
    }

    [Fact]
    public void MissingDerivationIsUnavailableRatherThanAnEmptyResult()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);

        Assert.Equal(PathInputAvailability.RequiredInputsUnavailable, reader.ReadPathInputs().Availability);
    }

    [Fact]
    public void AnUnscopedRunDoesNotClaimToHaveProducedPathInputs()
    {
        var directory = Captured();
        Derive(directory);
        var result = JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);

        Assert.Equal(PathInputAvailability.NotProduced, reader.ReadPathInputs().Availability);
    }

    [Fact]
    public void RecordedInputsRemainIncompleteAndDoNotActivateRequesterDiscovery()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var inputs = reader.ReadPathInputs();

        Assert.Equal((PathInputAvailability.Recorded, false, "NotStarted"),
            (inputs.Availability, inputs.Coverage.AnalysisComplete, inputs.RequesterDiscovery?.Verdict));
    }

    [Fact]
    public void AdmissionRemainsACandidateRatherThanACompletedOperation()
    {
        var directory = Captured($"O:{UserSid}G:SYD:");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var relation = reader.ReadPathInputs().AdmissionRelationships.Single(item => item.Affected.DistinguishedName == CoreDn);

        Assert.Equal((UserDn, Tier0State.Unknown, true),
            (relation.Controller.DistinguishedName, relation.State, relation.Witness?.IsOwner));
    }

    [Fact]
    public void PermissionReferencesRetainSupportsAndUnknownOwnerTransitions()
    {
        var directory = Captured($"O:SYG:SYD:(A;;WOWD;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var edges = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges;
        Assert.Contains(edges, edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl
            && edge.EvaluationState == ControlEvaluationState.Unknown && !edge.IsCounted);

        Assert.Equal(edges.Select(edge => edge.Id), reader.ReadPathInputs().PermissionIds);
    }

    [Fact]
    public void PassiveReadingDoesNotWriteOrPublishAnalysis()
    {
        var directory = Captured(member: true);
        Derive(directory);
        Judge(directory);
        var before = Snapshot(directory);
        using (var reader = Open(directory)) reader.ReadPathInputs();

        var after = Snapshot(directory);
        output.WriteLine("Removed/changed: " + string.Join(Environment.NewLine, before.Except(after)));
        output.WriteLine("Added/changed: " + string.Join(Environment.NewLine, after.Except(before)));
        Assert.Equal(before, after);
    }

    private static string[] Snapshot(string directory) => Directory.GetFiles(directory, "*", SearchOption.AllDirectories)
        // SQLite's read-only WAL connections can create coordination files, not analysis. A nonempty
        // WAL still participates so a pending write cannot be hidden by this exclusion.
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();

    [Fact]
    public void AnOpenReaderRefusesInputsAfterTheDerivationChanges()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        reader.ReadPathInputs();
        Derive(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadPathInputs());
    }

    [Fact]
    public void CancellationAfterSavingInputsKeepsThePreviousGenerationSelected()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        var before = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            new CancellingProgress(stopping), RunLog.Discarded, stopping.Token, selfMembershipDiscoveryBudget: null));

        Assert.Equal(before, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    private sealed class CancellingProgress(CancellationTokenSource stopping) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == JudgingPhase.SelectingOwnershipScope) stopping.Cancel();
        }
    }

    [Fact]
    public void AnExcludedDomainKeepsASymbolicForestGap()
    {
        var directory = TempDirectories.Create("path-input-exclusion");
        output.WriteLine(directory);
        var coverage = new PartitionCoverage(RootDn, NamingContextKind.Domain, "dc01.contoso.com",
            ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(coverage);
            writer.WriteObject(new(coverage, RootDn, Guid.NewGuid(),
                [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("domainDNS")])], Started));
            writer.Complete(RunCoverage.Of(
                CoverageId.ForDomainsExcluding("contoso.com", ["contoso.com", "child.contoso.com"], ["child.contoso.com"]),
                [DomainCoverage.Read("contoso.com"), DomainCoverage.Excluded("child.contoso.com", ExclusionKind.ByChoice, "Synthetic exclusion.")],
                [ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                 ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema)],
                SysvolCoverage.Of([])), Started.AddMinutes(1));
        }
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var gap = reader.ReadPathInputs().UncertaintyRegions.Single(item => item.Source.Reason == Tier0DiscoveryReason.CaptureIncomplete);

        Assert.Equal((PathTargetScope.Forest, PathSubjectScope.UnknownWithinForest, (Tier0Target?)null),
            (gap.Targets, gap.Subjects, gap.RecordedResource));
    }

    private string Captured(string? coreDescriptor = "O:SYG:SYD:", bool member = false)
    {
        var directory = Bundle(writeAdditional: (writer, coverage) =>
        {
            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(coverage, CoreDn, guid,
            [
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("group")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-512")!)]),
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                new("member", StoredAttributeCompleteness.Complete, member ? [EvidenceValue.OfText(UserDn)] : []),
            ], Started));
            if (coreDescriptor is null) return;
            var raw = new RawSecurityDescriptor(coreDescriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        });
        output.WriteLine(directory);
        return directory;
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
