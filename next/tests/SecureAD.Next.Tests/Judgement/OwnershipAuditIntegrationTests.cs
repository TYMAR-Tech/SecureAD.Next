using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class OwnershipAuditIntegrationTests(ITestOutputHelper output)
{
    private const string CoreDn = "CN=Domain Admins,DC=contoso,DC=com";

    /// <summary>
    /// The contract of decision 0114: every object received primitive control products and only
    /// ownership assessment was scoped, so an ordinary target kept its <c>CanSetOwner</c> primitive
    /// while no owner transition was evaluated for it. Under 0116 control itself is scoped and an
    /// unadmitted target has no primitives to retain, so this is kept on the unscoped path where the
    /// state it describes exists.
    /// <see cref="AnUnadmittedOrdinaryTargetHasNoDetailedProductsAndSaysSo"/> is its counterpart.
    /// </summary>
    [Fact]
    public void SelectedCoreIsAssessedWhileOrdinaryTargetRetainsItsPrimitiveOnly()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var core = reader.ReadControlEdges(CoreDn, null, null, true, 0);
        var ordinary = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        Assert.Equal((1, 0, 1, OwnershipAssessmentExecution.NotAssessed),
            (core.Edges.Count(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl),
             ordinary.Edges.Count(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl),
             ordinary.Edges.Count(edge => edge.Capability == ControlCapability.CanSetOwner), ordinary.OwnershipCoverage?.Execution));
    }

    /// <summary>
    /// The scope-aware replacement, per 0116: the Tier-0 seed is assessed and an ordinary target that
    /// no route reached has no detailed products at all. Its absence from the product is recorded as
    /// not assessed, which is never a statement that the object is safe.
    /// </summary>
    [Fact]
    public void AnUnadmittedOrdinaryTargetHasNoDetailedProductsAndSaysSo()
    {
        var directory = Captured();
        Derive(directory);
        JudgeGated(directory);
        using var reader = Open(directory);
        var core = reader.ReadControlEdges(CoreDn, null, null, true, 0);
        var ordinary = reader.ReadControlEdges(TargetDn, null, null, true, 0);
        Assert.Equal((true, 0, OwnershipAssessmentExecution.NotAssessed),
            (core.Edges.Count > 0, ordinary.Edges.Count, ordinary.OwnershipCoverage?.Execution));
    }

    [Fact]
    public void SelectedCompoundStillHasAnUncountedUnknownOwnerAssignmentGate()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var compound = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Single(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl);
        Assert.Equal((ControlEvaluationState.Unknown, false, ControlEvaluationState.Unknown),
            (compound.EvaluationState, compound.IsCounted, compound.Preconditions.Single(item => item.Name == "CanSetTakeoverOwnerSid").State));
    }

    [Fact]
    public void MissingDerivationPreservesPermissionsAndRecordsUnavailableAssessmentInputs()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var page = reader.ReadControlEdges(CoreDn, null, null, true, 0);
        Assert.Equal((false, OwnershipAssessmentExecution.NotAssessed, 1, 0),
            (page.OwnershipCoverage?.InputsAvailable, page.OwnershipCoverage?.Execution,
             page.Edges.Count(edge => edge.Capability == ControlCapability.CanSetOwner),
             page.Edges.Count(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl)));
    }

    [Fact]
    public void StoredStatusesUseTheApprovedTargetAndHolderWording()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var core = reader.ReadControlEdges(CoreDn, null, null, true, 0).OwnershipCoverage;
        var ordinary = reader.ReadControlEdges(TargetDn, null, null, true, 0).OwnershipCoverage;
        var holder = reader.ReadControlEdges(null, UserSid, null, true, 0).OwnershipCoverage;
        Assert.Equal((true, true, true),
            (core?.Description.StartsWith("Assessed automatically from captured evidence.", StringComparison.Ordinal),
             ordinary?.Description.StartsWith("Not assessed automatically.", StringComparison.Ordinal),
             holder?.Description.Contains("target-specific", StringComparison.Ordinal)));
    }

    [Fact]
    public void SelectedTargetAppendReusesCapturedPermissionValues()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        using var connection = Database(directory);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM (SELECT target,ordinal FROM permission_entry GROUP BY target,ordinal HAVING COUNT(*)>1)";
        Assert.Equal(0L, command.ExecuteScalar());
    }

    [Fact]
    public void ScopeAndAssessmentAppendLeaveEveryPrimitiveRowUnchanged()
    {
        var directory = Captured();
        Derive(directory);
        var witness = new PrimitiveWitness(directory);
        var judged = JudgingRun.Judge(directory, [], Started, Started, witness, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        using var connection = Database(directory);
        Assert.Equal(witness.Rows, PrimitiveRows(connection));
    }

    [Fact]
    public void PassiveReadbackDoesNotChangeSealedEvidenceOrJudgement()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        var path = JudgementPath(directory);
        var before = (BundleSealing.HashFile(BundleLayout.EvidencePath(directory)), BundleSealing.HashFile(path));
        using var reader = Open(directory);
        reader.ReadControlEdges(CoreDn, null, null, true, 0);
        reader.ReadControlEdges(TargetDn, null, null, true, 0);
        Assert.Equal(before, (BundleSealing.HashFile(BundleLayout.EvidencePath(directory)), BundleSealing.HashFile(path)));
    }

    [Theory]
    [InlineData(JudgingPhase.SelectingOwnershipScope)]
    [InlineData(JudgingPhase.AssessingOwnership)]
    [InlineData(JudgingPhase.PublishingJudgement)]
    public void CancellationBeforePublicationPreservesThePreviousGeneration(JudgingPhase phase)
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        var before = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var cancellation = new CancellationTokenSource();
        var error = Record.Exception(() => JudgingRun.Judge(directory, [], Started, Started,
            new CancellingProgress(phase, cancellation), RunLog.Discarded, cancellation.Token));
        var after = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        Assert.Equal((typeof(OperationCanceledException), before), (error?.GetType(), after));
    }

    [Theory]
    [InlineData("UPDATE ownership_audit SET completed=0")]
    [InlineData("UPDATE ownership_seed SET classification_fingerprint=zeroblob(32)")]
    [InlineData("DELETE FROM ownership_relation")]
    [InlineData("UPDATE ownership_target SET execution='Completed' WHERE target='CN=Target,DC=contoso,DC=com'")]
    [InlineData("UPDATE ownership_target SET transition_count=0 WHERE target='CN=Domain Admins,DC=contoso,DC=com'")]
    public void ResealedCoverageCorruptionIsRefused(string mutation)
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        SelfMembershipCoverageTests.Mutate(directory, connection => Execute(connection, mutation));
        using var reader = Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(CoreDn, null, null, true, 0));
    }

    [Fact]
    public void RemovingAnInclusionWitnessIsRefusedEvenAfterUpdatingItsManifestCount()
    {
        var directory = Captured();
        Derive(directory);
        Judge(directory);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            Execute(connection, "DELETE FROM ownership_relation; UPDATE ownership_audit SET header=json_set(header,'$.RelationCount',0)");
            using var read = connection.CreateCommand();
            read.CommandText = "SELECT header FROM ownership_audit WHERE id=1";
            var json = (string)read.ExecuteScalar()!;
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE ownership_audit SET fingerprint=$hash WHERE id=1";
            update.Parameters.AddWithValue("$hash", SHA256.HashData(Encoding.UTF8.GetBytes(json)));
            update.ExecuteNonQuery();
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(CoreDn, null, null, true, 0));
    }

    private static string JudgementPath(string directory) => BundleLayout.AnalysisGenerationDataPath(directory,
        AnalysisStoreKind.Judgement, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);

    private static SqliteConnection Database(string directory)
    {
        var connection = new SqliteConnection("Data Source=" + JudgementPath(directory) + ";Mode=ReadOnly;Pooling=False");
        connection.Open();
        return connection;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static IReadOnlyList<string> PrimitiveRows(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM control_edge WHERE capability<>'CanBecomeOwnerAndRewriteDacl' ORDER BY id";
        using var read = command.ExecuteReader();
        var rows = new List<string>();
        while (read.Read())
        {
            var values = new object[read.FieldCount];
            read.GetValues(values);
            rows.Add(JsonSerializer.Serialize(values));
        }
        return rows;
    }

    private sealed class PrimitiveWitness(string directory) : IProgress<JudgingRun.JudgingProgress>
    {
        internal IReadOnlyList<string>? Rows { get; private set; }
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase != JudgingPhase.SelectingOwnershipScope || Rows is not null) return;
            using var connection = new SqliteConnection("Data Source=" + BundleLayout.JudgementPartialPath(directory) + ";Mode=ReadOnly;Pooling=False");
            connection.Open();
            Rows = PrimitiveRows(connection);
        }
    }

    private sealed class CancellingProgress(JudgingPhase phase, CancellationTokenSource cancellation) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value)
        {
            if (value.Phase == phase) cancellation.Cancel();
        }
    }

    [Theory]
    [InlineData("(A;;WD;;;S-1-3-4)", ControlEvaluationState.Established)]
    [InlineData("(D;;WD;;;S-1-3-4)", ControlEvaluationState.NotEstablished)]
    [InlineData("(A;;RP;;;S-1-3-4)", ControlEvaluationState.NotEstablished)]
    public void SelectedAssessmentRetainsOwnerRightsSemantics(string rights, ControlEvaluationState expected)
    {
        var directory = Captured($"O:SYG:SYD:(A;;WO;;;{UserSid}){rights}");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var compound = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Single(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl);
        Assert.Equal(expected, compound.Preconditions.Single(check => check.Name == "OwnerWouldReceiveWriteDacl").State);
    }

    [Theory]
    [InlineData("O:SYG:SYD:(A;;WO;;;S-1-5-10)", "S-1-5-21-1-2-3-512")]
    [InlineData("O:SYG:SY", "S-1-1-0")]
    public void SelectedAssessmentRetainsSelfAndNullDaclHolderIdentity(string descriptor, string expectedHolder)
    {
        var directory = Captured(descriptor);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var compound = reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges
            .Single(edge => edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl);
        Assert.Equal(expectedHolder, compound.HolderSid);
    }

    [Fact]
    public void SelectedUnreadableDescriptorRecordsLimitedCompletionRatherThanAKnownEmptyAnswer()
    {
        var directory = Captured(coreDescriptor: false);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        Assert.Equal(OwnershipAssessmentExecution.CompletedWithLimitations,
            reader.ReadControlEdges(CoreDn, null, null, true, 0).OwnershipCoverage?.Execution);
    }

    private string Captured(string? suppliedDescriptor = null, bool coreDescriptor = true)
    {
        var descriptor = suppliedDescriptor ?? $"O:SYG:SYD:(A;;WOWD;;;{UserSid})";
        var directory = Bundle(sddl: descriptor, writeAdditional: (writer, coverage) =>
        {
            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(coverage, CoreDn, guid,
            [
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("group")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-512")!)]),
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                new("member", StoredAttributeCompleteness.Complete, []),
            ], Started));
            if (!coreDescriptor) return;
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        });
        output.WriteLine(directory);
        return directory;
    }

    private static void Judge(string directory)
    {
        var result = JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static void JudgeGated(string directory)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Tier0DiscoveryBudget.Laboratory,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
