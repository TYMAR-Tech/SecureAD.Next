using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class FullControlStorageTests
{
    internal static ControlObjectEvaluation Evaluation(params PermissionEntry[] entries) => ControlEdgeDeriverTests.DeriveWithTransitions(ControlEdgeDeriverTests.Permissions(entries));

    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    public void Tier0OnlyCatalogueChangesPreserveFullControlReadback(int version)
    {
        var evaluation = Evaluation(FullControlEvaluatorTests.Allow(0));
        evaluation = evaluation with
        {
            Edges = evaluation.Edges.Select(edge => edge with { PrincipalCatalogueVersion = version }).ToArray(),
            FullControlAssessments = evaluation.FullControlAssessments.Select(value => value with { PrincipalCatalogueVersion = version }).ToArray(),
        };
        using var reader = Open(Store([evaluation]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Equal((version, ControlEvaluationState.Established, 2),
            (Assert.Single(page.FullControlAssessments).PrincipalCatalogueVersion, page.FullControlAssessments[0].EvaluationState, page.FullControlSupports.Count));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(4)]
    public void AResealedUnsupportedFullControlCatalogueIsStillRejected(int version)
    {
        var directory = Store([Evaluation(FullControlEvaluatorTests.Allow(0))], connection => Execute(connection,
            $"UPDATE full_control_assessment SET proof=json_set(proof,'$.PrincipalCatalogueVersion',{version})"));
        using var reader = Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(null, null, null, true, 0));
    }

    [Fact]
    public void BothDirectionsCountOneSummaryAndRetainPrimitiveEvidence()
    {
        var directory = Store([Evaluation(FullControlEvaluatorTests.Allow(0))]);
        using var reader = Open(directory);
        var target = reader.ReadControlEdges(ControlEdgeDeriverTests.Subject.DistinguishedName, null, null, true, 0);
        var holder = reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, true, 0);
        Assert.Equal((1L, 2, 3, 1L), (target.UnknownCount, target.FullControlSupports.Count, target.Edges.Count, holder.UnknownCount));
    }

    [Fact]
    public void BothDirectionsReturnIdenticalStoredSummaryProof()
    {
        using var reader = Open(Store([Evaluation(FullControlEvaluatorTests.Allow(0), FullControlEvaluatorTests.Allow(1))]));
        var target = reader.ReadControlEdges(ControlEdgeDeriverTests.Subject.DistinguishedName, null, null, true, 0);
        var holder = reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, true, 0);
        Assert.Equal(JsonSerializer.Serialize(target.FullControlAssessments), JsonSerializer.Serialize(holder.FullControlAssessments));
    }

    [Fact]
    public void PrimitiveProofFlagsAreNotChangedBySummaryCounting()
    {
        using var reader = Open(Store([Evaluation(FullControlEvaluatorTests.Allow(0))]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.All(page.Edges.Where(edge => page.FullControlSupports.ContainsKey(edge.Id)), edge => Assert.True(edge.IsCounted));
    }

    [Theory]
    [InlineData(0x10000, 2)]
    [InlineData(0x40000, 1)]
    public void BrokenSummaryRestoresSurvivingPermissionCounts(int denied, long remaining)
    {
        using var reader = Open(Store([Evaluation(FullControlEvaluatorTests.Deny(0, denied), FullControlEvaluatorTests.Allow(1))]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Equal((remaining, 0, ControlEvaluationState.NotEstablished),
            (page.UnknownCount, page.FullControlSupports.Count, Assert.Single(page.FullControlAssessments).EvaluationState));
    }

    [Fact]
    public void UnknownSummaryDoesNotSuppressEstablishedPermissions()
    {
        var scoped = FullControlEvaluatorTests.Deny(0, 0x10000) with { HasObjectType = true, ObjectTypeGuid = null, AceType = "AccessDeniedObject" };
        using var reader = Open(Store([Evaluation(scoped, FullControlEvaluatorTests.Allow(1))]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Equal((2L, 0, ControlEvaluationState.Unknown),
            (page.UnknownCount, page.FullControlSupports.Count, Assert.Single(page.FullControlAssessments).EvaluationState));
    }

    [Fact]
    public void UnknownSummaryRemainsUnansweredCoverage()
    {
        var scoped = FullControlEvaluatorTests.Deny(0, 0x10000) with { HasObjectType = true, ObjectTypeGuid = null, AceType = "AccessDeniedObject" };
        var result = Evaluation(scoped, FullControlEvaluatorTests.Allow(1)) with { Uncertainty = ControlUncertainty.None };
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void StoredCompleteFlagCannotHideAnUnknownSummary()
    {
        var scoped = FullControlEvaluatorTests.Deny(0, 0x10000) with { HasObjectType = true, ObjectTypeGuid = null, AceType = "AccessDeniedObject" };
        using var reader = Open(Store([Evaluation(scoped, FullControlEvaluatorTests.Allow(1))],
            connection => Execute(connection, "UPDATE control_object SET is_complete=1")));
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(null, null, null, true, 0));
    }

    [Fact]
    public void NullDaclCountsOneEveryoneSummaryWithoutInventedAces()
    {
        var result = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions() with { DaclState = SecureAD.Kernel.Security.DaclState.Null });
        using var reader = Open(Store([result]));
        var page = reader.ReadControlEdges(null, "S-1-1-0", null, true, 0);
        Assert.Equal((1L, 0), (page.UnexpectedCount, Assert.Single(page.FullControlAssessments).Source.Entries.Count));
    }

    [Fact]
    public void RawGenericOnlyAssessmentCanBePagedWithoutPrimitiveRows()
    {
        using var reader = Open(Store([Evaluation(FullControlEvaluatorTests.Allow(0, 0x10000000))]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Equal((0, 1, 0L), (page.Edges.Count, page.FullControlAssessments.Count, page.UnknownCount));
    }

    [Fact]
    public void ExpectedSummaryHasOneHiddenCountAndFilterDoesNotChangeIt()
    {
        using var reader = Open(Store([Evaluation(ControlEdgeDeriverTests.Ace(0, "S-1-5-18", FullControlEvaluatorTests.FullMask))]));
        var hidden = reader.ReadControlEdges(null, "S-1-5-18", null, false, 0);
        var shown = reader.ReadControlEdges(null, "S-1-5-18", null, true, 0);
        Assert.Equal((1L, 0, 1L, 1), (hidden.ExpectedCount, hidden.FullControlAssessments.Count, shown.ExpectedCount, shown.FullControlAssessments.Count));
    }

    [Fact]
    public void MultipleHoldersShareTheOriginalObjectSource()
    {
        var directory = Store([Evaluation(FullControlEvaluatorTests.Allow(0), ControlEdgeDeriverTests.Ace(1, "S-1-5-21-1-2-3-1201", FullControlEvaluatorTests.FullMask))]);
        using var reader = Open(directory);
        using var connection = new SqliteConnection("Data Source=" + BundleLayout.AnalysisGenerationDataPath(directory,
            AnalysisStoreKind.Judgement, reader.Description.GenerationId) + ";Mode=ReadOnly;Pooling=False");
        connection.Open();
        TestSealing.AttachJudgementParts(connection, directory, reader.Description.GenerationId);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM full_control_source";
        Assert.Equal(1L, command.ExecuteScalar());
    }

    [Fact]
    public void PagingRetainsEverySummaryOnceAndResolvesOffPageSupportCounts()
    {
        var results = Enumerable.Range(0, 103).Select(index =>
        {
            var target = $"OU=Object{index},DC=contoso,DC=com";
            var subject = ControlEdgeDeriverTests.Subject with { DistinguishedName = target, ObjectGuid = Guid.NewGuid() };
            var permissions = ControlEdgeDeriverTests.Permissions(FullControlEvaluatorTests.Allow(0)) with { DistinguishedName = target };
            return ControlEdgeDeriverTests.DeriveWithTransitions(subject, permissions);
        }).ToArray();
        using var reader = Open(Store(results));
        var pages = new List<ControlEdgePage>();
        long after = 0;
        do
        {
            pages.Add(reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, true, after));
            after = pages[^1].LastId;
        } while (pages[^1].HasMore);
        Assert.Equal((103, 309, 206, 103L), (pages.SelectMany(page => page.FullControlAssessments).Select(value => value.Id).Distinct().Count(),
            pages.SelectMany(page => page.Edges).Select(edge => edge.Id).Distinct().Count(), pages.Sum(page => page.FullControlSupports.Count), pages[^1].UnknownCount));
    }

    [Theory]
    [InlineData("PRAGMA foreign_keys=OFF; DELETE FROM full_control_source")]
    [InlineData("DELETE FROM full_control_support")]
    [InlineData("DELETE FROM full_control_support; DELETE FROM full_control_assessment; DELETE FROM full_control_source_entry; DELETE FROM full_control_source")]
    [InlineData("UPDATE full_control_assessment SET support_count=0")]
    [InlineData("UPDATE full_control_assessment SET expectedness='Expected'")]
    [InlineData("UPDATE full_control_assessment SET expectedness='Expected',proof=json_set(proof,'$.Expectedness',0,'$.ExpectednessReason',0)")]
    [InlineData("UPDATE full_control_assessment SET generation='11111111-1111-1111-1111-111111111111'")]
    [InlineData("UPDATE full_control_assessment SET holder_sid='S-1-1-0'")]
    [InlineData("UPDATE full_control_assessment SET proof=json_set(proof,'$.Source.HolderScope','another-domain')")]
    [InlineData("UPDATE full_control_assessment SET proof=json_set(proof,'$.Rights[0].GrantOrdinals[0]',99)")]
    [InlineData("UPDATE full_control_assessment SET proof=json_set(proof,'$.HasIndependentGrantRoutes',json('true'))")]
    [InlineData("UPDATE permission_entry SET mask=131071 WHERE id IN (SELECT entry_id FROM full_control_source_entry WHERE position=0)")]
    [InlineData("UPDATE permission_entry SET mask=0 WHERE id IN (SELECT entry_id FROM control_ace)")]
    [InlineData("UPDATE full_control_assessment SET proof='{}'")]
    [InlineData("UPDATE full_control_assessment SET proof='not json'")]
    public void InconsistentProofIsRefusedBeforeCountsAreReturned(string mutation)
    {
        var directory = Store([Evaluation(FullControlEvaluatorTests.Allow(0))], connection => Execute(connection, mutation));
        using var reader = Open(directory);
        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadPage(reader, null, null, null, true, 0));
    }

    [Fact]
    public void CorruptionBeyondTheRequestedPageCannotSilentlyChangeCounts()
    {
        var first = Evaluation(FullControlEvaluatorTests.Allow(0));
        var second = ControlEdgeDeriver.Derive(ControlEdgeDeriverTests.Subject with { DistinguishedName = "OU=Other,DC=contoso,DC=com" },
            ControlEdgeDeriverTests.Permissions(FullControlEvaluatorTests.Allow(0)), JudgingContext.At(DateTimeOffset.UnixEpoch), Guid.Empty, null, ControlEdgeDeriverTests.DomainSid);
        using var reader = Open(Store([first, second], connection => Execute(connection, "UPDATE full_control_assessment SET support_count=99 WHERE id=1")));
        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadPage(reader, null, ControlEdgeDeriverTests.Holder, null, true, 3));
    }

    [Fact]
    public void ContradictoryWriteRollsBackTheWholeObject()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        var result = Evaluation(FullControlEvaluatorTests.Allow(0));
        var invalid = result with { FullControlAssessments = [result.FullControlAssessments[0] with { SupportingCapabilities = [] }] };
        Assert.Throws<InvalidOperationException>(() => StorageWrites.ControlEdges(connection, invalid, ownershipTarget: null));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM control_object";
        Assert.Equal(0L, command.ExecuteScalar());
    }

    [Theory]
    [InlineData(22)]
    [InlineData(21)]
    public void EarlierSchemasCannotClaimFullControlCoverage(int version)
    {
        var directory = Store([], connection => Execute(connection, $"UPDATE judgement SET schema_version={version}"));
        Assert.False(JudgementReader.Open(directory).IsSuccess);
    }

    [Fact]
    public void EarlierEngineCannotClaimFullControlCoverage()
    {
        using var reader = Open(Store([], connection => Execute(connection, "UPDATE control_product SET engine_version=6")));
        Assert.False(reader.ReadControlEdges(null, null, null, true, 0).ProductWasDerived);
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    internal static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }

    internal static string Store(IEnumerable<ControlObjectEvaluation> evaluations, Action<SqliteConnection>? mutate = null)
    {
        var directory = TempDirectories.Create("full-control-store");
        var seal = new string('a', 64);
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, seal)));
        using var writer = JudgementWriter.Create(directory, seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        writer.StartControlEdges(true);
        foreach (var result in evaluations)
            writer.WriteControlEdges(result with
            {
                Edges = result.Edges.Select(edge => edge with { GenerationId = writer.GenerationId }).ToArray(),
                FullControlAssessments = result.FullControlAssessments.Select(value => value with { GenerationId = writer.GenerationId }).ToArray(),
            }, ownershipTarget: null);
        writer.CompleteControlEdges();
        if (mutate is not null)
        {
            using var connection = new SqliteConnection("Data Source=" + BundleLayout.JudgementPartialPath(directory) + ";Pooling=False");
            connection.Open();
            TestSealing.AttachJudgementParts(connection, directory, writer.GenerationId, staged: true);
            mutate(connection);
        }
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }
}
