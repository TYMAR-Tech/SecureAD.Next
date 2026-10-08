using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void SharedCalculationManifestReferencesExistingUncertaintyInsteadOfCopyingIt()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof FROM tier0_path_calculation";
        var id = Assert.IsType<long>(command.ExecuteScalar());
        var json = PathProofVerification.Json(connection, id);
        using var manifest = JsonDocument.Parse(json);
        Assert.Equal(new[] { "Families" }, manifest.RootElement.EnumerateObject()
            .Where(property => property.Value.ValueKind == JsonValueKind.Array).Select(property => property.Name));
        Assert.DoesNotContain(manifest.RootElement.GetProperty("Inputs").EnumerateObject(),
            property => property.Value.ValueKind == JsonValueKind.Array);
        var uncertainties = manifest.RootElement.GetProperty("Inputs").GetProperty("UncertaintyRegions");
        Assert.Equal(JsonValueKind.Object, uncertainties.ValueKind);
        var original = reader.ReadPathInputs();
        Assert.NotEmpty(original.UncertaintyRegions);
        Assert.Equal(original.UncertaintyRegions.Count, uncertainties.GetProperty("Count").GetInt32());
        Assert.False(uncertainties.TryGetProperty("Source", out _));
        Assert.Equal(JsonValueKind.Object, manifest.RootElement.GetProperty("Selection").GetProperty("Candidates").ValueKind);
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(json) < 8_192, "A calculation manifest must not embed its unbounded detail lists.");
        Assert.Equal(JsonSerializer.Serialize(original.UncertaintyRegions, ProofSerialization.Options),
            JsonSerializer.Serialize(reader.ReadPathRequesterCoverage().Inputs.UncertaintyRegions, ProofSerialization.Options));
    }

    [Fact]
    public void SharedCalculationSummaryKeepsExactCountersWithoutReadingDetailBodies()
    {
        using var reader = Open(PrepareRisk(RiskCapture(coreDescriptor:
            $"O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-999999)(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})")));
        using var connection = RiskDatabase(reader, writableCopy: true);
        var proofs = PathRequesterRiskStorage.ReadProofs(connection, reader.Description, CancellationToken.None);
        Assert.Contains(proofs.Requesters, value => value.Assessment.Authorization == ControlEvaluationState.Unknown);
        var summary = Tier0PathStorage.ReadSummary(connection, reader.Description, CancellationToken.None);
        Assert.Equal(new[] { proofs.Requesters.Count, proofs.OwnAccounts.Count, proofs.MembershipDacls.Count },
            summary.Families.Select(family => family.StoredAssessments));
        Assert.Equal(proofs.OwnAccounts.Count(value => value.Assessment.Permission.MemberPresent is null),
            summary.Families[1].UnknownCurrentMembership);
        Assert.Equal(proofs.MembershipDacls.Count(value => value.Assessment.Membership.Permission.Readiness == ControlEvaluationState.Unknown),
            summary.Families[2].UnknownOperationReadiness);
        Assert.Equal(proofs.Requesters.Count(value => value.Assessment.Authorization == ControlEvaluationState.Unknown),
            summary.Families[0].UnresolvedResults);
        Assert.Equal(PathRequesterCoverageState.EvaluatedSupportedQuestions, summary.Verdict);
        Assert.True(summary.InputUncertaintyCount > 0);
        using var command = connection.CreateCommand();
        command.CommandText = """
            DELETE FROM path_proof_chunk WHERE proof_id IN (SELECT source_proof FROM path_requester_risk)
                OR proof_id IN (SELECT proof FROM path_calculation_record);
            UPDATE path_uncertainty SET proof='invalid detail';
            """;
        command.ExecuteNonQuery();
        using var trace = new JudgingInputReuseTests.Statements(connection);
        var after = Tier0PathStorage.ReadSummary(connection, reader.Description, CancellationToken.None);
        Assert.Equal(JsonSerializer.Serialize(summary), JsonSerializer.Serialize(after));
        Assert.DoesNotContain(trace.Sql, sql => sql.Contains("FROM path_requester_risk", StringComparison.OrdinalIgnoreCase)
            || sql.Contains("FROM path_calculation_record", StringComparison.OrdinalIgnoreCase)
            || sql.Contains("FROM path_uncertainty", StringComparison.OrdinalIgnoreCase));
        Assert.Throws<InvalidDataException>(() => Tier0PathStorage.ReadCoverage(connection, reader.Description));
    }

    [Theory]
    [InlineData("DELETE FROM path_requester_risk WHERE id=(SELECT MAX(id) FROM path_requester_risk)")]
    [InlineData("UPDATE path_requester_risk SET source_proof=(SELECT source_proof FROM path_requester_risk ORDER BY id DESC LIMIT 1) WHERE id=(SELECT MIN(id) FROM path_requester_risk)")]
    [InlineData("DELETE FROM path_uncertainty WHERE id=(SELECT MAX(id) FROM path_uncertainty)")]
    [InlineData("UPDATE path_calculation_record SET question_key='substituted question' WHERE kind='Candidates' AND ordinal=0")]
    [InlineData("UPDATE path_calculation_record SET ordinal=ordinal+10 WHERE kind='Sources'")]
    public void SharedCalculationPublicationRejectsMissingOrSubstitutedReferences(string sql)
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: true);
        PathCalculationStorage.RequirePublishable(connection, reader.Description, CancellationToken.None);
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        Assert.True(command.ExecuteNonQuery() > 0);
        Assert.Throws<InvalidDataException>(() => PathCalculationStorage.RequirePublishable(connection, reader.Description, CancellationToken.None));
    }

    [Fact]
    public void SharedCalculationSummaryRefusesAReplacedGeneration()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        var before = reader.ReadPathRequesterSummary();
        JudgeCoverage(directory);
        Assert.NotEqual(before.JudgementGenerationId,
            AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.Throws<InvalidOperationException>(() => reader.ReadPathRequesterSummary());
    }

    [Theory]
    [InlineData("$.Inputs.Input", "NULL")]
    [InlineData("$.Inputs.Coverage.ProcessingComplete", "json('false')")]
    [InlineData("$.Inputs.FixedTargets.Count", "0")]
    [InlineData("$.Inputs.UncertaintyRegions.Count", "0")]
    public void SharedCalculationSummaryCannotContradictItsBoundInputRecord(string path, string value)
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: true);
        PathProofVerification.AlterJson(connection, "tier0_path_calculation", $"json_set($json,'{path}',{value})");
        Assert.Throws<InvalidDataException>(() => Tier0PathStorage.ReadSummary(connection, reader.Description, CancellationToken.None));
    }

    [Fact]
    public void SharedCalculationSelectedPageDoesNotDecodeTheSameRequesterForEachQuestion()
    {
        using var reader = Open(PrepareRisk(RiskCapture(coreDescriptor:
            $"O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-999999)(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})")));
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT proof FROM path_shared_proof WHERE kind='Identity'
                AND json_extract(path_json(proof),'$.DistinguishedName')=$user
            """;
        command.Parameters.AddWithValue("$user", UserDn);
        var id = Assert.IsType<long>(command.ExecuteScalar());
        using var trace = new JudgingInputReuseTests.Statements(connection);
        var page = PathRequesterRiskStorage.ReadPage(connection, reader.Description, UserDn, PathRiskVerdict.Unknown, null, CancellationToken.None);
        Assert.True(page.Questions.Count >= 2);
        Assert.Single(trace.Sql.Where(sql => sql.Contains($"FROM path_shared_proof WHERE proof={id}", StringComparison.Ordinal)));
    }

    [Fact]
    public void SharedCalculationPreservesAllThreeFamiliesAgainstIndependentReferenceReaders()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        var coverage = PathProofVerification.ReadCoverage(reader);
        Assert.All(coverage.Families, family => Assert.True(family.StoredAssessments > 0));
        var path = PathProofVerification.ReadPath(reader, UserDn);
        Assert.NotEmpty(path.RequesterAssessments);
        Assert.NotEmpty(path.OwnAccountAssessments);
        Assert.NotEmpty(path.MembershipDaclAssessments);
    }
}
