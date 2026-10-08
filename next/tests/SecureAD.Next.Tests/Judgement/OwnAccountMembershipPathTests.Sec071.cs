using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task Sec071HostsPublishOneAccountFindingForAllQualifiedFamilies(string host)
    {
        var directory = RiskCapture();
        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings, value => value.RuleId == "SEC-071");
        var proof = Assert.IsType<Tier0RouteFindingEvidence>(finding.Evidence);
        var summary = Assert.IsType<Tier0FindingSummary>(reader.ReadTier0FindingSummary(CancellationToken.None));
        var risks = ReadRisks(reader).Assessments;

        Assert.Equal((Severity.High, "Tier0ControlPlane", 3), (finding.Severity, proof.Anchor, proof.UnexpectedChecks));
        Assert.Equal((1, 1, 0, RuleExecutionOutcome.Succeeded),
            (summary.AssessedAccounts, summary.AccountsWithFindings, summary.UnresolvedAccessChecks, summary.Outcome));
        Assert.Equal(Tier0PathCalculation.Fingerprint(risks), proof.QualificationFingerprint);
        Assert.Equal(reader.Description.GenerationId, proof.GenerationId);
        Assert.Equal(reader.Description.DerivationGenerationId, proof.DerivationGenerationId);
        Assert.Equal(reader.Description.EvidenceSeal, proof.EvidenceSeal);
        Assert.Equal(summary.CalculationFingerprint, proof.CalculationFingerprint);
        Assert.Equal(finding.ObjectGuid.ToString("D"), finding.Subject.Key);
        Assert.Equal(1, reader.ReadRuleExecutions().Executions.Single(value => value.RuleId == "SEC-071").ObjectsJudged);
        using var source = new BundleAssetSource();
        var selected = source.ReadSavedTier0Path(directory, UserDn);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
        Assert.Equal(proof, selected.Value!.Finding!.Evidence);
        Assert.Equal(3, selected.Value.Page.Questions.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Sec071ExpectedAndUnresolvedQuestionsAreNotFindings(bool unresolved)
    {
        var directory = PrepareSec071(RiskCapture(currentAdministrator: !unresolved, missingMembership: unresolved));
        using var reader = Open(directory);
        var summary = Assert.IsType<Tier0FindingSummary>(reader.ReadTier0FindingSummary(CancellationToken.None));

        Assert.DoesNotContain(reader.Read().Findings, finding => finding.RuleId == "SEC-071");
        Assert.Equal(0, summary.AccountsWithFindings);
        Assert.All(ReadRisks(reader).Assessments, value =>
            Assert.Equal(unresolved ? PathRiskVerdict.Unknown : PathRiskVerdict.ExpectedRoute, value.Verdict));
        Assert.Equal(unresolved ? 3 : 0, summary.UnresolvedAccessChecks);
        Assert.Equal(unresolved ? RuleExecutionOutcome.Indeterminate : RuleExecutionOutcome.Succeeded, summary.Outcome);
    }

    [Fact]
    public void Sec071DenialDoesNotEraseAnIndependentUnexpectedQuestion()
    {
        using var reader = Open(PrepareSec071(RiskCapture(
            coreDescriptor: $"O:SYG:SYD:(D;;WD;;;{UserSid})(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})")));
        var finding = Assert.Single(reader.Read().Findings);
        Assert.Equal(1, Assert.IsType<Tier0RouteFindingEvidence>(finding.Evidence).UnexpectedChecks);
        var page = reader.ReadPathRiskPage(UserDn, PathRiskVerdict.NotEstablished, null, CancellationToken.None);
        Assert.Equal((1, 2), (page.Counts.Unexpected, page.Questions.Count));
        Assert.All(page.Questions, question => Assert.Equal(PathRiskVerdict.NotEstablished, question.Risk.Verdict));
    }

    [Fact]
    public void Sec071ARecordedExpectedQuestionDoesNotHideUnexpectedQuestions()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: true);
        using var sources = ControlProofVerification.OpenSources(reader);
        using var command = connection.CreateCommand();
        // Publication consumes qualified answers; qualification itself has independent semantic tests.
        command.CommandText = """
            SELECT id,proof,path_json(proof) FROM path_requester_risk
            WHERE json_extract(path_json(proof),'$.Family')='RequesterDacl'
            """;
        long id;
        long proofId;
        PathRequesterRiskAssessment value;
        using (var read = command.ExecuteReader())
        {
            Assert.True(read.Read());
            id = read.GetInt64(0);
            proofId = read.GetInt64(1);
            value = JsonSerializer.Deserialize<PathRequesterRiskAssessment>(read.GetString(2), ProofSerialization.Options)!;
        }
        var expected = value with { Verdict = PathRiskVerdict.ExpectedRoute, Expectedness = ControlExpectedness.Expected,
            ExpectednessReason = ControlExpectednessReason.ExpectedSameDomainControlPlane };
        var json = JsonSerializer.Serialize(expected, ProofSerialization.Options);
        PathProofVerification.ReplaceJson(connection, proofId, json);
        command.CommandText = "UPDATE path_requester_risk SET verdict='ExpectedRoute',fingerprint=$hash WHERE id=$id";
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
        command.Parameters.AddWithValue("$id", id);
        Assert.Equal(1, command.ExecuteNonQuery());
        var coverage = reader.ReadPathRiskCoverage(CancellationToken.None);
        coverage = coverage with { Families = coverage.Families.Select(family => family.Family == PathRequesterFamily.RequesterDacl
            ? family with { UnexpectedRoutes = 0, ExpectedRoutes = 1 } : family).ToArray() };
        command.Parameters.Clear();
        json = JsonSerializer.Serialize(coverage, ProofSerialization.Options);
        command.CommandText = "UPDATE path_risk_product SET proof=$proof,fingerprint=$hash WHERE id=1";
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
        Assert.Equal(1, command.ExecuteNonQuery());

        var result = new UnexpectedTier0Route().JudgeSaved(connection, reader.Description, sources, CancellationToken.None);

        var finding = Assert.Single(result.Execution.Findings);
        Assert.Equal(2, Assert.IsType<Tier0RouteFindingEvidence>(finding.Evidence).UnexpectedChecks);
        Assert.Equal((1, 1), (result.Summary.AssessedAccounts, result.Summary.AccountsWithFindings));
    }

    [Fact]
    public void Sec071FindingIdentitySurvivesNameAndRouteChanges()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var sources = ControlProofVerification.OpenSources(reader);
        var subject = sources.Bundle.ReadObjectAttributes(UserDn)!;
        var risks = ReadRisks(reader);
        var rule = new UnexpectedTier0Route();
        var before = rule.CreateFinding(subject, risks.Assessments, risks.BatchCoverage);
        const string renamed = "CN=Renamed,DC=contoso,DC=com";
        var questions = risks.Assessments.Take(1).Select(value => value with
        {
            RequesterDn = renamed,
            CurrentAuthority = value.CurrentAuthority! with
            { Principal = value.CurrentAuthority.Principal with { DistinguishedName = renamed } },
        }).ToArray();
        var changed = rule.CreateFinding(subject with { DistinguishedName = renamed }, questions, risks.BatchCoverage);

        Assert.Equal((before.RuleId, before.Subject, before.ObjectGuid), (changed.RuleId, changed.Subject, changed.ObjectGuid));
        Assert.Equal(renamed, changed.DistinguishedName);
        Assert.Equal(1, Assert.IsType<Tier0RouteFindingEvidence>(changed.Evidence).UnexpectedChecks);
        var otherGuid = Guid.NewGuid();
        var otherQuestions = questions.Select(value => value with
        { CurrentAuthority = value.CurrentAuthority! with { Principal = value.CurrentAuthority.Principal with { ObjectGuid = otherGuid } } }).ToArray();
        var other = rule.CreateFinding(subject with { DistinguishedName = renamed, ObjectGuid = otherGuid }, otherQuestions, risks.BatchCoverage);
        Assert.NotEqual(changed.Subject, other.Subject);
    }

    [Fact]
    public void Sec071DisabledChecksDoNotBecomeAZeroRiskVerdict()
    {
        var directory = RiskCapture();
        Derive(directory);
        var result = JudgingRun.JudgeAudit(directory, [new UnexpectedTier0Route()], PathRequesterPolicy.Disabled,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);
        var summary = Assert.IsType<Tier0FindingSummary>(reader.ReadTier0FindingSummary(CancellationToken.None));
        Assert.Equal((PathRiskAvailability.NotRequested, RuleExecutionOutcome.DidNotRun),
            (summary.Availability, summary.Outcome));
        Assert.Empty(reader.Read().Findings);
    }

    [Fact]
    public void Sec071SelectedReadbackPreservesUnknownAddReadinessAndOriginalProofs()
    {
        var directory = PrepareSec071(RiskCapture());
        using var reader = Open(directory);
        var before = Snapshot(directory);
        var page = reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None);
        var combined = Assert.Single(page.Questions, question => question.Risk.Family == PathRequesterFamily.MembershipDacl);
        using var connection = RiskDatabase(reader, writableCopy: false);
        Assert.Equal((ControlEvaluationState.Unknown, (bool?)null),
            (combined.Risk.OrdinaryAddReadiness, combined.Risk.CapturedMemberPresent));
        Assert.Equal(PathProofVerification.SourceFingerprint(connection, reader.Description, PathRequesterFamily.MembershipDacl,
                new SavedMembershipDaclProof(combined.Membership!, combined.SourceFingerprint)),
            combined.Risk.SourceProofFingerprint);
        Assert.Equal(before, Snapshot(directory));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT path_json(proof) FROM tier0_path_calculation WHERE id=1";
        using var header = JsonDocument.Parse((string)command.ExecuteScalar()!);
        Assert.False(header.RootElement.TryGetProperty("Requesters", out _));
        Assert.False(header.RootElement.TryGetProperty("OwnAccounts", out _));
        Assert.False(header.RootElement.TryGetProperty("MembershipDacls", out _));
        Assert.Equal(1, header.RootElement.GetProperty("MembershipDaclCount").GetInt32());
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("requester")]
    [InlineData("group")]
    public void Sec071PagingRejectsAContinuationFromAnotherSelection(string changed)
    {
        using var reader = Open(PrepareSec071(RiskCapture()));
        var mark = new PathRiskPageMark(reader.Description.GenerationId, UserDn, PathRiskVerdict.UnexpectedRoute, 1);
        mark = changed switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "requester" => mark with { RequesterDn = CoreDn },
            _ => mark with { Verdict = PathRiskVerdict.ExpectedRoute },
        };
        Assert.Throws<InvalidDataException>(() => reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, mark, CancellationToken.None));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Sec071FailedOrCancelledPublicationKeepsThePreviousGeneration(bool cancel)
    {
        var directory = PrepareRisk(RiskCapture());
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var before = File.ReadAllText(manifest);
        using var stopping = new CancellationTokenSource();
        var observed = 0L;
        var progress = new Sec071Progress(value =>
        {
            if (value.Phase != JudgingPhase.PublishingJudgement) return;
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = BundleLayout.JudgementPartialPath(directory), Mode = SqliteOpenMode.ReadWrite, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM finding WHERE rule_id='SEC-071'";
            observed = (long)command.ExecuteScalar()!;
            if (cancel) stopping.Cancel();
            else
            {
                command.CommandText = "DELETE FROM finding_tier0_route";
                Assert.Equal(1, command.ExecuteNonQuery());
            }
        });
        var error = Record.Exception(() => JudgingRun.JudgeAudit(directory, [new UnexpectedTier0Route()], PathRequesterPolicy.SupportedCapturedQuestions,
            Started, Started, progress, RunLog.Discarded, stopping.Token, null));
        Assert.Equal(1, observed);
        if (cancel) Assert.IsAssignableFrom<OperationCanceledException>(error);
        else Assert.IsType<InvalidDataException>(error);
        Assert.Equal(before, File.ReadAllText(manifest));
    }

    private static string PrepareSec071(string directory)
    {
        Derive(directory);
        var error = Record.Exception(() =>
        {
            var result = JudgingRun.JudgeAudit(directory, [new UnexpectedTier0Route()], PathRequesterPolicy.SupportedCapturedQuestions,
                Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
            Assert.True(result.IsSuccess, result.Error?.Description);
        });
        Assert.Null(error);
        return directory;
    }

    internal static IReadOnlyList<Finding> ReadMixedEvidenceSample(IReadOnlyList<IRule> sampleRules, Xunit.Abstractions.ITestOutputHelper output)
    {
        var fixture = new OwnAccountMembershipPathTests(output);
        var directory = fixture.RiskCapture(extra: (writer, domain) =>
        {
            const string a = "CN=Cycle A,DC=contoso,DC=com";
            const string b = "CN=Cycle B,DC=contoso,DC=com";
            Write(writer, domain, a, ["top", "group"], "S-1-5-21-1-2-3-1800",
                [Text("groupType", "-2147483646"), Text("member", b), Text("memberOf", b)], "O:SYG:SYD:");
            Write(writer, domain, b, ["top", "group"], "S-1-5-21-1-2-3-1801",
                [Text("groupType", "-2147483646"), Text("member", a), Text("memberOf", a)], "O:SYG:SYD:");
        });
        Derive(directory);
        var result = JudgingRun.JudgeAudit(directory, [.. sampleRules, new UnexpectedTier0Route(), new CircularGroupMembership()],
            PathRequesterPolicy.SupportedCapturedQuestions, Started, Started, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = Open(directory);
        var page = reader.ReadPage(FindingsQuery.Everything());
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.False(page.Value.HasMore);
        return page.Value.Findings;
    }

    [Fact]
    public void Sec071DatabasePagingKeepsWholeAccountCountsAndEveryQuestion()
    {
        using var reader = Open(PrepareSec071(ManyRiskQuestions()));
        var first = reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None);
        Assert.Equal((50, 63), (first.Questions.Count, first.Counts.Unexpected));
        var mark = Assert.IsType<PathRiskPageMark>(first.Next);
        var second = reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, mark, CancellationToken.None);
        Assert.Equal((13, 63), (second.Questions.Count, second.Counts.Unexpected));
        Assert.Null(second.Next);
        Assert.Equal(63, first.Questions.Concat(second.Questions).Select(value => value.Id).Distinct().Count());
        Assert.Equal(1, reader.ReadTier0FindingSummary(CancellationToken.None)!.AccountsWithFindings);
    }

    [Fact]
    public void Sec071SelectedPageDoesNotDecodeProofsOnUnloadedPages()
    {
        var directory = PrepareSec071(ManyRiskQuestions());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT source_proof FROM path_requester_risk WHERE id=(SELECT MAX(id) FROM path_requester_risk)";
            PathProofVerification.ReplaceJson(connection, Assert.IsType<long>(command.ExecuteScalar()), "not json");
        });
        using var reader = Open(directory);
        PathRiskPage? first = null;
        var error = Record.Exception(() => first = reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None));
        Assert.Null(error);
        Assert.Equal(50, first!.Questions.Count);
        Assert.Throws<InvalidDataException>(() =>
            reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, first.Next, CancellationToken.None));
    }

    private string ManyRiskQuestions() => RiskCapture(
        coreDescriptor: "O:SYG:SYD:" + string.Concat(Enumerable.Range(3000, 60).Select(rid => $"(A;;WD;;;S-1-5-21-1-2-3-{rid})"))
            + $"(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})",
        extra: (writer, domain) =>
    {
        for (var index = 0; index < 60; index++)
            Write(writer, domain, $"CN=GrantGroup{index},DC=contoso,DC=com", ["top", "group"],
                $"S-1-5-21-1-2-3-{3000 + index}", [Text("groupType", "-2147483646")],
                $"O:SYG:SYD:(OA;;SW;{MemberGuid};;{UserSid})");
    });

    private sealed class Sec071Progress(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => report(value);
    }
}
