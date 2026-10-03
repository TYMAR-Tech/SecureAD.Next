using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData("shell")]
    [InlineData("cli-offline")]
    [InlineData("cli-capture")]
    public async Task RiskHostsSaveAllThreeQualifiedQuestionFamilies(string host)
    {
        var directory = RiskCapture();
        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        var risk = ReadRisks(reader);

        Assert.Equal(PathRiskAvailability.Recorded, risk.BatchCoverage.Availability);
        Assert.Equal(PathRiskReadVerdict.RecordedQuestions, risk.Verdict);
        Assert.Equal(Enum.GetValues<PathRequesterFamily>(), risk.Assessments.Select(value => value.Family));
        Assert.All(risk.Assessments, value => Assert.Equal(PathRiskVerdict.UnexpectedRoute, value.Verdict));
        Assert.All(risk.BatchCoverage.Families, value => Assert.Equal((1, 1, 0, 0, 0),
            (value.Questions, value.UnexpectedRoutes, value.ExpectedRoutes, value.NotEstablished, value.Unknown)));
    }

    [Fact]
    public void RiskCapturedAdministrativeMembershipIsExpected()
    {
        using var reader = Open(PrepareRisk(RiskCapture(currentAdministrator: true)));
        var risk = ReadRisks(reader);

        Assert.Equal(3, risk.Assessments.Count);
        Assert.All(risk.Assessments, value => Assert.Equal(PathRiskVerdict.ExpectedRoute, value.Verdict));
        Assert.All(risk.Assessments, value => Assert.Contains(value.CurrentAuthority!.CapturedAuthorityRoots,
            root => root.Sid == "S-1-5-21-1-2-3-512"));
    }

    [Fact]
    public void RiskDoesNotTransferTheGrantingGroupsExpectationToANewMember()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        var edge = Assert.Single(reader.ReadControlEdges(CoreDn, null, null, true, 0).Edges,
            value => value.HolderSid == TargetSid && value.Capability == ControlCapability.CanWriteDacl);
        Assert.Equal(ControlExpectedness.Expected, edge.Expectedness);
        var combined = Assert.Single(reader.ReadTier0Path(UserDn).MembershipDaclAssessments);
        Assert.Equal(OwnAccountMembershipBasis.ExistingOrAuthorizedAdd, combined.Membership.Basis);

        var risk = Assert.Single(ReadRisks(reader).Assessments, value => value.Family == PathRequesterFamily.MembershipDacl);

        Assert.Equal(PathRiskVerdict.UnexpectedRoute, risk.Verdict);
        Assert.Empty(risk.CurrentAuthority!.CapturedAuthorityRoots);
        Assert.Null(risk.CapturedMemberPresent);
        Assert.Equal(ControlEvaluationState.Unknown, risk.OrdinaryAddReadiness);
    }

    [Fact]
    public void RiskTier0MembershipDoesNotGiveAuthorityOutsideItsScope()
    {
        var directory = RiskCapture(schemaAdministrator: true);
        using var reader = Open(PrepareRisk(directory));
        Assert.Equal(Tier0Reachability.Reachable, reader.ReadTier0Path(UserDn).Reachability);

        var risk = Assert.Single(ReadRisks(reader).Assessments, value => value.Family == PathRequesterFamily.RequesterDacl);

        Assert.Contains(risk.CurrentAuthority!.CapturedAuthorityRoots, root => root.Sid.EndsWith("-518", StringComparison.Ordinal));
        Assert.Equal((PathRiskVerdict.UnexpectedRoute, ControlExpectedness.Unexpected),
            (risk.Verdict, risk.Expectedness));
    }

    [Theory]
    [InlineData(PathRequesterFamily.RequesterDacl)]
    [InlineData(PathRequesterFamily.MembershipDacl)]
    public void RiskDeniedQuestionsAreNotEstablishedRatherThanAClaimAboutEveryRoute(PathRequesterFamily family)
    {
        using var reader = Open(PrepareRisk(RiskCapture(
            coreDescriptor: $"O:SYG:SYD:(D;;WD;;;{UserSid})(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})")));
        var risks = ReadRisks(reader).Assessments;
        var denied = Assert.Single(risks, value => value.Family == family);

        Assert.Equal((ControlEvaluationState.NotEstablished, PathRiskVerdict.NotEstablished, PathRiskIssue.AuthorizationNotEstablished),
            (denied.Authorization, denied.Verdict, denied.Issue));
        Assert.Equal(PathRiskVerdict.UnexpectedRoute,
            Assert.Single(risks, value => value.Family == PathRequesterFamily.OwnAccountMembership).Verdict);
    }

    [Fact]
    public void RiskUnknownAuthorizationIsNotANegative()
    {
        using var reader = Open(PrepareRisk(RiskCapture(
            coreDescriptor: $"O:SYG:SYD:(D;;WD;;;S-1-5-21-1-2-3-1999)(A;;WD;;;{UserSid})(A;;WD;;;{TargetSid})")));
        var risk = Assert.Single(ReadRisks(reader).Assessments, value => value.Family == PathRequesterFamily.RequesterDacl);

        Assert.Equal((ControlEvaluationState.Unknown, PathRiskVerdict.Unknown, PathRiskIssue.AuthorizationUnknown),
            (risk.Authorization, risk.Verdict, risk.Issue));
    }

    [Fact]
    public void RiskUnknownCurrentAuthorityIsNotExpected()
    {
        using var reader = Open(PrepareRisk(RiskCapture(missingMembership: true)));
        var risk = Assert.Single(ReadRisks(reader).Assessments, value => value.Family == PathRequesterFamily.RequesterDacl);
        Assert.Equal(ControlEvaluationState.Established, risk.Authorization);

        Assert.Equal((PathRiskVerdict.Unknown, ControlExpectedness.Unknown, PathRiskIssue.AuthorityUnknown),
            (risk.Verdict, risk.Expectedness, risk.Issue));
        Assert.NotEqual(MembershipRouteIncompleteReason.None, risk.CurrentAuthority!.MembershipLimitations);
    }

    [Fact]
    public void RiskPreservesQuestionsNotChosenForTheDisplayedRoute()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        Assert.DoesNotContain(reader.ReadTier0Path(UserDn).Steps, step => step.MembershipDaclRequest is not null);
        var risk = ReadRisks(reader);

        Assert.Equal(3, risk.Assessments.Count);
        var membership = Assert.Single(risk.Assessments, value => value.Family == PathRequesterFamily.OwnAccountMembership);
        Assert.Equal(TargetDn, membership.TargetDn);
        Assert.Equal(CoreDn, membership.ReachedTarget?.DistinguishedName);
        Assert.Empty(reader.Read().Findings);
    }

    [Fact]
    public void RiskReadbackIsPassiveAndUsesOnlySavedSelectedResults()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        var expected = ReadRisks(reader);
        Assert.Equal(3, expected.Assessments.Count);
        var before = Snapshot(directory);
        var derivation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value;
        using (var evidenceLock = new FileStream(BundleLayout.EvidencePath(directory), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        using (var derivedLock = new FileStream(BundleLayout.AnalysisGenerationDataPath(directory, derivation.Kind, derivation.GenerationId),
            FileMode.Open, FileAccess.ReadWrite, FileShare.None))
        {
            var actual = ReadRisks(reader);
            Assert.Equal(JsonSerializer.Serialize(expected, ProofSerialization.Options), JsonSerializer.Serialize(actual, ProofSerialization.Options));
        }
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void RiskRetainsInputGenerationsAndCurrentMembershipBinding()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        var risk = ReadRisks(reader);
        using var sources = ControlProofVerification.OpenSources(reader);
        var current = sources.Facts.ProtectedPrincipals.Value!.Lookup(UserSid, null)!;

        Assert.Equal(3, risk.Assessments.Count);
        Assert.All(risk.Assessments, value =>
        {
            Assert.Equal((reader.Description.GenerationId, reader.Description.DerivationGenerationId, reader.Description.EvidenceSeal),
                (value.GenerationId, value.DerivationGenerationId, value.EvidenceSeal));
            Assert.Equal(Tier0PathCalculation.Fingerprint(current.MembershipRoutes), value.CurrentAuthority!.MembershipFingerprint);
            Assert.Equal(risk.BatchCoverage.DerivationSeal, value.CurrentAuthority.DerivationSeal);
            Assert.Equal(UserSid, value.CurrentAuthority.Principal.Sid);
            Assert.Equal(sources.Facts.ProtectedPrincipals.Value.CatalogueVersion, value.CurrentAuthority.MembershipCatalogueVersion);
        });
    }

    [Fact]
    public void RiskUnavailableInputsAndUnrequestedQuestionsRemainDistinct()
    {
        var unavailable = RiskCapture();
        JudgeCoverage(unavailable);
        using var first = Open(unavailable);
        Assert.Equal(PathRiskAvailability.InputsUnavailable, ReadRisks(first).BatchCoverage.Availability);
        Assert.Equal(PathRiskReadVerdict.InputsUnavailable, ReadRisks(first).Verdict);

        var unrequested = RiskCapture();
        Derive(unrequested);
        Judge(unrequested, []);
        using var second = Open(unrequested);
        Assert.Equal(PathRiskAvailability.NotRequested, ReadRisks(second).BatchCoverage.Availability);
        Assert.Equal(PathRiskReadVerdict.NotRequested, ReadRisks(second).Verdict);
    }

    [Fact]
    public void RiskEmptySupportedSelectionIsNotUnrequestedOrAWholeForestNegative()
    {
        var directory = Capture(descriptor: "O:SYG:SYD:", membershipTail: false);
        Derive(directory);
        JudgeCoverage(directory);
        using var reader = Open(directory);
        var risk = ReadRisks(reader);

        Assert.Equal(PathRiskAvailability.Recorded, risk.BatchCoverage.Availability);
        Assert.True(risk.BatchCoverage.AutomaticSelectionRequested);
        Assert.Empty(risk.Assessments);
        Assert.Equal(PathRiskReadVerdict.NoRecordedQuestions, risk.Verdict);
        Assert.Equal(0, risk.BatchCoverage.Families.Sum(value => value.Questions));
    }

    [Fact]
    public void RiskRefusesAChangedDerivationRatherThanRequalifying()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        ReadRisks(reader);
        Derive(directory);

        Assert.Throws<InvalidOperationException>(() => reader.ReadPathRequesterRisks(UserDn, CancellationToken.None));
    }

    [Fact]
    public void RiskReadHonorsCancellation()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();

        Assert.Throws<OperationCanceledException>(() => reader.ReadPathRiskCoverage(stopping.Token));
    }

    [Fact]
    public void RiskExplicitCaseEquivalentRequesterRetainsItsCapturedIdentity()
    {
        var directory = RiskCapture();
        Derive(directory);
        Judge(directory, [new(UserDn.ToUpperInvariant(), TargetDn)]);
        using var reader = Open(directory);
        var risk = Assert.Single(ReadRisks(reader).Assessments);

        Assert.Equal(PathRiskVerdict.UnexpectedRoute, risk.Verdict);
        Assert.Equal(UserSid, risk.CurrentAuthority?.Principal.Sid);
    }

    [Fact]
    public void RiskMissingSavedContinuationIsUnresolvedEvenWhenMembershipIsObtainable()
    {
        var directory = Capture(membershipTail: false, daclTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);
        var risk = Assert.Single(ReadRisks(reader).Assessments);

        Assert.Equal((ControlEvaluationState.Established, PathRiskVerdict.Unknown, PathRiskIssue.ContinuationUnavailable),
            (risk.Authorization, risk.Verdict, risk.Issue));
    }

    [Fact]
    public void RiskReaderDoesNotReturnAnotherRequestersQuestions()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        var expected = ReadRisks(reader).BatchCoverage;
        var other = reader.ReadPathRequesterRisks("CN=Other,DC=contoso,DC=com", CancellationToken.None);

        Assert.Empty(other.Assessments);
        Assert.Equal(PathRiskReadVerdict.NoRecordedQuestions, other.Verdict);
        Assert.Equal(expected.Families, other.BatchCoverage.Families);
    }

    [Fact]
    public void RiskReferencesTheOriginalSavedProofWithoutReplacingIt()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof FROM tier0_path_calculation WHERE id=1";
        using var header = JsonDocument.Parse((string)command.ExecuteScalar()!);
        var risks = ReadRisks(reader).Assessments;

        Assert.Equal(Tier0PathCalculation.Fingerprint(header.RootElement.GetProperty("Requesters")[0]
                .Deserialize<SavedRequesterDaclProof>(ProofSerialization.Options)),
            risks.Single(value => value.Family == PathRequesterFamily.RequesterDacl).SourceProofFingerprint);
        Assert.Equal(Tier0PathCalculation.Fingerprint(header.RootElement.GetProperty("OwnAccounts")[0]
                .Deserialize<SavedOwnAccountMembershipProof>(ProofSerialization.Options)),
            risks.Single(value => value.Family == PathRequesterFamily.OwnAccountMembership).SourceProofFingerprint);
        Assert.Equal(Tier0PathCalculation.Fingerprint(header.RootElement.GetProperty("MembershipDacls")[0]
                .Deserialize<SavedMembershipDaclProof>(ProofSerialization.Options)),
            risks.Single(value => value.Family == PathRequesterFamily.MembershipDacl).SourceProofFingerprint);
    }

    [Fact]
    public void RiskCancellationAfterAStoredQuestionRollsBackTheWholeCalculation()
    {
        var directory = PrepareRisk(RiskCapture());
        using var reader = Open(directory);
        using var connection = RiskDatabase(reader, writableCopy: true);
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM path_requester_risk; DELETE FROM path_risk_product; DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation";
        command.ExecuteNonQuery();
        using var stopping = new CancellationTokenSource();
        var inserted = 0;
        connection.CreateFunction("stop_risk_test", () => { inserted++; stopping.Cancel(); return 1; });
        command.CommandText = "CREATE TRIGGER stop_after_risk AFTER INSERT ON path_requester_risk BEGIN SELECT stop_risk_test(); END";
        command.ExecuteNonQuery();
        using var sources = ControlProofVerification.OpenSources(reader);

        Assert.Throws<OperationCanceledException>(() => Tier0PathStorage.Write(connection, reader.Description,
            sources, [], [], stopping.Token, [], true, _ => { }));

        Assert.Equal(1, inserted);
        command.CommandText = "SELECT (SELECT COUNT(*) FROM path_requester_risk)+(SELECT COUNT(*) FROM path_risk_product)+(SELECT COUNT(*) FROM tier0_path_node)+(SELECT COUNT(*) FROM tier0_path_calculation)";
        Assert.Equal(0L, command.ExecuteScalar());
        Assert.Equal(reader.Description.GenerationId, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void RiskPublicationRefusesAMissingAssessment()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: true);
        PathRequesterRiskStorage.RequirePublishable(connection);
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM path_requester_risk WHERE id=(SELECT MIN(id) FROM path_requester_risk)";
        Assert.Equal(1, command.ExecuteNonQuery());

        Assert.Throws<InvalidDataException>(() => PathRequesterRiskStorage.RequirePublishable(connection));
    }

    [Theory]
    [InlineData("$.GenerationId", "11111111-1111-1111-1111-111111111111")]
    [InlineData("$.DerivationGenerationId", "11111111-1111-1111-1111-111111111111")]
    [InlineData("$.EvidenceSeal", "changed")]
    [InlineData("$.CalculationFingerprint", "changed")]
    [InlineData("$.RequesterDn", "CN=Other,DC=contoso,DC=com")]
    [InlineData("$.TargetDn", "CN=Other,DC=contoso,DC=com")]
    [InlineData("$.CurrentAuthority.DerivationSeal", "changed")]
    public void RiskRejectsChangedBindingsEvenWhenTheRowHashIsRefreshed(string path, string value)
    {
        var directory = PrepareRisk(RiskCapture());
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE path_requester_risk SET proof=json_set(proof,$path,$value)";
            command.Parameters.AddWithValue("$path", path);
            command.Parameters.AddWithValue("$value", value);
            command.ExecuteNonQuery();
            command.CommandText = "SELECT id,proof FROM path_requester_risk";
            var rows = new List<(long Id, string Proof)>();
            using (var read = command.ExecuteReader()) while (read.Read()) rows.Add((read.GetInt64(0), read.GetString(1)));
            foreach (var row in rows)
            {
                command.CommandText = "UPDATE path_requester_risk SET fingerprint=$hash WHERE id=$id";
                command.Parameters.Clear();
                command.Parameters.AddWithValue("$hash", SHA256.HashData(Encoding.UTF8.GetBytes(row.Proof)));
                command.Parameters.AddWithValue("$id", row.Id);
                command.ExecuteNonQuery();
            }
        });
        using var reader = Open(directory);

        Assert.Throws<InvalidDataException>(() => reader.ReadPathRequesterRisks(UserDn, CancellationToken.None));
    }

    private string RiskCapture(bool currentAdministrator = false, bool schemaAdministrator = false,
        bool missingMembership = false, string? coreDescriptor = null) =>
        Capture(members: currentAdministrator ? [UserDn] : [],
            coreDescriptor: coreDescriptor ?? $"O:SYG:SYD:(A;;WD;;;{TargetSid})(A;;WD;;;{UserSid})",
            userAttributes: missingMembership
                ? [Text("userAccountControl", "512"), Text("primaryGroupID", "513"), Text("memberOf", "CN=Missing,DC=contoso,DC=com")]
                : null,
            additional: (writer, domain) =>
            {
                Write(writer, domain, "CN=Domain Users,DC=contoso,DC=com", ["top", "group"], "S-1-5-21-1-2-3-513",
                    [Text("groupType", "-2147483646")], "O:SYG:SYD:");
                var configuration = new PartitionCoverage("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration,
                    "dc01.contoso.com", ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                writer.WriteCoverage(configuration);
                Write(writer, configuration, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=contoso,DC=com",
                    ["top", "nTDSService"], null, [Text("dSHeuristics", "0")], "O:SYG:SYD:");
                if (schemaAdministrator)
                    Write(writer, domain, "CN=Schema Admins,DC=contoso,DC=com", ["top", "group"], "S-1-5-21-1-2-3-518",
                        [Text("groupType", "-2147483640"), Text("member", UserDn)], "O:SYG:SYD:");
            });

    private static string PrepareRisk(string directory)
    {
        Derive(directory);
        JudgeCoverage(directory);
        return directory;
    }

    private static PathRequesterRiskSet ReadRisks(JudgementReader reader)
    {
        PathRequesterRiskSet? result = null;
        var error = Record.Exception(() => result = reader.ReadPathRequesterRisks(UserDn, CancellationToken.None));
        Assert.Null(error);
        return Assert.IsType<PathRequesterRiskSet>(result);
    }

    private static SqliteConnection RiskDatabase(JudgementReader reader, bool writableCopy)
    {
        var path = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId);
        if (writableCopy)
        {
            var copy = Path.Combine(reader.BundleDirectory, "risk-working-" + Guid.NewGuid().ToString("N") + ".db");
            File.Copy(path, copy);
            path = copy;
        }
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Pooling = false, Mode = writableCopy ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
        }.ToString());
        connection.Open();
        return connection;
    }
}
