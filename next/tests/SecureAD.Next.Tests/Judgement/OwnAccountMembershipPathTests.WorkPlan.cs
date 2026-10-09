using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
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
    public void WorkPlanPreservesEveryAnswerAndOrderedWitnessFromTheIndependentProducers(string variant)
    {
        using var fixture = PrerequisiteFixtureFor(variant);
        var selection = RequesterSelectionEvaluation.Select(fixture.Sources.Bundle.ReadObjectAttributes,
            fixture.Sources.Bundle.ReadPermissions, fixture.Inputs, fixture.Nodes,
            fixture.Sources.ReadNamingContexts().Value, CancellationToken.None, null, fixture.Memberships);
        var requests = PathRequesterSelector.Requests(selection);
        Assert.NotEmpty(requests);
        var direct = TargetPermissionReference.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, requests, CancellationToken.None, null, fixture.Memberships,
            currentSourceFingerprints: true);
        var own = MembershipPrerequisiteReference.OwnAccounts(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, PathRequesterSelector.OwnAccounts(selection),
            CancellationToken.None, currentSourceFingerprints: true);
        var combined = MembershipPrerequisiteReference.Combined(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, fixture.Nodes, PathRequesterSelector.MembershipDacls(selection),
            CancellationToken.None, fixture.Memberships, currentSourceFingerprints: true);

        RewriteRequesterWork(fixture);

        var actual = PathRequesterRiskStorage.ReadProofs(fixture.Connection, fixture.Description, CancellationToken.None);
        Assert.Equal(WorkJson(direct), WorkJson(actual.Requesters));
        Assert.Equal(WorkJson(own), WorkJson(actual.OwnAccounts));
        Assert.Equal(WorkJson(combined), WorkJson(actual.MembershipDacls));
        var manifest = PathCalculationStorage.Read(fixture.Connection, fixture.Description, CancellationToken.None)!;
        Assert.Equal(WorkJson(selection), WorkJson(PathCalculationStorage.ReadSelection(
            fixture.Connection, fixture.Description, manifest, CancellationToken.None)));
        PathCalculationStorage.RequirePublishable(fixture.Connection, fixture.Description, CancellationToken.None);
    }

    [Fact]
    public void WorkPlanPreparesOneTargetForCapturedAndObtainedRequesterContexts()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", 4);
        using var trace = new JudgingInputReuseTests.Statements(fixture.Connection);

        RewriteRequesterWork(fixture);
        var sql = trace.Sql.ToArray();

        Assert.Single(sql.Where(value => value.StartsWith("SELECT id FROM control_edge WHERE target=", StringComparison.Ordinal)
            && value.Contains("capability='CanWriteDacl'", StringComparison.Ordinal)));
        Assert.Equal(6, sql.Count(IsMembershipEdgeQuery));
        var proofs = PathRequesterRiskStorage.ReadProofs(fixture.Connection, fixture.Description, CancellationToken.None);
        Assert.NotEmpty(proofs.Requesters);
        Assert.Equal(24, proofs.OwnAccounts.Count);
        Assert.Equal(8, proofs.MembershipDacls.Count);
        Assert.Equal(WorkJson(proofs.OwnAccounts.Select(value => value.Assessment.Request).OrderBy(OwnAccountMembershipProofs.Key, StringComparer.Ordinal)),
            WorkJson(proofs.OwnAccounts.Select(value => value.Assessment.Request)));
    }

    [Fact]
    public void WorkPlanSharesDecodedPrerequisitesWithinSixtyFourQuestionsAndReleasesEachPage()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", 83);
        using var trace = new JudgingInputReuseTests.Statements(fixture.Connection);

        RewriteRequesterWork(fixture);
        var sql = trace.Sql.ToArray();

        using var query = fixture.Connection.CreateCommand();
        query.CommandText = "SELECT proof FROM path_shared_proof WHERE kind='SchemaEvidence'";
        using var read = query.ExecuteReader();
        Assert.True(read.Read());
        var schema = read.GetInt64(0).ToString(CultureInfo.InvariantCulture);
        Assert.False(read.Read());
        var pattern = @"\bFROM path_shared_proof WHERE proof=" + schema + @"\s*;?\s*$";
        Assert.Equal(3, sql.Count(value => Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant)));
        var manifest = PathCalculationStorage.Read(fixture.Connection, fixture.Description, CancellationToken.None)!;
        Assert.Equal((1, 498, 166), (manifest.RequesterCount, manifest.OwnAccountCount, manifest.MembershipDaclCount));
        Assert.Equal(665, manifest.Work.Count);
    }

    [Theory]
    [InlineData("source_fingerprint")]
    [InlineData("canonical_fingerprint")]
    public void WorkPlanRefusesAnAlteredPreparedMembershipReceipt(string column)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var transaction = fixture.Connection.BeginTransaction();
        using var statements = new PreparedStatements(fixture.Connection);
        using var proofs = new PathProofStorage.Writer(fixture.Connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(fixture.Connection, fixture.Description, CancellationToken.None, proofs, transaction, statements);
        using var plan = new PathRequesterWorkPlan(fixture.Connection, transaction, fixture.Description, fixture.Sources, CancellationToken.None);
        var request = new OwnAccountMembershipRequest(UserDn, TargetDn);
        plan.Write([], [request], []);
        var original = Assert.Single(fixture.Prerequisites.PrepareResource(TargetDn, [request]));
        plan.SaveMembership(original, shared.PrepareOwnAccount(original.Assessment));
        using var corrupt = fixture.Connection.CreateCommand();
        corrupt.Transaction = transaction;
        corrupt.CommandText = "UPDATE temp.path_membership_prerequisite SET " + column + "=$value";
        corrupt.Parameters.AddWithValue("$value", new string('f', 64));
        Assert.Equal(1, corrupt.ExecuteNonQuery());

        Assert.Throws<InvalidDataException>(() => plan.ReadMembership(request, shared));
    }

    [Fact]
    public void WorkPlanPreparedReferencesCannotMoveToAnotherWriter()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        using var transaction = fixture.Connection.BeginTransaction();
        using var statements = new PreparedStatements(fixture.Connection);
        using var proofs = new PathProofStorage.Writer(fixture.Connection, transaction, CancellationToken.None);
        var first = new PathSharedProofStorage(fixture.Connection, fixture.Description, CancellationToken.None, proofs, transaction, statements);
        var second = new PathSharedProofStorage(fixture.Connection, fixture.Description, CancellationToken.None, proofs, transaction, statements);
        var original = Assert.Single(fixture.Prerequisites.PrepareResource(TargetDn, [new(UserDn, TargetDn)]));
        var reference = first.PrepareOwnAccount(original.Assessment);

        Assert.Throws<InvalidDataException>(() => second.WriteSource(original, reference));
    }

    [Fact]
    public void WorkPlanSelectedReadRefusesAQuestionWhoseResourceWasChanged()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        RewriteRequesterWork(fixture);
        using var corrupt = fixture.Connection.CreateCommand();
        corrupt.CommandText = "UPDATE path_requester_work SET target=$wrong WHERE family='RequesterDacl'";
        corrupt.Parameters.AddWithValue("$wrong", OtherGroupDn);
        Assert.Equal(1, corrupt.ExecuteNonQuery());

        Assert.Throws<InvalidDataException>(() => PathRequesterRiskStorage.ReadSelectedQuestion(fixture.Connection,
            fixture.Description, UserDn, PathRequesterFamily.RequesterDacl, CoreDn, null, null, CancellationToken.None));
    }

    [Fact]
    public void WorkPlanSelectedReadDoesNotInspectAnotherAccountsWorkButPublicationDoes()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        RewriteRequesterWork(fixture);
        using var corrupt = fixture.Connection.CreateCommand();
        corrupt.CommandText = "UPDATE path_requester_work SET target=$wrong WHERE requester=$other";
        corrupt.Parameters.AddWithValue("$wrong", "CN=Unrelated,DC=contoso,DC=com");
        corrupt.Parameters.AddWithValue("$other", OtherRequesterDn);
        Assert.True(corrupt.ExecuteNonQuery() > 0);

        var selected = PathRequesterRiskStorage.ReadSelectedQuestion(fixture.Connection, fixture.Description,
            UserDn, PathRequesterFamily.RequesterDacl, CoreDn, null, null, CancellationToken.None);

        Assert.Equal(ControlEvaluationState.Established, selected.Requester!.Authorization);
        Assert.Throws<InvalidDataException>(() =>
            PathCalculationStorage.RequirePublishable(fixture.Connection, fixture.Description, CancellationToken.None));
    }

    [Fact]
    public void WorkPlanPublicationRequiresTheExactAutomaticSelectionQuestionSet()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        RewriteRequesterWork(fixture);
        var manifest = PathCalculationStorage.Read(fixture.Connection, fixture.Description, CancellationToken.None)!;
        Assert.NotNull(manifest.Selection);
        Assert.True(manifest.Selection.Candidates.Count > 0);
        using var corrupt = fixture.Connection.CreateCommand();
        corrupt.CommandText = "DELETE FROM path_requester_work WHERE id=1";
        Assert.Equal(1, corrupt.ExecuteNonQuery());

        Assert.Throws<InvalidDataException>(() => PathRequesterWorkPlan.RequireSelectionMatchesWork(fixture.Connection));
    }

    [Fact]
    public void WorkPlanSelectedReadRefusesAReorderedSavedAnswer()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        RewriteRequesterWork(fixture);
        using var corrupt = fixture.Connection.CreateCommand();
        corrupt.CommandText = "UPDATE path_requester_risk SET id=999999 WHERE id=1";
        Assert.Equal(1, corrupt.ExecuteNonQuery());

        Assert.Throws<InvalidDataException>(() => PathRequesterRiskStorage.ReadSelectedQuestion(fixture.Connection,
            fixture.Description, UserDn, PathRequesterFamily.RequesterDacl, CoreDn, null, null, CancellationToken.None));
    }

    [Fact]
    public void WorkPlanBestRouteTiesUseCanonicalQuestionOrderRatherThanBatchArrival()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var proof = Assert.Single(fixture.Combined([new(UserDn, TargetDn, CoreDn)]));
        Assert.Equal(ControlEvaluationState.Established, proof.Assessment.Authorization);
        var canonical = new BestSupportedRouteSelection(fixture.Connection, fixture.Description, fixture.Inputs, CancellationToken.None);
        var batched = new BestSupportedRouteSelection(fixture.Connection, fixture.Description, fixture.Inputs, CancellationToken.None);
        canonical.Proof(proof, 100, new string('a', 64), 1);
        canonical.Proof(proof, 200, new string('b', 64), 2);
        batched.Proof(proof, 200, new string('b', 64), 2);
        batched.Proof(proof, 100, new string('a', 64), 1);
        var recorded = OwnershipAuditStorage.Targets(fixture.Connection);

        Assert.Equal(WorkJson(canonical.Results(recorded, new string('c', 64))),
            WorkJson(batched.Results(recorded, new string('c', 64))));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void WorkPlanInterruptedAfterSavedPrerequisitesPreservesThePreviousPublishedGeneration(bool cancel)
    {
        var directory = CoveragePrepared();
        var previous = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        var path = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, previous);
        var fingerprint = BundleSealing.HashFile(path);
        using var stopping = new CancellationTokenSource();
        var progress = new StopCoveragePhase(PathRequesterWorkPhase.MembershipDacl, () =>
        {
            if (cancel) stopping.Cancel();
            else throw new InvalidOperationException("Injected resource-batch failure.");
        });

        var error = Record.Exception(() => JudgeCoverage(directory, progress, stopping.Token));

        if (cancel) Assert.IsType<OperationCanceledException>(error);
        else Assert.IsType<InvalidOperationException>(error);
        Assert.Equal(previous, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        Assert.Equal(fingerprint, BundleSealing.HashFile(path));
    }

    private static void RewriteRequesterWork(PrerequisiteFixture fixture)
    {
        using (var clear = fixture.Connection.CreateCommand())
        {
            clear.CommandText = """
                DELETE FROM tier0_best_route; DELETE FROM tier0_distance; DELETE FROM tier0_distance_product;
                DELETE FROM path_requester_risk; DELETE FROM path_risk_product;
                DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation;
                """;
            clear.ExecuteNonQuery();
        }
        using var statements = new PreparedStatements(fixture.Connection);
        Tier0PathStorage.Write(fixture.Connection, fixture.Description, fixture.Sources, [], [], CancellationToken.None, [], true,
            _ => { }, null, statements);
    }

    private static string WorkJson<T>(T value) => JsonSerializer.Serialize(value, ProofSerialization.Options);
}
