using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReuseSelectorMatchesThePriorVerifiedSelectionOnSealedEvidence(bool expectedAdministration)
    {
        using var reader = Open(PrepareSec071(RiskCapture(currentAdministrator: expectedAdministration)));
        using var connection = RiskDatabase(reader, writableCopy: false);
        using var sources = ControlProofVerification.OpenSources(reader);
        var inputs = reader.ReadPathInputs();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT proof FROM tier0_path_node ORDER BY target";
        var nodes = new Dictionary<string, Tier0PathNode>(StringComparer.OrdinalIgnoreCase);
        using (var read = command.ExecuteReader())
            while (read.Read())
            {
                var node = JsonSerializer.Deserialize<Tier0PathNode>(read.GetString(0), ProofSerialization.Options)!;
                nodes.Add(node.Subject.DistinguishedName, node);
            }
        var expected = new RequesterSelectionReference(sources.Bundle.ReadObjectAttributes, sources.Bundle.ReadPermissions,
            inputs, nodes, sources.ReadNamingContexts().Value, CancellationToken.None).Select() with { Version = PathRequesterSelector.Version };
        var saved = reader.ReadTier0Path(UserDn).RequesterSelection;
        Assert.Equal(3, expected.Candidates.Count);
        Assert.Equal(Tier0PathCalculation.Fingerprint(expected), Tier0PathCalculation.Fingerprint(saved));
        var proofs = PathProofVerification.ReadPath(reader, UserDn);
        Assert.Equal((1, 1, 1), (proofs.RequesterAssessments.Count, proofs.OwnAccountAssessments.Count, proofs.MembershipDaclAssessments.Count));
        var findings = reader.Read().Findings.Where(value => value.RuleId == "SEC-071").ToArray();
        Assert.Equal(expectedAdministration ? 0 : 1, findings.Length);
        if (!expectedAdministration)
        {
            var evidence = Assert.IsType<Tier0RouteFindingEvidence>(findings[0].Evidence);
            Assert.Equal((3, reader.Description.GenerationId, reader.Description.EvidenceSeal),
                (evidence.UnexpectedChecks, evidence.GenerationId, evidence.EvidenceSeal));
            Assert.Equal(Tier0PathCalculation.Fingerprint(ReadRisks(reader).Assessments), evidence.QualificationFingerprint);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(300)]
    public void ReuseAnswerMatchingEnumeratesEachProofOnceRegardlessOfNodeCount(int objectCount)
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: false);
        var saved = PathRequesterRiskStorage.ReadProofs(connection, reader.Description, CancellationToken.None);
        var direct = new RequesterReuseTests.CountingList<SavedRequesterDaclProof>(saved.Requesters);
        var own = new RequesterReuseTests.CountingList<SavedOwnAccountMembershipProof>(saved.OwnAccounts);
        var combined = new RequesterReuseTests.CountingList<SavedMembershipDaclProof>(saved.MembershipDacls);
        var index = new PathRequesterRouteIndex();
        index.AddRequesters(direct, CancellationToken.None, null);
        index.AddOwnAccounts(own, CancellationToken.None, null);
        index.AddMembershipDacls(combined, CancellationToken.None, null);
        var principal = saved.Requesters[0].Assessment.Requester!;
        var selected = 0;
        for (var objectIndex = 0; objectIndex < objectCount; objectIndex++)
        {
            var subject = objectIndex == 0 ? principal : principal with { ObjectGuid = Guid.NewGuid(), DistinguishedName = $"CN=Other{objectIndex},DC=contoso,DC=com" };
            var node = new Tier0PathNode(subject, null, null, null, null);
            if (index.Requester(node) is not null) selected++;
            index.OwnAccount(node);
            index.MembershipDacl(node);
        }
        Assert.Equal(1, selected);
        Assert.Equal((saved.Requesters.Count, saved.OwnAccounts.Count, saved.MembershipDacls.Count), (direct.Visits, own.Visits, combined.Visits));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("zero")]
    [InlineData("terminal")]
    [InlineData("existing")]
    [InlineData("different-identity")]
    public void ReuseAnswerMatchingRetainsThePriorOrderingAndPrecedence(string variant)
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: false);
        var saved = PathRequesterRiskStorage.ReadProofs(connection, reader.Description, CancellationToken.None);
        var initial = saved.Requesters[0];
        var principal = initial.Assessment.Requester!;
        var direct = new[]
        {
            initial with { Assessment = initial.Assessment with { Request = new(UserDn, "CN=Z"), Steps = Repeat(initial.Assessment.Steps, 3) } },
            initial with { Assessment = initial.Assessment with { Request = new(UserDn, "CN=A"), Steps = Repeat(initial.Assessment.Steps, 3) } },
            initial with { Assessment = initial.Assessment with { Request = new(UserDn, "CN=Denied"), Authorization = ControlEvaluationState.NotEstablished, Steps = [] } },
        };
        var own = new[]
        {
            saved.OwnAccounts[0] with { Assessment = saved.OwnAccounts[0].Assessment with { Request = new(UserDn, "CN=Z") }, Steps = Repeat(saved.OwnAccounts[0].Steps, 2) },
            saved.OwnAccounts[0] with { Assessment = saved.OwnAccounts[0].Assessment with { Request = new(UserDn, "CN=A") }, Steps = Repeat(saved.OwnAccounts[0].Steps, 2) },
            saved.OwnAccounts[0] with { Assessment = saved.OwnAccounts[0].Assessment with { Request = new(UserDn, "CN=Empty") }, Steps = [] },
        };
        var combined = new[]
        {
            saved.MembershipDacls[0] with { Assessment = saved.MembershipDacls[0].Assessment with { Request = new(UserDn, "CN=Z", CoreDn), Steps = Repeat(saved.MembershipDacls[0].Assessment.Steps, 1) } },
            saved.MembershipDacls[0] with { Assessment = saved.MembershipDacls[0].Assessment with { Request = new(UserDn, "CN=A", CoreDn), Steps = Repeat(saved.MembershipDacls[0].Assessment.Steps, 1) } },
        };
        var node = new Tier0PathNode(variant == "different-identity" ? principal with { ObjectGuid = Guid.NewGuid() } : principal,
            variant == "zero" ? 0 : variant == "existing" ? 3 : null, null,
            variant == "terminal" ? initial.Assessment.Steps[^1] : null, null);
        var expected = ReferenceMatch(node, direct, own, combined);
        var index = new PathRequesterRouteIndex();
        index.AddRequesters(direct, CancellationToken.None, null);
        node = node with { RequesterRoute = index.Requester(node) };
        index.AddOwnAccounts(own, CancellationToken.None, null);
        node = node with { OwnAccountRoute = index.OwnAccount(node) };
        index.AddMembershipDacls(combined, CancellationToken.None, null);
        node = node with { MembershipDaclRoute = index.MembershipDacl(node) };

        Assert.Equal(expected, node);
        if (variant == "none") Assert.Equal(("CN=A", "CN=A", "CN=A"),
            (node.RequesterRoute!.TargetDn, node.OwnAccountRoute!.TargetDn, node.MembershipDaclRoute!.GroupDn));
        if (variant is "zero" or "terminal" or "different-identity")
            Assert.Equal((null, null, null), (node.RequesterRoute, node.OwnAccountRoute, node.MembershipDaclRoute));
    }

    [Fact]
    public void ReuseAnswerIndexDoesNotCollapseSelfMembershipAndWriteMembers()
    {
        using var reader = Open(PrepareRisk(RiskCapture()));
        using var connection = RiskDatabase(reader, writableCopy: false);
        var saved = PathRequesterRiskStorage.ReadProofs(connection, reader.Description, CancellationToken.None);
        var own = saved.OwnAccounts[0];
        var ordinary = own with { Assessment = own.Assessment with
        { Request = own.Assessment.Request with { PermissionKind = OwnAccountMembershipPermissionKind.WriteMembers } } };
        var node = new Tier0PathNode(own.Assessment.Requester!, null, null, null, null);
        var index = new PathRequesterRouteIndex();
        index.AddOwnAccounts([ordinary, own], CancellationToken.None, null);

        Assert.Equal(OwnAccountMembershipPermissionKind.SelfMembership, index.OwnAccount(node)!.PermissionKind);
        Assert.Equal(ReferenceMatch(node, [], [ordinary, own], []).OwnAccountRoute, index.OwnAccount(node));
    }

    [Fact]
    public void ReuseProgressReportsSelectionAndEveryMatchingFamilyWithoutObjectData()
    {
        var directory = RiskCapture();
        Derive(directory);
        var log = new RecordingRunLog();
        JudgeCoverage(directory, log: log);
        using var reader = Open(directory);
        var completed = log.Saying("post-pass status").Where(value => RecordingRunLog.Value(value, "outcome") == "completed"
            && RecordingRunLog.Value(value, "stage") is "Selecting account checks" or "Matching saved answers").ToArray();

        Assert.Equal(4, completed.Length);
        Assert.All(completed, value => Assert.Equal(reader.Description.GenerationId.ToString("D"), RecordingRunLog.Value(value, "generation")));
        var selection = Assert.Single(completed, value => RecordingRunLog.Value(value, "stage") == "Selecting account checks");
        Assert.Equal("3", RecordingRunLog.Value(selection, "distinctQuestions"));
        Assert.Equal(RecordingRunLog.Value(selection, "resourcesTotal"), RecordingRunLog.Value(selection, "resourcesProcessed"));
        Assert.Equal(RecordingRunLog.Value(selection, "resourcesTotal"), RecordingRunLog.Value(selection, "resourcesFingerprinted"));
        Assert.All(completed.Where(value => RecordingRunLog.Value(value, "stage") == "Matching saved answers"), value =>
        {
            Assert.Equal(("1", "1", "execution-only"), (RecordingRunLog.Value(value, "answersTotal"),
                RecordingRunLog.Value(value, "answersProcessed"), RecordingRunLog.Value(value, "kind")));
            Assert.Equal(RecordingRunLog.Value(value, "objectsTotal"), RecordingRunLog.Value(value, "objectsProcessed"));
        });
        foreach (var line in log.Saying("post-pass status").Concat(log.Saying("post-pass part")))
        {
            var text = JsonSerializer.Serialize(line);
            Assert.DoesNotContain(UserDn, text);
            Assert.DoesNotContain("S-1-5-", text);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ReuseInterruptedSelectionIsNotLoggedAsCompletedAndRetainsThePublishedRun(bool cancelled)
    {
        var directory = PrepareRisk(RiskCapture());
        var before = File.ReadAllText(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement));
        using var stopping = new CancellationTokenSource();
        var log = new ReuseStopLog(directory, stopping, cancelled);
        var failure = Record.Exception(() => JudgeCoverage(directory, cancellationToken: stopping.Token, log: log));

        Assert.NotNull(failure);
        Assert.Equal(cancelled ? "cancelled" : "failed", log.Outcome);
        Assert.Equal(before, File.ReadAllText(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement)));
    }

    private sealed class ReuseStopLog(string directory, CancellationTokenSource stopping, bool cancel) : IRunLog
    {
        internal string? Outcome { get; private set; }
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            var fields = detail.ToDictionary(value => value.Name, value => value.Value);
            if (message != "post-pass status" || fields.GetValueOrDefault("stage") != "Selecting account checks") return;
            Outcome = fields.GetValueOrDefault("outcome");
            if (Outcome != "started") return;
            if (cancel) stopping.Cancel();
            else
            {
                // Refuse changed source generations inside the operation, without deleting the old evidence.
                File.WriteAllText(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation), "synthetic changed source selection");
            }
        }
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) { }
    }

    private static Tier0PathStep[] Repeat(IReadOnlyList<Tier0PathStep> steps, int count) =>
        Enumerable.Range(0, count).Select(index => steps[index % steps.Count]).ToArray();

    private static Tier0PathNode ReferenceMatch(Tier0PathNode node, IReadOnlyList<SavedRequesterDaclProof> direct,
        IReadOnlyList<SavedOwnAccountMembershipProof> own, IReadOnlyList<SavedMembershipDaclProof> combined)
    {
        node = node with { RequesterRoute = RequesterRouteReference.Requester(node, direct) };
        node = node with { OwnAccountRoute = RequesterRouteReference.OwnAccount(node, own, direct) };
        return node with { MembershipDaclRoute = RequesterRouteReference.MembershipDacl(node, combined, direct, own) };
    }
}
