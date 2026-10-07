using System.Text.Json;
using SecureAD.Derivation;
using SecureAD.Evidence;
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
    public async Task BestRouteLongerExistingMembershipWinsWithoutChangingShortestDistance(string host)
    {
        var directory = BestRouteCapture();
        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        var best = Assert.IsType<SavedBestSupportedRoute>(reader.ReadBestSupportedRoute(UserDn));
        Assert.Equal((RouteFeasibility.Direct, 3, 2),
            (best.Selection.Best!.Grade.Feasibility, best.Selection.Best.Grade.Length,
                reader.ReadTier0ObjectDistance(UserDn)!.Facts.SupportedDistance));
        Assert.All(best.Steps, step => Assert.Equal(Tier0PathStepKind.Membership, step.Kind));
        Assert.True(best.Selection.CompleteCandidates >= 2);
        Assert.Equal(0, best.Selection.UngradedCandidates);
        Assert.Equal(RouteConfidence.High, best.Selection.Best.Grade.Confidence);
        Assert.Empty(best.Selection.Best.Grade.UnmetConditions);
    }

    [Theory]
    [InlineData(OwnAccountMembershipPermissionKind.SelfMembership)]
    [InlineData(OwnAccountMembershipPermissionKind.WriteMembers)]
    public void BestRouteGradesBothObtainedMembershipPermissionsAsConditional(OwnAccountMembershipPermissionKind kind)
    {
        using var reader = Open(ObtainedPrepared("nested", kind));
        var best = reader.ReadBestSupportedRoute(UserDn)!;
        var grade = best.Selection.Best!.Grade;
        Assert.Equal((RouteSourceKind.MembershipDacl, RouteFeasibility.Conditional, 4),
            (best.Selection.Best.Source, grade.Feasibility, grade.Length));
        Assert.Equal(new[] { "MembershipOutcome", "MembershipEnabledForAuthorization" }.Order(StringComparer.Ordinal),
            grade.UnmetConditions.Select(value => value.Kind).Order(StringComparer.Ordinal));
        Assert.All(grade.UnmetConditions, value =>
            Assert.Equal((UserDn, TargetDn), (value.Requester.DistinguishedName, value.Group.DistinguishedName)));
        Assert.Equal(Combined(reader).Steps, best.Steps);
        Assert.Equal(reader.Description.GenerationId, best.Selection.GenerationId);
        Assert.False(best.Coverage.IsComplete);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public void BestRouteComparisonUsesEveryCriterionBeforeLengthOrSignature(int criterion)
    {
        var baseline = new SupportedRouteGrade(RouteEvidenceClass.Definite, RouteFeasibility.Direct, [],
            RouteConfidence.High, 9, "z");
        var subject = new Tier0Target(Guid.NewGuid(), UserDn, "DC=contoso,DC=com", UserSid, "contoso.com", null);
        var condition = new RouteCondition("MembershipOutcome", subject, subject, null);
        var pairs = new[]
        {
            (baseline, baseline with { Evidence = RouteEvidenceClass.Possible, Length = 1, StableSignature = "a" }),
            (baseline, baseline with { Feasibility = RouteFeasibility.Conditional, Length = 1 }),
            (baseline with { Feasibility = RouteFeasibility.Conditional }, baseline with { Feasibility = RouteFeasibility.Potential, Length = 1 }),
            (baseline with { Feasibility = RouteFeasibility.Conditional }, baseline with { Feasibility = RouteFeasibility.Conditional, UnmetConditions = [condition], Length = 1 }),
            (baseline, baseline with { Confidence = RouteConfidence.Low, Length = 1 }),
            (baseline with { Length = 1 }, baseline),
            (baseline with { StableSignature = "a" }, baseline),
        };
        var (better, worse) = pairs[criterion];
        Assert.True(SupportedRouteGrade.Compare(better, worse) < 0);
        Assert.True(SupportedRouteGrade.Compare(worse, better) > 0);
        Assert.Equal(0, SupportedRouteGrade.Compare(baseline, baseline));
    }

    [Fact]
    public void BestRouteAggregationUsesWeakestStepAndDistinctScopedConditions()
    {
        var subject = new Tier0Target(Guid.NewGuid(), UserDn, "DC=contoso,DC=com", UserSid, "contoso.com", null);
        var condition = new RouteCondition("MembershipOutcome", subject, subject, null);
        var high = new SupportedRouteGrade(RouteEvidenceClass.Definite, RouteFeasibility.Direct, [],
            RouteConfidence.High, 1, "a");
        var low = high with { Evidence = RouteEvidenceClass.Possible, Feasibility = RouteFeasibility.Potential,
            Confidence = RouteConfidence.Low, UnmetConditions = [condition, condition] };
        var combined = SupportedRouteGrade.Combine([high, low, high with { UnmetConditions =
            [condition with { Requester = subject with { DistinguishedName = UserDn.ToUpperInvariant() } }] }], "stable");
        Assert.Equal((RouteEvidenceClass.Possible, RouteFeasibility.Potential, RouteConfidence.Low, 3, 1),
            (combined.Evidence, combined.Feasibility, combined.Confidence, combined.Length, combined.UnmetConditions.Count));
        var distinct = SupportedRouteGrade.Combine([low, high with { UnmetConditions = [condition with { ResourceContext = "DC=other" }] }], "stable");
        Assert.Equal(2, distinct.UnmetConditions.Count);
    }

    [Fact]
    public void BestRouteUnknownQuestionIsNotInventedAsAPossiblePath()
    {
        var directory = Capture(schema: false, membershipTail: true);
        Derive(directory);
        Judge(directory, [new(UserDn, TargetDn)]);
        using var reader = Open(directory);
        var best = Assert.IsType<SavedBestSupportedRoute>(reader.ReadBestSupportedRoute(UserDn));
        Assert.Null(best.Selection.Best);
        Assert.Empty(best.Steps);
        Assert.Equal(0, best.Selection.CompleteCandidates);
        Assert.Equal(ControlEvaluationState.Unknown, Assessment(reader).Obtainability);
        Assert.Null(reader.ReadBestSupportedRoute("CN=NotCaptured,DC=contoso,DC=com"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BestRouteRerunKeepsSignatureButRebindsTheSavedGeneration(bool permissionRoute)
    {
        var directory = permissionRoute ? ObtainedCapture("nested", OwnAccountMembershipPermissionKind.SelfMembership) : BestRouteCapture();
        Derive(directory);
        JudgeCoverage(directory);
        BestRouteSelection previous;
        using (var reader = Open(directory)) previous = reader.ReadBestSupportedRoute(UserDn)!.Selection;
        JudgeCoverage(directory);
        using var after = Open(directory);
        var current = after.ReadBestSupportedRoute(UserDn)!.Selection;
        Assert.Equal(previous.Best!.Grade.StableSignature, current.Best!.Grade.StableSignature);
        Assert.Equal(previous.Best.Grade.Length, current.Best.Grade.Length);
        Assert.NotEqual(previous.GenerationId, current.GenerationId);
    }

    [Theory]
    [InlineData("$.GenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("$.CalculationFingerprint", "'" + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" + "'")]
    [InlineData("$.Best.Grade.Length", "99")]
    [InlineData("$.Best.Grade.Feasibility", "'Direct'")]
    [InlineData("$.Best.ProofId", "987654321")]
    [InlineData("$.Best.ReachedTarget.DistinguishedName", "'CN=Wrong,DC=contoso,DC=com'")]
    [InlineData("$.Best.Grade.UnmetConditions", "json('[]')")]
    public void BestRouteSelectedReaderRefusesContradictorySavedGradeOrReference(string path, string value)
    {
        var directory = ObtainedPrepared("nested");
        PathProofVerification.ChangeJson(directory, "tier0_best_route", path, value, $"WHERE target='{UserDn}'");
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadBestSupportedRoute(UserDn));
    }

    [Fact]
    public void BestRouteSelectedReadDoesNotLoadOtherSubjectsOrReplayAnalysis()
    {
        var directory = ObtainedPrepared("nested");
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE tier0_best_route SET fingerprint=zeroblob(32) WHERE target<>$target";
            command.Parameters.AddWithValue("$target", UserDn);
            command.ExecuteNonQuery();
        });
        using var reader = Open(directory);
        var before = Snapshot(directory);
        SavedBestSupportedRoute? best = null;
        Assert.Null(Record.Exception(() => best = reader.ReadBestSupportedRoute(UserDn)));
        Assert.Equal(4, best!.Steps.Count);
        Assert.Equal(before, Snapshot(directory));
        Assert.Throws<InvalidDataException>(() => reader.ReadBestSupportedRoute(CoreDn));
    }

    [Fact]
    public void BestRouteReaderHonorsCancellationAndGenerationChanges()
    {
        var directory = ObtainedPrepared("nested");
        using var reader = Open(directory);
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => reader.ReadBestSupportedRoute(UserDn, stopping.Token));
        Derive(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadBestSupportedRoute(UserDn));
    }

    [Theory]
    [InlineData(false, "MembershipAssumptionUnavailable")]
    [InlineData(true, "UnsupportedStep")]
    public void BestRouteMissingGradingEvidenceIsRetainedRatherThanDefaulted(bool unsupportedStep, string reason)
    {
        using var reader = Open(ObtainedPrepared("nested"));
        var combined = Combined(reader);
        using var connection = RiskDatabase(reader, writableCopy: false);
        var selections = new BestSupportedRouteSelection(connection, reader.Description, reader.ReadPathInputs(), CancellationToken.None);
        object proof = unsupportedStep
            ? new SavedMembershipDaclProof(combined with { Steps = combined.Steps.Select((step, index) =>
                index == 0 ? step with { Kind = (Tier0PathStepKind)999 } : step).ToArray() }, new string('f', 64))
            : new SavedRequesterDaclProof(combined.Dacl!, new string('f', 64));
        selections.Proof(proof, 1, new string('f', 64));
        var row = Assert.Single(selections.Results(OwnershipAuditStorage.Targets(connection), new string('a', 64)),
            value => value.Subject.DistinguishedName == UserDn);
        Assert.Equal((1, 1), (row.CompleteCandidates, row.UngradedCandidates));
        Assert.Equal(reason, Assert.Single(row.GradingLimitations).ToString());
        Assert.Null(row.Best);
    }

    [Fact]
    public void BestRoutePublicationRequiresOneSavedSelectionForEveryRecordedSubject()
    {
        using var reader = Open(ObtainedPrepared("nested"));
        using var connection = RiskDatabase(reader, writableCopy: true);
        BestSupportedRouteStorage.RequirePublishable(connection);
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM tier0_best_route WHERE target=$target";
        command.Parameters.AddWithValue("$target", UserDn);
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => BestSupportedRouteStorage.RequirePublishable(connection));
    }

    [Fact]
    public void BestRouteCancelledPublicationKeepsThePriorSelection()
    {
        var directory = ObtainedPrepared("nested");
        BestRouteSelection previous;
        using (var reader = Open(directory)) previous = reader.ReadBestSupportedRoute(UserDn)!.Selection;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeAudit(directory, [],
            PathRequesterPolicy.SupportedCapturedQuestions, Started, Started, new CancelBeforePublication(stopping),
            SecureAD.Kernel.RunLog.Discarded, stopping.Token, null));
        using var after = Open(directory);
        Assert.Equal(Tier0PathCalculation.Fingerprint(previous),
            Tier0PathCalculation.Fingerprint(after.ReadBestSupportedRoute(UserDn)!.Selection));
    }

    private string BestRouteCapture()
    {
        const string middle = "CN=DirectMiddle,DC=contoso,DC=com";
        return Capture(coreMembers: [TargetDn, middle], additional: (writer, domain) =>
            Write(writer, domain, middle, ["top", "group"], "S-1-5-21-1-2-3-1750",
                [Text("groupType", "-2147483646"), Text("member", HolderDn)], "O:SYG:SYD:"));
    }
}
