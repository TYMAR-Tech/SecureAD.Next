using SecureAD.Derivation;
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
    public async Task SavedDistanceHostsPersistOneCheckedObjectRatherThanThreeQuestions(string host)
    {
        var directory = CoverageCapture();
        await RunCoverageHostAsync(host, directory, PathRequesterPolicy.SupportedCapturedQuestions);
        using var reader = Open(directory);
        Assert.Equal(3, reader.ReadPathRequesterCoverage().Families.Sum(value => value.StoredAssessments));
        var summary = Assert.IsType<Tier0RunSummary>(reader.ReadTier0RunSummary());
        Assert.Equal(1, summary.ObjectsWithRequesterChecks);
        Assert.True(summary.AutomaticRequesterSelectionRequested);
        Assert.True(summary.RequesterInputScanCompleted);
        var user = Assert.IsType<Tier0ObjectDistance>(reader.ReadTier0ObjectDistance(UserDn));
        Assert.True(user.Facts.HasRequesterChecks);
        Assert.Equal(1, user.Facts.SupportedDistance);
        Assert.False(user.Facts.IsMinimumEstablished);
        reader.ReadPathRiskPage(UserDn, PathRiskVerdict.UnexpectedRoute, null, CancellationToken.None);
        reader.ReadPathRiskPage(UserDn, PathRiskVerdict.ExpectedRoute, null, CancellationToken.None);
        Assert.Equal(summary, reader.ReadTier0RunSummary());
    }

    [Theory]
    [InlineData("requester", 2)]
    [InlineData("own", 2)]
    [InlineData("combined", 4)]
    public void SavedDistanceUsesTheSelectedRouteWithoutReconstructingItsProof(string family, int length)
    {
        string directory;
        if (family == "combined")
            directory = ObtainedPrepared("nested");
        else
        {
            directory = family == "own" ? Capture()
                : Capture(membershipTail: false, coreDescriptor: $"O:SYG:SYD:(A;;WD;;;{HolderSid})");
            Derive(directory);
            if (family == "own") Judge(directory, [new(UserDn, TargetDn)]);
            else
            {
                var result = JudgingRun.JudgeWithTier0Discovery(directory, [], new[] { new RequesterDaclRequest(UserDn, CoreDn) },
                    Started, Started, JudgingRun.NobodyIsWatching, SecureAD.Kernel.RunLog.Discarded, null, CancellationToken.None);
                Assert.True(result.IsSuccess, result.Error?.Description);
            }
        }
        using var reader = Open(directory);
        var summary = reader.ReadTier0RunSummary()!;
        var user = reader.ReadTier0ObjectDistance(UserDn)!;
        Assert.Equal((Tier0DistanceVerdict.SupportedRoute, length, true, false),
            (user.Facts.Verdict, user.Facts.SupportedDistance, user.Facts.HasRequesterChecks, user.Facts.IsMinimumEstablished));
        Assert.Equal(reader.ReadTier0Path(UserDn).ShortestProvenDistance, user.Facts.SupportedDistance);
        Assert.Equal(1, summary.ObjectsWithRequesterChecks);
    }

    [Fact]
    public void SavedDistancePublicationReconcilesWholeRunTotalsAgainstRows()
    {
        using var reader = Open(CoveragePrepared());
        using var connection = RiskDatabase(reader, writableCopy: true);
        Tier0DistanceStorage.RequirePublishable(connection, reader.Description, CancellationToken.None);
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM tier0_distance WHERE target=$target";
        command.Parameters.AddWithValue("$target", UserDn);
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => Tier0DistanceStorage.RequirePublishable(connection, reader.Description, CancellationToken.None));
    }

    [Fact]
    public void SavedDistanceCancelledPublicationPreservesThePriorSummary()
    {
        var directory = CoveragePrepared();
        Tier0RunSummary original;
        using (var before = Open(directory)) original = before.ReadTier0RunSummary()!;
        using var stopping = new CancellationTokenSource();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeAudit(directory, [],
            PathRequesterPolicy.SupportedCapturedQuestions, Started, Started,
            new CancelBeforePublication(stopping), SecureAD.Kernel.RunLog.Discarded, stopping.Token, null));
        using var reader = Open(directory);
        Assert.Equal(original, reader.ReadTier0RunSummary());
        Assert.Equal(original.GenerationId, reader.ReadTier0ObjectDistance(UserDn)!.GenerationId);
    }
}
