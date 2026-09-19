using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public void P248SavedPathsShareProtectedFilesAcrossObjects()
    {
        var directory = CreatePathRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();

        var first = source.ReadSavedTier0Path(directory, UserDn);
        var second = source.ReadSavedTier0Path(directory, CoreDn);

        Assert.Equal((Tier0Reachability.Reachable, (int?)0, 1L, 1L, 1L, 0L), (first.Value!.Path.Reachability, second.Value!.Path.ShortestProvenDistance,
            counts.EvidenceVerifications, counts.DerivationVerifications, counts.JudgementVerifications, counts.AnalyticalReads));
    }

    [Fact]
    public void P248SavedPathsVerifyAgainAfterClosingTheRun()
    {
        var directory = CreatePathRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ReadSavedTier0Path(directory, UserDn);
        source.CloseRun();
        source.SelectRun(directory);

        var saved = source.ReadSavedTier0Path(directory, UserDn).Value!;

        Assert.Equal((Tier0Reachability.Reachable, 2L, 2L, 2L), (saved.Path.Reachability,
            counts.EvidenceVerifications, counts.DerivationVerifications, counts.JudgementVerifications));
    }

    [Theory]
    [InlineData("Evidence")]
    [InlineData("Derivation")]
    [InlineData("Judgement")]
    public void P248SavedPathsRefuseCorruptRequiredFiles(string kind)
    {
        var directory = CreatePathRun();
        var path = kind == "Evidence" ? Path.Combine(directory, BundleLayout.EvidenceFileName)
            : BundleLayout.AnalysisGenerationDataPath(directory, Enum.Parse<AnalysisStoreKind>(kind),
                AnalysisStoreLifecycle.Resolve(directory, Enum.Parse<AnalysisStoreKind>(kind)).Value.GenerationId);
        File.AppendAllText(path, "corrupt");
        using var source = new BundleAssetSource();

        Assert.Equal("Evidence.ProtectedStoreMismatch", source.ReadSavedTier0Path(directory, UserDn).Error?.Code);
    }

    [Fact]
    public void P248SavedPathsRefuseThePreviousFormatWithoutFallback()
    {
        var directory = CreatePathRun();
        MutateControlRun(directory, "UPDATE judgement SET schema_version=38");
        using var source = new BundleAssetSource();

        Assert.Contains("schema version 38", source.ReadSavedTier0Path(directory, UserDn).Error?.Description ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void P248SavedPathsKeepTheOriginalTargetBoundPermission()
    {
        var directory = CreatePathRun();
        using var source = new BundleAssetSource();

        var permission = Assert.Single(source.ReadSavedTier0Path(directory, UserDn).Value!.Permissions);

        Assert.Equal(("DC=contoso,DC=com", UserSid, ControlCapability.CanWriteDacl),
            (permission.Target, permission.HolderSid, permission.Capability));
    }

    [Fact]
    public void P248SavedPathsRefuseAClosedRun()
    {
        var directory = CreatePathRun();
        using var source = new BundleAssetSource();
        source.ReadSavedTier0Path(directory, UserDn);
        source.CloseRun();

        Assert.Equal("Shell.SavedPathGenerationChanged", source.ReadSavedTier0Path(directory, UserDn).Error?.Code);
    }

    [Fact]
    public void P248SavedPathsWithholdAnEarlierResultDuringAnAttempt()
    {
        var directory = CreatePathRun();
        using var source = new BundleAssetSource();
        source.ReadSavedTier0Path(directory, UserDn);
        using var attempt = JudgementWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId, Started, Started);

        Assert.Equal("Shell.SavedPathUnfinished", source.ReadSavedTier0Path(directory, UserDn).Error?.Code);
    }

    [Fact]
    public void P248SavedPathsRefuseAReplacementGeneration()
    {
        var directory = CreatePathRun();
        using var source = new BundleAssetSource();
        source.ReadSavedTier0Path(directory, UserDn);
        var judged = JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(judged.IsSuccess, judged.Error?.Description);

        Assert.Equal("Shell.SavedPathGenerationChanged", source.ReadSavedTier0Path(directory, UserDn).Error?.Code);
    }

    [Fact]
    public void P248SavedPathsDoNotDeclareAnUncapturedObjectSafe()
    {
        var directory = CreatePathRun();
        using var source = new BundleAssetSource();

        var path = source.ReadSavedTier0Path(directory, "CN=NotCaptured,DC=contoso,DC=com").Value!.Path;

        Assert.Equal((Tier0Reachability.Unknown, (int?)null, 0), (path.Reachability, path.ShortestProvenDistance, path.Steps.Count));
    }

    [Fact]
    public void P248SavedPathsDoNotDecodeUnrelatedPathNodes()
    {
        var directory = CreatePathRun();
        MutateControlRun(directory, "UPDATE tier0_path_node SET proof='not json' WHERE target='" + TargetDn + "'");
        using var source = new BundleAssetSource();

        Assert.Equal(Tier0Reachability.Reachable, source.ReadSavedTier0Path(directory, UserDn).Value!.Path.Reachability);
    }

    [Fact]
    public void P248SavedClassificationsRetainTheirRecordedCoverage()
    {
        var directory = CreatePathRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE ownership_seed SET classification=json_set(classification,'$.Coverage.ProcessingComplete',json('false'))";
            update.ExecuteNonQuery();
            update.CommandText = "SELECT target,classification FROM ownership_seed";
            var rows = new List<(string Target, string Json)>();
            using (var read = update.ExecuteReader()) while (read.Read()) rows.Add((read.GetString(0), read.GetString(1)));
            foreach (var row in rows)
            {
                update.CommandText = "UPDATE ownership_seed SET classification_fingerprint=$hash WHERE target=$target";
                update.Parameters.Clear();
                update.Parameters.AddWithValue("$target", row.Target);
                update.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(row.Json));
                update.ExecuteNonQuery();
            }
        });
        using var source = new BundleAssetSource();

        var classification = source.ReadSavedTier0Path(directory, CoreDn).Value!.Path.Inputs.Classifications
            .Single(value => value.Target.DistinguishedName == CoreDn);

        Assert.False(classification.Coverage.ProcessingComplete);
    }

    [Fact]
    public void P248ClosingTheRunCancelsTheActiveReadToken()
    {
        var directory = CreatePathRun();
        using var run = new OpenedRunResults(directory);
        var cancelledInsideRead = false;

        var read = run.ReadJudgement<int>((reader, token) =>
        {
            reader.ReadTier0Path(UserDn);
            run.Dispose();
            cancelledInsideRead = token.IsCancellationRequested;
            token.ThrowIfCancellationRequested();
            return 0;
        });

        Assert.Equal((true, "Shell.SavedResultsGenerationChanged"), (cancelledInsideRead, read.Error?.Code));
    }

    private static string CreatePathRun()
    {
        var directory = Bundle(tier0Route: true, members: [UserDn], rootDescriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        var judged = JudgingRun.JudgeWithTier0Discovery(directory, [], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }
}
