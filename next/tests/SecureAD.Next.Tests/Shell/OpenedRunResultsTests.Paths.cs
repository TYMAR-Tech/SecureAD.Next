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
    public void Sec071AdminSavedReadbackBindsTheSelectedCapturedAccountNameWithoutAnalysis()
    {
        var directory = CreatePathRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        var captured = source.ReadObjectAttributes(directory, UserDn).Value!;
        var before = Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal).Select(path => (path, Hash: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))))).ToArray();

        var saved = FirstRecordedPathPage(source, directory);
        var empty = source.ReadSavedTier0Path(directory, CoreDn).Value!;

        var account = Assert.IsType<SavedPathAccount>(saved.Account);
        Assert.Equal((UserDn, captured.ObjectGuid), (account.DistinguishedName, account.ObjectGuid));
        Assert.Equal(captured.Find("sAMAccountName")?.OnlyValue?.Text, account.AccountName);
        Assert.Equal(captured.Find("givenName")?.OnlyValue?.Text, account.GivenName);
        Assert.Equal(captured.Find("displayName")?.OnlyValue?.Text ?? SecureAD.Kernel.Naming.DnHelper.ExtractNameFromDn(UserDn), account.Name);
        Assert.Empty(empty.Page.Questions);
        Assert.Null(empty.Account);
        Assert.Equal((0L, 1L, 1L, 1L), (counts.AnalyticalReads, counts.EvidenceVerifications, counts.DerivationVerifications, counts.JudgementVerifications));
        Assert.Equal(before, Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
            .Order(StringComparer.Ordinal).Select(path => (path, Hash: Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))))).ToArray());
    }

    [Fact]
    public void P248SavedPathsShareProtectedFilesAcrossObjects()
    {
        var directory = CreatePathRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();

        var first = source.ReadSavedTier0Path(directory, UserDn);
        var second = source.ReadSavedTier0Path(directory, CoreDn);

        Assert.Equal((PathRiskReadVerdict.RecordedQuestions, true, 1L, 1L, 1L, 0L), (first.Value!.Page.Verdict, second.Value!.Page.IsFixedTarget,
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

        Assert.Equal((PathRiskReadVerdict.RecordedQuestions, 2L, 2L, 2L), (saved.Page.Verdict,
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

    [Theory]
    [InlineData(38)]
    [InlineData(51)]
    [InlineData(52)]
    public void P248SavedPathsRefuseThePreviousFormatWithoutFallback(int format)
    {
        var directory = CreatePathRun();
        MutateControlRun(directory, "UPDATE judgement SET schema_version=" + format);
        using var source = new BundleAssetSource();

        Assert.Contains("schema version " + format, source.ReadSavedTier0Path(directory, UserDn).Error?.Description ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void P248SavedPathsKeepTheOriginalTargetBoundPermission()
    {
        var directory = CreatePathRun();
        using var source = new BundleAssetSource();

        var permission = Assert.Single(FirstRecordedPathPage(source, directory).Permissions);

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

        var path = source.ReadSavedTier0Path(directory, "CN=NotCaptured,DC=contoso,DC=com").Value!.Page;

        Assert.Equal((PathRiskReadVerdict.NoRecordedQuestions, 0), (path.Verdict, path.Questions.Count));
    }

    [Fact]
    public void P248SavedPathsDoNotDecodeUnrelatedPathNodes()
    {
        var directory = CreatePathRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
            PathProofVerification.AlterJson(connection, "tier0_path_node", "'not json'", "WHERE target='" + TargetDn + "'"));
        using var source = new BundleAssetSource();

        Assert.Single(FirstRecordedPathPage(source, directory).Page.Questions);
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

        using var run = new OpenedRunResults(directory);
        var classification = run.ReadJudgement(reader => reader.ReadPathInputs()).Value.Classifications
            .Single(value => value.Target.DistinguishedName == CoreDn);

        Assert.False(classification.Coverage.ProcessingComplete);
    }

    [Fact]
    public void SelectedSavedPathDoesNotReconstructWholeForestClassifications()
    {
        var directory = CreatePathRun();
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var update = connection.CreateCommand();
            update.CommandText = "UPDATE ownership_seed SET classification='not-json'";
            update.ExecuteNonQuery();
        });
        using var source = new BundleAssetSource();

        var selected = source.ReadSavedTier0Path(directory, UserDn);

        Assert.True(selected.IsSuccess, selected.Error?.Description);
        Assert.Equal(PathRiskReadVerdict.RecordedQuestions, selected.Value!.Page.Verdict);
        Assert.Single(FirstRecordedPathPage(source, directory).Page.Questions);
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
        var judged = JudgingRun.JudgeWithTier0Discovery(directory, [], [new RequesterDaclRequest(UserDn, "DC=contoso,DC=com")], Started, Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, selfMembershipDiscoveryBudget: null, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    private static SavedTier0Path FirstRecordedPathPage(BundleAssetSource source, string directory)
    {
        var first = source.ReadSavedTier0Path(directory, UserDn);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var saved = Assert.IsType<SavedTier0Path>(first.Value);
        var group = Enum.GetValues<PathRiskVerdict>().First(value => saved.Page.Counts.For(value) > 0);
        var page = source.ReadSavedTier0Path(directory, UserDn, group, null);
        Assert.True(page.IsSuccess, page.Error?.Description);
        return Assert.IsType<SavedTier0Path>(page.Value);
    }
}
