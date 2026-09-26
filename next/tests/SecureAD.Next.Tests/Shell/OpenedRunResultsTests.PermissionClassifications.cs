using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(UserDn)]
    [InlineData(TargetDn)]
    public void P248ClassificationIsProducedWithoutFindings(string target)
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();

        var saved = source.ReadPermissionClassification(directory, target);

        Assert.Equal(target, saved.Value.Classification.Permissions.DistinguishedName);
    }

    [Fact]
    public void P248ClassificationReadsRecordedWordsAndReasonsWithoutReplay()
    {
        var directory = CreateControlRun();
        // ONE COPY OF EACH READING, COVERED BY A DIGEST, so the recorded words go into the shared
        // row and the digest is restored afterwards. Without that repair the reader would refuse
        // the record and this case would prove nothing about replay.
        //
        // The reading now hangs off the distinct entry rather than the occurrence, and the
        // occurrence is keyed by descriptor rather than by name (P-280), so reaching this object's
        // readings is a join through the descriptor the object carries.
        MutateControlRun(directory, $"""
            UPDATE permission_classification_reading
            SET payload=json_set(payload,'$.Summary','Recorded wording','$.Scope.AppliesTo','Recorded scope','$.Rights[0].Assessment.Reason','Recorded explanation')
            WHERE id IN (
                SELECT v.reading_id FROM permission_classification_value v
                JOIN permission_classification_entry e ON e.entry_id=v.entry_id
                JOIN permission_classification_object o ON o.descriptor_id=e.descriptor_id
                WHERE o.target='{UserDn}')
            """);
        RepairReadingFingerprints(directory);
        using var source = new BundleAssetSource();

        var entry = source.ReadPermissionClassification(directory, UserDn).Value.Classification.Entries.Single();

        Assert.Equal(("Recorded wording", "Recorded scope", "Recorded explanation"),
            (entry.Summary, entry.Scope.AppliesTo, entry.Rights.Single().Assessment.Reason));
    }

    [Fact]
    public void P248ClassificationSharesProtectedVerificationAcrossObjects()
    {
        var directory = CreateControlRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ReadPermissionClassification(directory, UserDn);

        source.ReadPermissionClassification(directory, TargetDn);
        source.ReadObjectAttributes(directory, UserDn);

        Assert.Equal((1L, 1L, 1L, 0L), (counts.EvidenceVerifications, counts.JudgementVerifications,
            counts.EvidenceFormatChecks, counts.AnalyticalReads));
    }

    [Fact]
    public void P248ClassificationReverifiesAfterClosing()
    {
        var directory = CreateControlRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        source.ReadPermissionClassification(directory, UserDn);
        source.CloseRun();
        source.SelectRun(directory);

        source.ReadPermissionClassification(directory, UserDn);

        Assert.Equal((2L, 2L), (counts.EvidenceVerifications, counts.JudgementVerifications));
    }

    [Fact]
    public void P248ClassificationCaptureOnlyKeepsRawEvidenceWithoutRisk()
    {
        var directory = Bundle();
        using var source = new BundleAssetSource();

        var saved = source.ReadPermissionClassification(directory, UserDn);
        var raw = source.ReadPermissions(directory, UserDn);

        Assert.Equal(("This run has no saved permission classification.", UserDn),
            (saved.Error?.Description, raw.Value?.DistinguishedName));
    }

    [Fact]
    public void P248ClassificationCannotCrossAReplacementGeneration()
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();
        source.ReadPermissionClassification(directory, UserDn);
        SavedLapsTestRun.Judge(directory);

        var read = source.ReadPermissionClassification(directory, UserDn);

        Assert.Equal("Shell.SavedResultsGenerationChanged", read.Error?.Code);
    }

    [Fact]
    public void P248ClassificationCannotCrossAnUnpublishedAttempt()
    {
        var directory = CreateControlRun();
        using var source = new BundleAssetSource();
        source.ReadPermissionClassification(directory, UserDn);
        using var attempt = JudgementWriter.Create(directory, BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash,
            AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId, Started, Started);

        var read = source.ReadPermissionClassification(directory, UserDn);

        Assert.Equal("Shell.SavedResultsUnfinished", read.Error?.Code);
    }

    [Fact]
    public void P248ClassificationHonorsCancellation()
    {
        var directory = CreateControlRun();
        using var session = new OpenedRunResults(directory);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        Assert.Throws<OperationCanceledException>(() => session.ReadPermissionClassification(UserDn, cancellation.Token));
    }

    [Fact]
    public void P248ClassificationRejectsCorruptionBeforeReading()
    {
        var directory = CreateControlRun();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        File.AppendAllText(BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId), "corruption");
        using var source = new BundleAssetSource();

        var read = source.ReadPermissionClassification(directory, UserDn);

        Assert.Equal("Evidence.ProtectedStoreMismatch", read.Error?.Code);
    }
}
