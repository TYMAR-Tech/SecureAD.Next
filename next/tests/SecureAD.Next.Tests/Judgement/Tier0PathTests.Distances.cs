using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class Tier0PathTests
{
    [Theory]
    [InlineData(CoreDn, Tier0DistanceVerdict.FixedTarget, 0, true)]
    [InlineData(UserDn, Tier0DistanceVerdict.SupportedRoute, 3, false)]
    [InlineData(TargetDn, Tier0DistanceVerdict.Unresolved, null, false)]
    public void SavedDistanceKeepsSupportedLengthSeparateFromOverallMinimum(string target, Tier0DistanceVerdict verdict,
        int? length, bool minimum)
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var value = Assert.IsType<Tier0ObjectDistance>(reader.ReadTier0ObjectDistance(target));
        Assert.Equal((verdict, length, minimum), (value.Facts.Verdict, value.Facts.SupportedDistance, value.Facts.IsMinimumEstablished));
        Assert.Equal(reader.ReadTier0Path(target).ShortestProvenDistance, value.Facts.SupportedDistance);
        Assert.Equal((reader.Description.GenerationId, reader.Description.DerivationGenerationId, reader.Description.EvidenceSeal),
            (value.GenerationId, value.DerivationGenerationId, value.EvidenceSeal));
        Assert.False(value.Coverage.IsComplete);
    }

    [Fact]
    public void SavedDistanceTotalsSeparateAuthoritativeClassificationFromOtherReachers()
    {
        var directory = Captured(descriptor: $"O:SYG:SYD:(A;;WD;;;{UserSid})");
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var summary = Assert.IsType<Tier0RunSummary>(reader.ReadTier0RunSummary());
        var user = reader.ReadTier0ObjectDistance(UserDn)!;
        Assert.Equal((Tier0State.Unknown, Tier0DistanceVerdict.SupportedRoute, 1),
            (user.Facts.Classification, user.Facts.Verdict, user.Facts.SupportedDistance));
        Assert.Equal(reader.ReadPathInputs().Classifications.Count(value => value.State == Tier0State.Established),
            summary.ClassifiedTier0Objects);
        Assert.Equal(reader.ReadPathInputs().FixedTargets.Count, summary.FixedTargets);
        Assert.Equal(1, summary.OtherObjectsWithSupportedRoute);
        Assert.Equal(summary.RecordedSubjects,
            summary.ObjectsWithSupportedRoute + summary.UnresolvedObjects + summary.UnassessedObjects);
        Assert.Equal(0, summary.UnassessedObjects);
        Assert.Equal(0, summary.ObjectsWithRequesterChecks);
        Assert.False(summary.AutomaticRequesterSelectionRequested);
        Assert.False(summary.RequesterInputScanCompleted);
    }

    [Fact]
    public void SavedDistanceUnavailableInputsKeepRecordedObjectsUnassessed()
    {
        var directory = Captured(depth: 3);
        Judge(directory);
        using var reader = Open(directory);
        var summary = Assert.IsType<Tier0RunSummary>(reader.ReadTier0RunSummary());
        Assert.Equal(PathInputAvailability.RequiredInputsUnavailable, summary.Availability);
        Assert.True(summary.RecordedSubjects > 0);
        Assert.Equal(summary.RecordedSubjects, summary.UnassessedObjects);
        Assert.Equal((0, 0, 0), (summary.ObjectsWithSupportedRoute, summary.UnresolvedObjects, summary.ClassifiedTier0Objects));
        var user = Assert.IsType<Tier0ObjectDistance>(reader.ReadTier0ObjectDistance(UserDn));
        Assert.Equal(Tier0DistanceVerdict.NotAssessed, user.Facts.Verdict);
        Assert.Null(user.Facts.SupportedDistance);
        Assert.False(user.Facts.IsMinimumEstablished);
    }

    [Fact]
    public void SavedDistanceUnrequestedAndUnrecordedSubjectsDoNotInventZeroes()
    {
        var directory = Captured();
        Derive(directory);
        Assert.True(JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None).IsSuccess);
        using (var reader = Open(directory))
        {
            var summary = Assert.IsType<Tier0RunSummary>(reader.ReadTier0RunSummary());
            Assert.Equal(PathInputAvailability.NotProduced, summary.Availability);
            Assert.Equal(summary.RecordedSubjects, summary.UnassessedObjects);
            var user = Assert.IsType<Tier0ObjectDistance>(reader.ReadTier0ObjectDistance(UserDn));
            Assert.Equal(Tier0DistanceVerdict.NotAssessed, user.Facts.Verdict);
            Assert.Null(user.Facts.SupportedDistance);
        }
        Judge(directory);
        using var calculated = Open(directory);
        Assert.NotNull(calculated.ReadTier0RunSummary());
        Assert.Null(calculated.ReadTier0ObjectDistance("CN=NotCaptured," + RootDn));
    }

    [Fact]
    public void SavedDistanceReadsOnlyTheSelectedObjectAndDoesNotReplayAnalysis()
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        Mutate(directory, $"UPDATE tier0_distance SET fingerprint=zeroblob(32) WHERE target='{TargetDn}'");
        Mutate(directory, "UPDATE path_proof_chunk SET data=x'00'");
        using var reader = Open(directory);
        var before = Snapshot(directory);
        Tier0ObjectDistance? selected = null;
        Assert.Null(Record.Exception(() => selected = reader.ReadTier0ObjectDistance(UserDn)));
        Assert.Equal(3, selected!.Facts.SupportedDistance);
        Assert.True(reader.ReadTier0RunSummary()!.RecordedSubjects > 0);
        Assert.Equal(before, Snapshot(directory));
        Assert.Throws<InvalidDataException>(() => reader.ReadTier0ObjectDistance(TargetDn));
    }

    [Theory]
    [InlineData("supported_distance=7")]
    [InlineData("minimum_established=1")]
    [InlineData("classification='Unknown'")]
    [InlineData("requester_checked=1")]
    public void SavedDistanceRejectsChangedSelectedMetrics(string change)
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        Mutate(directory, $"UPDATE tier0_distance SET {change} WHERE target='{UserDn}'");
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadTier0ObjectDistance(UserDn));
    }

    [Theory]
    [InlineData("GenerationId", "'11111111-1111-1111-1111-111111111111'")]
    [InlineData("EvidenceSeal", "'changed'")]
    [InlineData("CalculationFingerprint", "'" + "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" + "'")]
    [InlineData("RecordedSubjects", "999")]
    public void SavedDistanceSummaryRejectsContradictoryOrReboundTotals(string field, string value)
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE tier0_distance_product SET proof=json_set(proof,'$.{field}',{value})";
            command.ExecuteNonQuery();
            command.CommandText = "SELECT proof FROM tier0_distance_product";
            var json = Assert.IsType<string>(command.ExecuteScalar());
            command.CommandText = "UPDATE tier0_distance_product SET fingerprint=$hash";
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
            command.ExecuteNonQuery();
        });
        using var reader = Open(directory);
        Assert.Throws<InvalidDataException>(() => reader.ReadTier0RunSummary());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void SavedDistanceMissingRowsAreRefusedRatherThanReportedAsUnassessed(bool summary)
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        Mutate(directory, summary ? "DELETE FROM tier0_distance_product" : $"DELETE FROM tier0_distance WHERE target='{UserDn}'");
        using var missing = Open(directory);
        if (summary) Assert.Throws<InvalidDataException>(() => missing.ReadTier0RunSummary());
        else Assert.Throws<InvalidDataException>(() => missing.ReadTier0ObjectDistance(UserDn));
    }

    [Fact]
    public void SavedDistanceDeclaredButUncapturedRootRemainsUnresolvedNotAnInventoryObject()
    {
        var directory = Bundle(rootObject: false);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var root = Assert.IsType<Tier0ObjectDistance>(reader.ReadTier0ObjectDistance(RootDn));
        Assert.Null(root.Subject.ObjectGuid);
        Assert.Equal((Tier0DistanceVerdict.Unresolved, Tier0State.Unknown, (int?)null),
            (root.Facts.Verdict, root.Facts.Classification, root.Facts.SupportedDistance));
        Assert.True(reader.ReadTier0RunSummary()!.UnresolvedObjects > 0);
    }

    [Fact]
    public void SavedDistanceOpenReaderRejectsChangedGenerationAndCancellation()
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => reader.ReadTier0ObjectDistance(UserDn, stopping.Token));
        Assert.ThrowsAny<OperationCanceledException>(() => reader.ReadTier0RunSummary(stopping.Token));
        Derive(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadTier0ObjectDistance(UserDn));
        Assert.Throws<InvalidOperationException>(() => reader.ReadTier0RunSummary());
    }
}
