using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public void Resp05OriginalPermissionsKeepStoredOrderAndDuplicatesWithoutWholeEvidenceVerification()
    {
        var directory = Bundle(userDescriptor: $"O:{UserSid}G:SYD:(A;;WD;;;{TargetSid})(D;;WD;;;{TargetSid})(A;;WD;;;{TargetSid})");
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        var read = source.ReadPermissions(directory, UserDn);
        Assert.True(read.IsSuccess, read.Error?.Description);
        var permissions = Assert.IsType<ObjectPermissions>(read.Value);
        Assert.Equal([0, 1, 2], permissions.Entries.Select(entry => entry.Ordinal));
        Assert.Equal(["AccessAllowed", "AccessDenied", "AccessAllowed"], permissions.Entries.Select(entry => entry.AceType));
        Assert.All(permissions.Entries, entry => Assert.Equal((TargetSid, 0x40000), (entry.Trustee.Sid, entry.AccessMask)));
        Assert.False(permissions.DaclWasCanonical);
        Assert.NotNull(permissions.DescriptorId);
        Assert.Equal(UserSid, permissions.Owner?.Sid);
        Assert.Equal(UserDn, permissions.Owner?.DistinguishedName);
        Assert.All(permissions.Entries, entry => Assert.Equal(TargetDn, entry.Trustee.DistinguishedName));
        Assert.Equal(0, counts.EvidenceVerifications);
    }

    [Fact]
    public void Resp05OriginalPermissionAbsenceIsNotAnEmptyDaclOrAnAbsentObject()
    {
        var directory = Bundle(targetDescriptor: false);
        using var source = new BundleAssetSource();
        var read = source.ReadPermissions(directory, TargetDn);
        Assert.True(read.IsSuccess, read.Error?.Description);
        var permissions = Assert.IsType<ObjectPermissions>(read.Value);
        Assert.Equal((DescriptorAvailability.NotAttempted, SecureAD.Kernel.Security.DaclState.Unreadable),
            (permissions.Availability, permissions.DaclState));
        Assert.Empty(permissions.Entries);
        Assert.Null(source.ReadPermissions(directory, "CN=Uncaptured,DC=contoso,DC=com").Value);
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void Resp05ClassificationChecksOnlyItsSelectedSavedSourcesAndKeepsWholeSealsSeparate(StoreSegmentRole role)
    {
        var directory = CreateControlRun();
        ChangeRequestedSource(directory, role, role == StoreSegmentRole.JudgementFacts
            ? $"UPDATE permission_classification_object SET unreadable_reason='unused' WHERE target='{TargetDn}'"
            : "UPDATE permission_payload_chunk SET data=CAST('!'||substr(CAST(data AS TEXT),2) AS BLOB) WHERE payload_id IN (SELECT proof_id FROM member_attribution_root)");
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        var read = source.ReadPermissionClassification(directory, UserDn);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(UserDn, read.Value.Classification.Permissions.DistinguishedName);
        Assert.Equal(0xF01FF, Assert.Single(read.Value.Classification.Entries).Entry.AccessMask);
        Assert.Equal((0L, 0L), (counts.PermissionProofVerifications, counts.FactsVerifications));
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var whole = ProtectedStoreFile.OpenAnalysisSegment(directory, generation, role);
        if (whole.IsSuccess) whole.Value.Dispose();
        Assert.False(whole.IsSuccess);
        Assert.Equal("Evidence.ProtectedStoreMismatch", whole.Error.Code);
    }

    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void Resp05ClassificationRefusesChangedSelectedPayloadsWithoutPublishingAnAnswer(StoreSegmentRole role)
    {
        var directory = CreateControlRun();
        ChangeRequestedSource(directory, role, role == StoreSegmentRole.JudgementFacts
            ? $"""
              UPDATE classification_payload_chunk
              SET data=CAST(replace(CAST(data AS TEXT),'"IsDaclProtected":false','"IsDaclProtected":true ') AS BLOB)
              WHERE payload_id=(SELECT descriptor_payload_id FROM permission_classification_descriptor
                  WHERE descriptor_id=(SELECT descriptor_id FROM permission_classification_object WHERE target='{UserDn}'))
                  AND instr(CAST(data AS TEXT),'"IsDaclProtected":false')>0
              """
            : $"UPDATE permission_entry SET mask=mask+1 WHERE id IN (SELECT entry_id FROM full_control_source_entry WHERE target='{UserDn}')");
        using var source = new BundleAssetSource();
        var read = source.ReadPermissionClassification(directory, UserDn);
        Assert.False(read.IsSuccess);
        Assert.Equal("Shell.SavedResultsInvalidEvidence", read.Error.Code);
    }

    [Fact]
    public void Resp05MemberPermissionPageDoesNotDecodeTheWholeGroupsStoredProof()
    {
        var directory = CreateControlRun();
        ChangeRequestedSource(directory, StoreSegmentRole.PermissionProof,
            "UPDATE permission_payload_chunk SET data=CAST('!'||substr(CAST(data AS TEXT),2) AS BLOB) WHERE payload_id IN (SELECT proof_id FROM member_attribution_root)");
        using var source = new BundleAssetSource();
        var read = source.ReadPermissionsThroughMembership(directory, UserSid, null, true, 0);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.True(read.Value.WasRun);
        Assert.False(read.Value.IsComplete);
        Assert.NotEmpty(read.Value.Permissions);
        Assert.All(read.Value.Permissions, permission =>
            Assert.Equal((TargetSid, UserDn), (permission.HolderSid, permission.Target)));
        var detail = source.ReadMemberAttribution(directory, TargetSid, null, UserDn);
        Assert.False(detail.IsSuccess);
    }

    [Fact]
    public void Resp05GroupHeldPermissionTotalsStayIndependentOfMembersAndIncompleteRoutes()
    {
        var directory = Bundle(userDescriptor: $"O:SYG:SYD:(A;;WD;;;{TargetSid})",
            members: [UserDn, "CN=Missing,DC=foreign,DC=example"]);
        using var prepared = MemberAttributionTests.Prepare(directory);
        using var source = new BundleAssetSource();
        var permissions = source.ReadControlEdges(directory, UserDn, null, null, true, 0);
        var members = source.ReadMemberAttribution(directory, TargetSid, null, UserDn);
        var reverse = source.ReadPermissionsThroughMembership(directory, UserSid, null, true, 0);
        Assert.True(permissions.IsSuccess, permissions.Error?.Description);
        Assert.True(members.IsSuccess, members.Error?.Description);
        Assert.True(reverse.IsSuccess, reverse.Error?.Description);
        Assert.Equal(1, permissions.Value.ExpectedCount + permissions.Value.UnknownCount + permissions.Value.UnexpectedCount);
        Assert.Equal((1, 1, false), (members.Value.Expansion!.ResolvedMemberCount,
            members.Value.Expansion.UnresolvedMemberCount, members.Value.Expansion.IsComplete));
        Assert.False(reverse.Value.IsComplete);
        Assert.Single(reverse.Value.Permissions);
    }

    [Fact]
    public void Resp05RequestedPathChunkCorruptionRefusesWithoutReturningAPartialPath()
    {
        var directory = CreatePathRun();
        ChangeRequestedSource(directory, StoreSegmentRole.PathProof,
            "UPDATE path_proof_chunk SET data=zeroblob(length(data))");
        using var source = new BundleAssetSource();
        var read = source.ReadSavedTier0Path(directory, UserDn);
        Assert.False(read.IsSuccess);
        Assert.Equal("Shell.SavedPathInvalidEvidence", read.Error.Code);
    }

    [Fact]
    public void Resp05PublishedPathsDeclareSourceOwnedPayloadsAndKeepTheSavedAnswer()
    {
        var directory = CreatePathRun();
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var root = System.Text.Json.JsonSerializer.Deserialize<StoreRootManifest>(File.ReadAllText(
            AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement)))!;
        var manifest = Assert.IsType<RequestedDetailManifest>(root.Segment(StoreSegmentRole.PathProof).RequestedDetails);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisSegmentDataPath(directory, generation, StoreSegmentRole.PathProof),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString()))
        {
            connection.Open();
            var map = new RequestedDetailMap(connection, "main", manifest, CancellationToken.None);
            var hash = map.Find(new(manifest.Root, manifest.Items), RequestedDetailIndex.TableKey("path_proof_chunk"));
            var table = map.Read<RequestedDetailIndex.Table>(Assert.IsType<string>(hash));
            Assert.Equal(Assert.Single(PathProofStorage.RequestedPayloads), table.Payload);
            Assert.True(table.Rows > 0);
            Assert.Equal(new[] { "proof_id", "ordinal", "data" }, table.Columns);
        }
        using var source = new BundleAssetSource();
        var permission = Assert.Single(FirstRecordedPathPage(source, directory).Permissions);
        Assert.Equal(("DC=contoso,DC=com", UserSid, ControlCapability.CanWriteDacl),
            (permission.Target, permission.HolderSid, permission.Capability));
        source.CloseRun();
        source.SelectRun(directory);
        var reopened = Assert.Single(FirstRecordedPathPage(source, directory).Permissions);
        Assert.Equal((permission.Target, permission.HolderSid, permission.Capability),
            (reopened.Target, reopened.HolderSid, reopened.Capability));
    }

    private static void ChangeRequestedSource(string directory, StoreSegmentRole role, string sql)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var path = BundleLayout.AnalysisSegmentDataPath(directory, generation, role);
        var length = new FileInfo(path).Length;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
        }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = sql;
            Assert.True(command.ExecuteNonQuery() > 0, "The deliberate source change touched no records.");
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            Assert.Equal(0L, command.ExecuteScalar());
        }
        Assert.Equal(length, new FileInfo(path).Length);
    }
}
