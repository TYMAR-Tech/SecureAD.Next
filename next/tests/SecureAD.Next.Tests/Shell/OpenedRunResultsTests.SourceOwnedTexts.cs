using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    public void Resp05SavedTextProductsDeclareFinalWritePayloadsInTheirOwnPublication(StoreSegmentRole role)
    {
        var directory = CreateControlRun();
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        var segment = root.Segment(role);
        var details = Assert.IsType<RequestedDetailManifest>(segment.RequestedDetails);
        var store = role == StoreSegmentRole.JudgementFacts
            ? SavedTextPayloadStorage.Classifications : SavedTextPayloadStorage.Permissions;
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, segment.FileName), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        var map = new RequestedDetailMap(connection, "main", details, CancellationToken.None);
        var reference = map.Find(new(details.Root, details.Items), RequestedDetailIndex.TableKey(store.Chunks));
        Assert.NotNull(reference);
        var table = map.Read<RequestedDetailIndex.Table>(reference);
        Assert.Equal(Assert.Single(store.RequestedPayloads), table.Payload);
        Assert.Equal(new[] { "payload_id", "ordinal", "data" }, table.Columns);
        Assert.True(table.Rows > 0);
        Assert.Equal((root.GenerationId, root.EvidenceSeal, role),
            (details.GenerationId, details.EvidenceSeal, details.Role));
    }

    [Fact]
    public void Resp05SavedTextsKeepClassificationControlAndMemberAnswersAcrossCloseAndReopen()
    {
        var directory = CreateControlRun();
        using var counts = new ReadbackCounts(directory);
        using var source = new BundleAssetSource();
        var before = ReadJourney();
        Assert.Equal((0L, 0L), (counts.FactsVerifications, counts.PermissionProofVerifications));
        source.CloseRun();
        source.SelectRun(directory);
        Assert.Equal(before, ReadJourney());
        Assert.Equal((0L, 0L), (counts.FactsVerifications, counts.PermissionProofVerifications));

        string ReadJourney()
        {
            var original = source.ReadPermissions(directory, UserDn);
            var classification = source.ReadPermissionClassification(directory, UserDn);
            var controls = source.ReadControlEdges(directory, UserDn, null, null, true, 0);
            var members = source.ReadMemberAttribution(directory, TargetSid, null, UserDn);
            var reverse = source.ReadPermissionsThroughMembership(directory, UserSid, null, true, 0);
            Assert.True(original.IsSuccess, original.Error?.Description);
            Assert.True(classification.IsSuccess, classification.Error?.Description);
            Assert.True(controls.IsSuccess, controls.Error?.Description);
            Assert.True(members.IsSuccess, members.Error?.Description);
            Assert.True(reverse.IsSuccess, reverse.Error?.Description);
            var entry = Assert.Single(classification.Value.Classification.Entries);
            Assert.Equal((UserDn, TargetSid, 0xF01FF),
                (classification.Value.Classification.Permissions.DistinguishedName, entry.Entry.Trustee.Sid, entry.Entry.AccessMask));
            Assert.NotEmpty(entry.Rights);
            Assert.NotNull(members.Value.Expansion);
            Assert.NotEmpty(reverse.Value.Permissions);
            return JsonSerializer.Serialize(new
            {
                Original = original.Value, Classification = classification.Value, Controls = controls.Value,
                Members = members.Value, Reverse = reverse.Value,
            });
        }
    }
}
