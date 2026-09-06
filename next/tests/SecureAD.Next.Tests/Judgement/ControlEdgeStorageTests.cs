using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ControlEdgeStorageTests
{
    private const string Seal = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Theory]
    [InlineData(14)]
    [InlineData(15)]
    public void OlderSchemasAreRefusedWithBothVersionNumbers(int version)
    {
        var directory = TempDirectories.Create("control-edge-old-schema");
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, Seal)));
        using (var writer = JudgementWriter.Create(directory, Seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch))
        {
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + BundleLayout.JudgementPartialPath(directory) + ";Pooling=False"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE judgement SET schema_version=$version";
                command.Parameters.AddWithValue("$version", version);
                command.ExecuteNonQuery();
            }
            writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        }
        var opened = JudgementReader.Open(directory);
        Assert.False(opened.IsSuccess);
        Assert.Contains(version.ToString(), opened.Error.Description);
        Assert.Contains(JudgementSchema.Version.ToString(), opened.Error.Description);
    }

    [Fact]
    public void MembershipKindsConstraintsAndOriginalAcesSurviveBothQueries()
    {
        var ace = GroupMembershipControlTests.Scoped(7, 0x28);
        var directory = Store(writer =>
        {
            writer.StartControlEdges(true);
            var result = GroupMembershipControlTests.Membership(ControlEdgeDeriverTests.Permissions(ace));
            writer.WriteControlEdges(result with { Edges = result.Edges.Select(edge => edge with { GenerationId = writer.GenerationId }).ToArray() });
            writer.CompleteControlEdges();
        });
        using var reader = Open(directory);
        var byObject = reader.ReadControlEdges(GroupMembershipControlTests.Group.DistinguishedName, null, null, false, 0);
        var byHolder = reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, false, 0);
        Assert.Equal(byObject.Edges.Select(edge => edge.Id), byHolder.Edges.Select(edge => edge.Id));
        Assert.Equal(2, byObject.Edges.Count);
        Assert.Equal(2, byObject.UnknownCount);
        Assert.Equal(1, byObject.UnansweredObjects);
        Assert.False(byObject.IsComplete);
        Assert.All(byObject.Edges, edge =>
        {
            Assert.Equal(ControlEdgeClass.MembershipEscalation, edge.EdgeClass);
            Assert.True(edge.IsCounted);
            var stored = Assert.Single(edge.Evidence);
            Assert.Equal(ace.Ordinal, stored.Ordinal);
            Assert.Equal(ace.AccessMask, stored.AccessMask);
            Assert.Equal(ace.ObjectTypeGuid, stored.ObjectTypeGuid);
            Assert.True(stored.HasObjectType);
            Assert.Equal("Computed", edge.DescriptorOutcome);
        });
        Assert.True(byObject.Edges.Single(edge => edge.Capability == ControlCapability.CanModifyGroupMembership).IsComplete);
        var self = byObject.Edges.Single(edge => edge.Capability == ControlCapability.CanAddSelfToGroup);
        Assert.Equal(ControlEvaluationState.Unknown, self.EvaluationState);
        Assert.Contains(self.Preconditions, condition => condition.Name == "AddedMemberSid == RequesterSid" && condition.State == ControlEvaluationState.Unknown);
        Assert.Equal("ResearchBlocked", self.ResearchStatus);
    }

    [Fact]
    public void OldControlEngineCannotClaimTheWiderMembershipScope()
    {
        var directory = TempDirectories.Create("control-edge-old-engine");
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, Seal)));
        using (var writer = JudgementWriter.Create(directory, Seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch))
        {
            writer.StartControlEdges(true);
            writer.CompleteControlEdges();
            using (var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + BundleLayout.JudgementPartialPath(directory) + ";Pooling=False"))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE control_product SET engine_version=1";
                command.ExecuteNonQuery();
            }
            writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        }
        using var reader = Open(directory);
        Assert.False(reader.ReadControlEdges(null, null, null, false, 0).ProductWasDerived);
    }

    [Fact]
    public void PagingVisitsEachStoredRowExactlyOnce()
    {
        var directory = Store(writer =>
        {
            writer.StartControlEdges(true);
            var original = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, 0x40000)));
            for (var i = 0; i < 105; i++)
            {
                var target = $"OU=Object{i},DC=contoso,DC=com";
                writer.WriteControlEdges(original with { Target = target, Edges = original.Edges.Select(edge => edge with { Target = target, GenerationId = writer.GenerationId }).ToArray() });
            }
            writer.CompleteControlEdges();
        });
        using var reader = Open(directory);
        var first = reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, false, 0);
        var last = reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, false, first.LastId);
        Assert.True(first.HasMore);
        Assert.False(last.HasMore);
        Assert.Equal(105, first.Edges.Concat(last.Edges).Select(edge => edge.Id).Distinct().Count());
        Assert.Equal(105, last.UnknownCount);
    }

    [Fact]
    public void BothQueriesReadTheSamePersistedEvidenceAndDoNotCountCompounds()
    {
        var directory = Store(writer =>
        {
            writer.StartControlEdges(true);
            var result = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(
                ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, 0x80000)));
            writer.WriteControlEdges(result with { Edges = result.Edges.Select(edge => edge with { GenerationId = writer.GenerationId }).ToArray() });
            writer.CompleteControlEdges();
        });
        using var reader = Open(directory);
        var byObject = reader.ReadControlEdges(ControlEdgeDeriverTests.Subject.DistinguishedName, null, null, false, 0);
        var byHolder = reader.ReadControlEdges(null, ControlEdgeDeriverTests.Holder, null, false, 0);
        Assert.True(byObject.ProductWasDerived);
        Assert.Equal(byObject.Edges.Select(edge => edge.Id), byHolder.Edges.Select(edge => edge.Id));
        Assert.Equal(1, byObject.UnknownCount);
        Assert.Equal(2, byObject.Edges.Count);
        Assert.Single(byObject.Edges[0].Evidence);
        Assert.Equal(3, byObject.Edges[1].Preconditions.Count);
        Assert.False(byObject.Edges[1].IsCounted);
    }

    [Fact]
    public void ExpectedEdgesAreStoredAndTheirHiddenCountIsAlwaysReturned()
    {
        var directory = Store(writer =>
        {
            writer.StartControlEdges(true);
            var result = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(ControlEdgeDeriverTests.Ace(0, "S-1-5-18", 0x40000)));
            writer.WriteControlEdges(result with { Edges = result.Edges.Select(edge => edge with { GenerationId = writer.GenerationId }).ToArray() });
            writer.CompleteControlEdges();
        });
        using var reader = Open(directory);
        var hidden = reader.ReadControlEdges(null, null, null, false, 0);
        Assert.Empty(hidden.Edges);
        Assert.Equal(1, hidden.ExpectedCount);
        var shown = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Single(shown.Edges);
        Assert.Equal(hidden.ExpectedCount, shown.ExpectedCount);
    }

    [Fact]
    public void UnreadObjectAndUnrunProductDoNotReadAsZeroControl()
    {
        var directory = Store(writer =>
        {
            writer.StartControlEdges(false);
            writer.WriteControlEdges(ControlEdgeDeriverTests.Derive(null));
            writer.CompleteControlEdges();
        });
        using var reader = Open(directory);
        var page = reader.ReadControlEdges(null, null, null, false, 0);
        Assert.False(page.IsComplete);
        Assert.Equal(1, page.UnansweredObjects);
        Assert.False(page.CaptureIsComplete);
        using var absent = Open(Store(_ => { }));
        Assert.False(absent.ReadControlEdges(null, null, null, false, 0).ProductWasDerived);
    }

    private static JudgementReader Open(string path)
    {
        var opened = JudgementReader.Open(path);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value!;
    }
    private static string Store(Action<JudgementWriter> write)
    {
        var directory = TempDirectories.Create("control-edge-store");
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, Seal)));
        using var writer = JudgementWriter.Create(directory, Seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        write(writer);
        writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        return directory;
    }
}
