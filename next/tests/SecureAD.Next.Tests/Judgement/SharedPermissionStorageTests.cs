using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SharedPermissionStorageTests
{
    [Fact]
    public void RepeatedAssociationsAndFullControlSourcesShareValuesWithoutCollapsingOrdinals()
    {
        var result = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0), FullControlEvaluatorTests.Allow(1));
        var directory = FullControlStorageTests.Store([result]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = OpenDatabase(directory, reader);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM permission_entry),(SELECT COUNT(*) FROM control_ace),(SELECT COUNT(*) FROM full_control_source_entry),(SELECT COUNT(DISTINCT entry_id) FROM (SELECT entry_id FROM control_ace UNION ALL SELECT entry_id FROM full_control_source_entry))";
        using var row = command.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal((2L, result.Edges.Sum(edge => (long)edge.Evidence.Count), 2L, 2L),
            (row.GetInt64(0), row.GetInt64(1), row.GetInt64(2), row.GetInt64(3)));
    }

    [Theory]
    [InlineData("Ordinal")]
    [InlineData("AceType")]
    [InlineData("Sid")]
    [InlineData("Name")]
    [InlineData("DistinguishedName")]
    [InlineData("DomainFqdn")]
    [InlineData("UnresolvedReason")]
    [InlineData("WellKnownRole")]
    [InlineData("Meaning")]
    [InlineData("AccessMask")]
    [InlineData("ObjectTypeGuid")]
    [InlineData("InheritedObjectTypeGuid")]
    [InlineData("IsInherited")]
    [InlineData("InheritanceFlags")]
    [InlineData("PropagationFlags")]
    [InlineData("HasObjectType")]
    [InlineData("HasInheritedObjectType")]
    [InlineData("ApplicationData")]
    public void DistinctCompleteValuesAtTheSameTargetAreNotMerged(string field)
    {
        var original = FullControlEvaluatorTests.Allow(0);
        var result = TwoEdges(original, Change(original, field));
        var directory = FullControlStorageTests.Store([result]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = OpenDatabase(directory, reader);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM permission_entry";
        Assert.Equal(2L, command.ExecuteScalar());
    }

    [Fact]
    public void EqualCallbackBytesInDifferentArraysShareOneEntry()
    {
        var first = FullControlEvaluatorTests.Allow(0) with { AceType = "AccessAllowedCallback", ApplicationData = [0, 1, 255] };
        var second = first with { ApplicationData = [0, 1, 255] };
        var directory = FullControlStorageTests.Store([TwoEdges(first, second)]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = OpenDatabase(directory, reader);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM permission_entry";
        Assert.Equal(1L, command.ExecuteScalar());
    }

    [Fact]
    public void FullControlRetainsRicherMetadataWhileControlEdgesKeepTheirExistingProjection()
    {
        var entry = FullControlEvaluatorTests.Allow(0);
        entry = entry with { Trustee = entry.Trustee with { UnresolvedReason = (UnresolvedReferenceReason)0, Meaning = "Captured meaning" } };
        using var reader = FullControlStorageTests.Open(FullControlStorageTests.Store([FullControlStorageTests.Evaluation(entry)]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        var source = Assert.Single(page.FullControlAssessments).Source.Entries;
        var projected = entry with { Trustee = entry.Trustee with { UnresolvedReason = null, Meaning = null } };
        Assert.Equal((JsonSerializer.Serialize(new[] { entry }), JsonSerializer.Serialize(new[] { projected })),
            (JsonSerializer.Serialize(source), JsonSerializer.Serialize(page.Edges[0].Evidence)));
    }

    [Fact]
    public void FullControlRoundTripsEverySourceFieldIncludingUnsupportedInputs()
    {
        var entry = FullControlEvaluatorTests.Allow(7) with
        {
            AceType = "AccessDeniedCallbackObject", AccessMask = unchecked((int)0x80000000),
            ObjectTypeGuid = "ABCDEF00-1234-1234-1234-123456789ABC", InheritedObjectTypeGuid = "",
            IsInherited = true, InheritanceFlags = 3, PropagationFlags = 8,
            HasObjectType = true, HasInheritedObjectType = true, ApplicationData = [0, 255, 128, 1],
        };
        entry = entry with { Trustee = new("S-1-5-10", "", "CN=MixedCase", null, (UnresolvedReferenceReason)0, null, "") };
        var result = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0), entry);
        using var reader = FullControlStorageTests.Open(FullControlStorageTests.Store([result]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.All(page.FullControlAssessments, assessment => Assert.Equal(JsonSerializer.Serialize(result.FullControlAssessments[0].Source.Entries),
            JsonSerializer.Serialize(assessment.Source.Entries)));
        Assert.NotEmpty(page.FullControlAssessments);
    }

    [Theory]
    [InlineData("UPDATE permission_entry SET target='OU=Wrong,DC=contoso,DC=com'")]
    [InlineData("UPDATE permission_entry SET generation='11111111-1111-1111-1111-111111111111'")]
    [InlineData("UPDATE permission_entry SET ordinal=ordinal+10")]
    [InlineData("UPDATE permission_entry SET ace_type='AccessDenied'")]
    [InlineData("UPDATE permission_entry SET ace_type=lower(ace_type)")]
    [InlineData("UPDATE permission_entry SET name=COALESCE(name,'') || 'changed'")]
    [InlineData("UPDATE permission_entry SET meaning='changed'")]
    [InlineData("UPDATE permission_entry SET application_data=X'0001FF'")]
    [InlineData("UPDATE permission_entry SET has_object_type=1")]
    [InlineData("UPDATE control_ace SET ordinal=ordinal+10")]
    [InlineData("UPDATE control_ace SET entry_id=999999")]
    [InlineData("UPDATE control_ace SET fingerprint=zeroblob(32)")]
    [InlineData("UPDATE full_control_source_entry SET entry_id=999999")]
    [InlineData("UPDATE full_control_source_entry SET position=position+10")]
    [InlineData("UPDATE full_control_source_entry SET ordinal=ordinal+10")]
    [InlineData("DELETE FROM full_control_source_entry")]
    [InlineData("UPDATE full_control_source SET ace_count=99")]
    [InlineData("DELETE FROM permission_entry")]
    public void DamagedSharedProofOutsideThePageIsRefusedBeforeCounts(string mutation)
    {
        var directory = FullControlStorageTests.Store([FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0))], connection => Mutate(connection, mutation));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadPage(reader, null, null, null, true, long.MaxValue));
    }

    [Theory]
    [InlineData("control_ace")]
    [InlineData("full_control_source_entry")]
    public void ValidEntryFromAnotherTargetCannotReplaceAReference(string table)
    {
        var first = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0));
        var subject = ControlEdgeDeriverTests.Subject with { DistinguishedName = "OU=Other,DC=contoso,DC=com" };
        var second = ControlEdgeDeriver.Derive(subject, ControlEdgeDeriverTests.Permissions(FullControlEvaluatorTests.Allow(0)),
            JudgingContext.At(DateTimeOffset.UnixEpoch), Guid.Empty, null, ControlEdgeDeriverTests.DomainSid);
        var directory = FullControlStorageTests.Store([first, second], connection =>
            Mutate(connection, $"UPDATE {table} SET entry_id=(SELECT MAX(id) FROM permission_entry)"));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(first.Target, null, null, true, 0));
    }

    [Fact]
    public void ReorderedValidSourcesAreRefusedEvenWhenCountsAndOrdinalsRemainValid()
    {
        var result = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0), FullControlEvaluatorTests.Allow(1));
        var directory = FullControlStorageTests.Store([result], connection => Mutate(connection,
            "UPDATE full_control_source_entry SET position=-(position+1); UPDATE full_control_source_entry SET position=position+2"));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadPage(reader, null, null, null, true, long.MaxValue));
    }

    [Fact]
    public void SameTargetSameOrdinalReferenceCannotSubstituteHiddenMetadata()
    {
        var entry = FullControlEvaluatorTests.Allow(0);
        var other = entry with { Trustee = entry.Trustee with { Meaning = "Another captured representation" } };
        var directory = FullControlStorageTests.Store([TwoEdges(entry, other)], connection => Mutate(connection,
            "UPDATE control_ace SET entry_id=(SELECT MAX(id) FROM permission_entry) WHERE edge_id=(SELECT MIN(id) FROM control_edge)"));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(null, null, null, true, 0));
    }

    private static ControlObjectEvaluation TwoEdges(PermissionEntry first, PermissionEntry second)
    {
        var result = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0));
        var seed = result.Edges.Single(edge => edge.Capability == ControlCapability.CanWriteDacl);
        return result with
        {
            FullControlAssessments = [],
            Edges = [seed with { Evidence = [first] }, seed with { HolderSid = "S-1-5-21-1-2-3-9999", Evidence = [second] }],
        };
    }

    private static PermissionEntry Change(PermissionEntry entry, string field) => field switch
    {
        "Ordinal" => entry with { Ordinal = 1 },
        "AceType" => entry with { AceType = "AccessDenied" },
        "Sid" => entry with { Trustee = entry.Trustee with { Sid = "S-1-5-10" } },
        "Name" => entry with { Trustee = entry.Trustee with { Name = "" } },
        "DistinguishedName" => entry with { Trustee = entry.Trustee with { DistinguishedName = "" } },
        "DomainFqdn" => entry with { Trustee = entry.Trustee with { DomainFqdn = "" } },
        "UnresolvedReason" => entry with { Trustee = entry.Trustee with { UnresolvedReason = (UnresolvedReferenceReason)0 } },
        "WellKnownRole" => entry with { Trustee = entry.Trustee with { WellKnownRole = (SecureAD.Kernel.Security.WellKnownSidRole)0 } },
        "Meaning" => entry with { Trustee = entry.Trustee with { Meaning = "" } },
        "AccessMask" => entry with { AccessMask = 0x10000000 },
        "ObjectTypeGuid" => entry with { ObjectTypeGuid = "" },
        "InheritedObjectTypeGuid" => entry with { InheritedObjectTypeGuid = "" },
        "IsInherited" => entry with { IsInherited = true },
        "InheritanceFlags" => entry with { InheritanceFlags = 1 },
        "PropagationFlags" => entry with { PropagationFlags = 8 },
        "HasObjectType" => entry with { HasObjectType = true },
        "HasInheritedObjectType" => entry with { HasInheritedObjectType = true },
        "ApplicationData" => entry with { ApplicationData = [0, 255] },
        _ => throw new ArgumentOutOfRangeException(nameof(field)),
    };

    private static void Mutate(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        // Deliberately damage storage even where normal writes refuse a dangling reference.
        command.CommandText = "PRAGMA foreign_keys=OFF";
        command.ExecuteNonQuery();
        command.CommandText = sql;
        Assert.True(command.ExecuteNonQuery() > 0);
    }

    private static SqliteConnection OpenDatabase(string directory, JudgementReader reader)
    {
        var connection = new SqliteConnection("Data Source=" + BundleLayout.AnalysisGenerationDataPath(directory,
            AnalysisStoreKind.Judgement, reader.Description.GenerationId) + ";Mode=ReadOnly;Pooling=False");
        connection.Open();
        return connection;
    }
}
