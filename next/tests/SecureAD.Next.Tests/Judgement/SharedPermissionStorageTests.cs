using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SharedPermissionStorageTests
{
    [Fact]
    public void IdentityOnlyWriteSharesTheValueWithTargetBoundWrites()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        using var statements = new PreparedStatements(connection);
        using var transaction = connection.BeginTransaction();
        var storage = new SharedPermissionStorage(connection, transaction, statements, new PermissionWriteSession());
        var generation = Guid.NewGuid();
        var entry = FullControlEvaluatorTests.Allow(0) with
        {
            Trustee = new("S-1-5-10", "This object (Alice)", null, null, null, null, null),
        };

        var id = storage.WriteValue(generation, entry);
        var bound = storage.Write("CN=Alice,DC=example", generation, entry);

        Assert.Equal(id, bound.Id);
    }

    [Fact]
    public void TargetBoundProofStillDiffersAcrossObjectsAfterIdentityOnlyWrite()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        using var statements = new PreparedStatements(connection);
        using var transaction = connection.BeginTransaction();
        var storage = new SharedPermissionStorage(connection, transaction, statements, new PermissionWriteSession());
        var generation = Guid.NewGuid();
        var entry = FullControlEvaluatorTests.Allow(0);
        storage.WriteValue(generation, entry);

        var first = storage.Write("CN=First,DC=example", generation, entry);
        var second = storage.Write("CN=Second,DC=example", generation, entry);

        Assert.False(first.Fingerprint.AsSpan().SequenceEqual(second.Fingerprint));
    }

    [Fact]
    public void RepeatedAssociationsAndFullControlSourcesShareValuesWithoutCollapsingOrdinals()
    {
        var result = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0), FullControlEvaluatorTests.Allow(1));
        var directory = FullControlStorageTests.Store([result]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = OpenDatabase(directory, reader);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM permission_entry),(SELECT COUNT(*) FROM control_ace),(SELECT COUNT(*) FROM full_control_source_entry),(SELECT COUNT(DISTINCT entry_id) FROM (SELECT entry_id FROM control_ace UNION ALL SELECT entry_id FROM full_control_source_entry)),(SELECT COUNT(DISTINCT ordinal) FROM (SELECT ordinal FROM control_ace UNION ALL SELECT ordinal FROM full_control_source_entry))";
        using var row = command.ExecuteReader();
        Assert.True(row.Read());
        // One stored entry behind every position, because these two differ only in ordinal and P-279
        // moved the ordinal onto the link - and still two ordinals, which is what not collapsing them
        // means. ExactExplanationIsSharedAndReconstructed is where they are read back apart.
        Assert.Equal((1L, result.Edges.Sum(edge => (long)edge.Evidence.Count), 2L, 1L, 2L),
            (row.GetInt64(0), row.GetInt64(1), row.GetInt64(2), row.GetInt64(3), row.GetInt64(4)));
    }

    // Ordinal is absent on purpose: since P-279 it is a fact about a position rather than about the
    // entry, so two positions of one entry share a row. The statement that they are still told apart
    // is made by RepeatedAssociationsAndFullControlSourcesShareValuesWithoutCollapsingOrdinals and
    // read back by SharedProofStorageTests.ExactExplanationIsSharedAndReconstructed.
    [Theory]
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
        // AN ORDINARY SID, WHERE THIS USED TO NAME S-1-5-10. Since P-285 the trustee's name is not a
        // round-tripped source field for PRINCIPAL SELF: it is stored as the catalogue's own name and
        // resolved against the target on the way out, which is what lets two objects share the row.
        // Swapping the SID keeps this test saying what its name says - every field survives - and the
        // SELF behaviour is checked directly by the three tests below rather than as a side effect
        // here.
        entry = entry with { Trustee = new("S-1-5-21-1-2-3-4400", "", "CN=MixedCase", null, (UnresolvedReferenceReason)0, null, "") };
        var result = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0), entry);
        using var reader = FullControlStorageTests.Open(FullControlStorageTests.Store([result]));
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.All(page.FullControlAssessments, assessment => Assert.Equal(JsonSerializer.Serialize(result.FullControlAssessments[0].Source.Entries),
            JsonSerializer.Serialize(assessment.Source.Entries)));
        Assert.NotEmpty(page.FullControlAssessments);
    }

    // -------------------------------------------------------------------------------------------
    // PRINCIPAL SELF is shared, and still reads back as the object it was found on (P-285)
    // -------------------------------------------------------------------------------------------
    //
    // S-1-5-10 grants the object itself, and ObjectPermissions renders it as "This object (Alice)"
    // against whatever is being read. That rendering used to be inside the sharing identity, so a
    // SELF entry never deduplicated - measured on a real forest, 34,593 of 36,484 rows in
    // permission_entry were this one SID. The entry is now stored in its shared form and the name is
    // resolved after the occurrence's fingerprint has been verified.
    //
    // The two halves have to be asserted together. Sharing alone is what the broken P-280 proposal
    // would have done, and it would have shown one object's name against another object's
    // permission; separate names alone is what the code did before, at one row per object.

    /// <summary>Two objects carrying the identical SELF entry share one stored row.</summary>
    [Fact]
    public void TwoObjectsCarryingTheSameSelfEntryShareOneRow()
    {
        using var connection = OpenDatabase(SelfOnTwoObjects(out var reader), reader);
        reader.Dispose();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM permission_entry WHERE sid='S-1-5-10'";

        Assert.Equal(1L, command.ExecuteScalar());
    }

    /// <summary>And each still reads back naming itself, not the other.</summary>
    /// <remarks>
    /// <b>The failure an audit tool cannot have</b>, and the one the review caught in the proposal:
    /// sharing the row must not make the second object display the first object's name. The stored
    /// row names neither.
    /// </remarks>
    [Fact]
    public void EachObjectStillReadsItsOwnNameForTheSharedSelfEntry()
    {
        var directory = SelfOnTwoObjects(out var reader);
        using (reader)
        {
            Assert.Equal(
                new List<string?> { "This object (Test)", "This object (Other)" },
                new[] { "OU=Test,DC=contoso,DC=com", "OU=Other,DC=contoso,DC=com" }
                    .Select(target => reader.ReadControlEdges(target, null, null, true, 0)
                        .Edges.SelectMany(edge => edge.Evidence)
                        .First(entry => entry.Trustee.Sid == "S-1-5-10").Trustee.Name)
                    .ToList());
        }

        Assert.True(Directory.Exists(directory));
    }

    /// <summary>The stored row names neither object, which is why it can be shared.</summary>
    /// <remarks>
    /// The negative control for the two above. Without it a build that stored one object's rendering
    /// and re-derived nothing would satisfy the sharing test, and the name test would pass for
    /// whichever object happened to be written first.
    /// </remarks>
    [Fact]
    public void TheStoredSelfRowCarriesTheCatalogueNameRatherThanEitherObjects()
    {
        using var connection = OpenDatabase(SelfOnTwoObjects(out var reader), reader);
        reader.Dispose();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM permission_entry WHERE sid='S-1-5-10'";

        Assert.Equal("Principal Self", command.ExecuteScalar());
    }

    /// <summary>
    /// Two objects, at different distinguished names, each carrying the same <c>SELF</c> entry.
    /// </summary>
    private static string SelfOnTwoObjects(out JudgementReader reader)
    {
        var self = ControlEdgeDeriverTests.Ace(0, "S-1-5-10", FullControlEvaluatorTests.FullMask) with
        {
            // As capture renders it: the RDN's value, not the whole relative name. Written out
            // rather than derived, so this fixture states what it expects instead of computing the
            // answer the same way the code under test does.
            Trustee = new("S-1-5-10", "This object (Test)", null, null, null, SecureAD.Kernel.Security.WellKnownSidRole.Placeholder, null),
        };

        var first = ControlEdgeDeriver.Derive(ControlEdgeDeriverTests.Subject,
            ControlEdgeDeriverTests.Permissions(self),
            JudgingContext.At(DateTimeOffset.UnixEpoch), Guid.Empty, null, ControlEdgeDeriverTests.DomainSid);

        var other = ControlEdgeDeriverTests.Subject with { DistinguishedName = "OU=Other,DC=contoso,DC=com" };
        var second = ControlEdgeDeriver.Derive(other,
            ControlEdgeDeriverTests.Permissions(self with
            {
                // As capture would have resolved it against the second object. The two entries differ
                // in exactly the way that used to stop them sharing a row and in no other.
                Trustee = self.Trustee with { Name = "This object (Other)" },
            }) with { DistinguishedName = other.DistinguishedName },
            JudgingContext.At(DateTimeOffset.UnixEpoch), Guid.Empty, null, ControlEdgeDeriverTests.DomainSid);

        var directory = FullControlStorageTests.Store([first, second]);
        reader = FullControlStorageTests.Open(directory);
        return directory;
    }

    [Theory]
    [InlineData("UPDATE permission_entry SET generation='11111111-1111-1111-1111-111111111111'")]
    [InlineData("UPDATE permission_entry SET entry_hash='0000000000000000000000000000000000000000000000000000000000000000'")]
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

    // THE SECOND OBJECT'S ENTRY MUST DIFFER, or this measures nothing. Since P-279 two objects
    // carrying an identical entry share its row, so repointing a link at MAX(id) would select the row
    // it already pointed at and the mutation would be a no-op that still passed. Only the trustee's
    // display name differs, which leaves the rights and so the derived edges alone.
    [Theory]
    [InlineData("control_ace")]
    [InlineData("full_control_source_entry")]
    public void ValidEntryFromAnotherTargetCannotReplaceAReference(string table)
    {
        var first = FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0));
        var subject = ControlEdgeDeriverTests.Subject with { DistinguishedName = "OU=Other,DC=contoso,DC=com" };
        var second = ControlEdgeDeriver.Derive(subject, ControlEdgeDeriverTests.Permissions(Change(FullControlEvaluatorTests.Allow(0), "Name")),
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
