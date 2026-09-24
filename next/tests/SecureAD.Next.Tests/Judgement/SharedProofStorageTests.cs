using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class SharedProofStorageTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Case")]
    [InlineData("case")]
    [InlineData(" Case ")]
    [InlineData("café 🚀")]
    public void ExactExplanationIsSharedAndReconstructed(string? meaning)
    {
        var first = FullControlEvaluatorTests.Allow(0);
        first = first with { Trustee = first.Trustee with { Meaning = meaning } };
        var second = first with { Ordinal = 1 };
        var directory = FullControlStorageTests.Store([FullControlStorageTests.Evaluation(first, second)]);
        using var reader = FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        var proof = Assert.Single(page.FullControlAssessments);
        Assert.Equal(JsonSerializer.Serialize(new[] { first, second }), JsonSerializer.Serialize(proof.Source.Entries));
        using var connection = OpenDatabase(directory, reader);
        Assert.Equal(meaning is null ? 0 : 1, Count(connection, "SELECT COUNT(*) FROM shared_proof_value WHERE kind='Meaning'"));
        // One row for the entry, two links to it: the two positions differ only in ordinal, which
        // P-279 moved onto the link. The exact reconstruction asserted above is what proves the
        // sharing did not cost them their positions.
        Assert.Equal((1, 2), (Count(connection, "SELECT COUNT(*) FROM permission_entry"),
            Count(connection, "SELECT COUNT(*) FROM full_control_source_entry")));
        Assert.All(page.Edges.SelectMany(edge => edge.Evidence), entry => Assert.Null(entry.Trustee.Meaning));
    }

    [Fact]
    public void LookupCollisionsNeverMergeUnequalValuesOrGenerations()
    {
        using var connection = Memory();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        var store = new SharedProofStorage(connection, transaction, _ => new byte[32], statements);
        var generation = Guid.NewGuid();
        var a = store.WriteMeaning(generation, "entry-A", "Case");
        var same = store.WriteMeaning(generation, "entry-B", "Case");
        var differentCase = store.WriteMeaning(generation, "entry-A", "case");
        var differentSpace = store.WriteMeaning(generation, "entry-A", " Case ");
        var otherGeneration = store.WriteMeaning(Guid.NewGuid(), "entry-A", "Case");
        var empty = store.WriteMeaning(generation, "entry-A", "");
        var absent = store.WriteMeaning(generation, "entry-A", null);
        Assert.Equal(a.Id, same.Id);
        Assert.False(a.Fingerprint.AsSpan().SequenceEqual(same.Fingerprint));
        Assert.Equal(5, new[] { a.Id, differentCase.Id, differentSpace.Id, otherGeneration.Id, empty.Id }.Distinct().Count());
        Assert.Null(absent.Id);
        Assert.False(empty.Fingerprint.AsSpan().SequenceEqual(absent.Fingerprint));
        Assert.Equal(5, Count(connection, "SELECT COUNT(*) FROM shared_proof_value"));
    }

    [Fact]
    public void RolledBackValueIdsCannotEscapeTheirTransaction()
    {
        using var connection = Memory();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        var store = new SharedProofStorage(connection, transaction, statements);
        var generation = Guid.NewGuid();
        Assert.NotNull(store.WriteMeaning(generation, "entry-A", "value").Id);
        transaction.Rollback();
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM shared_proof_value"));
        Assert.ThrowsAny<InvalidOperationException>(() => store.WriteMeaning(generation, "entry-A", "value"));
        using var next = connection.BeginTransaction();
        using var nextStatements = new PreparedStatements(connection);
        Assert.NotNull(new SharedProofStorage(connection, next, nextStatements).WriteMeaning(generation, "entry-A", "value").Id);
        next.Commit();
        Assert.Equal(1, Count(connection, "SELECT COUNT(*) FROM shared_proof_value"));
    }

    [Fact]
    public void CompleteRoutesShareAcrossConsumersWithoutCollapsingOrderOrBindings()
    {
        var routes = Routes();
        var first = ControlOnly("OU=First,DC=contoso,DC=com", routes);
        var second = ControlOnly("OU=Second,DC=contoso,DC=com", routes);
        var directory = FullControlStorageTests.Store([first, second]);
        using var reader = FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Equal(2, page.Edges.Count);
        Assert.All(page.Edges, edge => Assert.Equal(JsonSerializer.Serialize(routes), JsonSerializer.Serialize(edge.MembershipRoutes)));
        using var connection = OpenDatabase(directory, reader);
        Assert.Equal(1, Count(connection, "SELECT COUNT(*) FROM shared_proof_value WHERE kind='MembershipRoutes'"));
        Assert.Equal(2, Count(connection, "SELECT COUNT(*) FROM control_membership_route"));
        Assert.Equal(2, Count(connection, "SELECT COUNT(DISTINCT hex(fingerprint)) FROM control_membership_route"));
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM membership_route_summary WHERE subject_id LIKE 'control:%'"));
        Assert.Equal(6, Count(connection, "SELECT COUNT(*) FROM membership_route_step"));
        var objectPage = reader.ReadControlEdges(first.Target.ToUpperInvariant(), null, null, true, 0);
        var holderPage = reader.ReadControlEdges(null, page.Edges[0].HolderSid, null, true, 0);
        Assert.Equal(JsonSerializer.Serialize(objectPage.Edges[0]), JsonSerializer.Serialize(holderPage.Edges.Single(edge => edge.Target == first.Target)));
        Assert.Equal(JsonSerializer.Serialize(objectPage), JsonSerializer.Serialize(reader.ReadControlEdges(first.Target.ToUpperInvariant(), null, null, true, 0)));
    }

    [Theory]
    [InlineData("target")]
    [InlineData("holder")]
    [InlineData("scope")]
    [InlineData("generation")]
    [InlineData("derivation")]
    [InlineData("catalogue")]
    [InlineData("capability")]
    public void AValidSharedRouteCannotBeReboundToAnotherConsumer(string change)
    {
        var directory = FullControlStorageTests.Store([ControlOnly("OU=First,DC=contoso,DC=com", Routes())]);
        using var reader = FullControlStorageTests.Open(directory);
        var edge = Assert.Single(reader.ReadControlEdges(null, null, null, true, 0).Edges);
        using var connection = OpenDatabase(directory, reader);
        var changed = change switch
        {
            "target" => edge with { Target = edge.Target.ToLowerInvariant() },
            "holder" => edge with { HolderSid = "S-1-1-0" },
            "scope" => edge with { HolderScope = "other.contoso.com" },
            "generation" => edge with { GenerationId = Guid.NewGuid() },
            "derivation" => edge with { DerivationGenerationId = Guid.NewGuid() },
            "catalogue" => edge with { PrincipalCatalogueVersion = edge.PrincipalCatalogueVersion + 1 },
            "capability" => edge with { Capability = ControlCapability.CanSetOwner },
            _ => throw new ArgumentOutOfRangeException(nameof(change)),
        };
        Assert.Throws<InvalidOperationException>(() => SharedProofStorage.ReadControlRoutes(connection, changed));
    }

    [Fact]
    public void EmptyRouteProofIsSharedByControlAndFullControlWithoutAnEmbeddedPlaceholder()
    {
        var directory = FullControlStorageTests.Store([FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0))]);
        using var reader = FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(null, null, null, true, 0);
        Assert.Equal(JsonSerializer.Serialize(MembershipRouteSummary.NotDerived), JsonSerializer.Serialize(Assert.Single(page.FullControlAssessments).Source.MembershipRoutes));
        using var connection = OpenDatabase(directory, reader);
        Assert.Equal(1, Count(connection, "SELECT COUNT(*) FROM shared_proof_value WHERE kind='MembershipRoutes'"));
        Assert.Equal(1, Count(connection, "SELECT COUNT(DISTINCT value_id) FROM (SELECT value_id FROM control_membership_route UNION ALL SELECT route_value_id FROM full_control_assessment)"));
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM full_control_assessment WHERE json_type(proof,'$.Source.MembershipRoutes') IS NOT NULL"));
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"));
    }

    [Theory]
    [InlineData("UPDATE shared_proof_value SET payload=payload||'changed' WHERE kind='Meaning'")]
    [InlineData("DELETE FROM shared_proof_value WHERE kind='Meaning'")]
    [InlineData("UPDATE permission_entry SET meaning=NULL")]
    [InlineData("UPDATE permission_entry SET meaning_binding=zeroblob(32)")]
    [InlineData("UPDATE shared_proof_value SET format_version=99")]
    [InlineData("UPDATE shared_proof_value SET generation='11111111-1111-1111-1111-111111111111'")]
    [InlineData("UPDATE shared_proof_value SET derivation_generation='11111111-1111-1111-1111-111111111111'")]
    [InlineData("UPDATE shared_proof_value SET catalogue_version=99")]
    [InlineData("UPDATE shared_proof_value SET fingerprint=zeroblob(32)")]
    [InlineData("DELETE FROM shared_proof_value WHERE kind='MembershipRoutes'")]
    [InlineData("DELETE FROM control_membership_route")]
    [InlineData("UPDATE control_membership_route SET fingerprint=zeroblob(32)")]
    [InlineData("UPDATE full_control_assessment SET route_value_id=999999")]
    [InlineData("UPDATE full_control_assessment SET route_fingerprint=zeroblob(32)")]
    [InlineData("UPDATE membership_route_summary SET incomplete_reasons=0 WHERE subject_id LIKE 'proof-route:%'")]
    [InlineData("UPDATE full_control_assessment SET proof=json_set(proof,'$.Source.MembershipRoutes',json('{}'))")]
    public void SharedProofCorruptionIsRefusedBeforeOffPageCounts(string mutation)
    {
        var entry = FullControlEvaluatorTests.Allow(0);
        entry = entry with { Trustee = entry.Trustee with { Meaning = "captured explanation" } };
        var directory = FullControlStorageTests.Store([FullControlStorageTests.Evaluation(entry)], connection => Mutate(connection, mutation));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadPage(reader, null, null, null, true, long.MaxValue));
    }

    [Theory]
    [InlineData("meaning")]
    [InlineData("control")]
    [InlineData("full-control")]
    public void RedirectingToAnotherIntactValueStillFailsTheOriginalBinding(string kind)
    {
        var entry = FullControlEvaluatorTests.Allow(0);
        entry = entry with { Trustee = entry.Trustee with { Meaning = "first explanation" } };
        var first = FullControlStorageTests.Evaluation(entry);
        var second = ControlOnly("OU=Second,DC=contoso,DC=com", Routes(), "second explanation");
        var mutation = kind switch
        {
            "meaning" => "UPDATE permission_entry SET meaning=(SELECT id FROM shared_proof_value WHERE kind='Meaning' AND payload='second explanation')",
            "control" => "UPDATE control_membership_route SET value_id=(SELECT MAX(id) FROM shared_proof_value WHERE kind='MembershipRoutes')",
            "full-control" => "UPDATE full_control_assessment SET route_value_id=(SELECT MAX(id) FROM shared_proof_value WHERE kind='MembershipRoutes')",
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var directory = FullControlStorageTests.Store([first, second], connection => Mutate(connection, mutation));
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => ControlProofVerification.ReadPage(reader, null, null, null, true, long.MaxValue));
    }

    [Fact]
    public void RehashedAndStructurallyConsistentRouteChangeStillFailsTheConsumerBinding()
    {
        var directory = FullControlStorageTests.Store([FullControlStorageTests.Evaluation(FullControlEvaluatorTests.Allow(0))], connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT id,generation,derivation_generation,catalogue_version FROM shared_proof_value WHERE kind='MembershipRoutes'";
            long id;
            Guid generation;
            Guid? derived;
            int catalogue;
            using (var read = command.ExecuteReader())
            {
                Assert.True(read.Read());
                id = read.GetInt64(0); generation = Guid.Parse(read.GetString(1));
                derived = read.IsDBNull(2) ? null : Guid.Parse(read.GetString(2)); catalogue = read.GetInt32(3);
            }
            var payload = JsonSerializer.Serialize(new MembershipRouteSummary([], MembershipRouteIncompleteReason.None));
            command.CommandText = "UPDATE shared_proof_value SET payload=$payload,fingerprint=$hash WHERE id=$id";
            command.Parameters.AddWithValue("$payload", payload);
            command.Parameters.AddWithValue("$hash", SharedProofStorage.ValueFingerprint("MembershipRoutes", generation, derived, catalogue, payload));
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, command.ExecuteNonQuery());
            command.Parameters.Clear();
            command.CommandText = "UPDATE membership_route_summary SET incomplete_reasons=0 WHERE subject_id='proof-route:'||$id";
            command.Parameters.AddWithValue("$id", id);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = FullControlStorageTests.Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(null, null, null, true, 0));
    }

    [Fact]
    public void FailedObjectRollsBackSharedRowsAndReferencesWhilePreservingEarlierObjects()
    {
        using var connection = Memory();
        StorageWrites.ControlEdges(connection, ControlOnly("OU=Saved,DC=contoso,DC=com", Routes(), "saved"), ownershipTarget: null);
        var tables = new[] { "control_object", "control_edge", "permission_entry", "control_ace", "control_precondition", "shared_proof_value",
            "control_membership_route", "membership_route_summary", "membership_route", "membership_route_step", "full_control_manifest", "full_control_source", "full_control_source_entry", "full_control_assessment", "full_control_support" };
        var before = tables.Select(table => Count(connection, "SELECT COUNT(*) FROM " + table)).ToArray();
        var entry = FullControlEvaluatorTests.Allow(0);
        entry = entry with { Trustee = entry.Trustee with { Meaning = "only the failed object" } };
        var result = FullControlStorageTests.Evaluation(entry);
        var invalid = result with { FullControlAssessments = [result.FullControlAssessments[0] with { SupportingCapabilities = [] }] };
        Assert.Throws<InvalidOperationException>(() => StorageWrites.ControlEdges(connection, invalid, ownershipTarget: null));
        Assert.Equal(before, tables.Select(table => Count(connection, "SELECT COUNT(*) FROM " + table)).ToArray());
        StorageWrites.ControlEdges(connection, result, ownershipTarget: null);
        Assert.Equal(2, Count(connection, "SELECT COUNT(*) FROM control_object"));
        Assert.Equal(0, Count(connection, "SELECT COUNT(*) FROM pragma_foreign_key_check"));
    }

    private static MembershipRouteSummary Routes()
    {
        var first = new MembershipRoutePrincipal("S-1-5-21-1-2-3-1000", null, "CN=Account,DC=contoso,DC=com");
        var initial = new MembershipRoutePrincipal("S-1-5-32-544", "contoso.com", "CN=MixedCase,CN=Builtin,DC=contoso,DC=com");
        var root = new MembershipRoutePrincipal("S-1-5-21-1-2-3-512", null, "CN=Root,DC=contoso,DC=com");
        var other = new MembershipRoutePrincipal("S-1-5-21-1-2-3-519", null, "CN=OtherRoot,DC=contoso,DC=com");
        return new([new(initial,
            [new(1, "First root", MembershipRouteAuthorization.SecurityEnabled, false, [new(first, false), new(initial, true), new(root, false)]),
             new(2, "Second root", MembershipRouteAuthorization.DistributionGroup, false, [new(first, false), new(initial, true), new(other, false)])],
            MembershipRouteIncompleteReason.MembershipEvidenceIncomplete | MembershipRouteIncompleteReason.CycleBoundary)],
            MembershipRouteIncompleteReason.MembershipEvidenceIncomplete | MembershipRouteIncompleteReason.CycleBoundary);
    }

    private static ControlObjectEvaluation ControlOnly(string target, MembershipRouteSummary routes, string? meaning = null)
    {
        var entry = FullControlEvaluatorTests.Allow(0);
        entry = entry with { Trustee = entry.Trustee with { Meaning = meaning } };
        var result = FullControlStorageTests.Evaluation(entry);
        var edge = result.Edges.Single(value => value.Capability == ControlCapability.CanWriteDacl);
        return result with { Target = target, FullControlAssessments = [], Edges = [edge with { Target = target, MembershipRoutes = routes }] };
    }

    private static void Mutate(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys=OFF"; command.ExecuteNonQuery();
        command.CommandText = sql; Assert.True(command.ExecuteNonQuery() > 0);
    }

    private static SqliteConnection Memory()
    {
        var connection = new SqliteConnection("Data Source=:memory:"); connection.Open();
        JudgementSchema.CreateTables(connection); return connection;
    }

    private static SqliteConnection OpenDatabase(string directory, JudgementReader reader)
    {
        var connection = new SqliteConnection("Data Source=" + BundleLayout.AnalysisGenerationDataPath(directory,
            AnalysisStoreKind.Judgement, reader.Description.GenerationId) + ";Mode=ReadOnly;Pooling=False");
        connection.Open(); return connection;
    }

    private static long Count(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand(); command.CommandText = sql; return (long)command.ExecuteScalar()!;
    }
}
