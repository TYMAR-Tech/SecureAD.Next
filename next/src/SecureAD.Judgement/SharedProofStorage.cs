using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence.Findings;
using SecureAD.Storage;

namespace SecureAD.Judgement;

// Reuse lasts only for the owning object transaction; rolled-back IDs never escape it.
internal sealed class SharedProofStorage(SqliteConnection connection, SqliteTransaction transaction,
    Func<string, byte[]> lookupHash, PreparedStatements statements)
{
    internal const int FormatVersion = 1;
    private readonly Dictionary<string, long> written = new(StringComparer.Ordinal);
    private readonly Func<string, byte[]> lookup = lookupHash ?? throw new ArgumentNullException(nameof(lookupHash));

    internal SharedProofStorage(SqliteConnection connection, SqliteTransaction transaction,
        PreparedStatements statements)
        : this(connection, transaction, Hash, statements)
    {
    }

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE shared_proof_value (id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL CHECK(kind IN ('Meaning','MembershipRoutes')), format_version INTEGER NOT NULL,
                generation TEXT NOT NULL, derivation_generation TEXT NULL, catalogue_version INTEGER NOT NULL,
                payload TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),
                lookup_hash BLOB NOT NULL CHECK(length(lookup_hash)=32));
            CREATE INDEX ix_shared_proof_lookup ON shared_proof_value(lookup_hash);
            CREATE TABLE control_membership_route (edge_id INTEGER PRIMARY KEY REFERENCES control_edge(id),
                value_id INTEGER NOT NULL REFERENCES shared_proof_value(id),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal (long? Id, byte[] Fingerprint) WriteMeaning(string target, Guid generation, int ordinal, string? meaning)
    {
        Active();
        long? id = null;
        if (meaning is not null)
        {
            var key = ValueKey("Meaning", generation, null, 0, meaning);
            id = Put("Meaning", generation, null, 0, meaning, out _);
            written[key] = id.Value;
        }
        return (id, MeaningBinding(target, generation, ordinal, meaning));
    }

    internal void WriteControlRoutes(ControlEdge edge)
    {
        var value = WriteRoutes(edge.MembershipRoutes, edge.GenerationId, edge.DerivationGenerationId, edge.PrincipalCatalogueVersion);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO control_membership_route VALUES ($edge,$value,$hash)";
        command.Parameters.AddWithValue("$edge", edge.Id);
        command.Parameters.AddWithValue("$value", value);
        command.Parameters.AddWithValue("$hash", ControlBinding(edge, JsonSerializer.Serialize(edge.MembershipRoutes)));
        command.ExecuteNonQuery();
    }

    internal (long Id, byte[] Fingerprint) WriteFullControlRoutes(FullControlAssessment assessment)
    {
        var value = WriteRoutes(assessment.Source.MembershipRoutes, assessment.GenerationId,
            assessment.DerivationGenerationId, assessment.PrincipalCatalogueVersion);
        return (value, FullControlBinding(assessment, JsonSerializer.Serialize(assessment.Source.MembershipRoutes)));
    }

    private long WriteRoutes(MembershipRouteSummary routes, Guid generation, Guid? derived, int catalogue)
    {
        Active();
        if (routes is null || routes.Memberships is null) throw FullControlEvaluator.InvalidProof();
        var payload = JsonSerializer.Serialize(routes);
        var key = ValueKey("MembershipRoutes", generation, derived, catalogue, payload);
        if (written.TryGetValue(key, out var cached)) return cached;
        var id = Put("MembershipRoutes", generation, derived, catalogue, payload, out var created);
        if (created)
            MembershipRouteStorage.Write(connection, transaction, RouteSubject(id), routes);
        else if (JsonSerializer.Serialize(ReadRoutes(connection, id, generation, derived, catalogue)) != payload)
            throw FullControlEvaluator.InvalidProof();
        written.Add(key, id);
        return id;
    }

    private long Put(string kind, Guid generation, Guid? derived, int catalogue, string payload, out bool created)
    {
        Active();
        var key = ValueKey(kind, generation, derived, catalogue, payload);
        if (written.TryGetValue(key, out var cached))
        {
            created = false;
            return cached;
        }
        var bucket = lookup(key);
        const string select = "SELECT id,kind,format_version,generation,derivation_generation,catalogue_version,payload,fingerprint FROM shared_proof_value WHERE lookup_hash=$lookup ORDER BY id";
        const string insert = """
            INSERT INTO shared_proof_value(kind,format_version,generation,derivation_generation,catalogue_version,payload,fingerprint,lookup_hash)
            VALUES ($kind,$version,$generation,$derived,$catalogue,$payload,$hash,$lookup);
            SELECT last_insert_rowid();
            """;
        var find = statements.Bind(select, transaction, ("$lookup", bucket));
        using (var read = find.ExecuteReader())
        {
            while (read.Read())
            {
                var storedKey = ValueKey(read.GetString(1), Guid.Parse(read.GetString(3)),
                    read.IsDBNull(4) ? null : Guid.Parse(read.GetString(4)), read.GetInt32(5), read.GetString(6));
                if (read.GetInt32(2) != FormatVersion || !Hash(storedKey).AsSpan().SequenceEqual((byte[])read.GetValue(7)))
                    throw FullControlEvaluator.InvalidProof();
                // The bucket is an index, not identity: compare complete, ordinal values after a hash collision.
                if (storedKey == key)
                {
                    created = false;
                    return read.GetInt64(0);
                }
            }
        }

        (string Name, object? Value)[] values =
        [
            ("$kind", kind), ("$version", FormatVersion), ("$generation", generation.ToString("D")),
            ("$derived", derived is { } source ? source.ToString("D") : null), ("$catalogue", catalogue),
            ("$payload", payload), ("$hash", Hash(key)), ("$lookup", bucket),
        ];
        created = true;
        return (long)statements.Bind(insert, transaction, values).ExecuteScalar()!;
    }

    internal static MembershipRouteSummary ReadControlRoutes(SqliteConnection connection, ControlEdge edge)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT value_id,fingerprint FROM control_membership_route WHERE edge_id=$edge";
        command.Parameters.AddWithValue("$edge", edge.Id);
        long id;
        byte[] fingerprint;
        using (var read = command.ExecuteReader())
        {
            if (!read.Read()) throw FullControlEvaluator.InvalidProof();
            id = read.GetInt64(0);
            fingerprint = (byte[])read.GetValue(1);
        }
        var routes = ReadRoutes(connection, id, edge.GenerationId, edge.DerivationGenerationId, edge.PrincipalCatalogueVersion);
        if (!ControlBinding(edge, JsonSerializer.Serialize(routes)).AsSpan().SequenceEqual(fingerprint))
            throw FullControlEvaluator.InvalidProof();
        return routes;
    }

    internal static MembershipRouteSummary ReadFullControlRoutes(SqliteConnection connection, FullControlAssessment assessment,
        long id, byte[] fingerprint)
    {
        var routes = ReadRoutes(connection, id, assessment.GenerationId, assessment.DerivationGenerationId, assessment.PrincipalCatalogueVersion);
        if (!FullControlBinding(assessment, JsonSerializer.Serialize(routes)).AsSpan().SequenceEqual(fingerprint))
            throw FullControlEvaluator.InvalidProof();
        return routes;
    }

    private static MembershipRouteSummary ReadRoutes(SqliteConnection connection, long id, Guid generation, Guid? derived, int catalogue)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT kind,format_version,generation,derivation_generation,catalogue_version,payload,fingerprint FROM shared_proof_value WHERE id=$id";
        command.Parameters.AddWithValue("$id", id);
        string payload;
        using (var read = command.ExecuteReader())
        {
            if (!read.Read() || read.GetString(0) != "MembershipRoutes" || read.GetInt32(1) != FormatVersion
                || read.GetString(2) != generation.ToString("D") || Text(read, 3) != derived?.ToString("D")
                || read.GetInt32(4) != catalogue) throw FullControlEvaluator.InvalidProof();
            payload = read.GetString(5);
            if (!ValueFingerprint("MembershipRoutes", generation, derived, catalogue, payload).AsSpan().SequenceEqual((byte[])read.GetValue(6)))
                throw FullControlEvaluator.InvalidProof();
        }
        var subject = RouteSubject(id);
        if (!MembershipRouteStorage.Read(connection, subject).TryGetValue(subject, out var routes)
            || JsonSerializer.Serialize(routes) != payload) throw FullControlEvaluator.InvalidProof();
        return routes;
    }

    internal static byte[] MeaningBinding(string target, Guid generation, int ordinal, string? value) =>
        Binding("PermissionMeaning", generation, null, 0, JsonSerializer.Serialize(new object[] { target, ordinal }), value);

    private static byte[] ControlBinding(ControlEdge edge, string payload) =>
        Binding("ControlRoutes", edge.GenerationId, edge.DerivationGenerationId, edge.PrincipalCatalogueVersion,
            JsonSerializer.Serialize(new object?[] { edge.Id, edge.Target, edge.HolderSid, edge.HolderScope, edge.Capability.ToString() }), payload);

    private static byte[] FullControlBinding(FullControlAssessment value, string payload) =>
        Binding("FullControlRoutes", value.GenerationId, value.DerivationGenerationId, value.PrincipalCatalogueVersion,
            JsonSerializer.Serialize(new object?[] { value.Source.Target, value.Source.Holder.Sid, value.Source.HolderScope }), payload);

    private static byte[] Binding(string kind, Guid generation, Guid? derived, int catalogue, string consumer, string? payload) =>
        Hash(JsonSerializer.Serialize(new object?[] { FormatVersion, kind, generation.ToString("D"), derived?.ToString("D"), catalogue, consumer, payload }));

    internal static byte[] ValueFingerprint(string kind, Guid generation, Guid? derived, int catalogue, string payload) =>
        Hash(ValueKey(kind, generation, derived, catalogue, payload));

    private static string ValueKey(string kind, Guid generation, Guid? derived, int catalogue, string payload) =>
        JsonSerializer.Serialize(new object?[] { FormatVersion, kind, generation.ToString("D"), derived?.ToString("D"), catalogue, payload });

    private static string RouteSubject(long id) => "proof-route:" + id.ToString(CultureInfo.InvariantCulture);
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static string? Text(SqliteDataReader read, int index) => read.IsDBNull(index) ? null : read.GetString(index);

    private void Active()
    {
        if (transaction.Connection != connection) throw FullControlEvaluator.InvalidProof();
    }
}
