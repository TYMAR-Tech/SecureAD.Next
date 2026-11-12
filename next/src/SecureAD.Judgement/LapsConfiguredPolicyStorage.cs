using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

internal static class LapsConfiguredPolicyStorage
{
    internal static JsonSerializerOptions Options { get; } = CreateOptions();

    private static JsonSerializerOptions CreateOptions()
    {
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info =>
        {
            if (info.Type != typeof(WqlConditionToken)) return;
            info.PolymorphismOptions = new JsonPolymorphismOptions
            {
                TypeDiscriminatorPropertyName = "Kind",
                DerivedTypes =
                {
                    new JsonDerivedType(typeof(WqlComparisonToken), "Comparison"),
                    new JsonDerivedType(typeof(WqlLogicalToken), "Logical"),
                },
            };
        });
        var options = new JsonSerializerOptions(ProofSerialization.Options)
        {
            IgnoreReadOnlyProperties = true,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            TypeInfoResolver = resolver,
        };
        options.Converters.Insert(0, new JsonStringEnumConverter(allowIntegerValues: false));
        return options;
    }

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        var schema = JudgementStoreLayout.Schema(connection, StoreSegmentRole.JudgementFacts);
        command.CommandText = $"""
            CREATE TABLE {schema}.laps_configured_selection (
                computer_id INTEGER PRIMARY KEY,
                computer_guid TEXT NULL,
                fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64));
            CREATE TABLE {schema}.laps_configured_calculation (
                computer_id INTEGER PRIMARY KEY REFERENCES laps_configured_selection(computer_id),
                payload TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction,
        SavedLapsConfiguredPolicy value, CancellationToken token)
    {
        value.Validate(token);
        var payload = JsonSerializer.Serialize(value, Options);
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO laps_configured_selection VALUES ($computer,$guid,$fingerprint);
            INSERT INTO laps_configured_calculation VALUES ($computer,$payload);
            """;
        command.Parameters.AddWithValue("$computer", value.Computer.ObjectId);
        command.Parameters.AddWithValue("$guid", (object?)value.Computer.ObjectGuid?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$fingerprint", Fingerprint(payload));
        command.Parameters.AddWithValue("$payload", payload);
        command.ExecuteNonQuery();
        token.ThrowIfCancellationRequested();
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT EXISTS(
                SELECT 1 FROM laps_configured_selection s
                LEFT JOIN laps_configured_calculation c USING(computer_id) WHERE c.computer_id IS NULL)
            OR EXISTS(
                SELECT 1 FROM laps_configured_calculation c
                LEFT JOIN laps_configured_selection s USING(computer_id) WHERE s.computer_id IS NULL)
            """;
        if ((long)command.ExecuteScalar()! != 0) throw Invalid();
    }

    internal static Result<SavedLapsConfiguredPolicy> Read(SqliteConnection connection,
        JudgementDescription description, CapturedObjectIdentity computer, string? derivationSeal, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT s.computer_guid,s.fingerprint,c.payload
            FROM laps_configured_selection s LEFT JOIN laps_configured_calculation c USING(computer_id)
            WHERE s.computer_id=$computer
            """;
        command.Parameters.AddWithValue("$computer", computer.ObjectId);
        using var row = command.ExecuteReader();
        if (!row.Read())
        {
            using var orphan = connection.CreateCommand();
            orphan.CommandText = "SELECT EXISTS(SELECT 1 FROM laps_configured_calculation WHERE computer_id=$computer)";
            orphan.Parameters.AddWithValue("$computer", computer.ObjectId);
            if ((long)orphan.ExecuteScalar()! != 0) throw Invalid();
            return Result<SavedLapsConfiguredPolicy>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "LapsConfiguredCalculationNotSaved", ErrorSeverity.Degraded,
                "No configured LAPS calculation was saved for this captured computer; it is unassessed scope, not an empty or safe policy.",
                computer.DistinguishedName));
        }
        if (row.GetValue(1) is not string fingerprint || row.GetValue(2) is not string payload
            || Fingerprint(payload) != fingerprint
            || (row.IsDBNull(0) ? null : row.GetString(0)) != computer.ObjectGuid?.ToString("D")) throw Invalid();
        SavedLapsConfiguredPolicy? value;
        try { value = JsonSerializer.Deserialize<SavedLapsConfiguredPolicy>(payload, Options); }
        catch (JsonException error) { throw new InvalidDataException(Invalid().Message, error); }
        if (value is null || value.JudgementGenerationId != description.GenerationId
            || value.EvidenceSeal != description.EvidenceSeal || value.DerivationGenerationId != description.DerivationGenerationId
            || value.DerivationSeal != derivationSeal || value.Computer != computer
            || value.CaptureGenerationId != computer.CaptureGenerationId) throw Invalid();
        value.Validate(token);
        return value;
    }

    internal static string Fingerprint(string payload) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));

    internal static InvalidDataException Invalid() =>
        new("The saved configured LAPS calculation is missing, invalid, or bound to different captured sources.");
}
