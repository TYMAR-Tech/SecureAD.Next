using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

internal static class LapsSchedulingStorage
{
    private sealed record Unassessed(CapturedObjectIdentity Computer, AuditError Reason);

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        var main = JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement);
        var facts = JudgementStoreLayout.Schema(connection, StoreSegmentRole.JudgementFacts);
        command.CommandText = $"""
            CREATE TABLE {main}.laps_configured_scope (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                generation TEXT NOT NULL, capture_generation TEXT NOT NULL,
                evidence_seal TEXT NOT NULL, derivation_generation TEXT NULL,
                policy TEXT NOT NULL, state TEXT NOT NULL,
                observed INTEGER NOT NULL CHECK(observed>=0),
                considered INTEGER NOT NULL CHECK(considered>=0),
                calculated INTEGER NOT NULL CHECK(calculated>=0),
                unassessed INTEGER NOT NULL CHECK(unassessed>=0),
                capture_complete INTEGER NOT NULL CHECK(capture_complete IN (0,1)));
            CREATE TABLE {facts}.laps_configured_unassessed (
                computer_id INTEGER PRIMARY KEY,
                payload TEXT NOT NULL,
                fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Start(SqliteConnection connection, SqliteTransaction transaction,
        ConfiguredLapsSchedulingSummary value)
    {
        if (!Enum.IsDefined(value.Policy) || value.State != ConfiguredLapsSchedulingState.Writing
            || value.ObservedComputers < 0) throw Invalid();
        using var empty = connection.CreateCommand();
        empty.Transaction = transaction;
        empty.CommandText = "SELECT EXISTS(SELECT 1 FROM laps_configured_selection) OR EXISTS(SELECT 1 FROM laps_configured_unassessed)";
        if ((long)empty.ExecuteScalar()! != 0) throw Invalid();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO laps_configured_scope VALUES
                (1,$generation,$capture,$seal,$derived,$policy,'Writing',$observed,0,0,0,$complete)
            """;
        Bind(command, value);
        command.ExecuteNonQuery();
    }

    internal static void WriteUnassessed(SqliteConnection connection, SqliteTransaction transaction,
        CapturedObjectIdentity computer, AuditError reason)
    {
        var payload = JsonSerializer.Serialize(new Unassessed(computer, reason), LapsConfiguredPolicyStorage.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO laps_configured_unassessed VALUES ($computer,$payload,$hash)";
        command.Parameters.AddWithValue("$computer", computer.ObjectId);
        command.Parameters.AddWithValue("$payload", payload);
        command.Parameters.AddWithValue("$hash", LapsConfiguredPolicyStorage.Fingerprint(payload));
        command.ExecuteNonQuery();
    }

    internal static void Complete(SqliteConnection connection, SqliteTransaction transaction,
        ConfiguredLapsSchedulingSummary value)
    {
        Validate(value);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE laps_configured_scope SET state=$state,considered=$considered,calculated=$calculated,unassessed=$unassessed
            WHERE singleton=1 AND state='Writing' AND generation=$generation AND capture_generation=$capture
                AND evidence_seal=$seal AND derivation_generation IS $derived AND policy=$policy AND observed=$observed
            """;
        Bind(command, value);
        command.Parameters.AddWithValue("$state", value.State.ToString());
        command.Parameters.AddWithValue("$considered", value.QuestionsConsidered);
        command.Parameters.AddWithValue("$calculated", value.SavedCalculations);
        command.Parameters.AddWithValue("$unassessed", value.UnassessedComputers);
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static bool RequirePublishable(SqliteConnection connection, ConfiguredLapsSchedulingSummary? expected)
    {
        var value = Read(connection);
        if (value != expected) throw Invalid();
        using var counts = connection.CreateCommand();
        counts.CommandText = """
            SELECT (SELECT COUNT(*) FROM laps_configured_selection),
                (SELECT COUNT(*) FROM laps_configured_unassessed),
                EXISTS(SELECT 1 FROM laps_configured_selection s JOIN laps_configured_unassessed u USING(computer_id))
            """;
        using var row = counts.ExecuteReader();
        if (!row.Read() || row.GetInt64(2) != 0) throw Invalid();
        if (value is null)
        {
            if (row.GetInt64(1) != 0) throw Invalid();
            return false;
        }
        Validate(value);
        if (value.SavedCalculations != row.GetInt64(0)
            || (value.Policy == ConfiguredLapsPolicy.Disabled ? row.GetInt64(1) != 0
                : value.UnassessedComputers != row.GetInt64(1))) throw Invalid();
        return value.Policy != ConfiguredLapsPolicy.Disabled && value.UnassessedComputers != 0;
    }

    internal static Result<ConfiguredLapsSchedulingSummary> ReadSummary(SqliteConnection connection, JudgementDescription description)
    {
        var value = Read(connection);
        if (value is null)
            return Result<ConfiguredLapsSchedulingSummary>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "LapsConfiguredScopeNotRecorded", ErrorSeverity.Degraded,
                "No automatic configured LAPS scope was recorded for this generation.", null));
        ValidateBinding(value, description);
        return value;
    }

    internal static AuditError? ReadRefusal(SqliteConnection connection, JudgementDescription description,
        CapturedObjectIdentity computer)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT payload,fingerprint FROM laps_configured_unassessed WHERE computer_id=$computer";
        command.Parameters.AddWithValue("$computer", computer.ObjectId);
        using var row = command.ExecuteReader();
        if (row.Read())
        {
            if (row.GetValue(0) is not string payload || row.GetValue(1) is not string fingerprint
                || LapsConfiguredPolicyStorage.Fingerprint(payload) != fingerprint) throw Invalid();
            Unassessed? value;
            try { value = JsonSerializer.Deserialize<Unassessed>(payload, LapsConfiguredPolicyStorage.Options); }
            catch (JsonException error) { throw new InvalidDataException(Invalid().Message, error); }
            if (value is null || value.Computer is null || value.Computer.ObjectId != computer.ObjectId
                || value.Computer.CaptureGenerationId != computer.CaptureGenerationId
                || value.Computer.ObjectGuid != computer.ObjectGuid || value.Computer.DistinguishedName != computer.DistinguishedName
                || value.Computer.DomainFqdn != computer.DomainFqdn || value.Reason is null
                || string.IsNullOrWhiteSpace(value.Reason.Code)
                || string.IsNullOrWhiteSpace(value.Reason.Description)) throw Invalid();
            var scope = Read(connection) ?? throw Invalid();
            ValidateBinding(scope, description);
            if (scope.CaptureGenerationId != computer.CaptureGenerationId
                || scope.Policy != ConfiguredLapsPolicy.AllCapturedComputers) throw Invalid();
            return value.Reason;
        }
        var recorded = Read(connection);
        if (recorded is null) return null;
        ValidateBinding(recorded, description);
        if (recorded.CaptureGenerationId != computer.CaptureGenerationId) throw Invalid();
        if (recorded.Policy == ConfiguredLapsPolicy.AllCapturedComputers) throw Invalid();
        return AuditError.Create(ErrorCategory.Evidence, "LapsConfiguredCalculationDisabled", ErrorSeverity.Degraded,
            "Automatic configured LAPS calculation was disabled for this generation; the computer is unassessed, not a confirmed empty policy.",
            computer.DistinguishedName);
    }

    private static ConfiguredLapsSchedulingSummary? Read(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT generation,capture_generation,evidence_seal,derivation_generation,policy,state,
                observed,considered,calculated,unassessed,capture_complete FROM laps_configured_scope WHERE singleton=1
            """;
        using var row = command.ExecuteReader();
        if (!row.Read()) return null;
        if (!Guid.TryParseExact(row.GetString(0), "D", out var generation)
            || !Guid.TryParseExact(row.GetString(1), "D", out var capture)
            || !Enum.TryParse<ConfiguredLapsPolicy>(row.GetString(4), out var policy) || !Enum.IsDefined(policy)
            || policy.ToString() != row.GetString(4)
            || !Enum.TryParse<ConfiguredLapsSchedulingState>(row.GetString(5), out var state) || !Enum.IsDefined(state)
            || state.ToString() != row.GetString(5)
            || row.GetInt64(10) is not (0 or 1)) throw Invalid();
        Guid? derivation = null;
        if (!row.IsDBNull(3))
        {
            if (!Guid.TryParseExact(row.GetString(3), "D", out var parsed)) throw Invalid();
            derivation = parsed;
        }
        return new(generation, capture, row.GetString(2), derivation, policy, state,
            row.GetInt64(6), row.GetInt64(7), row.GetInt64(8), row.GetInt64(9), row.GetInt64(10) == 1);
    }

    private static void ValidateBinding(ConfiguredLapsSchedulingSummary value, JudgementDescription description)
    {
        Validate(value);
        if (value.JudgementGenerationId != description.GenerationId || value.EvidenceSeal != description.EvidenceSeal
            || value.DerivationGenerationId != description.DerivationGenerationId) throw Invalid();
    }

    private static void Validate(ConfiguredLapsSchedulingSummary value)
    {
        if (value.JudgementGenerationId == Guid.Empty || value.CaptureGenerationId == Guid.Empty
            || value.EvidenceSeal.Length != 64 || !value.EvidenceSeal.All(Uri.IsHexDigit)
            || !Enum.IsDefined(value.Policy) || !Enum.IsDefined(value.State)
            || value.ObservedComputers < 0 || value.QuestionsConsidered < 0 || value.SavedCalculations < 0
            || value.UnassessedComputers < 0 || value.State == ConfiguredLapsSchedulingState.Writing)
            throw Invalid();
        if (value.Policy == ConfiguredLapsPolicy.Disabled)
        {
            if (value.State != ConfiguredLapsSchedulingState.Disabled || value.QuestionsConsidered != 0
                || value.SavedCalculations != 0 || value.UnassessedComputers != value.ObservedComputers) throw Invalid();
        }
        else if (value.QuestionsConsidered != value.ObservedComputers
            || value.SavedCalculations + value.UnassessedComputers != value.QuestionsConsidered
            || value.State != (value.UnassessedComputers == 0 ? ConfiguredLapsSchedulingState.Complete
                : ConfiguredLapsSchedulingState.CompleteWithUnassessed)) throw Invalid();
    }

    private static void Bind(SqliteCommand command, ConfiguredLapsSchedulingSummary value)
    {
        command.Parameters.AddWithValue("$generation", value.JudgementGenerationId.ToString("D"));
        command.Parameters.AddWithValue("$capture", value.CaptureGenerationId.ToString("D"));
        command.Parameters.AddWithValue("$seal", value.EvidenceSeal);
        command.Parameters.AddWithValue("$derived", (object?)value.DerivationGenerationId?.ToString("D") ?? DBNull.Value);
        command.Parameters.AddWithValue("$policy", value.Policy.ToString());
        command.Parameters.AddWithValue("$observed", value.ObservedComputers);
        command.Parameters.AddWithValue("$complete", value.CaptureScopeComplete ? 1 : 0);
    }

    internal static InvalidDataException Invalid() =>
        new("The saved automatic configured LAPS scope is missing, incomplete, or bound to different inputs.");
}
