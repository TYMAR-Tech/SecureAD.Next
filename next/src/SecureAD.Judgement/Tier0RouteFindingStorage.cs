using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>Complete SEC-071 publication counts, bound to the saved qualification rather than a displayed page.</summary>
public sealed record Tier0FindingSummary(int Version, Guid GenerationId, Guid? DerivationGenerationId,
    string EvidenceSeal, string CalculationFingerprint, int RuleVersion, PathRiskAvailability Availability,
    RuleExecutionOutcome Outcome, int AssessedAccounts, int AccountsWithFindings, int UnresolvedAccessChecks);

internal static class Tier0RouteFindingStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_tier0_route (finding_id INTEGER PRIMARY KEY,
                proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.tier0_finding_product (id INTEGER PRIMARY KEY CHECK(id=1), proof TEXT NOT NULL,
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), availability TEXT NOT NULL,
                unresolved_checks INTEGER NOT NULL CHECK(unresolved_checks>=0));
            """;
        command.ExecuteNonQuery();
    }

    internal static void WriteEvidence(SqliteConnection connection, SqliteTransaction transaction,
        long findingId, Tier0RouteFindingEvidence evidence) =>
        Write(connection, transaction, "INSERT INTO finding_tier0_route VALUES ($id,$proof,$hash)", findingId, evidence);

    internal static void WriteSummary(SqliteConnection connection, SqliteTransaction transaction, Tier0FindingSummary summary) =>
        Write(connection, transaction, """
            INSERT INTO tier0_finding_product
            SELECT $id,$proof,$hash,json_extract(r.proof,'$.Availability'),
                (SELECT SUM(json_extract(value,'$.Unknown')) FROM json_each(r.proof,'$.Families'))
            FROM path_risk_product r WHERE r.id=1
            """, 1, summary);

    private static void Write<T>(SqliteConnection connection, SqliteTransaction transaction, string sql, long id, T value)
    {
        var json = JsonSerializer.Serialize(value, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
        if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
    }

    internal static Tier0RouteFindingEvidence ReadEvidence(string json, byte[] hash, JudgementDescription description,
        Guid requesterGuid, string requesterDn, string calculationFingerprint)
    {
        var value = Decode<Tier0RouteFindingEvidence>(json, hash);
        if (value.GenerationId != description.GenerationId || value.DerivationGenerationId != description.DerivationGenerationId
            || value.EvidenceSeal != description.EvidenceSeal || value.CalculationFingerprint != calculationFingerprint
            || value.Anchor != UnexpectedTier0Route.Anchor || value.RequesterGuid != requesterGuid || requesterGuid == Guid.Empty
            || value.RequesterDn != requesterDn || string.IsNullOrWhiteSpace(value.RequesterSid)
            || value.UnexpectedChecks <= 0 || value.QualificationFingerprint is not { Length: 64 })
            throw Tier0PathStorage.InvalidProof();
        return value;
    }

    internal static Tier0FindingSummary? ReadSummary(SqliteConnection connection, JudgementDescription description,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT p.proof,p.fingerprint,r.rule_version,r.outcome,p.availability,p.unresolved_checks,c.fingerprint
            FROM (SELECT 1 AS id) root
            LEFT JOIN rule_execution r ON r.rule_id='SEC-071'
            LEFT JOIN tier0_finding_product p ON p.id=root.id
            LEFT JOIN tier0_path_calculation c ON c.id=root.id
            """;
        Tier0FindingSummary result;
        using (var read = command.ExecuteReader())
        {
            if (!read.Read()) throw Tier0PathStorage.InvalidProof();
            if (read.IsDBNull(0) && read.IsDBNull(2)) return null;
            if (read.IsDBNull(0) || read.IsDBNull(2) || read.IsDBNull(4) || read.IsDBNull(5) || read.IsDBNull(6))
                throw Tier0PathStorage.InvalidProof();
            result = Decode<Tier0FindingSummary>(read.GetString(0), (byte[])read.GetValue(1));
            if (result.Version != 1 || result.GenerationId != description.GenerationId
                || result.DerivationGenerationId != description.DerivationGenerationId || result.EvidenceSeal != description.EvidenceSeal
                || result.RuleVersion != read.GetInt32(2) || result.Outcome.ToString() != read.GetString(3)
                || !Enum.IsDefined(result.Outcome) || !Enum.IsDefined(result.Availability)
                || result.AssessedAccounts < 0 || result.AccountsWithFindings < 0 || result.UnresolvedAccessChecks < 0
                || result.AccountsWithFindings > result.AssessedAccounts
                || result.CalculationFingerprint != Convert.ToHexString((byte[])read.GetValue(6))
                || result.Availability.ToString() != read.GetString(4) || result.UnresolvedAccessChecks != read.GetInt64(5))
                throw Tier0PathStorage.InvalidProof();
        }
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM rule_execution WHERE rule_id='SEC-071'),
                   (SELECT COUNT(*) FROM tier0_finding_product)
            """;
        using (var read = command.ExecuteReader())
        {
            if (!read.Read() || read.GetInt64(0) != read.GetInt64(1)) throw Tier0PathStorage.InvalidProof();
            if (read.GetInt64(0) == 0) return;
        }
        command.CommandText = """
            SELECT json_extract(p.proof,'$.AccountsWithFindings'),
                   (SELECT COUNT(*) FROM finding WHERE rule_id='SEC-071'),
                   (SELECT COUNT(*) FROM finding_tier0_route),
                   (SELECT COUNT(DISTINCT requester) FROM path_requester_risk WHERE verdict='UnexpectedRoute'),
                   (SELECT COUNT(*) FROM path_requester_risk WHERE verdict='UnexpectedRoute'),
                   COALESCE((SELECT SUM(json_extract(proof,'$.UnexpectedChecks')) FROM finding_tier0_route),0),
                   json_extract(p.proof,'$.UnresolvedAccessChecks'),
                   (SELECT COUNT(*) FROM path_requester_risk WHERE verdict='Unknown')
            FROM tier0_finding_product p WHERE p.id=1
            """;
        using var counts = command.ExecuteReader();
        if (!counts.Read() || counts.GetInt64(0) != counts.GetInt64(1) || counts.GetInt64(1) != counts.GetInt64(2)
            || counts.GetInt64(2) != counts.GetInt64(3) || counts.GetInt64(4) != counts.GetInt64(5)
            || counts.GetInt64(6) != counts.GetInt64(7))
            throw Tier0PathStorage.InvalidProof();
    }

    private static T Decode<T>(string json, byte[] hash)
    {
        if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual(hash)) throw Tier0PathStorage.InvalidProof();
        return JsonSerializer.Deserialize<T>(json, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
    }
}
