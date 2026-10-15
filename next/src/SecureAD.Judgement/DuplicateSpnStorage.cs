using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal static class DuplicateSpnStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_duplicate_spn (finding_id INTEGER PRIMARY KEY,
                generation TEXT NOT NULL, proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, DuplicateSpnEvidence evidence)
    {
        Validate(evidence);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_duplicate_spn VALUES($id,$generation,$proof,$hash)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
    }

    internal static DuplicateSpnEvidence Read(string json, byte[] hash, string generation,
        JudgementDescription description, Guid subject, string dn, string domain, string subjectKey, Severity severity)
    {
        if (generation != description.GenerationId.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(hash)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<DuplicateSpnEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence);
        if (evidence.EvidenceSeal != description.EvidenceSeal || evidence.SubjectGuid != subject
            || subjectKey != subject.ToString("D") || severity != Severity.High
            || evidence.Duplicates.Any(match => match.Owners.Single(owner => owner.ObjectGuid == subject) is var owner
                && (owner.DistinguishedName != dn || owner.DomainFqdn != domain))) throw Invalid();
        return evidence;
    }

    private static void Validate(DuplicateSpnEvidence value)
    {
        if (value.EvidenceSeal is not { Length: 64 } || string.IsNullOrWhiteSpace(value.ForestFqdn)
            || value.SubjectGuid == Guid.Empty || value.Duplicates is not { Count: > 0 } || value.Limitations is null
            || value.Limitations.Any(string.IsNullOrWhiteSpace)
            || value.Duplicates.Any(match => match is null || string.IsNullOrWhiteSpace(match.MatchKey))
            || value.Duplicates.Select(match => match.MatchKey).Distinct(StringComparer.OrdinalIgnoreCase).Count() != value.Duplicates.Count)
            throw Invalid();
        foreach (var match in value.Duplicates)
        {
            if (match.Owners is not { Count: >= 2 } || match.Occurrences is not { Count: >= 2 }
                || !DuplicateServicePrincipalNames.Supports(match.MatchKey)
                || match.Owners.Any(owner => owner is null || owner.ObjectGuid == Guid.Empty || string.IsNullOrWhiteSpace(owner.DistinguishedName)
                    || string.IsNullOrWhiteSpace(owner.DomainFqdn) || string.IsNullOrWhiteSpace(owner.ObjectClass))
                || match.Owners.Select(owner => owner.ObjectGuid).Distinct().Count() != match.Owners.Count
                || match.Owners.Select(owner => owner.DistinguishedName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != match.Owners.Count
                || match.Owners.All(owner => owner.ObjectGuid != value.SubjectGuid)) throw Invalid();
            var ids = match.Owners.Select(owner => owner.ObjectGuid).ToHashSet();
            if (match.Occurrences.Any(occurrence => occurrence is null || occurrence.Ordinal < 0 || !ids.Contains(occurrence.OwnerGuid)
                    || !string.Equals(occurrence.Value, match.MatchKey, StringComparison.OrdinalIgnoreCase))
                || ids.Any(id => !match.Occurrences.Any(occurrence => occurrence.OwnerGuid == id))) throw Invalid();
        }
    }

    private static InvalidDataException Invalid() => new("The saved duplicate-SPN finding does not match its captured owners or judgement generation.");
}
