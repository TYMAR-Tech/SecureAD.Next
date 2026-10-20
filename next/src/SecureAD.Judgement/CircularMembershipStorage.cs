using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal static class CircularMembershipStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PermissionProof)}.finding_circular_membership (finding_id INTEGER PRIMARY KEY,
                generation TEXT NOT NULL, proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.finding_circular_group (finding_id INTEGER NOT NULL REFERENCES finding(finding_id),
                object_guid TEXT NOT NULL, distinguished_name TEXT NOT NULL, domain_fqdn TEXT NOT NULL,
                PRIMARY KEY(finding_id,object_guid));
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.ix_finding_circular_group_object ON finding_circular_group(distinguished_name COLLATE NOCASE,finding_id);
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, long findingId,
        Guid generation, CircularMembershipEvidence evidence)
    {
        Validate(evidence);
        var json = JsonSerializer.Serialize(evidence, ProofSerialization.Options);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO finding_circular_membership VALUES ($id,$generation,$proof,$hash)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$proof", json);
        command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(generation.ToString("D") + "\0" + json));
        if (command.ExecuteNonQuery() != 1) throw Invalid();
        command.Parameters.Clear();
        command.CommandText = "INSERT INTO finding_circular_group VALUES ($id,$guid,$dn,$domain)";
        command.Parameters.AddWithValue("$id", findingId);
        command.Parameters.Add("$guid", SqliteType.Text);
        command.Parameters.Add("$dn", SqliteType.Text);
        command.Parameters.Add("$domain", SqliteType.Text);
        foreach (var group in evidence.Groups)
        {
            command.Parameters["$guid"].Value = group.ObjectGuid.ToString("D");
            command.Parameters["$dn"].Value = group.DistinguishedName;
            command.Parameters["$domain"].Value = group.DomainFqdn;
            if (command.ExecuteNonQuery() != 1) throw Invalid();
        }
    }

    internal static CircularMembershipEvidence Read(string json, byte[] fingerprint, string generation,
        JudgementDescription description, Guid anchor, string distinguishedName, string subjectKey, Severity severity)
    {
        if (generation != description.GenerationId.ToString("D")
            || !OwnershipAuditStorage.Hash(generation + "\0" + json).AsSpan().SequenceEqual(fingerprint)) throw Invalid();
        var evidence = JsonSerializer.Deserialize<CircularMembershipEvidence>(json, ProofSerialization.Options) ?? throw Invalid();
        Validate(evidence);
        if (evidence.EvidenceSeal != description.EvidenceSeal || evidence.DerivationGenerationId != description.DerivationGenerationId
            || evidence.Groups[0].ObjectGuid != anchor || evidence.Groups[0].DistinguishedName != distinguishedName
            || evidence.ComponentKey != subjectKey || severity != Severity.Medium) throw Invalid();
        return evidence;
    }

    private static void Validate(CircularMembershipEvidence evidence)
    {
        if (evidence.EvidenceSeal is not { Length: 64 } || evidence.DerivationGenerationId == Guid.Empty
            || evidence.Groups is not { Count: > 0 } || evidence.Links is not { Count: > 0 }
            || evidence.Groups.Any(group => group is null || group.ObjectGuid == Guid.Empty
                || string.IsNullOrWhiteSpace(group.DistinguishedName) || string.IsNullOrWhiteSpace(group.DomainFqdn)
                || string.IsNullOrWhiteSpace(group.Sid))
            || evidence.Groups.Select(group => group.ObjectGuid).Distinct().Count() != evidence.Groups.Count
            || !evidence.Groups.SequenceEqual(evidence.Groups.OrderBy(group => group.ObjectGuid.ToString("D"), StringComparer.Ordinal))
            || evidence.ComponentKey != CircularMembershipIndex.Key(evidence.Groups)) throw Invalid();
        var groups = evidence.Groups.ToDictionary(group => group.ObjectGuid);
        foreach (var link in evidence.Links)
        {
            if (link is null || !groups.TryGetValue(link.GroupGuid, out var group) || !groups.TryGetValue(link.MemberGuid, out var member)
                || link.Witnesses is not { Count: > 0 }) throw Invalid();
            foreach (var witness in link.Witnesses)
            {
                if (witness is null || witness.Ordinal < 0 || (witness.Attribute switch
                {
                    "member" => witness.SourceObjectGuid != group.ObjectGuid
                        || !string.Equals(witness.Value, member.DistinguishedName, StringComparison.OrdinalIgnoreCase),
                    "memberOf" => witness.SourceObjectGuid != member.ObjectGuid
                        || !string.Equals(witness.Value, group.DistinguishedName, StringComparison.OrdinalIgnoreCase),
                    _ => true,
                })) throw Invalid();
            }
        }
        if (!CircularMembershipIndex.Connected(evidence.Groups, evidence.Links, CancellationToken.None)) throw Invalid();
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id FROM finding f LEFT JOIN finding_circular_membership c ON c.finding_id=f.finding_id
            WHERE f.rule_id='SEC-052' AND (c.finding_id IS NULL OR
                json_array_length(c.proof,'$.Groups')<>(SELECT COUNT(*) FROM finding_circular_group g WHERE g.finding_id=f.finding_id))
            UNION ALL
            SELECT g.finding_id FROM finding_circular_group g
            LEFT JOIN finding_circular_membership c ON c.finding_id=g.finding_id
            WHERE c.finding_id IS NULL OR NOT EXISTS (
                SELECT 1 FROM json_each(c.proof,'$.Groups') m
                WHERE json_extract(m.value,'$.ObjectGuid')=g.object_guid
                  AND json_extract(m.value,'$.DistinguishedName')=g.distinguished_name
                  AND json_extract(m.value,'$.DomainFqdn')=g.domain_fqdn)
            LIMIT 1
            """;
        if (command.ExecuteScalar() is not null) throw Invalid();
    }

    private static InvalidDataException Invalid() => new("The saved circular-membership finding does not match its group evidence or generation.");
}
