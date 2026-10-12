using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal static class DelegationScopeReader
{
    internal static DelegationResourceScope? Read(SqliteConnection connection, JudgementDescription description,
        string target, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        var header = OwnershipAuditStorage.ReadHeader(connection, requireComplete: true);
        if (header?.Input is not { } binding) return null;
        if (!binding.IsSupported || header.Generation != description.GenerationId || header.EvidenceSeal != description.EvidenceSeal
            || header.DerivationGeneration != description.DerivationGenerationId) throw Invalid();
        var identities = new Dictionary<string, Tier0Target>(StringComparer.OrdinalIgnoreCase);
        var classifications = new Dictionary<string, Tier0Classification>(StringComparer.OrdinalIgnoreCase);
        var digest = new StringBuilder();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                WITH RECURSIVE reached(target) AS (
                    SELECT $target UNION SELECT r.affected_target FROM ownership_relation r JOIN reached q ON r.controller_target=q.target)
                SELECT t.target,t.identity_json,t.fingerprint,t.selection,s.classification,s.classification_fingerprint
                FROM reached q JOIN ownership_target t ON t.target=q.target
                LEFT JOIN ownership_seed s ON s.target=t.target ORDER BY t.target
                """;
            command.Parameters.AddWithValue("$target", target);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                token.ThrowIfCancellationRequested();
                var json = row.GetString(1);
                if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual((byte[])row.GetValue(2))) throw Invalid();
                var identity = JsonSerializer.Deserialize<Tier0Target>(json, ProofSerialization.Options) ?? throw Invalid();
                if (!identity.IsValid || !Same(identity.DistinguishedName, row.GetString(0))) throw Invalid();
                digest.Append(json).Append('\0').Append(row.GetString(3)).Append('\0');
                if (row.GetString(3) != nameof(OwnershipScopeState.Included))
                {
                    if (Same(row.GetString(0), target)) return null;
                    throw Invalid();
                }
                identities.Add(identity.DistinguishedName, identity);
                if (!row.IsDBNull(4))
                {
                    var proof = row.GetString(4);
                    if (!OwnershipAuditStorage.Hash(proof).AsSpan().SequenceEqual((byte[])row.GetValue(5))) throw Invalid();
                    var classification = JsonSerializer.Deserialize<Tier0Classification>(proof, ProofSerialization.Options) ?? throw Invalid();
                    if (classification.Input != binding || classification.Target != identity || classification.State != Tier0State.Established)
                        throw Invalid();
                    classifications.Add(identity.DistinguishedName, classification);
                    digest.Append(proof).Append('\0');
                }
            }
        }
        if (!identities.TryGetValue(target, out var resource)) return null;
        var relationIds = new List<long>();
        var relations = new List<Tier0RelevanceRelation>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                WITH RECURSIVE reached(target) AS (
                    SELECT $target UNION SELECT r.affected_target FROM ownership_relation r JOIN reached q ON r.controller_target=q.target)
                SELECT r.id,r.edge_id,r.controller_target,r.affected_target,r.witness_target,r.witness_ordinal,
                       r.witness_trustee,r.witness_is_owner,r.witness_capability,r.witness_membership
                FROM ownership_relation r JOIN reached q ON q.target=r.controller_target ORDER BY r.id
                """;
            command.Parameters.AddWithValue("$target", target);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                token.ThrowIfCancellationRequested();
                if (!identities.TryGetValue(row.GetString(2), out var controller)
                    || !identities.TryGetValue(row.GetString(3), out var affected)) throw Invalid();
                Tier0RelevanceRelation relation;
                if (!row.IsDBNull(1))
                {
                    relation = Tier0RelevanceRelation.FromControlEdge(binding, controller, affected,
                        ControlEdgeStorage.ReadExact(connection, description, affected.DistinguishedName, row.GetInt64(1)));
                }
                else
                {
                    if (row.IsDBNull(4) || row.IsDBNull(6) || row.IsDBNull(8)
                        || !Enum.TryParse<ControlCapability>(row.GetString(8), out var capability) || !Enum.IsDefined(capability)) throw Invalid();
                    var witness = new Tier0CaptureWitness(row.GetString(4), row.IsDBNull(5) ? null : row.GetInt32(5),
                        row.GetString(6), row.GetBoolean(7));
                    if (!row.IsDBNull(9))
                        witness = witness with { GroupMembership = JsonSerializer.Deserialize<RequesterMembershipEvidence>(row.GetString(9),
                            ProofSerialization.Options) ?? throw Invalid() };
                    relation = Tier0RelevanceRelation.FromCapturedPermission(binding, controller, affected, capability, witness);
                }
                relations.Add(relation);
                relationIds.Add(row.GetInt64(0));
                digest.Append(row.GetInt64(0)).Append('\0').Append(JsonSerializer.Serialize(relation, ProofSerialization.Options)).Append('\0');
            }
        }
        var selected = OwnershipScopeSelector.Select(binding, description.GenerationId, classifications.Values, relations, header.Coverage, token, null);
        if (selected.WasCancelled) throw new OperationCanceledException(token);
        var decision = selected.For(resource);
        if (decision.State != OwnershipScopeState.Included) throw Invalid();
        var established = classifications.GetValueOrDefault(target);
        return new(description.GenerationId, resource.ObjectGuid ?? throw Invalid(), resource.DistinguishedName,
            Convert.ToHexString(OwnershipAuditStorage.Hash(digest.ToString())), established is not null,
            established?.Supports.Select(support => support.Basis.ToString()).Distinct().Order(StringComparer.Ordinal).ToArray() ?? [],
            classifications.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray(), relationIds.ToArray(),
            Enum.GetValues<Tier0Limitations>().Where(value => value != Tier0Limitations.None && decision.Coverage.Limitations.HasFlag(value))
                .Select(value => value.ToString()).ToArray());
    }

    internal static void Validate(SqliteConnection connection, JudgementDescription description, DelegationResourceScope evidence, CancellationToken token)
    {
        var current = Read(connection, description, evidence.TargetDn, token);
        if (current is null || JsonSerializer.Serialize(current, ProofSerialization.Options) != JsonSerializer.Serialize(evidence, ProofSerialization.Options))
            throw Invalid();
    }

    private static bool Same(string left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static InvalidDataException Invalid() => new("The saved delegation resource does not match the shared Tier-0 classification/relevance witnesses.");
}
