using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed record SavedRequesterDaclProof(RequesterDaclAssessment Assessment, string SourceFingerprint);

internal static class RequesterDaclProofs
{
    internal static IReadOnlyList<SavedRequesterDaclProof> Create(SqliteConnection connection,
        JudgementDescription description, string directory, PathInputs inputs,
        IReadOnlyList<RequesterDaclRequest> requests, CancellationToken cancellationToken,
        OwnAccountMembershipAssessment? obtainedMembership)
    {
        if (requests.Count == 0) return [];
        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess) throw Tier0PathStorage.InvalidProof();
        using var bundle = opened.Value;
        var contexts = bundle.ReadNamingContexts();
        if (!contexts.IsSuccess) throw Tier0PathStorage.InvalidProof();
        var identities = OwnershipAuditStorage.Targets(connection).Select(row => row.Identity)
            .ToDictionary(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var results = new List<SavedRequesterDaclProof>();
        foreach (var request in requests.OrderBy(Key, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var permissions = bundle.ReadPermissions(request.TargetDn);
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability='CanWriteDacl' ORDER BY id";
            query.Parameters.AddWithValue("$target", request.TargetDn);
            var ids = new List<long>();
            using (var read = query.ExecuteReader()) while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ids.Add(read.GetInt64(0));
            }
            var edges = ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id)).ToArray();
            var assessment = RequesterDaclEvaluator.Assess(request, inputs, description, identities,
                bundle.ReadObjectAttributes, permissions, contexts.Value, edges, bundle.Description.ForestFqdn, cancellationToken, obtainedMembership);
            var holders = new List<ObjectAttributes?>();
            foreach (var dn in (permissions?.Entries ?? []).Select(entry => entry.Trustee.DistinguishedName)
                .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                holders.Add(bundle.ReadObjectAttributes(dn));
            }
            var source = Tier0PathCalculation.Fingerprint(new
            {
                Requester = bundle.ReadObjectAttributes(request.RequesterDn), Target = bundle.ReadObjectAttributes(request.TargetDn),
                Permissions = permissions, Holders = holders, Forest = bundle.Description.ForestFqdn,
                Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray(),
                ObtainedMembership = obtainedMembership,
            });
            results.Add(new(assessment, source));
        }
        return results;
    }

    internal static void Validate(SqliteConnection connection, JudgementDescription description, string directory,
        PathInputs inputs, IReadOnlyList<SavedRequesterDaclProof> proofs, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (proofs.Any(proof => proof is null || proof.Assessment is null || proof.Assessment.Request is null
            || string.IsNullOrWhiteSpace(proof.Assessment.Request.RequesterDn) || string.IsNullOrWhiteSpace(proof.Assessment.Request.TargetDn))
            || proofs.Select(proof => Key(proof.Assessment.Request)).Distinct(StringComparer.Ordinal).Count() != proofs.Count)
            throw Tier0PathStorage.InvalidProof();
        // Replay only the saved questions as a proof check, never as discovery or replacement output.
        // This also rejects a changed verdict, membership witness or source reference with a refreshed hash.
        var replay = Create(connection, description, directory, inputs, proofs.Select(proof => proof.Assessment.Request).ToArray(), cancellationToken, obtainedMembership: null);
        if (Tier0PathCalculation.Fingerprint(proofs) != Tier0PathCalculation.Fingerprint(replay)) throw Tier0PathStorage.InvalidProof();
    }

    internal static RequesterDaclRequest? Best(Tier0PathNode node, IReadOnlyList<SavedRequesterDaclProof> proofs)
    {
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        if (node.MembershipDistance == 0) return null;
        var candidate = proofs.Select(proof => proof.Assessment)
            .Where(value => value.Authorization == ControlEvaluationState.Established && value.Requester == node.Subject)
            .OrderBy(value => value.Steps.Count).ThenBy(value => Key(value.Request), StringComparer.Ordinal).FirstOrDefault();
        return candidate is not null && (previous is null || candidate.Steps.Count < previous)
            ? candidate.Request : null;
    }

    internal static string Key(RequesterDaclRequest value) => value.RequesterDn.ToUpperInvariant() + "\0" + value.TargetDn.ToUpperInvariant();
}
