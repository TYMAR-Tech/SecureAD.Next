using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed record SavedOwnAccountMembershipProof(OwnAccountMembershipAssessment Assessment,
    string SourceFingerprint, IReadOnlyList<Tier0PathStep> Steps);

internal static class OwnAccountMembershipProofs
{
    internal static IReadOnlyList<SavedOwnAccountMembershipProof> Create(SqliteConnection connection,
        JudgementDescription description, string directory, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<OwnAccountMembershipRequest> requests,
        CancellationToken cancellationToken, bool membershipContinuation = true)
    {
        if (requests.Count == 0) return [];
        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess) throw Tier0PathStorage.InvalidProof();
        using var bundle = opened.Value;
        var contexts = bundle.ReadNamingContexts();
        if (!contexts.IsSuccess) throw Tier0PathStorage.InvalidProof();
        var identities = OwnershipAuditStorage.Targets(connection).Select(row => row.Identity)
            .ToDictionary(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var schema = new List<ObjectAttributes>();
        foreach (var identity in identities.Values.OrderBy(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!contexts.Value.TryGetValue(identity.NamingContext, out var kind) || kind != NamingContextKind.Schema) continue;
            var definition = bundle.ReadObjectAttributes(identity.DistinguishedName);
            if (definition?.Find("lDAPDisplayName")?.OnlyValue?.Text is { } name
                && new[] { "member", "group", "user" }.Contains(name, StringComparer.OrdinalIgnoreCase)) schema.Add(definition);
        }
        var catalogue = bundle.ReadSchemaGuids();
        var roots = contexts.Value.Where(pair => pair.Value == NamingContextKind.Domain)
            .OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).Select(pair => bundle.ReadObjectAttributes(pair.Key)).ToArray();
        var result = new List<SavedOwnAccountMembershipProof>();
        foreach (var request in requests.OrderBy(Key, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var permissions = bundle.ReadPermissions(request.TargetDn);
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability=$capability ORDER BY id";
            query.Parameters.AddWithValue("$target", request.TargetDn);
            query.Parameters.AddWithValue("$capability", request.PermissionKind == OwnAccountMembershipPermissionKind.WriteMembers
                ? nameof(ControlCapability.CanModifyGroupMembership) : nameof(ControlCapability.CanAddSelfToGroup));
            var ids = new List<long>();
            using (var read = query.ExecuteReader()) while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ids.Add(read.GetInt64(0));
            }
            var edges = ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id)).ToArray();
            var assessment = OwnAccountMembershipEvaluator.Assess(request, inputs, description, identities,
                bundle.ReadObjectAttributes, permissions, schema, catalogue, contexts.Value, edges,
                bundle.Description.ForestFqdn, cancellationToken);
            var steps = membershipContinuation ? Steps(assessment, inputs, nodes, cancellationToken) : [];
            if (membershipContinuation && assessment.Obtainability == ControlEvaluationState.Established && steps.Count == 0)
                assessment = assessment with { Issues = [.. assessment.Issues, OwnAccountMembershipIssue.MembershipContinuationUnresolved] };
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
                Permissions = permissions, Holders = holders, Roots = roots, Schema = schema, Catalogue = catalogue.Entries,
                Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray(), Forest = bundle.Description.ForestFqdn,
            });
            result.Add(new(assessment, source, steps));
        }
        return result;
    }

    internal static void Validate(SqliteConnection connection, JudgementDescription description, string directory,
        PathInputs inputs, IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<SavedOwnAccountMembershipProof> proofs,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (proofs.Any(proof => proof is null || proof.Assessment is null || proof.Assessment.Request is null
            || string.IsNullOrWhiteSpace(proof.Assessment.Request.RequesterDn) || string.IsNullOrWhiteSpace(proof.Assessment.Request.TargetDn)
            || !Enum.IsDefined(proof.Assessment.Request.PermissionKind))
            || proofs.Select(proof => Key(proof.Assessment.Request)).Distinct(StringComparer.Ordinal).Count() != proofs.Count)
            throw Tier0PathStorage.InvalidProof();
        // Only saved questions are replayed. A changed outcome or witness is rejected even when
        // someone recomputes the JSON hash; reading never schedules new work or writes a replacement.
        var replay = Create(connection, description, directory, inputs, nodes,
            proofs.Select(proof => proof.Assessment.Request).ToArray(), cancellationToken);
        if (Tier0PathCalculation.Fingerprint(proofs) != Tier0PathCalculation.Fingerprint(replay)) throw Tier0PathStorage.InvalidProof();
    }

    internal static OwnAccountMembershipRequest? Best(Tier0PathNode node, IReadOnlyList<SavedOwnAccountMembershipProof> proofs,
        IReadOnlyList<SavedRequesterDaclProof> requesters)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        if (node.RequesterRoute is { } existing)
            previous = requesters.Single(proof => proof.Assessment.Request == existing).Assessment.Steps.Count;
        var candidate = proofs.Where(proof => proof.Assessment.Obtainability == ControlEvaluationState.Established
            && proof.Assessment.Requester == node.Subject && proof.Steps.Count != 0)
            .OrderBy(proof => proof.Steps.Count).ThenBy(proof => Key(proof.Assessment.Request), StringComparer.Ordinal).FirstOrDefault();
        return candidate is not null && (previous is null || candidate.Steps.Count < previous) ? candidate.Assessment.Request : null;
    }

    private static IReadOnlyList<Tier0PathStep> Steps(OwnAccountMembershipAssessment assessment, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, CancellationToken cancellationToken)
    {
        if (assessment.Obtainability != ControlEvaluationState.Established || assessment.Requester is not { } requester
            || assessment.Target is not { } target || !nodes.TryGetValue(target.DistinguishedName, out var current)
            || current.Subject != target || current.MembershipDistance is null) return [];
        var steps = new List<Tier0PathStep>();
        if (assessment.Basis == OwnAccountMembershipBasis.ExistingMembership)
            steps.Add(new(requester, target, Tier0PathStepKind.Membership, null, null, assessment.MembershipEvidence[0], null)
            { OwnAccountRequest = assessment.Request });
        else if (assessment.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd)
            steps.Add(new(requester, target, Tier0PathStepKind.OwnAccountMembership, null, null, null, assessment.Permissions.Single().Id)
            { OwnAccountRequest = assessment.Request });
        else throw Tier0PathStorage.InvalidProof();

        // Only the original membership certificate can continue this new relationship. A target's
        // terminal WRITE_DAC, requester proof, or another hypothetical addition is not a membership.
        while (current.MembershipNext is { } next)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (next.From != current.Subject || next.Kind != Tier0PathStepKind.Membership
                || !nodes.TryGetValue(next.To.DistinguishedName, out var parent) || parent.Subject != next.To
                || parent.MembershipDistance != current.MembershipDistance - 1) throw Tier0PathStorage.InvalidProof();
            steps.Add(next);
            current = parent;
        }
        if (current.MembershipDistance != 0 || !inputs.FixedTargets.Contains(current.Subject)) throw Tier0PathStorage.InvalidProof();
        return steps;
    }

    internal static string Key(OwnAccountMembershipRequest value) => value.RequesterDn.ToUpperInvariant() + "\0"
        + value.TargetDn.ToUpperInvariant() + "\0" + value.PermissionKind;
}
