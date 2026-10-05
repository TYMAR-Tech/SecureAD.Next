using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Schema;

namespace SecureAD.Judgement;

internal sealed record SavedOwnAccountMembershipProof(OwnAccountMembershipAssessment Assessment,
    string SourceFingerprint, IReadOnlyList<Tier0PathStep> Steps);

internal sealed class OwnAccountMembershipProofs(SqliteConnection connection, JudgementDescription description,
    JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs,
    CancellationToken cancellationToken)
{
    private sealed record Preparation(IReadOnlyDictionary<string, NamingContextKind> Contexts,
        IReadOnlyList<ObjectAttributes> Schema, SchemaGuidCatalog Catalogue, RequesterMembershipContext? Memberships,
        PathSourceFingerprints Fingerprints);

    private readonly Dictionary<OwnAccountMembershipRequest, SavedOwnAccountMembershipProof> _prerequisites = [];
    private Preparation? _preparation;

    internal void RequireFor(SqliteConnection expectedConnection, JudgementDescription expectedDescription,
        JudgingInputs expectedSources, IReadOnlyDictionary<string, Tier0Target> expectedIdentities, PathInputs expectedInputs,
        CancellationToken expectedCancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        expectedCancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(connection, expectedConnection) || description != expectedDescription
            || !ReferenceEquals(sources, expectedSources) || !ReferenceEquals(identities, expectedIdentities)
            || !ReferenceEquals(inputs, expectedInputs) || cancellationToken != expectedCancellationToken
            || inputs.JudgementGenerationId != description.GenerationId
            || inputs.Input is { } binding && (binding.EvidenceSeal != description.EvidenceSeal
                || binding.DerivationGenerationId != description.DerivationGenerationId))
            throw Tier0PathStorage.InvalidProof();
        sources.RequireFor(description);
    }

    internal IReadOnlyList<SavedOwnAccountMembershipProof> Create(
        IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<OwnAccountMembershipRequest> requests,
        bool membershipContinuation = true)
    {
        if (requests.Count == 0) return [];
        RequireFor(connection, description, sources, identities, inputs, cancellationToken);
        var ordered = requests.OrderBy(Key, StringComparer.Ordinal).ToArray();
        var result = new SavedOwnAccountMembershipProof[ordered.Length];
        // Exact spellings preserve the source reader's SQLite name-resolution behavior.
        foreach (var group in ordered.Select((request, index) => (Request: request, Index: index))
            .GroupBy(value => value.Request.TargetDn, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var pending = group.Select(value => value.Request).Where(request => !_prerequisites.ContainsKey(request)).Distinct().ToArray();
            if (pending.Length != 0) PrepareGroup(group.Key, pending);
            foreach (var (request, index) in group)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var proof = _prerequisites[request];
                var assessment = proof.Assessment;
                var steps = membershipContinuation ? Steps(assessment, inputs, nodes, cancellationToken) : [];
                if (membershipContinuation && assessment.Obtainability == ControlEvaluationState.Established && steps.Count == 0)
                    assessment = assessment with { Issues = [.. assessment.Issues, OwnAccountMembershipIssue.MembershipContinuationUnresolved] };
                // Continuation limitations belong to this family, never to the reusable pre-change question.
                result[index] = proof with { Assessment = assessment, Steps = steps };
            }
        }
        sources.RequireFor(description);
        return result;
    }

    private Preparation Prepare()
    {
        if (_preparation is { } prepared) return prepared;
        var memberships = RequesterMembershipContext.Create(sources, identities, inputs, cancellationToken);
        var bundle = sources.Bundle;
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw Tier0PathStorage.InvalidProof();
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
        var fingerprints = new PathSourceFingerprints(PathSourceFamily.OwnAccountMembership, description, inputs, new
        {
            Roots = roots, Schema = schema, Catalogue = catalogue.Entries,
            Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray(), Forest = bundle.Description.ForestFqdn,
        }, cancellationToken);
        return _preparation = new(contexts.Value, schema, catalogue, memberships, fingerprints);
    }

    private void PrepareGroup(string targetDn, IReadOnlyList<OwnAccountMembershipRequest> requests)
    {
        var prepared = Prepare();
        var bundle = sources.Bundle;
        var permissions = bundle.ReadPermissions(targetDn);
        var target = bundle.ReadObjectAttributes(targetDn);
        var holders = new Dictionary<string, ObjectAttributes?>(StringComparer.Ordinal);
        foreach (var dn in (permissions?.Entries ?? []).Select(entry => entry.Trustee.DistinguishedName)
            .OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            holders.Add(dn, string.Equals(dn, targetDn, StringComparison.Ordinal) ? target : bundle.ReadObjectAttributes(dn));
        }
        var holderValues = holders.Values.ToArray();
        var fingerprint = prepared.Fingerprints.PrepareTarget(target, permissions, holderValues);
        var edges = new Dictionary<OwnAccountMembershipPermissionKind, IReadOnlyList<ControlEdge>>();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT id FROM control_edge WHERE target=$target COLLATE NOCASE AND capability=$capability ORDER BY id";
        query.Parameters.AddWithValue("$target", targetDn);
        var capability = query.Parameters.Add("$capability", SqliteType.Text);
        query.Prepare();
        foreach (var kind in requests.Select(request => request.PermissionKind).Distinct())
        {
            cancellationToken.ThrowIfCancellationRequested();
            capability.Value = kind == OwnAccountMembershipPermissionKind.WriteMembers
                ? nameof(ControlCapability.CanModifyGroupMembership) : nameof(ControlCapability.CanAddSelfToGroup);
            var ids = new List<long>();
            using (var read = query.ExecuteReader()) while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ids.Add(read.GetInt64(0));
            }
            edges.Add(kind, ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id)).ToArray());
        }
        string? previousRequester = null;
        ObjectAttributes? requester = null;
        foreach (var request in requests)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.Equals(previousRequester, request.RequesterDn, StringComparison.Ordinal))
            {
                requester = string.Equals(request.RequesterDn, targetDn, StringComparison.Ordinal) ? target
                    : holders.TryGetValue(request.RequesterDn, out var holder) ? holder : bundle.ReadObjectAttributes(request.RequesterDn);
                previousRequester = request.RequesterDn;
            }
            var assessment = OwnAccountMembershipEvaluator.Assess(request, inputs, description, identities,
                Attributes, permissions, prepared.Schema, prepared.Catalogue, prepared.Contexts, edges[request.PermissionKind],
                bundle.Description.ForestFqdn, cancellationToken, prepared.Memberships);
            var source = fingerprint.OwnAccount(requester);
            _prerequisites.Add(request, new(assessment, source, []));

            ObjectAttributes? Attributes(string dn)
            {
                if (string.Equals(dn, request.RequesterDn, StringComparison.Ordinal)) return requester;
                if (string.Equals(dn, targetDn, StringComparison.Ordinal)) return target;
                return holders.TryGetValue(dn, out var holder) ? holder : bundle.ReadObjectAttributes(dn);
            }
        }
    }

    private static IReadOnlyList<Tier0PathStep> Steps(OwnAccountMembershipAssessment assessment, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, CancellationToken cancellationToken)
    {
        if (assessment.Obtainability != ControlEvaluationState.Established || assessment.Requester is not { } requester
            || assessment.Target is not { } target || !nodes.TryGetValue(target.DistinguishedName, out var current)
            || current.Subject != target || current.MembershipDistance is null) return [];
        var steps = new List<Tier0PathStep>();
        steps.Add(InitialStep(assessment));

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

    internal static Tier0PathStep InitialStep(OwnAccountMembershipAssessment assessment)
    {
        var requester = assessment.Requester ?? throw Tier0PathStorage.InvalidProof();
        var target = assessment.Target ?? throw Tier0PathStorage.InvalidProof();
        return assessment.Basis switch
        {
            OwnAccountMembershipBasis.ExistingMembership => new(requester, target, Tier0PathStepKind.Membership,
                null, null, assessment.MembershipEvidence[0], null) { OwnAccountRequest = assessment.Request },
            OwnAccountMembershipBasis.ExistingOrAuthorizedAdd => new(requester, target, Tier0PathStepKind.OwnAccountMembership,
                null, null, null, assessment.Permissions.Single().Id) { OwnAccountRequest = assessment.Request },
            _ => throw Tier0PathStorage.InvalidProof(),
        };
    }

    internal static string Key(OwnAccountMembershipRequest value) => value.RequesterDn.ToUpperInvariant() + "\0"
        + value.TargetDn.ToUpperInvariant() + "\0" + value.PermissionKind;
}
