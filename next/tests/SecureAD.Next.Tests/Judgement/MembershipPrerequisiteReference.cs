using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

// Preserved format-52 producer from .v-proofstore-20261004-e91c, before prerequisite reuse.
// This test-only reference retains its repeated reads and separate family calculations.
internal static class MembershipPrerequisiteReference
{
    internal static IReadOnlyList<SavedOwnAccountMembershipProof> OwnAccounts(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<OwnAccountMembershipRequest> requests,
        CancellationToken cancellationToken, bool membershipContinuation = true, bool currentSourceFingerprints = false)
    {
        if (requests.Count == 0) return [];
        sources.RequireFor(description);
        var membershipContext = RequesterMembershipContext.Create(sources, identities, inputs, cancellationToken);
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
        var result = new List<SavedOwnAccountMembershipProof>();
        foreach (var request in requests.OrderBy(OwnAccountMembershipProofs.Key, StringComparer.Ordinal))
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
                bundle.Description.ForestFqdn, cancellationToken, membershipContext);
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
            var material = new
            {
                Requester = bundle.ReadObjectAttributes(request.RequesterDn), Target = bundle.ReadObjectAttributes(request.TargetDn),
                Permissions = permissions, Holders = holders, Roots = roots, Schema = schema, Catalogue = catalogue.Entries,
                Contexts = contexts.Value.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase).ToArray(), Forest = bundle.Description.ForestFqdn,
            };
            var source = currentSourceFingerprints
                ? SourceFingerprintReference.FromLegacy(PathSourceFamily.OwnAccountMembership, description, inputs, material)
                : Tier0PathCalculation.Fingerprint(material);
            result.Add(new(assessment, source, steps));
        }
        return result;
    }

    private static IReadOnlyList<Tier0PathStep> Steps(OwnAccountMembershipAssessment assessment, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, CancellationToken cancellationToken)
    {
        if (assessment.Obtainability != ControlEvaluationState.Established || assessment.Requester is not { } requester
            || assessment.Target is not { } target || !nodes.TryGetValue(target.DistinguishedName, out var current)
            || current.Subject != target || current.MembershipDistance is null) return [];
        var steps = new List<Tier0PathStep> { OwnAccountMembershipProofs.InitialStep(assessment) };
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

    internal static IReadOnlyList<SavedMembershipDaclProof> Combined(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<MembershipDaclRequest> requests,
        CancellationToken cancellationToken, RequesterMembershipContext? membershipContext, bool currentSourceFingerprints = false)
    {
        if (requests.Count == 0) return [];
        var questions = requests.Select(request => new OwnAccountMembershipRequest(request.RequesterDn, request.GroupDn)
            { PermissionKind = request.PermissionKind }).DistinctBy(OwnAccountMembershipProofs.Key).ToArray();
        var memberships = OwnAccounts(connection, description, sources, identities, inputs, nodes,
            questions, cancellationToken, membershipContinuation: false, currentSourceFingerprints)
            .ToDictionary(proof => OwnAccountMembershipProofs.Key(proof.Assessment.Request), StringComparer.Ordinal);
        var result = new List<SavedMembershipDaclProof>();
        foreach (var request in requests.OrderBy(MembershipDaclProofs.Key, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var membership = memberships[OwnAccountMembershipProofs.Key(new(request.RequesterDn, request.GroupDn)
                { PermissionKind = request.PermissionKind })];
            SavedRequesterDaclProof? dacl = null;
            var state = membership.Assessment.Obtainability;
            var issues = new List<MembershipDaclIssue>();
            IReadOnlyList<Tier0PathStep> steps = [];
            if (state == ControlEvaluationState.Established)
            {
                dacl = TargetPermissionReference.Create(connection, description, sources, identities, inputs,
                    [new(request.RequesterDn, request.TargetDn)], cancellationToken, membership.Assessment, membershipContext, currentSourceFingerprints).Single();
                state = dacl.Assessment.Authorization;
                if (state == ControlEvaluationState.Established)
                    steps = MembershipDaclProofs.Steps(dacl.Assessment, membership.Assessment.Request, request);
                else issues.Add(MembershipDaclIssue.DaclPermissionNotEstablished);
            }
            else issues.Add(MembershipDaclIssue.MembershipNotEstablished);
            var assessment = new MembershipDaclAssessment(request, membership.Assessment, dacl?.Assessment,
                state, issues, steps) { AuthorizationContext = MembershipDaclAssessment.Context };
            result.Add(new(assessment, Tier0PathCalculation.Fingerprint(new
            {
                Membership = membership.SourceFingerprint,
                Dacl = dacl?.SourceFingerprint,
            })));
        }
        return result;
    }
}
