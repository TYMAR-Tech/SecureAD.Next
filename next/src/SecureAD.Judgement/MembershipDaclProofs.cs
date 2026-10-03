using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal sealed record SavedMembershipDaclProof(MembershipDaclAssessment Assessment, string SourceFingerprint);

internal static class MembershipDaclProofs
{
    internal static IReadOnlyList<SavedMembershipDaclProof> Create(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs,
        IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<MembershipDaclRequest> requests,
        CancellationToken cancellationToken)
    {
        if (requests.Count == 0) return [];
        var questions = requests.Select(request => new OwnAccountMembershipRequest(request.RequesterDn, request.GroupDn)
            { PermissionKind = request.PermissionKind }).DistinctBy(OwnAccountMembershipProofs.Key).ToArray();
        var memberships = OwnAccountMembershipProofs.Create(connection, description, sources, identities, inputs, nodes,
            questions, cancellationToken, membershipContinuation: false)
            .ToDictionary(proof => OwnAccountMembershipProofs.Key(proof.Assessment.Request), StringComparer.Ordinal);
        var result = new List<SavedMembershipDaclProof>();
        foreach (var request in requests.OrderBy(Key, StringComparer.Ordinal))
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
                dacl = RequesterDaclProofs.Create(connection, description, sources, identities, inputs,
                    [new(request.RequesterDn, request.TargetDn)], cancellationToken, membership.Assessment).Single();
                state = dacl.Assessment.Authorization;
                if (state == ControlEvaluationState.Established)
                    steps = dacl.Assessment.Steps.Select(step => step with
                    {
                        RequesterRequest = null,
                        OwnAccountRequest = membership.Assessment.Request,
                        MembershipDaclRequest = request,
                    }).ToArray();
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

    internal static MembershipDaclRequest? Best(Tier0PathNode node, IReadOnlyList<SavedMembershipDaclProof> proofs,
        IReadOnlyList<SavedRequesterDaclProof> requesters, IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        if (node.RequesterRoute is { } requester)
            previous = requesters.Single(proof => proof.Assessment.Request == requester).Assessment.Steps.Count;
        if (node.OwnAccountRoute is { } ownAccount)
            previous = ownAccounts.Single(proof => proof.Assessment.Request == ownAccount).Steps.Count;
        var candidate = proofs.Where(proof => proof.Assessment.Authorization == ControlEvaluationState.Established
                && proof.Assessment.Membership.Requester == node.Subject && proof.Assessment.Steps.Count != 0)
            .OrderBy(proof => proof.Assessment.Steps.Count).ThenBy(proof => Key(proof.Assessment.Request), StringComparer.Ordinal).FirstOrDefault();
        return candidate is not null && (previous is null || candidate.Assessment.Steps.Count < previous)
            ? candidate.Assessment.Request : null;
    }

    internal static bool Valid(MembershipDaclRequest? request) => request is not null
        && !string.IsNullOrWhiteSpace(request.RequesterDn) && !string.IsNullOrWhiteSpace(request.GroupDn)
        && !string.IsNullOrWhiteSpace(request.TargetDn) && Enum.IsDefined(request.PermissionKind);

    internal static string Key(MembershipDaclRequest request) => request.RequesterDn.ToUpperInvariant() + "\0"
        + request.GroupDn.ToUpperInvariant() + "\0" + request.TargetDn.ToUpperInvariant() + "\0" + request.PermissionKind;
}
