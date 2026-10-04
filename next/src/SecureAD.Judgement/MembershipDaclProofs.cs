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
        CancellationToken cancellationToken, RequesterMembershipContext? membershipContext)
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
                    [new(request.RequesterDn, request.TargetDn)], cancellationToken, membership.Assessment, membershipContext).Single();
                state = dacl.Assessment.Authorization;
                if (state == ControlEvaluationState.Established)
                    steps = Steps(dacl.Assessment, membership.Assessment.Request, request);
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

    internal static Tier0PathStep[] Steps(RequesterDaclAssessment dacl, OwnAccountMembershipRequest membership, MembershipDaclRequest request) =>
        dacl.Steps.Select(step => step with { RequesterRequest = null, OwnAccountRequest = membership, MembershipDaclRequest = request }).ToArray();

    internal static bool Valid(MembershipDaclRequest? request) => request is not null
        && !string.IsNullOrWhiteSpace(request.RequesterDn) && !string.IsNullOrWhiteSpace(request.GroupDn)
        && !string.IsNullOrWhiteSpace(request.TargetDn) && Enum.IsDefined(request.PermissionKind);

    internal static string Key(MembershipDaclRequest request) => request.RequesterDn.ToUpperInvariant() + "\0"
        + request.GroupDn.ToUpperInvariant() + "\0" + request.TargetDn.ToUpperInvariant() + "\0" + request.PermissionKind;
}
