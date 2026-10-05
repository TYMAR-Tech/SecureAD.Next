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
        CancellationToken cancellationToken, RequesterMembershipContext? membershipContext, OwnAccountMembershipProofs prerequisites)
    {
        if (requests.Count == 0) return [];
        prerequisites.RequireFor(connection, description, sources, identities, inputs, cancellationToken);
        var questions = requests.Select(request => new OwnAccountMembershipRequest(request.RequesterDn, request.GroupDn)
            { PermissionKind = request.PermissionKind }).DistinctBy(OwnAccountMembershipProofs.Key).ToArray();
        var memberships = prerequisites.Create(nodes, questions, membershipContinuation: false)
            .ToDictionary(proof => OwnAccountMembershipProofs.Key(proof.Assessment.Request), StringComparer.Ordinal);
        var selected = requests.OrderBy(Key, StringComparer.Ordinal).Select(request => (Request: request,
            Membership: memberships[OwnAccountMembershipProofs.Key(new(request.RequesterDn, request.GroupDn)
                { PermissionKind = request.PermissionKind })])).ToArray();
        var daclQuestions = selected.Where(value => value.Membership.Assessment.Obtainability == ControlEvaluationState.Established)
            .Select(value => new RequesterDaclProofs.Question(new(value.Request.RequesterDn, value.Request.TargetDn), value.Membership.Assessment)).ToArray();
        var dacls = RequesterDaclProofs.Create(connection, description, sources, identities, inputs, daclQuestions,
            cancellationToken, membershipContext);
        var nextDacl = 0;
        var result = new List<SavedMembershipDaclProof>();
        foreach (var (request, membership) in selected)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SavedRequesterDaclProof? dacl = null;
            var state = membership.Assessment.Obtainability;
            var issues = new List<MembershipDaclIssue>();
            IReadOnlyList<Tier0PathStep> steps = [];
            if (state == ControlEvaluationState.Established)
            {
                dacl = dacls[nextDacl++];
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
