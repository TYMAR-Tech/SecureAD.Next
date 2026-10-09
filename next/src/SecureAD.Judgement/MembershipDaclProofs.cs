namespace SecureAD.Judgement;

internal sealed record SavedMembershipDaclProof(MembershipDaclAssessment Assessment, string SourceFingerprint);

internal static class MembershipDaclProofs
{
    internal static SavedMembershipDaclProof Combine(MembershipDaclRequest request,
        SavedOwnAccountMembershipProof membership, SavedRequesterDaclProof? dacl)
    {
        if (OwnAccountMembershipProofs.Key(membership.Assessment.Request) != OwnAccountMembershipProofs.Key(
                new OwnAccountMembershipRequest(request.RequesterDn, request.GroupDn) { PermissionKind = request.PermissionKind })
            || dacl is not null && (dacl.Assessment.Request != new RequesterDaclRequest(request.RequesterDn, request.TargetDn)
                || dacl.Assessment.ObtainedMembership != membership.Assessment.Request))
            throw Tier0PathStorage.InvalidProof();
        var state = membership.Assessment.Obtainability;
        var issues = new List<MembershipDaclIssue>();
        IReadOnlyList<Tier0PathStep> steps = [];
        if (state == ControlEvaluationState.Established)
        {
            if (dacl is null) throw Tier0PathStorage.InvalidProof();
            state = dacl.Assessment.Authorization;
            if (state == ControlEvaluationState.Established)
                steps = Steps(dacl.Assessment, membership.Assessment.Request, request);
            else issues.Add(MembershipDaclIssue.DaclPermissionNotEstablished);
        }
        else
        {
            if (dacl is not null) throw Tier0PathStorage.InvalidProof();
            issues.Add(MembershipDaclIssue.MembershipNotEstablished);
        }
        var assessment = new MembershipDaclAssessment(request, membership.Assessment, dacl?.Assessment,
            state, issues, steps) { AuthorizationContext = MembershipDaclAssessment.Context };
        return new(assessment, Tier0PathCalculation.Fingerprint(new
        {
            Membership = membership.SourceFingerprint,
            Dacl = dacl?.SourceFingerprint,
        }));
    }

    internal static Tier0PathStep[] Steps(RequesterDaclAssessment dacl, OwnAccountMembershipRequest membership, MembershipDaclRequest request) =>
        dacl.Steps.Select(step => step with { RequesterRequest = null, OwnAccountRequest = membership, MembershipDaclRequest = request }).ToArray();

    internal static bool Valid(MembershipDaclRequest? request) => request is not null
        && !string.IsNullOrWhiteSpace(request.RequesterDn) && !string.IsNullOrWhiteSpace(request.GroupDn)
        && !string.IsNullOrWhiteSpace(request.TargetDn) && Enum.IsDefined(request.PermissionKind);

    internal static string Key(MembershipDaclRequest request) => request.RequesterDn.ToUpperInvariant() + "\0"
        + request.GroupDn.ToUpperInvariant() + "\0" + request.TargetDn.ToUpperInvariant() + "\0" + request.PermissionKind;
}
