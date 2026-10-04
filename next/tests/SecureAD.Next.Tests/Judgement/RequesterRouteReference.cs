using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

// Retains the prior route-choice semantics independently of the production index.
internal static class RequesterRouteReference
{
    internal static RequesterDaclRequest? Requester(Tier0PathNode node, IReadOnlyList<SavedRequesterDaclProof> proofs)
    {
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        if (node.MembershipDistance == 0) return null;
        var candidate = proofs.Select(proof => proof.Assessment)
            .Where(value => value.Authorization == ControlEvaluationState.Established && value.Requester == node.Subject)
            .OrderBy(value => value.Steps.Count).ThenBy(value => RequesterDaclProofs.Key(value.Request), StringComparer.Ordinal).FirstOrDefault();
        return candidate is not null && (previous is null || candidate.Steps.Count < previous) ? candidate.Request : null;
    }

    internal static OwnAccountMembershipRequest? OwnAccount(Tier0PathNode node,
        IReadOnlyList<SavedOwnAccountMembershipProof> proofs, IReadOnlyList<SavedRequesterDaclProof> requesters)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        if (node.RequesterRoute is { } existing)
            previous = requesters.Single(proof => proof.Assessment.Request == existing).Assessment.Steps.Count;
        var candidate = proofs.Where(proof => proof.Assessment.Obtainability == ControlEvaluationState.Established
                && proof.Assessment.Requester == node.Subject && proof.Steps.Count != 0)
            .OrderBy(proof => proof.Steps.Count).ThenBy(proof => OwnAccountMembershipProofs.Key(proof.Assessment.Request), StringComparer.Ordinal).FirstOrDefault();
        return candidate is not null && (previous is null || candidate.Steps.Count < previous) ? candidate.Assessment.Request : null;
    }

    internal static MembershipDaclRequest? MembershipDacl(Tier0PathNode node,
        IReadOnlyList<SavedMembershipDaclProof> proofs, IReadOnlyList<SavedRequesterDaclProof> requesters,
        IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        if (node.RequesterRoute is { } requester)
            previous = requesters.Single(proof => proof.Assessment.Request == requester).Assessment.Steps.Count;
        if (node.OwnAccountRoute is { } own)
            previous = ownAccounts.Single(proof => proof.Assessment.Request == own).Steps.Count;
        var candidate = proofs.Where(proof => proof.Assessment.Authorization == ControlEvaluationState.Established
                && proof.Assessment.Membership.Requester == node.Subject && proof.Assessment.Steps.Count != 0)
            .OrderBy(proof => proof.Assessment.Steps.Count).ThenBy(proof => MembershipDaclProofs.Key(proof.Assessment.Request), StringComparer.Ordinal).FirstOrDefault();
        return candidate is not null && (previous is null || candidate.Assessment.Steps.Count < previous) ? candidate.Assessment.Request : null;
    }
}
