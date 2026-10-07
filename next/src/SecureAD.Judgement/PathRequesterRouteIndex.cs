using SecureAD.Derivation;

namespace SecureAD.Judgement;

internal sealed class PathRequesterRouteIndex
{
    private readonly Dictionary<Tier0Target, SavedRequesterDaclProof> _requesters = [];
    private readonly Dictionary<Tier0Target, SavedOwnAccountMembershipProof> _ownAccounts = [];
    private readonly Dictionary<Tier0Target, SavedMembershipDaclProof> _membershipDacls = [];
    private readonly Dictionary<RequesterDaclRequest, int> _requesterLengths = [];
    private readonly Dictionary<OwnAccountMembershipRequest, int> _ownAccountLengths = [];

    internal void AddRequesters(IEnumerable<SavedRequesterDaclProof> proofs, CancellationToken cancellationToken,
        PostPassDiagnostics? diagnostic)
    {
        var processed = 0L;
        foreach (var proof in proofs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = proof.Assessment;
            _requesterLengths.Add(value.Request, value.Steps.Count);
            if (value.Authorization == ControlEvaluationState.Established && value.Requester is { } requester
                && (!_requesters.TryGetValue(requester, out var previous)
                    || Earlier(value.Steps.Count, RequesterDaclProofs.Key(value.Request),
                        previous.Assessment.Steps.Count, RequesterDaclProofs.Key(previous.Assessment.Request))))
                _requesters[requester] = proof;
            diagnostic?.Counter("answersProcessed", ++processed);
        }
    }

    internal void AddOwnAccounts(IEnumerable<SavedOwnAccountMembershipProof> proofs, CancellationToken cancellationToken,
        PostPassDiagnostics? diagnostic)
    {
        var processed = 0L;
        foreach (var proof in proofs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = proof.Assessment;
            _ownAccountLengths.Add(value.Request, proof.Steps.Count);
            if (value.Obtainability == ControlEvaluationState.Established && value.Requester is { } requester
                && proof.Steps.Count != 0 && (!_ownAccounts.TryGetValue(requester, out var previous)
                    || Earlier(proof.Steps.Count, OwnAccountMembershipProofs.Key(value.Request),
                        previous.Steps.Count, OwnAccountMembershipProofs.Key(previous.Assessment.Request))))
                _ownAccounts[requester] = proof;
            diagnostic?.Counter("answersProcessed", ++processed);
        }
    }

    internal void AddMembershipDacls(IEnumerable<SavedMembershipDaclProof> proofs, CancellationToken cancellationToken,
        PostPassDiagnostics? diagnostic)
    {
        var processed = 0L;
        foreach (var proof in proofs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = proof.Assessment;
            if (value.Authorization == ControlEvaluationState.Established && value.Membership.Requester is { } requester
                && value.Steps.Count != 0 && (!_membershipDacls.TryGetValue(requester, out var previous)
                    || Earlier(value.Steps.Count, MembershipDaclProofs.Key(value.Request),
                        previous.Assessment.Steps.Count, MembershipDaclProofs.Key(previous.Assessment.Request))))
                _membershipDacls[requester] = proof;
            diagnostic?.Counter("answersProcessed", ++processed);
        }
    }

    internal RequesterDaclRequest? Requester(Tier0PathNode node)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        return _requesters.TryGetValue(node.Subject, out var candidate)
            && (previous is null || candidate.Assessment.Steps.Count < previous) ? candidate.Assessment.Request : null;
    }

    internal OwnAccountMembershipRequest? OwnAccount(Tier0PathNode node)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.RequesterRoute is { } requester ? _requesterLengths[requester]
            : node.Terminal is not null ? 1 : node.MembershipDistance;
        return _ownAccounts.TryGetValue(node.Subject, out var candidate)
            && (previous is null || candidate.Steps.Count < previous) ? candidate.Assessment.Request : null;
    }

    internal MembershipDaclRequest? MembershipDacl(Tier0PathNode node)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.OwnAccountRoute is { } own ? _ownAccountLengths[own]
            : node.RequesterRoute is { } requester ? _requesterLengths[requester]
            : node.Terminal is not null ? 1 : node.MembershipDistance;
        return _membershipDacls.TryGetValue(node.Subject, out var candidate)
            && (previous is null || candidate.Assessment.Steps.Count < previous) ? candidate.Assessment.Request : null;
    }

    internal int? SupportedDistance(Tier0PathNode node) =>
        node.MembershipDaclRoute is not null ? _membershipDacls[node.Subject].Assessment.Steps.Count
        : node.OwnAccountRoute is not null ? _ownAccounts[node.Subject].Steps.Count
        : node.RequesterRoute is not null ? _requesters[node.Subject].Assessment.Steps.Count
        : node.MembershipDistance == 0 ? 0
        : node.Terminal is not null ? 1 : node.MembershipDistance;

    private static bool Earlier(int length, string key, int previousLength, string previousKey) =>
        length < previousLength || length == previousLength && StringComparer.Ordinal.Compare(key, previousKey) < 0;
}
