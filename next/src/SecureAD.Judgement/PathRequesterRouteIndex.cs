using SecureAD.Derivation;

namespace SecureAD.Judgement;

internal sealed class PathRequesterRouteIndex
{
    private sealed record Candidate<T>(T Request, int Length, string Key);
    private readonly Dictionary<Tier0Target, Candidate<RequesterDaclRequest>> _requesters = [];
    private readonly Dictionary<Tier0Target, Candidate<OwnAccountMembershipRequest>> _ownAccounts = [];
    private readonly Dictionary<Tier0Target, Candidate<MembershipDaclRequest>> _membershipDacls = [];

    internal void AddRequesters(IEnumerable<SavedRequesterDaclProof> proofs, CancellationToken cancellationToken,
        PostPassDiagnostics? diagnostic)
    {
        var processed = 0L;
        foreach (var proof in proofs)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = proof.Assessment;
            if (value.Authorization == ControlEvaluationState.Established && value.Requester is { } requester
                && (!_requesters.TryGetValue(requester, out var previous)
                    || Earlier(value.Steps.Count, RequesterDaclProofs.Key(value.Request),
                        previous.Length, previous.Key)))
                _requesters[requester] = new(value.Request, value.Steps.Count, RequesterDaclProofs.Key(value.Request));
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
            if (value.Obtainability == ControlEvaluationState.Established && value.Requester is { } requester
                && proof.Steps.Count != 0 && (!_ownAccounts.TryGetValue(requester, out var previous)
                    || Earlier(proof.Steps.Count, OwnAccountMembershipProofs.Key(value.Request),
                        previous.Length, previous.Key)))
                _ownAccounts[requester] = new(value.Request, proof.Steps.Count, OwnAccountMembershipProofs.Key(value.Request));
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
                        previous.Length, previous.Key)))
                _membershipDacls[requester] = new(value.Request, value.Steps.Count, MembershipDaclProofs.Key(value.Request));
            diagnostic?.Counter("answersProcessed", ++processed);
        }
    }

    internal RequesterDaclRequest? Requester(Tier0PathNode node)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.Terminal is not null ? 1 : node.MembershipDistance;
        return _requesters.TryGetValue(node.Subject, out var candidate)
            && (previous is null || candidate.Length < previous) ? candidate.Request : null;
    }

    internal OwnAccountMembershipRequest? OwnAccount(Tier0PathNode node)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.RequesterRoute is not null ? _requesters[node.Subject].Length
            : node.Terminal is not null ? 1 : node.MembershipDistance;
        return _ownAccounts.TryGetValue(node.Subject, out var candidate)
            && (previous is null || candidate.Length < previous) ? candidate.Request : null;
    }

    internal MembershipDaclRequest? MembershipDacl(Tier0PathNode node)
    {
        if (node.MembershipDistance == 0) return null;
        var previous = node.OwnAccountRoute is not null ? _ownAccounts[node.Subject].Length
            : node.RequesterRoute is not null ? _requesters[node.Subject].Length
            : node.Terminal is not null ? 1 : node.MembershipDistance;
        return _membershipDacls.TryGetValue(node.Subject, out var candidate)
            && (previous is null || candidate.Length < previous) ? candidate.Request : null;
    }

    internal int? SupportedDistance(Tier0PathNode node) =>
        node.MembershipDaclRoute is not null ? _membershipDacls[node.Subject].Length
        : node.OwnAccountRoute is not null ? _ownAccounts[node.Subject].Length
        : node.RequesterRoute is not null ? _requesters[node.Subject].Length
        : node.MembershipDistance == 0 ? 0
        : node.Terminal is not null ? 1 : node.MembershipDistance;

    private static bool Earlier(int length, string key, int previousLength, string previousKey) =>
        length < previousLength || length == previousLength && StringComparer.Ordinal.Compare(key, previousKey) < 0;
}
