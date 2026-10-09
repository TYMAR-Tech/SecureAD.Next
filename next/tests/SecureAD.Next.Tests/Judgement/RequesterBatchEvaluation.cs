using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

// Eager test drivers retain historical batch/occurrence checks without retaining the old
// accumulating production path. WorkPlan tests exercise the shipping lifetime and persistence.
internal static class RequesterBatchEvaluation
{
    internal static IReadOnlyList<SavedRequesterDaclProof> Create(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities,
        PathInputs inputs, IReadOnlyList<RequesterDaclProofs.Question> questions, CancellationToken token,
        RequesterMembershipContext? memberships)
    {
        if (questions.Count == 0) return [];
        var preparation = new RequesterDaclProofs.Preparation(connection, description, sources, identities, inputs, token, memberships);
        var result = new SavedRequesterDaclProof[questions.Count];
        foreach (var group in questions.Select((question, index) =>
            {
                token.ThrowIfCancellationRequested();
                return (Question: question, Index: index);
            })
            .GroupBy(value => value.Question.Request.TargetDn, StringComparer.Ordinal))
        {
            token.ThrowIfCancellationRequested();
            var target = preparation.PrepareTarget(group.Key);
            foreach (var value in group) result[value.Index] = target.Assess(value.Question, null);
        }
        sources.RequireFor(description);
        return result;
    }

    internal static IReadOnlyList<SavedMembershipDaclProof> Combined(SqliteConnection connection,
        JudgementDescription description, JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities,
        PathInputs inputs, IReadOnlyDictionary<string, Tier0PathNode> nodes, IReadOnlyList<MembershipDaclRequest> requests,
        CancellationToken token, RequesterMembershipContext? memberships, OwnAccountBatchEvaluation prerequisites)
    {
        if (requests.Count == 0) return [];
        prerequisites.RequireFor(connection, description, sources, identities, inputs, token);
        var questions = requests.Select(request => new OwnAccountMembershipRequest(request.RequesterDn, request.GroupDn)
            { PermissionKind = request.PermissionKind }).DistinctBy(OwnAccountMembershipProofs.Key).ToArray();
        var prepared = prerequisites.Create(nodes, questions, membershipContinuation: false)
            .ToDictionary(value => OwnAccountMembershipProofs.Key(value.Assessment.Request), StringComparer.Ordinal);
        var selected = requests.OrderBy(MembershipDaclProofs.Key, StringComparer.Ordinal).Select(request => (Request: request,
            Membership: prepared[OwnAccountMembershipProofs.Key(new(request.RequesterDn, request.GroupDn)
                { PermissionKind = request.PermissionKind })])).ToArray();
        var dacls = Create(connection, description, sources, identities, inputs,
            selected.Where(value => value.Membership.Assessment.Obtainability == ControlEvaluationState.Established)
                .Select(value => new RequesterDaclProofs.Question(new(value.Request.RequesterDn, value.Request.TargetDn),
                    value.Membership.Assessment)).ToArray(), token, memberships);
        var next = 0;
        return selected.Select(value => MembershipDaclProofs.Combine(value.Request, value.Membership,
            value.Membership.Assessment.Obtainability == ControlEvaluationState.Established ? dacls[next++] : null)).ToArray();
    }
}

internal sealed class OwnAccountBatchEvaluation(SqliteConnection connection, JudgementDescription description,
    JudgingInputs sources, IReadOnlyDictionary<string, Tier0Target> identities, PathInputs inputs, CancellationToken token)
{
    private readonly OwnAccountMembershipProofs _producer = new(connection, description, sources, identities, inputs, token);
    private readonly Dictionary<OwnAccountMembershipRequest, SavedOwnAccountMembershipProof> _answers = [];

    internal void RequireFor(SqliteConnection expectedConnection, JudgementDescription expectedDescription,
        JudgingInputs expectedSources, IReadOnlyDictionary<string, Tier0Target> expectedIdentities,
        PathInputs expectedInputs, CancellationToken expectedToken) =>
        _producer.RequireFor(expectedConnection, expectedDescription, expectedSources, expectedIdentities, expectedInputs, expectedToken);

    internal IEnumerable<SavedOwnAccountMembershipProof> PrepareResource(string group,
        IReadOnlyList<OwnAccountMembershipRequest> requests) => _producer.PrepareResource(group, requests);

    internal IReadOnlyList<SavedOwnAccountMembershipProof> Create(IReadOnlyDictionary<string, Tier0PathNode> nodes,
        IReadOnlyList<OwnAccountMembershipRequest> requests, bool membershipContinuation = true)
    {
        if (requests.Count == 0) return [];
        RequireFor(connection, description, sources, identities, inputs, token);
        var ordered = requests.OrderBy(OwnAccountMembershipProofs.Key, StringComparer.Ordinal).ToArray();
        foreach (var group in ordered.GroupBy(value => value.TargetDn, StringComparer.Ordinal))
        {
            var pending = group.Where(request => !_answers.ContainsKey(request)).Distinct().ToArray();
            if (pending.Length == 0) continue;
            foreach (var value in _producer.PrepareResource(group.Key, pending)) _answers.Add(value.Assessment.Request, value);
        }
        var result = ordered.Select(request => membershipContinuation ? _producer.WithMembershipContinuation(_answers[request], nodes) : _answers[request]).ToArray();
        sources.RequireFor(description);
        return result;
    }
}
