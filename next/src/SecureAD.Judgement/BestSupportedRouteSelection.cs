using Microsoft.Data.Sqlite;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Consumes the existing evaluated candidates, independently of the shortest-route index.</summary>
internal sealed class BestSupportedRouteSelection(SqliteConnection connection, JudgementDescription description,
    PathInputs inputs, CancellationToken cancellationToken)
{
    private readonly Dictionary<string, (int Complete, int Ungraded, BestRouteCandidate? Best, long Order)> _selected = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<long, string> _permissionSignatures = [];
    private readonly Dictionary<string, HashSet<RouteGradingLimitation>> _limitations = new(StringComparer.OrdinalIgnoreCase);

    internal void Terminal(Tier0PathStep step, ControlEdge edge)
    {
        RememberPermission(edge);
        Add(new(step.From, step.To, Direct(1, Signature([step], step.To)),
            RouteSourceKind.Terminal, null, Tier0PathCalculation.Fingerprint(edge), step), 0);
    }

    internal void Memberships(IReadOnlyList<Tier0PathNode> nodes)
    {
        var signatures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var endpoints = new Dictionary<string, Tier0Target>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in nodes.Where(node => node.MembershipDistance is not null)
            .OrderBy(node => node.MembershipDistance).ThenBy(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var seed = node.MembershipDistance == 0;
            var next = node.MembershipNext;
            if (!seed && next is null) throw Tier0PathStorage.InvalidProof();
            var endpoint = seed ? node.Subject : endpoints[next!.To.DistinguishedName];
            var signature = seed ? IdentitySignature(node.Subject)
                : Extend(next!, signatures[next!.To.DistinguishedName]);
            signatures.Add(node.Subject.DistinguishedName, signature);
            endpoints.Add(node.Subject.DistinguishedName, endpoint);
            Add(new(node.Subject, endpoint, Direct(node.MembershipDistance!.Value, signature),
                seed ? RouteSourceKind.FixedTarget : RouteSourceKind.Membership, null, null, null), 0);
        }
    }

    internal void Proof(object source, long proofId, string fingerprint, long order)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var (subject, state, steps, own, kind) = source switch
        {
            SavedRequesterDaclProof value => (value.Assessment.Requester, value.Assessment.Authorization,
                value.Assessment.Steps, (OwnAccountMembershipAssessment?)null, RouteSourceKind.Requester),
            SavedOwnAccountMembershipProof value => (value.Assessment.Requester, value.Assessment.Obtainability,
                value.Steps, (OwnAccountMembershipAssessment?)value.Assessment, RouteSourceKind.OwnAccount),
            SavedMembershipDaclProof value => (value.Assessment.Membership.Requester, value.Assessment.Authorization,
                value.Assessment.Steps, (OwnAccountMembershipAssessment?)value.Assessment.Membership, RouteSourceKind.MembershipDacl),
            _ => throw Tier0PathStorage.InvalidProof(),
        };
        // Unknown questions have no supported route to grade. A positive operation without
        // a supported continuation is also not a candidate path.
        if (state != ControlEvaluationState.Established || subject is null || steps.Count == 0) return;
        var endpoint = steps[^1].To;
        var current = subject;
        foreach (var step in steps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (step.From != current) throw Tier0PathStorage.InvalidProof();
            current = step.To;
        }
        if (!inputs.FixedTargets.Contains(endpoint)) throw Tier0PathStorage.InvalidProof();
        var assumptions = new List<RouteCondition>();
        if (steps.Any(step => step.Kind == Tier0PathStepKind.OwnAccountMembership))
        {
            if (own is not { Basis: OwnAccountMembershipBasis.ExistingOrAuthorizedAdd, Target: not null, Requester: not null })
            {
                Ungraded(subject, RouteGradingLimitation.MembershipAssumptionUnavailable);
                return;
            }
            assumptions.Add(new("MembershipOutcome", own.Requester, own.Target, null));
            if (kind == RouteSourceKind.MembershipDacl)
                assumptions.Add(new("MembershipEnabledForAuthorization", own.Requester, own.Target, endpoint.NamingContext));
        }
        // Confidence describes these supported, completed proof semantics, not a generic
        // holder edge's unresolved requester check or a claim about live LDAP success.
        if (steps.Any(step => !Enum.IsDefined(step.Kind)))
        {
            Ungraded(subject, RouteGradingLimitation.UnsupportedStep);
            return;
        }
        var grade = SupportedRouteGrade.Combine(steps.Select(step => new SupportedRouteGrade(
            RouteEvidenceClass.Definite,
            step.Kind == Tier0PathStepKind.OwnAccountMembership ? RouteFeasibility.Conditional : RouteFeasibility.Direct,
            step.Kind == Tier0PathStepKind.OwnAccountMembership ? assumptions : [],
            RouteConfidence.High, 1, "")).ToArray(), Signature(steps, endpoint));
        Add(new(subject, endpoint, grade, kind, proofId, fingerprint, null), order);
    }

    private void Ungraded(Tier0Target subject, RouteGradingLimitation reason)
    {
        var previous = _selected.GetValueOrDefault(subject.DistinguishedName);
        _selected[subject.DistinguishedName] = (checked(previous.Complete + 1), checked(previous.Ungraded + 1), previous.Best, previous.Order);
        if (!_limitations.TryGetValue(subject.DistinguishedName, out var reasons))
            _limitations.Add(subject.DistinguishedName, reasons = []);
        reasons.Add(reason);
    }

    private void Add(BestRouteCandidate candidate, long order)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var previous = _selected.GetValueOrDefault(candidate.Subject.DistinguishedName);
        var comparison = previous.Best is null ? -1 : SupportedRouteGrade.Compare(candidate.Grade, previous.Best.Grade);
        var replace = comparison < 0 || comparison == 0 && order < previous.Order;
        _selected[candidate.Subject.DistinguishedName] = (checked(previous.Complete + 1), previous.Ungraded,
            replace ? candidate : previous.Best, replace ? order : previous.Order);
    }

    internal IEnumerable<BestRouteSelection> Results(IReadOnlyList<OwnershipAuditStorage.TargetRow> targets, string calculation)
    {
        foreach (var target in targets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = _selected.GetValueOrDefault(target.Identity.DistinguishedName);
            yield return new(1, description.GenerationId, description.DerivationGenerationId, description.EvidenceSeal,
                calculation, target.Identity, value.Complete, value.Ungraded, value.Best)
                { GradingLimitations = _limitations.TryGetValue(target.Identity.DistinguishedName, out var reasons) ? reasons.Order().ToArray() : [] };
        }
    }

    private static SupportedRouteGrade Direct(int length, string signature) =>
        new(RouteEvidenceClass.Definite, RouteFeasibility.Direct, [], RouteConfidence.High, length, signature);

    private string Signature(IReadOnlyList<Tier0PathStep> steps, Tier0Target endpoint)
    {
        var signature = IdentitySignature(endpoint);
        for (var index = steps.Count - 1; index >= 0; index--)
        {
            cancellationToken.ThrowIfCancellationRequested();
            signature = Extend(steps[index], signature);
        }
        return signature;
    }

    private string Extend(Tier0PathStep step, string suffix)
    {
        string? permission = null;
        if (step.PermissionId is { } id)
        {
            if (!_permissionSignatures.TryGetValue(id, out permission))
            {
                RememberPermission(ControlEdgeStorage.ReadEdge(connection, description, id));
                permission = _permissionSignatures[id];
            }
        }
        return Tier0PathCalculation.Fingerprint(new
        {
            From = IdentitySignature(step.From), To = IdentitySignature(step.To), step.Kind,
            Attribute = step.MembershipWitness?.Attribute,
            Ordinal = step.MembershipWitness?.Ordinal,
            Value = step.MembershipWitness?.Value.ToUpperInvariant(),
            Permission = permission, Suffix = suffix,
        });
    }

    private void RememberPermission(ControlEdge edge)
    {
        if (_permissionSignatures.ContainsKey(edge.Id)) return;
        _permissionSignatures.Add(edge.Id, Tier0PathCalculation.Fingerprint(new
        {
            Target = edge.Target.ToUpperInvariant(), edge.TargetGuid, edge.Capability,
            Sid = edge.HolderSid.ToUpperInvariant(), Scope = edge.HolderScope?.ToUpperInvariant(),
            Evidence = ControlEdgeStorage.ReadExactAces(connection, edge),
        }));
    }

    private static string IdentitySignature(Tier0Target target) => Tier0PathCalculation.Fingerprint(new
    {
        target.ObjectGuid, Dn = target.DistinguishedName.ToUpperInvariant(),
        Context = target.NamingContext.ToUpperInvariant(), Sid = target.Sid?.ToUpperInvariant(),
        Scope = target.SidScope?.ToUpperInvariant(),
    });
}
