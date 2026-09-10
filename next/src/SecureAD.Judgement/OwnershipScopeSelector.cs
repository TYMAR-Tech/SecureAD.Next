using System.Collections.Immutable;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Selects assessment relevance over supplied captured facts; no membership discovery, path enumeration or audit activation.</summary>
public static class OwnershipScopeSelector
{
    /// <summary>The selection semantics, independent of Tier-0 classification and ownership evaluation versions.</summary>
    public const int Version = 1;

    /// <summary>Follows incoming relations from established shared classifications, retaining partial results on caller cancellation.</summary>
    /// <remarks>Callers verify source stores first. Completing this finite walk does not establish complete forest coverage.</remarks>
    public static OwnershipScopeSelection Select(Tier0InputBinding input, Guid judgementGenerationId,
        IEnumerable<Tier0Classification> classifications, IEnumerable<Tier0RelevanceRelation> relations,
        Tier0Coverage sourceCoverage, CancellationToken cancellationToken, IProgress<OwnershipScopeProgress>? progress)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(classifications);
        ArgumentNullException.ThrowIfNull(relations);
        ArgumentNullException.ThrowIfNull(sourceCoverage);
        if (!input.IsSupported) throw new ArgumentException(null, nameof(input));
        if (judgementGenerationId == Guid.Empty) throw new ArgumentException(null, nameof(judgementGenerationId));
        ValidateCoverage(sourceCoverage);
        var coverage = sourceCoverage;
        var originals = new List<Tier0Classification>();
        var facts = new Dictionary<Tier0Target, Tier0Classification>();
        var targets = new HashSet<Tier0Target>();
        var ambiguous = new HashSet<Tier0Target>();
        var byGuid = new Dictionary<Guid, Tier0Target>();
        var byDn = new Dictionary<string, Tier0Target>(StringComparer.OrdinalIgnoreCase);
        var bySid = new Dictionary<(string Sid, string? Scope), Tier0Target>();
        var sourceEdges = new Dictionary<long, Tier0RelevanceRelation>();
        var retained = new SortedSet<Tier0RelevanceRelation>(Comparer<Tier0RelevanceRelation>.Create(CompareRelations));
        var incoming = new Dictionary<Tier0Target, List<Tier0RelevanceRelation>>();
        var followable = new HashSet<Tier0RelevanceRelation>();
        var selected = new HashSet<Tier0Target>();
        var reasons = new Dictionary<Tier0Target, List<Tier0RelevanceRelation>>();
        var pending = new Queue<Tier0Target>();
        var visited = 0;
        var examined = 0;
        var cancelled = false;
        var inputsRead = false;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var classification in classifications)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (classification is null || classification.Input != input) throw new ArgumentException(null, nameof(classifications));
                coverage = Merge(coverage, classification.Coverage);
                if (!classification.Target.IsValid)
                {
                    originals.Add(classification);
                    IncompleteIdentity();
                    continue;
                }
                AddTarget(classification.Target);
                if (facts.TryGetValue(classification.Target, out var previous))
                {
                    if (Equivalent(previous, classification)) continue;
                    ambiguous.Add(classification.Target);
                }
                else facts.Add(classification.Target, classification);
                originals.Add(classification);
            }
            foreach (var relation in relations)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (relation is null || relation.Input != input
                    || relation.JudgementGenerationId is { } generation && generation != judgementGenerationId)
                    throw new ArgumentException(null, nameof(relations));
                AddTarget(relation.Controller);
                AddTarget(relation.Affected);
                if (relation.ControlEdgeId is { } id)
                {
                    if (sourceEdges.TryGetValue(id, out var previous) && previous != relation)
                        throw new ArgumentException(null, nameof(relations));
                    sourceEdges[id] = relation;
                }
                retained.Add(relation);
            }
            foreach (var target in targets)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!facts.ContainsKey(target))
                    coverage = coverage with { InputsComplete = false, Limitations = coverage.Limitations | Tier0Limitations.InputIncomplete };
            }
            if (ambiguous.Count != 0) IncompleteIdentity();
            foreach (var relation in retained)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (relation.Limitations != Tier0Limitations.None)
                    coverage = coverage with { AnalysisComplete = false, Limitations = coverage.Limitations | relation.Limitations };
                if (CanFollow(relation)) followable.Add(relation);
                if (!incoming.TryGetValue(relation.Affected, out var links)) incoming[relation.Affected] = links = [];
                links.Add(relation);
            }
            inputsRead = true;
            foreach (var target in targets.Order(Comparer<Tier0Target>.Create(CompareTargets)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!ambiguous.Contains(target) && facts.TryGetValue(target, out var classification)
                    && classification.State == Tier0State.Established)
                {
                    selected.Add(target);
                    pending.Enqueue(target);
                }
            }
            while (pending.TryDequeue(out var target))
            {
                cancellationToken.ThrowIfCancellationRequested();
                foreach (var relation in incoming.GetValueOrDefault(target) ?? [])
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    examined++;
                    if (!followable.Contains(relation) || ambiguous.Contains(relation.Controller) || ambiguous.Contains(relation.Affected)) continue;
                    if (!reasons.TryGetValue(relation.Controller, out var supports)) reasons[relation.Controller] = supports = [];
                    supports.Add(relation);
                    if (selected.Add(relation.Controller)) pending.Enqueue(relation.Controller);
                }
                visited++;
                progress?.Report(new(visited, examined, selected.Count));
            }
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (OperationCanceledException error) when (cancellationToken.IsCancellationRequested && error.CancellationToken == cancellationToken)
        {
            cancelled = true;
            coverage = coverage with { ProcessingComplete = false, Limitations = coverage.Limitations | Tier0Limitations.ProcessingIncomplete };
            if (!inputsRead)
                coverage = coverage with { InputsComplete = false, Limitations = coverage.Limitations | Tier0Limitations.InputIncomplete };
        }
        // Identity conflicts discovered before cancellation must not disappear with the unfinished walk.
        if (ambiguous.Count != 0) IncompleteIdentity();
        var decisions = targets.Order(Comparer<Tier0Target>.Create(CompareTargets)).Select(target =>
        {
            var included = selected.Contains(target);
            var classification = !ambiguous.Contains(target) && facts.TryGetValue(target, out var fact)
                && (included || fact.State != Tier0State.Established) ? fact : null;
            return new OwnershipScopeDecision(input, target, included ? OwnershipScopeState.Included
                : coverage.IsComplete ? OwnershipScopeState.OutsideComputedScope : OwnershipScopeState.Undetermined,
                coverage, classification, reasons.TryGetValue(target, out var supports) ? supports.ToImmutableArray() : []);
        }).ToImmutableArray();
        return new(input, judgementGenerationId, originals.ToImmutableArray(), retained.ToImmutableArray(),
            decisions, coverage, cancelled, visited, examined);

        void IncompleteIdentity() => coverage = coverage with
        {
            InputsComplete = false,
            Limitations = coverage.Limitations | Tier0Limitations.IdentityUnverified,
        };

        void AddTarget(Tier0Target target)
        {
            if (!target.IsValid) throw new ArgumentException(null, nameof(target));
            if (!targets.Add(target)) return;
            Track(byDn, target.DistinguishedName, target);
            if (target.ObjectGuid is { } guid) Track(byGuid, guid, target);
            if (target.Sid is { } sid) Track(bySid, (sid.ToUpperInvariant(), target.SidScope?.ToUpperInvariant()), target);
        }

        void Track<TKey>(Dictionary<TKey, Tier0Target> index, TKey key, Tier0Target target) where TKey : notnull
        {
            if (index.TryGetValue(key, out var previous) && previous != target)
            {
                ambiguous.Add(previous);
                ambiguous.Add(target);
            }
            else index[key] = target;
        }

        bool CanFollow(Tier0RelevanceRelation relation)
        {
            if (relation.Kind == Tier0RelevanceKind.EffectiveMembership) return relation.State == Tier0State.Established;
            if (relation.Kind != Tier0RelevanceKind.ControlCandidate)
            {
                coverage = coverage with { AnalysisComplete = false,
                    Limitations = coverage.Limitations | Tier0Limitations.DependencyQualificationUnsupported };
                return false;
            }
            if ((relation.PermissionUncertainty & (ControlUncertainty.HolderUnresolved | ControlUncertainty.HolderIsPlaceholder
                | ControlUncertainty.ResourceContextUnverified)) != 0)
            {
                IncompleteIdentity();
                return false;
            }
            return relation.PermissionState is ControlEvaluationState.Established or ControlEvaluationState.Unknown;
        }
    }

    private static bool Equivalent(Tier0Classification left, Tier0Classification right) => left.Target == right.Target
        && left.Coverage == right.Coverage && left.Supports.Length == right.Supports.Length
        && left.Supports.Zip(right.Supports).All(pair => pair.First.Basis == pair.Second.Basis && pair.First.Root == pair.Second.Root
            && pair.First.Evidence.SequenceEqual(pair.Second.Evidence));

    private static Tier0Coverage Merge(Tier0Coverage left, Tier0Coverage right)
    {
        ValidateCoverage(right);
        return new(left.InputsComplete && right.InputsComplete, left.AnalysisComplete && right.AnalysisComplete,
            left.ProcessingComplete && right.ProcessingComplete, left.Limitations | right.Limitations
                | (right.InputsComplete ? Tier0Limitations.None : Tier0Limitations.InputIncomplete)
                | (right.ProcessingComplete ? Tier0Limitations.None : Tier0Limitations.ProcessingIncomplete));
    }

    private static void ValidateCoverage(Tier0Coverage coverage)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        var known = Enum.GetValues<Tier0Limitations>().Aggregate(Tier0Limitations.None, (all, value) => all | value);
        if ((coverage.Limitations & ~known) != 0 || !coverage.IsComplete && coverage.Limitations == Tier0Limitations.None)
            throw new ArgumentException(null, nameof(coverage));
    }

    private static int CompareTargets(Tier0Target left, Tier0Target right)
    {
        var order = string.CompareOrdinal(left.DistinguishedName, right.DistinguishedName);
        if (order != 0) return order;
        order = string.CompareOrdinal(left.NamingContext, right.NamingContext);
        if (order != 0) return order;
        order = Nullable.Compare(left.ObjectGuid, right.ObjectGuid);
        if (order != 0) return order;
        order = string.CompareOrdinal(left.DomainFqdn, right.DomainFqdn);
        if (order != 0) return order;
        order = string.CompareOrdinal(left.Sid, right.Sid);
        return order != 0 ? order : string.CompareOrdinal(left.SidScope, right.SidScope);
    }

    private static int CompareRelations(Tier0RelevanceRelation left, Tier0RelevanceRelation right)
    {
        var order = CompareTargets(left.Controller, right.Controller);
        if (order != 0) return order;
        order = CompareTargets(left.Affected, right.Affected);
        if (order != 0) return order;
        order = left.Kind.CompareTo(right.Kind);
        if (order != 0) return order;
        order = Nullable.Compare(left.JudgementGenerationId, right.JudgementGenerationId);
        if (order != 0) return order;
        order = Nullable.Compare(left.ControlEdgeId, right.ControlEdgeId);
        if (order != 0) return order;

        // CAPABILITY AND WITNESS ARE COMPARED BECAUSE CAPTURE-BACKED CANDIDATES HAVE NO EDGE ID.
        // This comparer is the identity used by the deduplicating set the traversal reads from, so
        // two relations that compare equal become one. Edge-backed relations stayed distinct only
        // because every stored edge carries a unique id; a discovered candidate has none, and
        // without the lines below a WRITE_DAC grant and a WRITE_OWNER grant from the same holder on
        // the same object - or two separate entries granting the same right - would collapse into a
        // single retained route. Decision 0116 requires each independent witness survive.
        order = Nullable.Compare(left.Capability, right.Capability);
        if (order != 0) return order;
        order = CompareWitnesses(left.Witness, right.Witness);
        if (order != 0) return order;
        var first = left.Membership?.Evidence ?? [];
        var second = right.Membership?.Evidence ?? [];
        for (var i = 0; i < Math.Min(first.Length, second.Length); i++)
        {
            order = CompareTargets(first[i].Object, second[i].Object);
            if (order != 0) return order;
            order = string.CompareOrdinal(first[i].Attribute, second[i].Attribute);
            if (order != 0) return order;
            order = first[i].Ordinal.CompareTo(second[i].Ordinal);
            if (order != 0) return order;
            order = string.CompareOrdinal(first[i].Value, second[i].Value);
            if (order != 0) return order;
        }
        return first.Length.CompareTo(second.Length);
    }

    private static int CompareWitnesses(Tier0CaptureWitness? left, Tier0CaptureWitness? right)
    {
        if (ReferenceEquals(left, right)) return 0;
        if (left is null) return -1;
        if (right is null) return 1;
        var order = string.CompareOrdinal(left.TargetDn, right.TargetDn);
        if (order != 0) return order;
        order = Nullable.Compare(left.PermissionOrdinal, right.PermissionOrdinal);
        if (order != 0) return order;
        order = string.CompareOrdinal(left.TrusteeSid, right.TrusteeSid);
        return order != 0 ? order : left.IsOwner.CompareTo(right.IsOwner);
    }
}
