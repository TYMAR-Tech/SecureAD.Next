using System.Collections.Immutable;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Traversal counters, not permission, effective-member or completed-path counts.</summary>
public sealed record OwnershipScopeProgress(int VisitedTargets, int ExaminedRelations, int IncludedTargets);

/// <summary>An immutable offline selection; neither persistence nor automatic audit activation is performed here.</summary>
public sealed record OwnershipScopeSelection
{
    private readonly ImmutableDictionary<Tier0Target, OwnershipScopeDecision> byTarget;

    internal OwnershipScopeSelection(Tier0InputBinding input, Guid judgementGenerationId,
        ImmutableArray<Tier0Classification> classifications, ImmutableArray<Tier0RelevanceRelation> relations,
        ImmutableArray<OwnershipScopeDecision> decisions, Tier0Coverage coverage, bool wasCancelled,
        int visitedTargets, int examinedRelations)
    {
        Input = input;
        SelectorVersion = OwnershipScopeSelector.Version;
        JudgementGenerationId = judgementGenerationId;
        Classifications = classifications;
        Relations = relations;
        Decisions = decisions;
        Coverage = coverage;
        WasCancelled = wasCancelled;
        VisitedTargets = visitedTargets;
        ExaminedRelations = examinedRelations;
        byTarget = decisions.ToImmutableDictionary(item => item.Target);
    }

    /// <summary>The source capture, derivation and shared classification semantics.</summary>
    public Tier0InputBinding Input { get; }
    /// <summary>The selector semantics that produced this snapshot, distinct from the input classifier version.</summary>
    public int SelectorVersion { get; }
    /// <summary>The one audit generation allowed for supplied control relations.</summary>
    public Guid JudgementGenerationId { get; }
    /// <summary>Original classification witnesses, not relabelled by relevance traversal.</summary>
    public ImmutableArray<Tier0Classification> Classifications { get; }
    /// <summary>Consumed source relations, including alternatives not used to select a target.</summary>
    public ImmutableArray<Tier0RelevanceRelation> Relations { get; }
    /// <summary>Deterministically ordered decisions for the identities consumed by this call.</summary>
    public ImmutableArray<OwnershipScopeDecision> Decisions { get; }
    /// <summary>Input and analysis limitations survive a completed traversal.</summary>
    public Tier0Coverage Coverage { get; }
    /// <summary>Whether the caller cancelled this traversal; discovered inclusions are retained.</summary>
    public bool WasCancelled { get; }
    /// <summary>The number of selected targets whose incoming relations were completely examined.</summary>
    public int VisitedTargets { get; }
    /// <summary>The number of distinct incoming source relations examined, not a holder-edge count.</summary>
    public int ExaminedRelations { get; }

    /// <summary>Reads a stored decision; an unlisted identity remains unresolved and never starts traversal.</summary>
    public OwnershipScopeDecision For(Tier0Target target)
    {
        ArgumentNullException.ThrowIfNull(target);
        if (!target.IsValid) throw new ArgumentException(null, nameof(target));
        return byTarget.TryGetValue(target, out var decision) ? decision
            : new(Input, target, OwnershipScopeState.Undetermined,
                Coverage with { InputsComplete = false, Limitations = Coverage.Limitations | Tier0Limitations.InputIncomplete }, null, []);
    }
}
