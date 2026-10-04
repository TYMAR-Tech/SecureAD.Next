using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>The source of relevance, not a claim that the related object is confirmed Tier 0.</summary>
/// <remarks>
/// <b><c>DependencyCandidate</c> was removed on 2026-09-11.</b> No relation ever carried it: a
/// dependency needing capability-specific interpretation is recorded as
/// <see cref="SecureAD.Derivation.Tier0Limitations.DependencyQualificationUnsupported"/> on the
/// coverage, which is a statement that the product declined to qualify something rather than a kind
/// of relation it found. Keeping both left a reader to decide which one a dependency was, when only
/// one was ever written. Decision 0119.
/// </remarks>
public enum Tier0RelevanceKind
{
    /// <summary>An independently checked effective membership witness.</summary>
    EffectiveMembership,
    /// <summary>A named permission whose operational classification still requires qualification.</summary>
    ControlCandidate,
}

/// <summary>
/// The captured fact a discovery candidate rests on, for a relation found before any control edge exists.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is what lets discovery run before the detailed pass rather than after it.</b> A relation
/// built by <see cref="Tier0RelevanceRelation.FromControlEdge"/> names its source by the identity of
/// a stored edge, which cannot exist until the evaluation this slice is deciding whether to run has
/// already run. Naming the ACE instead - the object, its position in the stored DACL and the trustee
/// it names - identifies the same fact using only what capture already holds.
/// </para>
/// <para>
/// <b>An owner is not an entry, so <see cref="PermissionOrdinal"/> is null for one.</b> Ownership is
/// recorded on the descriptor rather than in the DACL, and giving it a position would invent an ACE
/// that the capture does not contain.
/// </para>
/// </remarks>
/// <param name="TargetDn">The object whose captured descriptor carries this fact.</param>
/// <param name="PermissionOrdinal">The entry's position in the stored DACL, or null for an owner or a NULL DACL.</param>
/// <param name="TrusteeSid">The SID the entry names, unresolved trustees included.</param>
/// <param name="IsOwner">Whether the fact is the captured owner rather than an access control entry.</param>
public sealed record Tier0CaptureWitness(string TargetDn, int? PermissionOrdinal, string TrusteeSid, bool IsOwner = false)
{
    /// <summary>Captured nesting from an assessed group to the named holder, not requester authorization.</summary>
    public RequesterMembershipEvidence? GroupMembership { get; init; }

    /// <summary>Whether this witness names a captured fact precisely enough to be found again.</summary>
    public bool IsValid => !string.IsNullOrWhiteSpace(TargetDn) && !string.IsNullOrWhiteSpace(TrusteeSid)
        && PermissionOrdinal is null or >= 0 && (!IsOwner || PermissionOrdinal is null)
        && (GroupMembership is null || !IsOwner && PermissionOrdinal is not null && GroupMembership.Links is { Count: > 0 });
}

/// <summary>A directed relation from a controller/dependency to the object it could affect.</summary>
public sealed record Tier0RelevanceRelation
{
    private Tier0RelevanceRelation(Tier0InputBinding input, Tier0Target controller, Tier0Target affected,
        Tier0RelevanceKind kind, Tier0State state, Tier0Limitations limitations, Tier0Support? membership,
        Guid? judgementGeneration, long? edgeId, int? edgeCatalogueVersion, ControlCapability? capability,
        ControlEvaluationState? permissionState, ControlUncertainty uncertainty, Tier0CaptureWitness? witness)
    {
        Input = input;
        Controller = controller;
        Affected = affected;
        Kind = kind;
        State = state;
        Limitations = limitations;
        Membership = membership;
        JudgementGenerationId = judgementGeneration;
        ControlEdgeId = edgeId;
        EdgeCatalogueVersion = edgeCatalogueVersion;
        Capability = capability;
        PermissionState = permissionState;
        PermissionUncertainty = uncertainty;
        Witness = witness;
    }

    /// <summary>The source capture, derivation and classification policy.</summary>
    public Tier0InputBinding Input { get; }
    /// <summary>The object at the start of the relation, never everything a Tier-0 administrator manages.</summary>
    public Tier0Target Controller { get; }
    /// <summary>The object affected by this relation.</summary>
    public Tier0Target Affected { get; }
    /// <summary>The interpretation of this relation's source.</summary>
    public Tier0RelevanceKind Kind { get; }
    /// <summary>Qualification of the relation, not of the controller's Tier-0 classification.</summary>
    public Tier0State State { get; }
    /// <summary>Unresolved qualification remains visible independently of the source permission.</summary>
    public Tier0Limitations Limitations { get; }
    /// <summary>The independently checked membership witness, when this is a membership relation.</summary>
    public Tier0Support? Membership { get; }
    /// <summary>The immutable audit containing a source control edge.</summary>
    public Guid? JudgementGenerationId { get; }
    /// <summary>The retained source edge; no permission rows or ownership alternatives are removed.</summary>
    public long? ControlEdgeId { get; }
    /// <summary>The source edge's original catalogue, not silently replaced by the classification version.</summary>
    public int? EdgeCatalogueVersion { get; }
    /// <summary>The named primitive or compound, without an inferred operation.</summary>
    public ControlCapability? Capability { get; }
    /// <summary>The unchanged source permission conclusion.</summary>
    public ControlEvaluationState? PermissionState { get; }
    /// <summary>The unchanged source permission limitations.</summary>
    public ControlUncertainty PermissionUncertainty { get; }
    /// <summary>The captured fact behind a discovered candidate, or null when a stored edge is the source.</summary>
    public Tier0CaptureWitness? Witness { get; }

    /// <summary>
    /// Whether this relation was qualified in full. It matters beside <see cref="Membership"/>,
    /// because an absent witness on an unresolved relation means the qualification did not finish
    /// rather than that no membership exists.
    /// </summary>
    public bool IsComplete => State != Tier0State.Unknown && Limitations == Tier0Limitations.None;

    /// <summary>Tests the affected end only; it does not walk a graph or infer reverse relevance.</summary>
    public bool IsIncomingTo(Tier0Target target)
    {
        ArgumentNullException.ThrowIfNull(target);
        return Affected == target;
    }

    /// <summary>Creates a relation from a qualified shared membership support without re-expanding members.</summary>
    public static Tier0RelevanceRelation FromMembership(Tier0Classification classification, int supportIndex)
    {
        ArgumentNullException.ThrowIfNull(classification);
        ArgumentOutOfRangeException.ThrowIfNegative(supportIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(supportIndex, classification.Supports.Length);
        var support = classification.Supports[supportIndex];
        if (!classification.Input.IsSupported || !classification.Target.IsValid
            || support.Basis != Tier0Basis.EffectiveMembership) throw new ArgumentException(null, nameof(classification));
        return new(classification.Input, classification.Target, support.Root, Tier0RelevanceKind.EffectiveMembership,
            Tier0State.Established, Tier0Limitations.None, support, null, null, null, null, null, ControlUncertainty.None,
            witness: null);
    }

    /// <summary>References a persisted permission as a candidate; even Established does not qualify operational direct control.</summary>
    public static Tier0RelevanceRelation FromControlEdge(Tier0InputBinding input, Tier0Target controller,
        Tier0Target affected, ControlEdge edge)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(controller);
        ArgumentNullException.ThrowIfNull(affected);
        ArgumentNullException.ThrowIfNull(edge);
        if (!input.IsSupported || !controller.IsValid || !affected.IsValid || edge.Id <= 0
            || edge.GenerationId == Guid.Empty || edge.DerivationGenerationId != input.DerivationGenerationId
            || edge.PrincipalCatalogueVersion is not (2 or 3) || !Enum.IsDefined(edge.Capability) || !Enum.IsDefined(edge.EvaluationState)
            || edge.TargetGuid != affected.ObjectGuid || edge.Target != affected.DistinguishedName
            || edge.HolderSid != controller.Sid || edge.HolderScope != controller.SidScope)
            throw new ArgumentException(null, nameof(edge));
        return new(input, controller, affected, Tier0RelevanceKind.ControlCandidate, Tier0State.Unknown,
            Tier0Limitations.ControlQualificationUnsupported | Tier0Limitations.ConditionalOperation,
            null, edge.GenerationId, edge.Id, edge.PrincipalCatalogueVersion, edge.Capability, edge.EvaluationState, edge.Uncertainty,
            witness: null);
    }

    /// <summary>
    /// References a captured owner or access control entry as a candidate, before any control edge exists.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The named permission is not an established control operation.</b> This carries the same
    /// <see cref="Tier0Limitations.ControlQualificationUnsupported"/> and
    /// <see cref="Tier0Limitations.ConditionalOperation"/> that <see cref="FromControlEdge"/> carries,
    /// and <see cref="State"/> stays <see cref="Tier0State.Unknown"/>. Discovery admits a target for
    /// assessment; it does not decide what the permission grants, and the existing evaluators remain
    /// the only authority on that.
    /// </para>
    /// <para>
    /// <b><paramref name="uncertainty"/> is how an unresolved or broad trustee stays visible.</b> A
    /// candidate whose holder could not be resolved to a captured object is recorded with
    /// <see cref="ControlUncertainty.HolderUnresolved"/> rather than dropped, so the incompleteness
    /// reaches coverage instead of being silently absent.
    /// </para>
    /// </remarks>
    /// <param name="input">The pinned source capture, derivation and classification policy.</param>
    /// <param name="controller">The principal the captured fact names.</param>
    /// <param name="affected">The object whose descriptor carries the fact.</param>
    /// <param name="capability">The named primitive, without an inferred operation.</param>
    /// <param name="witness">The captured owner or entry this candidate rests on.</param>
    /// <param name="uncertainty">Retained limitations of the captured fact, never cleared to imply safety.</param>
    public static Tier0RelevanceRelation FromCapturedPermission(Tier0InputBinding input, Tier0Target controller,
        Tier0Target affected, ControlCapability capability, Tier0CaptureWitness witness,
        ControlUncertainty uncertainty = ControlUncertainty.None)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(controller);
        ArgumentNullException.ThrowIfNull(affected);
        ArgumentNullException.ThrowIfNull(witness);
        if (!input.IsSupported || !controller.IsValid || !affected.IsValid || !Enum.IsDefined(capability)
            || !witness.IsValid || witness.TargetDn != affected.DistinguishedName)
            throw new ArgumentException(null, nameof(witness));
        return new(input, controller, affected, Tier0RelevanceKind.ControlCandidate, Tier0State.Unknown,
            Tier0Limitations.ControlQualificationUnsupported | Tier0Limitations.ConditionalOperation,
            null, null, null, null, capability, ControlEvaluationState.Unknown, uncertainty, witness);
    }
}
