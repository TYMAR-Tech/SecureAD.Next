using System.Collections.ObjectModel;
using System.Diagnostics.Metrics;
using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Availability of saved inputs, never a reachability or safety verdict.</summary>
public enum PathInputAvailability
{
    /// <summary>This judging entry point did not produce path inputs.</summary>
    NotProduced,
    /// <summary>Discovery was requested but its required source generation was unavailable.</summary>
    RequiredInputsUnavailable,
    /// <summary>Inputs were saved; their coverage still describes unsupported or missing evidence.</summary>
    Recorded,
}

/// <summary>A symbolic set that does not require enumerating unknown trustees.</summary>
public enum PathSubjectScope
{
    /// <summary>Unidentified subjects anywhere in the forest, including uncaptured principals.</summary>
    UnknownWithinForest,
    /// <summary>The recorded SID in the source witness, not a resolved authorization identity.</summary>
    RecordedTrustee,
}

/// <summary>The region affected by a missing or unsupported discovery input.</summary>
public enum PathTargetScope
{
    /// <summary>The named captured object only, not everything contained beneath it.</summary>
    Object,
    /// <summary>The forest, including its unread portions; no narrower scope was established.</summary>
    Forest,
}

/// <summary>Why an input is uncertain, independently of how much processing completed.</summary>
public enum PathUncertaintyCause
{
    /// <summary>The required directory evidence was not fully captured.</summary>
    CapturedEvidenceIncomplete,
    /// <summary>The producer cannot interpret this kind of relationship.</summary>
    AnalysisUnsupported,
    /// <summary>A captured identity could not be qualified.</summary>
    IdentityUnresolved,
    /// <summary>A broad principal remains a symbolic witness rather than individual requesters.</summary>
    BroadPrincipalNotExpanded,
}

/// <summary>
/// A saved source limitation and its symbolic scope. Resource identity is recorded, not proof of a
/// serving domain; all capability kinds remain in doubt in this input-only checkpoint.
/// </summary>
public sealed record PathUncertaintyRegion(Tier0DiscoveryLimitation Source, PathUncertaintyCause Cause,
    PathSubjectScope Subjects, PathTargetScope Targets, Tier0Target? RecordedResource)
{
    /// <summary>No capability restriction has been established; later analysis must not invent one.</summary>
    public bool AllCapabilityKinds => true;
}

/// <summary>
/// Source-bound inputs for later path analysis. Fixed targets alone attach to the future synthetic
/// anchor; classifications and admission relationships do not assert distances or completed control.
/// Permission identifiers reference unchanged records in this same Judgement generation, including
/// independent supports and uncounted unknowns. Requester discovery retains its separate saved status.
/// </summary>
public sealed record PathInputs(Guid JudgementGenerationId, PathInputAvailability Availability,
    Tier0InputBinding? Input, Tier0Coverage Coverage, IReadOnlyList<Tier0Target> FixedTargets,
    IReadOnlyList<Tier0Classification> Classifications, IReadOnlyList<Tier0RelevanceRelation> AdmissionRelationships,
    IReadOnlyList<long> PermissionIds, IReadOnlyList<PathUncertaintyRegion> UncertaintyRegions,
    SelfMembershipSummary? RequesterDiscovery)
{
    private FixedTargetValues _fixedTargets = new(FixedTargets);

    /// <summary>Owned ordered targets; metadata-only copies share their exact lookup safely.</summary>
    public IReadOnlyList<Tier0Target> FixedTargets
    {
        get => _fixedTargets;
        init => _fixedTargets = value is FixedTargetValues owned ? owned : new(value);
    }

    internal bool IsFixedTarget(Tier0Target target, CancellationToken token) =>
        _fixedTargets.ContainsTarget(target, JudgementGenerationId, token);

    private sealed class FixedTargetValues(IReadOnlyList<Tier0Target> targets) : ReadOnlyCollection<Tier0Target>(targets.ToArray())
    {
        private static readonly Meter Meter = new("SecureAD.Judgement.PathPackage");
        private static readonly Counter<long> Indexes = Meter.CreateCounter<long>("path.fixed_target_indexes");
        private HashSet<Tier0Target>? _index;

        internal bool ContainsTarget(Tier0Target target, Guid generation, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (_index is null)
            {
                var index = new HashSet<Tier0Target>();
                foreach (var value in this)
                {
                    token.ThrowIfCancellationRequested();
                    index.Add(value);
                }
                _index = index;
                Indexes.Add(1, new KeyValuePair<string, object?>("generation", generation.ToString("D")));
            }
            return _index.Contains(target);
        }
    }
}

/// <summary>
/// The bounded saved-input projection needed to display one selected path.
/// Whole-forest classifications, relations and permission identifiers remain behind
/// <see cref="JudgementReader.ReadPathInputs"/>.
/// </summary>
internal sealed record SavedPathInputs(Guid JudgementGenerationId, PathInputAvailability Availability,
    Tier0InputBinding? Input, Tier0Coverage Coverage, IReadOnlyList<Tier0Target> FixedTargets,
    IReadOnlyList<PathUncertaintyRegion> UncertaintyRegions, SelfMembershipSummary? RequesterDiscovery)
{
    internal static SavedPathInputs From(PathInputs inputs) => new(inputs.JudgementGenerationId,
        inputs.Availability, inputs.Input, inputs.Coverage, inputs.FixedTargets,
        inputs.UncertaintyRegions, inputs.RequesterDiscovery);
}
