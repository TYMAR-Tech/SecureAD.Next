using System.Collections.Immutable;
using SecureAD.Derivation;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Whether the audit's computed automatic scope includes this target.</summary>
public enum OwnershipScopeState
{
    /// <summary>Scope evidence or processing is incomplete.</summary>
    Undetermined,
    /// <summary>A classified object or identified controller/dependency is included.</summary>
    Included,
    /// <summary>The completed supported selection did not include this target; not a safety verdict.</summary>
    OutsideComputedScope,
}

/// <summary>Why detailed assessment was requested, independent of automatic scope.</summary>
public enum OwnershipAssessmentOrigin
{
    /// <summary>Selected during an audit.</summary>
    AutomaticAudit,
    /// <summary>Explicit offline assessment of one object.</summary>
    ExplicitObjectRequest,
}

/// <summary>Execution state, separate from each candidate's conclusion and read availability.</summary>
public enum OwnershipAssessmentExecution
{
    /// <summary>No detailed assessment ran.</summary>
    NotAssessed,
    /// <summary>The requested work finished without unresolved candidate conclusions.</summary>
    Completed,
    /// <summary>The work finished but one or more inputs or conclusions remain limited.</summary>
    CompletedWithLimitations,
    /// <summary>The attempt was cancelled; it must not replace a published result.</summary>
    Cancelled,
    /// <summary>The attempt failed; it must not replace a published result.</summary>
    Failed,
}

/// <summary>Contract availability; a future store reader must also verify seals and replay source proof.</summary>
public enum OwnershipAssessmentAvailability
{
    /// <summary>The structural contract matches the requested input identities and versions.</summary>
    Available,
    /// <summary>No stored assessment was found; never an implicit negative.</summary>
    Missing,
    /// <summary>The stored result names different input, target or evaluation context.</summary>
    Stale,
    /// <summary>The stored semantics require another reader.</summary>
    UnsupportedVersion,
    /// <summary>The result contract is inconsistent or malformed.</summary>
    InvalidProof,
}

/// <summary>Selection evidence shared by the selector and result contracts, without an implied negative on missing scope.</summary>
public sealed record OwnershipScopeDecision(Tier0InputBinding Input, Tier0Target Target, OwnershipScopeState State,
    Tier0Coverage Coverage, Tier0Classification? Classification, ImmutableArray<Tier0RelevanceRelation> Reasons)
{
    /// <summary>Validates internal references; qualification of the route to its anchor belongs to the selector.</summary>
    public bool IsValid => Input is not null && Input.IsSupported && Target is not null && Target.IsValid
        && Coverage is not null && Enum.IsDefined(State) && !Reasons.IsDefault
        && (Classification is null || Classification.Input == Input && Classification.Target == Target)
        && Reasons.All(reason => reason is not null && reason.Input == Input && reason.Controller == Target)
        && (State switch
        {
            OwnershipScopeState.Included => Classification?.State == Tier0State.Established || Reasons.Length != 0,
            OwnershipScopeState.OutsideComputedScope => Coverage.IsComplete && Reasons.Length == 0
                && Classification?.State != Tier0State.Established,
            OwnershipScopeState.Undetermined => !Coverage.IsComplete && Reasons.Length == 0
                && Classification?.State != Tier0State.Established,
            _ => false,
        });
}

/// <summary>Exact inputs for one ownership evaluation, including context not encoded by a target SID.</summary>
public sealed record OwnershipAssessmentBinding(Tier0InputBinding Input, Tier0Target Target,
    Guid JudgementGenerationId, string? JudgementSeal, DateTimeOffset EvaluationAsOf,
    string OwnerRightsContextHash, int EvaluatorVersion = 1, int ContractVersion = 1)
{
    /// <summary>Whether the binding is structurally usable; this does not verify files or hash contents.</summary>
    public bool IsValid => Input is not null && Input.IsValid && Target is not null && Target.IsValid
        && JudgementGenerationId != Guid.Empty && (JudgementSeal is null || IsHash(JudgementSeal))
        && EvaluationAsOf != default && IsHash(OwnerRightsContextHash) && EvaluatorVersion > 0 && ContractVersion > 0;

    /// <summary>Whether these semantics are implemented by the current contract validator.</summary>
    public bool IsSupported => IsValid && Input.IsSupported && EvaluatorVersion == 1 && ContractVersion == 1;

    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
}

/// <summary>A result referencing retained WRITE_OWNER source proof, not another counted holder edge.</summary>
public sealed record OwnershipCandidateAssessment(long SourceEdgeId, string HolderSid, string? HolderScope,
    ControlEvaluationState State, ImmutableArray<ControlPrecondition> Preconditions)
{
    /// <summary>Checks the contract and the still-open owner-assignment gate; full source replay is a future reader responsibility.</summary>
    public bool IsValid => SourceEdgeId > 0 && !string.IsNullOrWhiteSpace(HolderSid) && Sid.ToBytes(HolderSid) is not null
        && (Sid.IsBuiltinDomain(HolderSid) ? !string.IsNullOrWhiteSpace(HolderScope) : HolderScope is null)
        && State == ControlEvaluationState.Unknown && !Preconditions.IsDefault
        && Preconditions.All(check => check is not null && !string.IsNullOrWhiteSpace(check.Name)
            && Enum.IsDefined(check.State) && !string.IsNullOrWhiteSpace(check.EvidenceSource))
        && Preconditions.Select(check => check.Name).Distinct(StringComparer.Ordinal).Count() == Preconditions.Length
        && Preconditions.Count(check => check.Name == "CanSetTakeoverOwnerSid" && check.State == ControlEvaluationState.Unknown) == 1;
}

/// <summary>Versioned ownership result or attempt outcome; no persistence or assessment is performed by this type.</summary>
public sealed record OwnershipAssessmentResult(Guid ResultGenerationId, OwnershipAssessmentBinding Binding,
    OwnershipAssessmentOrigin Origin, OwnershipScopeDecision Scope, OwnershipAssessmentExecution Execution,
    ImmutableArray<OwnershipCandidateAssessment> Candidates)
{
    /// <summary>Checks structure and immutable input equality, without replacing seal verification or permission replay.</summary>
    public OwnershipAssessmentAvailability CheckBinding(OwnershipAssessmentBinding expected)
    {
        ArgumentNullException.ThrowIfNull(expected);
        if (Binding is null || !Binding.IsValid || !expected.IsValid) return OwnershipAssessmentAvailability.InvalidProof;
        if (!Binding.IsSupported || !expected.IsSupported) return OwnershipAssessmentAvailability.UnsupportedVersion;
        if (!IsValid) return OwnershipAssessmentAvailability.InvalidProof;
        return Binding == expected ? OwnershipAssessmentAvailability.Available : OwnershipAssessmentAvailability.Stale;
    }

    /// <summary>A completed contract can be staged later; this property neither publishes nor validates file proof.</summary>
    public bool CanPublish => IsValid && Execution is OwnershipAssessmentExecution.Completed or OwnershipAssessmentExecution.CompletedWithLimitations;

    private bool IsValid => ResultGenerationId != Guid.Empty && Binding is not null && Binding.IsSupported
        && Enum.IsDefined(Origin) && Enum.IsDefined(Execution) && Scope is not null && Scope.IsValid
        && Scope.Input == Binding.Input && Scope.Target == Binding.Target
        && Scope.Reasons.All(reason => reason.JudgementGenerationId is null || reason.JudgementGenerationId == Binding.JudgementGenerationId)
        && (Origin == OwnershipAssessmentOrigin.ExplicitObjectRequest ? Binding.JudgementSeal is not null : Binding.JudgementSeal is null)
        && !Candidates.IsDefault && Candidates.All(candidate => candidate is not null && candidate.IsValid)
        && Candidates.Select(candidate => candidate.SourceEdgeId).Distinct().Count() == Candidates.Length
        && (Origin != OwnershipAssessmentOrigin.AutomaticAudit || Execution is not (OwnershipAssessmentExecution.Completed
            or OwnershipAssessmentExecution.CompletedWithLimitations) || Scope.State == OwnershipScopeState.Included)
        && (Execution switch
        {
            OwnershipAssessmentExecution.NotAssessed => Origin == OwnershipAssessmentOrigin.AutomaticAudit && Candidates.Length == 0,
            OwnershipAssessmentExecution.Completed => Candidates.Length == 0,
            OwnershipAssessmentExecution.CompletedWithLimitations => true,
            OwnershipAssessmentExecution.Cancelled or OwnershipAssessmentExecution.Failed => true,
            _ => false,
        });
}
