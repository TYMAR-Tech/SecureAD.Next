using SecureAD.Derivation;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>A conclusion about one saved requester question, never whole-forest safety or a finding.</summary>
public enum PathRiskVerdict
{
    UnexpectedRoute,
    ExpectedRoute,
    NotEstablished,
    Unknown,
}

/// <summary>Why a question has not established an unexpected route.</summary>
public enum PathRiskIssue
{
    InputsUnavailable,
    AuthorizationNotEstablished,
    AuthorizationUnknown,
    ContinuationUnavailable,
    RequesterUnresolved,
    AuthorityUnknown,
}

/// <summary>Whether the producer had requested questions and the inputs needed to qualify them.</summary>
public enum PathRiskAvailability
{
    NotRequested,
    InputsUnavailable,
    Recorded,
}

/// <summary>
/// References only captured, pre-change authority in the bound derivation. Acquired memberships
/// remain in the original operation proof and cannot supply this evidence.
/// </summary>
public sealed record PathRiskAuthorityEvidence(Tier0Target Principal, Guid DerivationGenerationId,
    string DerivationSeal, int MembershipCatalogueVersion, bool MembershipSourceAvailable,
    string MembershipFingerprint, MembershipRouteIncompleteReason MembershipLimitations,
    IReadOnlyList<MembershipRoutePrincipal> CapturedAuthorityRoots);

/// <summary>
/// A saved risk qualification referencing its unchanged requester proof and exact input generations.
/// TargetDn is the original question's target; ReachedTarget is the endpoint of its saved route.
/// </summary>
public sealed record PathRequesterRiskAssessment(
    Guid GenerationId, Guid? DerivationGenerationId, string EvidenceSeal,
    string CalculationFingerprint, string SourceProofFingerprint,
    PathRequesterFamily Family, string RequesterDn, string TargetDn, string? GroupDn,
    OwnAccountMembershipPermissionKind? PermissionKind, Tier0Target? ReachedTarget,
    ControlEvaluationState Authorization, PathRiskVerdict Verdict, PathRiskIssue? Issue,
    ControlExpectedness? Expectedness, ControlExpectednessReason? ExpectednessReason,
    PathRiskAuthorityEvidence? CurrentAuthority, ControlEvaluationState? OrdinaryAddReadiness,
    bool? CapturedMemberPresent);

/// <summary>Question counts, not distinct accounts, permission holders, routes or security findings.</summary>
public sealed record PathRiskFamilyCoverage(PathRequesterFamily Family, int Questions,
    int UnexpectedRoutes, int ExpectedRoutes, int NotEstablished, int Unknown);

/// <summary>Scope and counts of this saved qualification; a completed batch does not cover all possible paths.</summary>
public sealed record PathRiskCoverage(int Version, Guid GenerationId, Guid? DerivationGenerationId,
    string EvidenceSeal, string? DerivationSeal, string CalculationFingerprint, int ControlPolicyVersion,
    PathRiskAvailability Availability, bool AutomaticSelectionRequested, Tier0Coverage PathCoverage,
    IReadOnlyList<PathRiskFamilyCoverage> Families);

internal enum PathRiskReadVerdict
{
    NotRequested,
    InputsUnavailable,
    NoRecordedQuestions,
    RecordedQuestions,
}

/// <summary>Only the selected requester's saved answers, with the separately named whole-batch coverage.</summary>
internal sealed record PathRequesterRiskSet(PathRiskCoverage BatchCoverage,
    IReadOnlyList<PathRequesterRiskAssessment> Assessments)
{
    public PathRiskReadVerdict Verdict => BatchCoverage.Availability switch
    {
        PathRiskAvailability.NotRequested => PathRiskReadVerdict.NotRequested,
        PathRiskAvailability.InputsUnavailable => PathRiskReadVerdict.InputsUnavailable,
        PathRiskAvailability.Recorded => Assessments.Count == 0
            ? PathRiskReadVerdict.NoRecordedQuestions : PathRiskReadVerdict.RecordedQuestions,
        _ => throw Tier0PathStorage.InvalidProof(),
    };
}
