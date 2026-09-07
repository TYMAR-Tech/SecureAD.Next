using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

/// <summary>The own-account membership change being assessed, not general member modification.</summary>
public enum SelfMembershipOperation { Add, Remove }

/// <summary>An explicit question; a null member name asks about the requester's own account.</summary>
public sealed record SelfMembershipRequest(string RequesterDn, string TargetDn, SelfMembershipOperation Operation,
    string? MemberDn);

/// <summary>Explicit deterministic limits, not a claim about safe forest-wide expansion size.</summary>
public sealed record SelfMembershipBudget(int Requests, int PermissionEntries)
{
    /// <summary>A starting budget for selected requests; no forest-wide expansion is performed.</summary>
    public static SelfMembershipBudget Default { get; } = new(100, 10000);
}

/// <summary>Missing evidence and known blockers, independent of the permission answer.</summary>
public enum SelfMembershipIssue
{
    RequesterMissing, RequesterNotUser, TargetMissing, TargetNotGroup, MemberMissing,
    DescriptorUnreadable, DescriptorIncomplete, PermissionBudgetExceeded, ScopeUnknown,
    TrusteeUnknown, UnsupportedAce, AccountStatusMissing, AccountDisabled, AlreadyMember,
    MembershipStateUnknown, LiveOperationNotEvaluated,
}

/// <summary>An original permission entry beside its bounded scope and trustee applicability.</summary>
public sealed record SelfMembershipAceEvidence(PermissionEntry Entry, ControlEvaluationState Scope,
    RequesterTrusteeEvidence Trustee);

/// <summary>A generation-bound requester answer, never an additional counted holder edge.</summary>
public sealed record SelfMembershipAssessment(
    SelfMembershipRequest Request,
    Guid GenerationId,
    Guid? DerivationGenerationId,
    string EvidenceSeal,
    Guid? RequesterGuid,
    string? RequesterSid,
    Guid? TargetGuid,
    string? TargetSid,
    Guid? MemberGuid,
    string? MemberSid,
    ControlEvaluationState Authorization,
    ControlEvaluationState OwnAccount,
    ControlEvaluationState Readiness,
    string DescriptorOutcome,
    DateTimeOffset? RequesterCapturedUtc,
    long? UserAccountControl,
    bool? MemberPresent,
    IReadOnlyList<SelfMembershipIssue> Issues,
    IReadOnlyList<SelfMembershipAceEvidence> Evidence,
    IReadOnlyList<long> HolderEdgeIds)
{
    /// <summary>The authorization assumptions, not a statement about an observed live token.</summary>
    public const string Context = "Ordinary authenticated directory user; direct identity or one explicit same-domain global-security-group membership. Not a live token or LDAP-success prediction.";
    /// <summary>The principal permission answer that vouches the supporting collections.</summary>
    public string Verdict => Authorization.ToString();
}

/// <summary>Stored explicit assessments; an empty complete list means no requests were scheduled.</summary>
public sealed record SelfMembershipAssessmentSet(
    IReadOnlyList<SelfMembershipAssessment> Assessments,
    bool ProductWasDerived,
    Guid? GenerationId)
{
    /// <summary>Capture-wide discovery coverage, including limitations that cannot be assigned to this selection.</summary>
    public SelfMembershipSummary? Summary { get; init; }

    /// <summary>Whether the collection is a completed stored product or no product was derived.</summary>
    public string Verdict => ProductWasDerived ? "Complete" : "NotDerived";
}
