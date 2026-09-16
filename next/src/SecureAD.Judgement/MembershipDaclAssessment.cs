using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>An explicit offline membership outcome followed by WRITE_DAC on one fixed target.</summary>
public sealed record MembershipDaclRequest(string RequesterDn, string GroupDn, string TargetDn)
{
    /// <summary>The separate pre-change permission used to obtain the requester's own membership.</summary>
    public OwnAccountMembershipPermissionKind PermissionKind { get; init; }
}

/// <summary>Why the combined route could not be established; not a negative reachability verdict.</summary>
public enum MembershipDaclIssue
{
    /// <summary>The pre-change own-account membership proof did not establish an outcome.</summary>
    MembershipNotEstablished,
    /// <summary>The target access check did not establish the obtained group's supported grant.</summary>
    DaclPermissionNotEstablished,
}

/// <summary>
/// A saved combined proof, separate from captured requester authorization and ordinary Add readiness.
/// The requester remains the user; the membership assumption does not transfer account identity.
/// </summary>
public sealed record MembershipDaclAssessment(MembershipDaclRequest Request,
    OwnAccountMembershipAssessment Membership, RequesterDaclAssessment? Dacl,
    ControlEvaluationState Authorization, IReadOnlyList<MembershipDaclIssue> Issues,
    IReadOnlyList<Tier0PathStep> Steps)
{
    /// <summary>The static authorization model, not an observed authentication context or live operation.</summary>
    public const string Context = "Ordinary authenticated directory user with the obtained same-domain global security membership enabled for authorization on the fixed target. Existing sessions/tickets, authentication, replication convergence and live operation success are not established; no account identity is transferred.";

    /// <summary>The assumption saved with this proof and checked on replay, not a live-session observation.</summary>
    public required string AuthorizationContext { get; init; }

    /// <summary>The exact Judgement generation containing both permission proofs.</summary>
    public Guid GenerationId => Membership.GenerationId;

    /// <summary>The exact source Derivation generation, never a replacement inferred at read time.</summary>
    public Guid? DerivationGenerationId => Membership.DerivationGenerationId;

    /// <summary>The immutable source Evidence identity.</summary>
    public string EvidenceSeal => Membership.EvidenceSeal;
}
