using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>Reachability to the saved fixed targets, independently of operational Tier-0 classification.</summary>
public enum Tier0Reachability
{
    /// <summary>At least one route is established by the supported evidence.</summary>
    Reachable,
    /// <summary>Both definite and relevant possible routes have been excluded; incomplete analysis cannot emit this.</summary>
    NotReachable,
    /// <summary>No definite route was found and relevant possibilities remain unresolved.</summary>
    Unknown,
}

/// <summary>Supported path steps; DACL steps terminate at a fixed target and no step transfers account identity.</summary>
public enum Tier0PathStepKind
{
    /// <summary>A qualified existing security-group membership, including supported primary-group links.</summary>
    Membership,
    /// <summary>The named holder can write the fixed target's DACL, not act as the target account.</summary>
    WriteDacl,
    /// <summary>The captured owner has an established bounded DACL-rewrite operation on the fixed target.</summary>
    CurrentOwnerDacl,
    /// <summary>Membership is obtainable by the own-account two-case operation proof, not observed as added.</summary>
    OwnAccountMembership,
}

/// <summary>
/// One source-backed step. Membership names the qualifying saved classification and its support;
/// permission steps name the unchanged control edge in the same Judgement generation.
/// </summary>
public sealed record Tier0PathStep(Tier0Target From, Tier0Target To, Tier0PathStepKind Kind,
    string? MembershipSubject, int? MembershipSupport, Tier0Evidence? MembershipWitness, long? PermissionId)
{
    /// <summary>The saved concrete access check supporting this step, not a transferable group-held grant.</summary>
    public RequesterDaclRequest? RequesterRequest { get; init; }

    /// <summary>The separate saved own-account proof, without asserting current membership or Add success.</summary>
    public OwnAccountMembershipRequest? OwnAccountRequest { get; init; }

    /// <summary>The combined requester check using an explicit obtained-membership context.</summary>
    public MembershipDaclRequest? MembershipDaclRequest { get; init; }
}

/// <summary>
/// Passive reading of a saved calculation. Inputs retain availability, coverage, scoped uncertainty
/// and unpromoted permission references. Missing or unsupported analysis is not a negative answer.
/// This is a shortest proven route, not a route count, remediation proof or authentication claim.
/// </summary>
public sealed record Tier0PathResult(PathInputs Inputs, Tier0Target? Subject, Tier0Reachability Reachability,
    int? ShortestProvenDistance, IReadOnlyList<Tier0PathStep> Steps)
{
    /// <summary>Saved explicit questions for this requester; an empty set never means discovery ran.</summary>
    public IReadOnlyList<RequesterDaclAssessment> RequesterAssessments { get; init; } = [];

    /// <summary>Saved own-account operation questions, separate from ordinary Add readiness and holder counts.</summary>
    public IReadOnlyList<OwnAccountMembershipAssessment> OwnAccountAssessments { get; init; } = [];

    /// <summary>Saved combined questions, not automatic requester coverage or captured-only authorization.</summary>
    public IReadOnlyList<MembershipDaclAssessment> MembershipDaclAssessments { get; init; } = [];

    /// <summary>Saved offline selection and its limitations; null means selection was not requested.</summary>
    public PathRequesterSelection? RequesterSelection { get; init; }

    /// <summary>Overall coverage, not merely whether a positive route was proved.</summary>
    public Tier0Coverage Coverage => Inputs.Coverage;

    /// <summary>Only a fixed target's zero distance excludes every potentially shorter unsupported alternative.</summary>
    public bool IsMinimumEstablished => ShortestProvenDistance == 0;
}
