using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>Capabilities evaluated by the bounded control slices; not a complete stage-6 catalogue.</summary>
public enum ControlCapability
{
    /// <summary>The named trustee holds WRITE_DAC.</summary>
    CanWriteDacl,
    /// <summary>The named trustee holds WRITE_OWNER, independently of any subsequent takeover.</summary>
    CanSetOwner,
    /// <summary>The compound owner-to-DACL transition, still gated by its recorded preconditions.</summary>
    CanBecomeOwnerAndRewriteDacl,
    /// <summary>WRITE_PROPERTY reaches member on a group, without the own-account restriction.</summary>
    CanModifyGroupMembership,
    /// <summary>A Self-Membership candidate, limited to the requester's own account; requester evaluation is separate.</summary>
    CanAddSelfToGroup,
}
/// <summary>Semantic categories accepted under 0110, never an ordered risk score.</summary>
public enum ControlEdgeClass
{
    /// <summary>Authority over the object's security descriptor.</summary>
    DirectoryControl,
    /// <summary>Credential-related capabilities.</summary>
    CredentialExposure,
    /// <summary>Conditional escalation, retained from the capability contract.</summary>
    ConditionalEscalation,
    /// <summary>Group-membership changes, with each capability's own constraints.</summary>
    MembershipEscalation,
    /// <summary>Replication capabilities against their recorded naming context.</summary>
    ReplicationControl,
}
/// <summary>What the evidence establishes about this particular capability.</summary>
public enum ControlEvaluationState
{
    /// <summary>Supported by the available evidence.</summary>
    Established,
    /// <summary>The evaluated conditions do not establish it.</summary>
    NotEstablished,
    /// <summary>A required evaluation or input remains unresolved.</summary>
    Unknown,
}
/// <summary>Whether the holder's control is routine under the accepted scoped catalogue.</summary>
public enum ControlExpectedness
{
    /// <summary>Within independently established authority and capability scope.</summary>
    Expected,
    /// <summary>Outside the accepted expectation.</summary>
    Unexpected,
    /// <summary>Expectedness could not be established either way.</summary>
    Unknown,
}
/// <summary>The stored reason for expectedness, separate from authorization and ownership.</summary>
public enum ControlExpectednessReason
{
    /// <summary>Within the holder's domain authority.</summary>
    ExpectedSameDomainControlPlane,
    /// <summary>Within the forest-root principal's forest authority.</summary>
    ExpectedForestControlPlane,
    /// <summary>Schema administration inside the captured forest's schema.</summary>
    ExpectedSchemaControlPlane,
    /// <summary>An applicable effective ACE names SYSTEM directly.</summary>
    ExpectedPlatformIdentityDirectAce,
    /// <summary>A broad principal is never expected.</summary>
    UnexpectedBroadPrincipal,
    /// <summary>The target is outside the established authority.</summary>
    UnexpectedOutsideAuthorityScope,
    /// <summary>No accepted control-plane basis was found in complete input.</summary>
    UnexpectedNotControlPlane,
    /// <summary>Incomplete membership evidence prevents a negative classification.</summary>
    UnknownMembershipIncomplete,
    /// <summary>The issuing domain or authority boundary is unverified.</summary>
    UnknownAuthorityScope,
    /// <summary>The SID names a placeholder rather than an acting principal.</summary>
    UnknownHolderIsPlaceholder,
    /// <summary>SYSTEM expectedness lacks a complete effective descriptor.</summary>
    UnknownDescriptorIncomplete,
    /// <summary>A restricted entry's required-operation scope is not yet evaluated.</summary>
    UnknownCapabilityScope,
}

/// <summary>Named limits on a capability evaluation; flags do not weaken other independent primitives.</summary>
[Flags]
public enum ControlUncertainty
{
    /// <summary>No unresolved capability input was identified.</summary>
    None = 0,
    /// <summary>The descriptor was not available.</summary>
    DescriptorUnreadable = 1,
    /// <summary>Not every declared ACE was parsed.</summary>
    DescriptorIncomplete = 2,
    /// <summary>A possibly applicable deny names another trustee.</summary>
    CrossTrusteeDeny = 4,
    /// <summary>A callback or unsupported ACE needs further evaluation.</summary>
    ConditionalOrUnsupportedAce = 8,
    /// <summary>The acting identity is unresolved.</summary>
    HolderUnresolved = 16,
    /// <summary>The holder is a placeholder.</summary>
    HolderIsPlaceholder = 32,
    /// <summary>The resource authorization context is not established.</summary>
    ResourceContextUnverified = 64,
    /// <summary>The controlled-owner SID transition needs the 0103 laboratory gate.</summary>
    OwnerTransitionLabRequired = 128,
    /// <summary>The resulting owner's concrete modification has not been evaluated.</summary>
    OwnerRightsOperationNotEvaluated = 256,
    /// <summary>Object-specific scope for the standard-right candidate remains unevaluated.</summary>
    ObjectSpecificScopeNotEvaluated = 512,
    /// <summary>The captured schema does not establish whether an entry reaches member.</summary>
    MembershipScopeNotEvaluated = 1024,
    /// <summary>No concrete requester operation or group-held Self-Membership expansion was evaluated.</summary>
    SelfMembershipRequesterNotEvaluated = 2048,
    /// <summary>The target's captured class does not establish whether it is a group.</summary>
    TargetClassNotRead = 4096,
}

/// <summary>A named condition, with its own evaluation; uncertainty never flows back into its primitive.</summary>
public sealed record ControlPrecondition(string Name, ControlEvaluationState State, string EvidenceSource);

/// <summary>A persisted capability attributed to the named trustee, never multiplied by its members.</summary>
public sealed record ControlEdge(
    long Id,
    Guid? TargetGuid,
    string Target,
    string? TargetClass,
    string HolderSid,
    string? HolderName,
    string? HolderScope,
    ControlCapability Capability,
    ControlEvaluationState EvaluationState,
    ControlUncertainty Uncertainty,
    ControlExpectedness Expectedness,
    ControlExpectednessReason ExpectednessReason,
    int PrincipalCatalogueVersion,
    Guid GenerationId,
    Guid? DerivationGenerationId,
    bool IsCounted,
    IReadOnlyList<PermissionEntry> Evidence,
    IReadOnlyList<ControlPrecondition> Preconditions,
    MembershipRouteSummary MembershipRoutes)
{
    /// <summary>The descriptor-level source, including a NULL DACL that has no granting ACE.</summary>
    public string DescriptorOutcome { get; init; } = "NotRecorded";
    /// <summary>The capability's semantic category, not a severity or target privilege classification.</summary>
    public ControlEdgeClass EdgeClass => Capability is ControlCapability.CanModifyGroupMembership or ControlCapability.CanAddSelfToGroup
        ? ControlEdgeClass.MembershipEscalation : ControlEdgeClass.DirectoryControl;
    /// <summary>Whether the capability evaluation has no unresolved input; expectedness is separate.</summary>
    public bool IsComplete => EvaluationState != ControlEvaluationState.Unknown && Uncertainty == ControlUncertainty.None;
    /// <summary>Whether an additional transition is required.</summary>
    public string Feasibility => Capability is ControlCapability.CanBecomeOwnerAndRewriteDacl or ControlCapability.CanAddSelfToGroup ? "Conditional" : "Direct";
    /// <summary>Unverified owner transitions and self-membership requester operations remain blocked.</summary>
    public string ResearchStatus => Capability is ControlCapability.CanBecomeOwnerAndRewriteDacl or ControlCapability.CanAddSelfToGroup ? "ResearchBlocked" : "Verified";
    /// <summary>Evidence quality, never a substitute for establishing a capability.</summary>
    public string Confidence => IsComplete ? "High" : "Low";
}

/// <summary>Per-object coverage persists even when no edge can be identified.</summary>
public sealed record ControlObjectEvaluation(
    string Target,
    string? PrincipalSid,
    string? PrincipalScope,
    string DescriptorOutcome,
    ControlUncertainty Uncertainty,
    IReadOnlyList<ControlEdge> Edges)
{
    /// <summary>Whether supported primitives were evaluated without gaps; excludes the separately gated compound.</summary>
    public bool IsComplete => Uncertainty == ControlUncertainty.None && Edges.All(edge => edge.IsComplete || !edge.IsCounted);
}

/// <summary>One bounded page with stored coverage and counts, including expected edges hidden by default.</summary>
public sealed record ControlEdgePage(
    IReadOnlyList<ControlEdge> Edges,
    long UnexpectedCount,
    long UnknownCount,
    long ExpectedCount,
    long UnansweredObjects,
    bool ProductWasDerived,
    bool CaptureIsComplete,
    bool HasMore,
    long LastId)
{
    /// <summary>The selected immutable generation, used to refuse mixed-generation paging.</summary>
    public Guid? GenerationId { get; init; }
    /// <summary>Completeness of the supported primitive slice, not of all stage-6 capabilities.</summary>
    public bool IsComplete => ProductWasDerived && CaptureIsComplete && UnansweredObjects == 0;
    /// <summary>The boundary stated wherever this partial capability catalogue is shown.</summary>
    public const string SupportedScope = "Bounded control-edge slices: WRITE_DAC, WRITE_OWNER and group-membership rights. "
        + "General membership writes and own-account-only Self-Membership are separate; self-membership requester operations remain unknown. "
        + "Ownership-derived control, credentials, replication, full-control aggregation "
        + "and effective member expansion are not yet derived. Counts are not totals for all control capabilities.";
}
