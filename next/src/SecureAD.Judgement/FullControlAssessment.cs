using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>One required specific right, with alternative grants preceding its first denial or unresolved entry.</summary>
public sealed record FullControlRight(
    int Mask,
    string? ObjectType,
    ControlEvaluationState State,
    ControlUncertainty Uncertainty,
    IReadOnlyList<int> GrantOrdinals,
    IReadOnlyList<int> BlockingOrdinals)
{
    /// <summary>Whether an empty source list is an evaluated answer rather than missing or unsupported evidence.</summary>
    public bool IsComplete => State != ControlEvaluationState.Unknown && Uncertainty == ControlUncertainty.None;
}

/// <summary>Captured inputs for replaying a named-holder full-control question, never an executed operation.</summary>
public sealed record FullControlSource(
    string Target,
    Guid? TargetGuid,
    string? TargetSid,
    string? TargetDomain,
    IReadOnlyList<string> Classes,
    PermissionTrustee Holder,
    string? HolderScope,
    bool ResourceContextEstablished,
    bool NamingContextRootEstablished,
    DescriptorAvailability Availability,
    DaclState Dacl,
    DaclCompleteness Completeness,
    bool DaclWasCanonical,
    IReadOnlyList<PermissionEntry> Entries)
{
    /// <summary>The captured forest boundary used for authority scope, not a serving-DC behavior baseline.</summary>
    public string? ForestFqdn { get; init; }
    /// <summary>Captured issuing-domain SID answers consumed by expectedness and BUILTIN resource-context checks.</summary>
    public IReadOnlyDictionary<string, string?> AuthorityDomainSids { get; init; } = new Dictionary<string, string?>();
    /// <summary>Separate current authorization routes used for expectedness; never an expansion of held permissions.</summary>
    public MembershipRouteSummary MembershipRoutes { get; init; } = MembershipRouteSummary.NotDerived;
}

/// <summary>A full-control presentation assessment; primitive capabilities remain independently stored.</summary>
public sealed record FullControlAssessment(
    long Id,
    FullControlSource Source,
    Guid GenerationId,
    Guid? DerivationGenerationId,
    int PrincipalCatalogueVersion,
    ControlEvaluationState EvaluationState,
    ControlUncertainty Uncertainty,
    ControlExpectedness Expectedness,
    ControlExpectednessReason ExpectednessReason,
    IReadOnlyList<FullControlRight> Rights,
    IReadOnlyList<ControlCapability> SupportingCapabilities)
{
    /// <summary>Only a fully established aggregate replaces its supporting permissions in headline counts.</summary>
    public bool IsCounted => EvaluationState == ControlEvaluationState.Established;
    /// <summary>Two source-disjoint complete grant sets were proved; false does not assert that alternatives are absent.</summary>
    public bool HasIndependentGrantRoutes { get; init; }
}
