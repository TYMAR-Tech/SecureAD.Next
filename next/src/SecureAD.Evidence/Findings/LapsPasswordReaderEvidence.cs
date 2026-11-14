using SecureAD.Kernel.Schema;

namespace SecureAD.Evidence.Findings;

/// <summary>The independently established specific rights, not password retrieval or decryption.</summary>
public enum LapsReadRights
{
    Neither,
    ReadPropertyOnly,
    ControlAccessOnly,
    Both,
}

/// <summary>The captured scope of supporting permissions, not an originating container.</summary>
public enum LapsGrantReach
{
    ThisAttributeOnly,
    EveryAttribute,
    PropertySet,
    ObjectClass,
    Mixed,
    Unresolved,
}

/// <summary>A captured named-holder permission conclusion, never a concrete requester token.</summary>
public enum LapsReadState
{
    NotEstablished,
    Established,
    Unresolved,
}

/// <summary>Whether the captured schema requires Control Access in addition to Read Property.</summary>
public enum LapsConfidentiality
{
    NotConfidential,
    Confidential,
    Unresolved,
}

/// <summary>One captured membership witness, retaining identity independently of its saved name.</summary>
public sealed record PathStep(string Sid, string? Name)
{
    public string Display => Name ?? Sid;
}

/// <summary>One right's ordered grants, blockers and explicit interpretation limits.</summary>
public sealed record LapsReadRightProof(int Mask, LapsReadState State,
    IReadOnlyList<int> GrantOrdinals, IReadOnlyList<int> BlockingOrdinals,
    IReadOnlyList<string> Limitations);

/// <summary>An unchanged permission occurrence and the captured schema scope used to qualify it.</summary>
public sealed record LapsReadEntryEvidence(PermissionEntry Entry, LapsReadState Scope,
    string ScopeReason, IReadOnlyList<SchemaGuidEntry> Definitions,
    IReadOnlyList<string>? PropertySetMembers);

/// <summary>One independent named-holder/attribute exposure supporting a broad-identity finding.</summary>
public sealed record LapsReadExposure(
    string Target,
    Guid TargetGuid,
    string? ResourceDomain,
    string TrusteeSid,
    string? TrusteeName,
    string? TrusteeScope,
    string Attribute,
    string AttributeGuid,
    string? TargetClass,
    string? TargetClassGuid,
    int? SearchFlags,
    int? SystemFlags,
    LapsConfidentiality Confidentiality,
    LapsReadState State,
    LapsReadRights Rights,
    LapsGrantReach Reach,
    bool IsInherited,
    IReadOnlyList<string> InheritedClassGuids,
    IReadOnlyList<PathStep> MembershipPath,
    bool MembershipIsComplete,
    LapsReadRightProof ReadProperty,
    LapsReadRightProof ControlAccess,
    IReadOnlyList<int> EntryOrdinals,
    IReadOnlyList<LapsReadEntryEvidence>? Entries);

/// <summary>Prepared whole-finding counts and independent source limitations, not loaded-page totals.</summary>
public sealed record LapsReadSummary(int ExposureCount, int EstablishedExposureCount,
    bool DescriptorIsComplete, bool SchemaIsComplete, bool MembershipIsComplete,
    bool ReadChecksAreComplete, IReadOnlyList<string> Limitations)
{
    public bool IsComplete => DescriptorIsComplete && SchemaIsComplete && MembershipIsComplete
        && ReadChecksAreComplete;
    public int UnresolvedExposureCount => ExposureCount - EstablishedExposureCount;
}

/// <summary>
/// A broad-identity finding's selected witness and saved whole-finding assessment.
/// SupportingExposures is null when those separate, explicitly paged values were not requested.
/// </summary>
public sealed record LapsPasswordReaderEvidence(
    string TrusteeSid,
    string? TrusteeName,
    string BroadPrincipalSid,
    string? BroadPrincipalName,
    IReadOnlyList<PathStep> MembershipPath,
    string Attribute,
    LapsReadRights Rights,
    LapsGrantReach Reach,
    string? InheritedClassGuid,
    bool ExpansionWasComplete) : FindingEvidence
{
    public required bool IsInherited { get; init; }
    public required LapsReadSummary Assessment { get; init; }
    public required IReadOnlyList<LapsReadExposure>? SupportingExposures { get; init; }
    public bool IsComplete => Assessment.IsComplete;
    public bool SupportsWereLoaded => SupportingExposures is not null;
    public bool HasEstablishedReadPermission => Assessment.EstablishedExposureCount > 0;
    public string Route => string.Join(" -> ", MembershipPath.Select(step => step.Display));
    public int NestingDepth => Math.Max(0, MembershipPath.Count - 1);
}
