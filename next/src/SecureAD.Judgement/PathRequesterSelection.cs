using SecureAD.Derivation;

namespace SecureAD.Judgement;

/// <summary>The existing proof family to which a selected question is sent, not a permission verdict.</summary>
public enum PathRequesterFamily
{
    /// <summary>A concrete requester DACL check on a fixed target.</summary>
    RequesterDacl,
    /// <summary>Own-account obtainability followed by qualified existing memberships.</summary>
    OwnAccountMembership,
    /// <summary>Own-account obtainability followed by a concrete requester DACL check.</summary>
    MembershipDacl,
}

/// <summary>Why the supported selection cannot describe all possible requesters or paths.</summary>
public enum PathRequesterSelectionReason
{
    /// <summary>The required saved path inputs were unavailable.</summary>
    InputsUnavailable,
    /// <summary>The bound path inputs contain their own scoped uncertainty.</summary>
    CapturedInputUncertainty,
    /// <summary>Other authorization routes and path compositions were not selected.</summary>
    OtherPathFamiliesNotSelected,
    /// <summary>A relevant descriptor could not be read completely.</summary>
    DescriptorUnavailable,
    /// <summary>Captured member values do not establish full attribute visibility.</summary>
    MembershipVisibilityUnknown,
    /// <summary>An identity was missing, ambiguous or inconsistent with its source.</summary>
    IdentityUnresolved,
    /// <summary>The verified same-domain resource context was not established.</summary>
    ResourceContextUnsupported,
    /// <summary>The identity is not an ordinary directory user.</summary>
    RequesterKindUnsupported,
    /// <summary>The granting or obtained group is not a supported global security group.</summary>
    GlobalGroupRequired,
    /// <summary>A broad identity remains symbolic, not enumerated into users.</summary>
    BroadIdentityNotExpanded,
    /// <summary>The captured permission cannot be interpreted by this selector.</summary>
    PermissionUnsupported,
}

/// <summary>A source-scoped limitation; a null resource names the bound input scope, never an invented subject.</summary>
public sealed record PathRequesterSelectionLimitation(PathRequesterSelectionReason Reason, string? ResourceDn,
    int? PermissionOrdinal, string? TrusteeSid, string? MemberDn);

/// <summary>A captured resource and its original attributes, permissions and named-holder fingerprint.</summary>
public sealed record PathRequesterSelectionSource(string ResourceDn, string Fingerprint);

/// <summary>The captured entry and requester, with the direct member value or qualified nested witnesses.</summary>
public sealed record PathRequesterSelectionWitness(string ResourceDn, int PermissionOrdinal, int RequiredMask,
    string HolderDn, string? MemberDn)
{
    /// <summary>The actual source-linked chain when the requester is not a direct member of the holder.</summary>
    public RequesterMembershipEvidence? Membership { get; init; }
}

/// <summary>Presence of selection-source references, separately from their validation or authorization.</summary>
public enum PathRequesterSourceState
{
    /// <summary>No selection-source references are recorded.</summary>
    Unrecorded,
    /// <summary>Selection-source references are recorded; they do not themselves establish access.</summary>
    Recorded,
}

/// <summary>A question with its original selection supports; multiple supports do not multiply questions or holder counts.</summary>
public sealed record PathRequesterCandidate(PathRequesterFamily Family, string RequesterDn, string TargetDn,
    string? GroupDn, OwnAccountMembershipPermissionKind? PermissionKind, string RequesterFingerprint,
    IReadOnlyList<PathRequesterSelectionWitness> Witnesses)
{
    /// <summary>Whether source references are present, never a permission, operation or reachability verdict.</summary>
    public PathRequesterSourceState Verdict => Witnesses is { Count: > 0 }
        ? PathRequesterSourceState.Recorded : PathRequesterSourceState.Unrecorded;
}

/// <summary>
/// Offline selection bound to one saved path input. A completed supported scan is not complete requester coverage
/// or NotReachable. A null selection on a path result means this work was not requested.
/// </summary>
internal sealed record PathRequesterSelection(int Version, Guid JudgementGenerationId, string InputFingerprint,
    bool InputScanCompleted, IReadOnlyList<PathRequesterCandidate> Candidates,
    IReadOnlyList<PathRequesterSelectionSource> Sources, IReadOnlyList<PathRequesterSelectionLimitation> Limitations);
