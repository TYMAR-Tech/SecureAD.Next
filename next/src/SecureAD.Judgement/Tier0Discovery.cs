namespace SecureAD.Judgement;

/// <summary>
/// Why Tier-0 discovery cannot claim complete coverage, separately from any individual admission.
/// </summary>
/// <remarks>
/// <para>
/// <b>None of these mean the objects behind them are safe.</b> Each names a captured fact discovery
/// could not follow, so an object left unreached for one of these reasons is unassessed rather than
/// cleared. Decision 0116 requires this stay explicit rather than collapsing into an empty success.
/// </para>
/// <para>
/// <b>Every member here is one the scan actually emits.</b> A reason the scanner cannot produce
/// would tell a reader the product looks for something it never looks for - membership completeness,
/// for instance, which this bounded scan does not examine at all.
/// </para>
/// </remarks>
public enum Tier0DiscoveryReason
{
    /// <summary>The capture does not cover every declared domain, so unseen objects may control seeds.</summary>
    CaptureIncomplete,
    /// <summary>The object's security descriptor is absent or unreadable, which is not an empty ACL.</summary>
    DescriptorUnavailable,
    /// <summary>The DACL arrived partially, so an unseen entry could name a further controller.</summary>
    DescriptorIncomplete,
    /// <summary>A NULL DACL grants everyone everything; it is one unresolved candidate, not an expansion.</summary>
    NullDacl,
    /// <summary>Everyone, Authenticated Users or a comparable broad principal, retained unexpanded.</summary>
    BroadTrustee,
    /// <summary>The entry names a SID this capture holds no object for.</summary>
    UnresolvedTrustee,
    /// <summary>The trustee resolved but carries no usable GUID or SID identity.</summary>
    MissingIdentity,
    /// <summary>The route kind is outside this producer's supported scope and was not guessed at.</summary>
    UnsupportedRoute,
}

/// <summary>The captured source of a limitation, never a fabricated controller identity.</summary>
public sealed record Tier0DiscoveryLimitation(Tier0DiscoveryReason Reason, string? TargetDn,
    int? PermissionOrdinal, string? TrusteeSid);

/// <summary>
/// Scan progress and limitations; finishing a scan does not prove forest or membership completeness.
/// </summary>
/// <remarks>
/// <b>The counts here are work accounting, not security coverage.</b> They say how much captured
/// input was inspected and how many candidates came out of it. They do not say the forest is
/// understood, and an object absent from every candidate was not examined and not cleared.
/// </remarks>
public sealed record Tier0DiscoveryCoverage(int Version, bool CaptureIsComplete,
    long ObjectsVisited, long PermissionEntriesVisited, long OwnersVisited,
    int CandidatesDiscovered, IReadOnlyList<Tier0DiscoveryLimitation> Limitations)
{
    /// <summary>The semantics that produced this coverage, distinct from the classifier and selector versions.</summary>
    public const int CurrentVersion = 1;

    /// <summary>The supported scan's state, not an admission verdict or a completeness claim.</summary>
    /// <remarks>
    /// <b>There is one reachable state, and that is the point.</b> The scan has no work ceiling, so it
    /// reads what was captured or the operator cancels it - and a cancellation throws rather than
    /// returning a coverage that under-reports itself. A second verdict here would name an outcome
    /// the scan cannot produce.
    /// </remarks>
    public string Verdict => "CapturedInputScanFinished";

    /// <summary>Whether anything prevented this scan from inspecting all supported captured input.</summary>
    public bool IsComplete => CaptureIsComplete && Limitations.Count == 0;
}
