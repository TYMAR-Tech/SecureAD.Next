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
    /// <summary>The configured object budget stopped the scan with input left unvisited.</summary>
    ObjectsBudgetExceeded,
    /// <summary>The configured permission-entry budget stopped the scan.</summary>
    PermissionBudgetExceeded,
    /// <summary>The configured candidate budget stopped the scan.</summary>
    CandidateBudgetExceeded,
}

/// <summary>Explicit work limits for automatic discovery; no production default has been selected.</summary>
/// <remarks>
/// A null budget disables automatic discovery entirely rather than substituting a guessed limit.
/// Production values require measurement against the recorded nine-domain forest shape.
/// </remarks>
public sealed record Tier0DiscoveryBudget(long Objects, long PermissionEntries, int Candidates)
{
    /// <summary>
    /// A bound large enough not to bind on a laboratory capture. <b>Not a production budget.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// The laboratory forest holds 8,383 objects; the production shape this product is built for
    /// holds roughly 347,000 objects and 5.9 million access control entries. These figures are
    /// chosen to exceed the former comfortably, so the lab exercises discovery rather than its
    /// limits. They are <b>not</b> derived from any measurement of the latter.
    /// </para>
    /// <para>
    /// A production budget needs measurement against the nine-domain shape under explicit
    /// authorization. Until then, a run that exceeds these limits stops and says so through
    /// <see cref="Tier0DiscoveryCoverage.Verdict"/> - which is the honest outcome, and is why the
    /// alternative of quietly assessing every object instead was rejected.
    /// </para>
    /// </remarks>
    public static Tier0DiscoveryBudget Laboratory { get; } = new(1_000_000, 20_000_000, 1_000_000);

    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegative(Objects);
        ArgumentOutOfRangeException.ThrowIfNegative(PermissionEntries);
        ArgumentOutOfRangeException.ThrowIfNegative(Candidates);
    }
}

/// <summary>The captured source of a limitation, never a fabricated controller identity.</summary>
public sealed record Tier0DiscoveryLimitation(Tier0DiscoveryReason Reason, string? TargetDn,
    int? PermissionOrdinal, string? TrusteeSid)
{
    /// <summary>Whether available input was left unvisited because a configured limit was reached.</summary>
    public bool IsProcessingStop => Reason is Tier0DiscoveryReason.ObjectsBudgetExceeded
        or Tier0DiscoveryReason.PermissionBudgetExceeded or Tier0DiscoveryReason.CandidateBudgetExceeded;
}

/// <summary>
/// Scan progress and limitations; finishing a scan does not prove forest or membership completeness.
/// </summary>
/// <remarks>
/// <b>The counts here are work accounting, not security coverage.</b> They say how much captured
/// input was inspected and how many candidates came out of it. They do not say the forest is
/// understood, and an object absent from every candidate was not examined and not cleared.
/// </remarks>
public sealed record Tier0DiscoveryCoverage(int Version, bool InputScanCompleted, bool CaptureIsComplete,
    Tier0DiscoveryBudget? Budget, long ObjectsVisited, long PermissionEntriesVisited, long OwnersVisited,
    int CandidatesDiscovered, IReadOnlyList<Tier0DiscoveryLimitation> Limitations)
{
    /// <summary>The semantics that produced this coverage, distinct from the classifier and selector versions.</summary>
    public const int CurrentVersion = 1;

    /// <summary>The supported scan's state, not an admission verdict or a completeness claim.</summary>
    public string Verdict => Budget is null ? "NotStarted"
        : InputScanCompleted ? "CapturedInputScanFinished" : "ProcessingStopped";

    /// <summary>Whether anything prevented this scan from inspecting all supported captured input.</summary>
    public bool IsComplete => InputScanCompleted && CaptureIsComplete && Limitations.Count == 0;
}
