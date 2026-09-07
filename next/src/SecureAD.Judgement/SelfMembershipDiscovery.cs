namespace SecureAD.Judgement;

/// <summary>Explicit work limits for automatic discovery; no production default has been selected.</summary>
public sealed record SelfMembershipDiscoveryBudget(long Objects, long PermissionEntries, long MembershipValues, int Pairs)
{
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegative(Objects);
        ArgumentOutOfRangeException.ThrowIfNegative(PermissionEntries);
        ArgumentOutOfRangeException.ThrowIfNegative(MembershipValues);
        ArgumentOutOfRangeException.ThrowIfNegative(Pairs);
    }
}

/// <summary>How requester questions were supplied; a completed product does not establish an automatic scan.</summary>
public enum SelfMembershipDiscoveryMode { ExplicitRequests, Automatic }

/// <summary>Why discovery cannot claim complete coverage, separately from an individual authorization answer.</summary>
public enum SelfMembershipDiscoveryReason
{
    ProductionBudgetNotConfigured, CaptureIncomplete, TargetClassMissing, DescriptorUnavailable,
    DescriptorIncomplete, UnresolvedTrustee, MissingIdentity, GroupTypeMissing, MembershipNotCaptured,
    MembershipCompletenessUnknown, UnsupportedRoute, BroadTrustee,
    ObjectsBudgetExceeded, PermissionBudgetExceeded, MembershipBudgetExceeded, PairBudgetExceeded,
}

/// <summary>The captured source of a limitation, never a fabricated requester identity.</summary>
public sealed record SelfMembershipDiscoveryLimitation(SelfMembershipDiscoveryReason Reason,
    string? TargetDn, int? PermissionOrdinal, string? TrusteeSid, string? MemberDn)
{
    /// <summary>Whether available input was left unvisited because a configured limit was reached.</summary>
    public bool IsProcessingStop => Reason is SelfMembershipDiscoveryReason.ObjectsBudgetExceeded
        or SelfMembershipDiscoveryReason.PermissionBudgetExceeded or SelfMembershipDiscoveryReason.MembershipBudgetExceeded
        or SelfMembershipDiscoveryReason.PairBudgetExceeded;
}

/// <summary>Stored scan progress and limitations; finishing a scan does not prove forest or membership completeness.</summary>
public sealed record SelfMembershipDiscoveryCoverage(int Version, SelfMembershipDiscoveryMode Mode,
    bool InputScanCompleted, bool CaptureIsComplete, SelfMembershipDiscoveryBudget? Budget,
    long ObjectsVisited, long PermissionEntriesVisited, long MembershipValuesVisited, int PairsDiscovered,
    IReadOnlyList<SelfMembershipDiscoveryLimitation> Limitations)
{
    /// <summary>The supported scan's state, not an authorization verdict or a forest-wide completeness claim.</summary>
    public string Verdict => Mode == SelfMembershipDiscoveryMode.ExplicitRequests ? "ExplicitRequestsOnly"
        : Budget is null ? "NotStarted" : InputScanCompleted ? "CapturedInputScanFinished" : "ProcessingStopped";
}

/// <summary>A generation-bound summary read without materializing every requester assessment.</summary>
public sealed record SelfMembershipSummary(Guid GenerationId, string EvidenceSeal, int EvaluatorVersion,
    long AssessmentsStored, long AuthorizationUnknown, long ReadinessUnknown, SelfMembershipDiscoveryCoverage Discovery)
{
    /// <summary>What discovery accomplished; stored answer counts do not imply definitive authorization.</summary>
    public string Verdict => Discovery.Verdict;
}
