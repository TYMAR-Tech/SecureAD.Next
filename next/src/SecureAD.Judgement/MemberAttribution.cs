using SecureAD.Evidence;

namespace SecureAD.Judgement;

/// <summary>Explicit limits shared by an offline member-attribution batch; no production default is supplied.</summary>
public sealed record MemberAttributionBudget(long MaxNodes, long MaxLinks, long MaxRecords, TimeSpan MaxTime)
{
    internal void Validate()
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxNodes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxLinks);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(MaxRecords);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(MaxTime, TimeSpan.Zero);
    }
}

/// <summary>Why a stored member expansion did not finish.</summary>
public enum MemberAttributionStop
{
    None, NotRun, NodeBudgetExceeded, LinkBudgetExceeded, StorageBudgetExceeded, TimeBudgetExceeded,
}

/// <summary>Whether captured membership establishes a current security-group relationship, not requester authorization.</summary>
public enum MemberAttributionState { Established, NotEstablished, Unknown }

/// <summary>A distinct captured member or unresolved endpoint, with its strongest evidenced membership route.</summary>
public sealed record MemberAttributionMember(string Identity, ObjectAttributes? Source, MemberAttributionState State)
{
    /// <summary>Whether the underlying principal, rather than merely a foreign-principal stub, was resolved.</summary>
    public bool IsResolved => Source?.ObjectGuid is not null
        && SecureAD.Derivation.RequesterTrusteeReading.SidOf(Source) is not null
        && !SecureAD.Derivation.RequesterTrusteeReading.HasClass(Source, "foreignSecurityPrincipal");
    /// <summary>Whether a captured tombstone is excluded from current-member totals.</summary>
    public bool IsDeleted => string.Equals(Source?.Find("isDeleted")?.OnlyValue?.Text, "TRUE", StringComparison.OrdinalIgnoreCase);
}

/// <summary>A source-linked membership relationship; endpoints retain their directory identity rather than just a SID.</summary>
public sealed record MemberAttributionLink(string Group, string Member, string SourceDn, string Attribute, int Ordinal);

/// <summary>A representative chain grouped by initial membership, retaining a parent route rather than copying every path.</summary>
public sealed record MemberAttributionRoute(int Id, string Member, string InitialGroup, MemberAttributionState State, int? ParentRouteId, int LinkIndex);

/// <summary>One persisted group expansion; membership, resource usability and requester authorization remain separate.</summary>
public sealed record MemberAttribution(
    string HolderSid,
    string? HolderScope,
    ObjectAttributes? Holder,
    Guid GenerationId,
    Guid DerivationGenerationId,
    MemberAttributionBudget? Budget,
    MemberAttributionStop Stop,
    long VisitedNodes,
    long TraversedLinks,
    long StoredRecords,
    TimeSpan Elapsed,
    string? ProcessingPosition,
    IReadOnlyList<string> Limitations,
    IReadOnlyList<MemberAttributionMember> Members,
    IReadOnlyList<MemberAttributionLink> Links,
    IReadOnlyList<MemberAttributionRoute> Routes)
{
    /// <summary>Whether the required membership inputs and the bounded walk were complete.</summary>
    public bool IsComplete => Stop == MemberAttributionStop.None && Limitations.Count == 0;
    /// <summary>Distinct resolved current security-group members; never multiplied by routes.</summary>
    public int ResolvedMemberCount => Members.Count(member => member.IsResolved && !member.IsDeleted && member.State == MemberAttributionState.Established);
    /// <summary>Retained unresolved identities, including foreign stubs.</summary>
    public int UnresolvedMemberCount => Members.Count(member => !member.IsResolved && !member.IsDeleted);
    /// <summary>Resolved identities for which security membership remains unconfirmed.</summary>
    public int UnconfirmedMemberCount => Members.Count(member => member.IsResolved && !member.IsDeleted && member.State == MemberAttributionState.Unknown);
}
