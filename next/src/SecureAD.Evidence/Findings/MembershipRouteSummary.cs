namespace SecureAD.Evidence.Findings;

[Flags]
public enum MembershipRouteIncompleteReason
{
    None = 0,
    NotDerived = 1,
    MembershipEvidenceIncomplete = 2,
    ForestIdentityUnknown = 4,
    ForestMaskUnreadable = 8,
    NodeBudgetReached = 16,
    EdgeBudgetReached = 32,
    StorageBudgetReached = 64,
    TimeBudgetReached = 128,
    CycleBoundary = 256,
}

public enum MembershipRouteAuthorization
{
    SecurityEnabled,
    DistributionGroup,
    UnknownGroupType,
}

/// <summary>A captured principal, retaining the domain scope of built-in identifiers.</summary>
public sealed record MembershipRoutePrincipal(string Sid, string? Scope, string? DistinguishedName);

/// <summary>A step from the account towards a root; primary-group membership is labelled explicitly.</summary>
public sealed record MembershipRouteStep(MembershipRoutePrincipal Principal, bool IsPrimaryGroup);

/// <summary>One supporting chain, not a claim to enumerate every possible chain through the same membership.</summary>
public sealed record MembershipRoute(
    int CatalogueEntryId,
    string RootName,
    MembershipRouteAuthorization Authorization,
    bool EstablishesProtection,
    IReadOnlyList<MembershipRouteStep> Steps);

/// <summary>All reached roots sharing one initial membership, rather than separate removal instructions.</summary>
public sealed record InitialMembershipRoutes(
    MembershipRoutePrincipal InitialMembership,
    IReadOnlyList<MembershipRoute> Routes,
    MembershipRouteIncompleteReason Completeness);

/// <summary>Membership explanations and their limits; neither owner acceptance nor a remediation guarantee.</summary>
public sealed record MembershipRouteSummary(
    IReadOnlyList<InitialMembershipRoutes> Memberships,
    MembershipRouteIncompleteReason IncompleteReasons)
{
    public bool IsComplete => IncompleteReasons == MembershipRouteIncompleteReason.None;

    /// <summary>Carry discovery limits on each group as well as on the overall count.</summary>
    public MembershipRouteSummary WithIncompleteReasons(MembershipRouteIncompleteReason reasons) => this with
    {
        IncompleteReasons = reasons,
        Memberships = Memberships.Select(group => group with { Completeness = reasons }).ToArray(),
    };

    public string CompletenessDescription => IsComplete ? "Complete membership summary." :
        "Partial membership summary: " + string.Join("; ", Enum.GetValues<MembershipRouteIncompleteReason>()
            .Where(reason => reason != MembershipRouteIncompleteReason.None && IncompleteReasons.HasFlag(reason))
            .Select(reason => reason switch
            {
                MembershipRouteIncompleteReason.NotDerived => "routes were not derived",
                MembershipRouteIncompleteReason.MembershipEvidenceIncomplete => "membership evidence or capture coverage is incomplete",
                MembershipRouteIncompleteReason.ForestIdentityUnknown => "the forest-root identity is unknown",
                MembershipRouteIncompleteReason.ForestMaskUnreadable => "the forest's protection exclusions could not be read",
                MembershipRouteIncompleteReason.NodeBudgetReached => "the visited-principal limit was reached",
                MembershipRouteIncompleteReason.EdgeBudgetReached => "the examined-membership limit was reached",
                MembershipRouteIncompleteReason.StorageBudgetReached => "the stored-evidence size limit was reached",
                MembershipRouteIncompleteReason.TimeBudgetReached => "the expansion time limit was reached",
                MembershipRouteIncompleteReason.CycleBoundary => "a membership cycle prevents a complete simple-route summary for this group",
                _ => throw new InvalidOperationException("Unknown membership completeness reason."),
            })) + ". The listed count is not a total.";

    public static MembershipRouteSummary NotDerived { get; } = new([], MembershipRouteIncompleteReason.NotDerived);
}
