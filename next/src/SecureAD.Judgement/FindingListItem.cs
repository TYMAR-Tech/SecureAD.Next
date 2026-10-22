using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

public enum FindingListKind
{
    Standard,
    Membership,
    Tier0Routes,
}

public sealed record FindingMembershipDisplay(
    int? ProtectionCatalogueVersion,
    int? DirectProtectionCatalogueEntryId,
    string? DirectProtectionName,
    MembershipRouteSummary MembershipRoutes);

/// <summary>Saved list values, not a replacement for the original finding proof.</summary>
public sealed record FindingListItem(
    string RuleId,
    int RuleVersion,
    Severity Severity,
    FindingSubject Subject,
    Guid ObjectGuid,
    string DistinguishedName,
    string DomainFqdn,
    string ObjectClass,
    string Detail,
    EvidenceCompleteness Coverage,
    string PrincipalName,
    FindingListKind Kind,
    bool EvidenceIsComplete,
    FindingMembershipDisplay? Membership)
{
    /// <summary>Projects an original finding without retaining its detailed proof.</summary>
    public static FindingListItem FromFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var membership = finding.Evidence is KerberoastableAccountEvidence account
            ? new FindingMembershipDisplay(account.ProtectionCatalogueVersion, account.DirectProtectionCatalogueEntryId,
                account.DirectProtectionName, account.MembershipRoutes)
            : null;
        return new(finding.RuleId, finding.RuleVersion, finding.Severity, finding.Subject, finding.ObjectGuid,
            finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass, finding.Detail, finding.Coverage,
            finding.PrincipalName, membership is not null ? FindingListKind.Membership
                : finding.Evidence is Tier0RouteFindingEvidence ? FindingListKind.Tier0Routes : FindingListKind.Standard,
            Complete(finding.Evidence), membership);
    }

    internal static bool Complete(FindingEvidence evidence) => evidence switch
    {
        KerberoastableAccountEvidence value => value.MembershipRoutes.IsComplete,
        BroadGroupMembershipEvidence value => value.IsComplete,
        GroupMembershipReviewEvidence value => value.IsComplete,
        DelegationConfigurationEvidence value => value.IsComplete,
        ServiceAccountFindingEvidence value => value.IsComplete,
        AttributeWritePermissionEvidence value => value.IsComplete,
        ReplicationPermissionEvidence value => value.IsComplete,
        PrivilegedSidHistoryEvidence value => value.IsComplete,
        ObjectTakeoverEvidence value => value.IsComplete,
        ObjectOwnershipEvidence value => value.IsComplete,
        LapsPasswordReaderEvidence value => value.IsComplete,
        LapsDecryptorEvidence value => value.IsComplete,
        _ => true,
    };
}

public sealed record FindingListPage(
    IReadOnlyList<FindingListItem> Findings,
    FindingsPageMark? Next,
    int RulesRan)
{
    public bool HasMore => Next is not null;
    /// <summary>Whether no saved rule execution exists, rather than a judged scope with no findings.</summary>
    public bool DidNotRun => RulesRan == 0;
    public bool NothingWasFound => Findings.Count == 0 && RulesRan > 0;
}
