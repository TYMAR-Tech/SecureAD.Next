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

/// <summary>The exact saved finding within its original judgement generation.</summary>
public readonly record struct FindingReference(Guid GenerationId, long FindingId);

public sealed record SavedDelegationContext(bool IsComputer, DomainControllerSignals ControllerSignals);

/// <summary>One selected account option, bound to its original saved finding, rule and object.</summary>
public sealed record SavedAccountSetting(
    FindingReference Reference,
    string RuleId,
    Guid ObjectGuid,
    FindingSubject Subject,
    string DistinguishedName,
    UserAccountControlEvidence AccountControl)
{
    public SavedDelegationContext? Delegation { get; init; }

    public static bool SupportsRule(string ruleId) => DefinitionFor(ruleId) is not null;

    public static bool UsesDelegationHeader(string ruleId) => ruleId is "SEC-010" or "SEC-011";

    public bool HasReportedSetting => DefinitionFor(RuleId) is { } definition
        && (AccountControl.UserAccountControl & definition.Flag) != 0;

    public bool HasExpectedContext => UsesDelegationHeader(RuleId)
        ? Delegation is { } context && context.IsComputer == (RuleId == "SEC-011")
        : Delegation is null;

    public string SettingName => DefinitionFor(RuleId)?.Name
        ?? throw new InvalidOperationException("The selected rule has no supported account setting.");

    private static (uint Flag, string Name)? DefinitionFor(string ruleId) => ruleId switch
    {
        "SEC-010" or "SEC-011" => (UnconstrainedDelegation.TrustedForDelegation, "Unconstrained delegation"),
        "SEC-022" => (NoKerberosPreauthentication.DontRequirePreauth, "Do not require Kerberos preauthentication"),
        "SEC-028" => (PasswordNotRequired.PasswordNotRequiredFlag, "Password not required"),
        "SEC-029" => (ReversiblePasswordEncryption.ReversibleEncryption, "Store password using reversible encryption"),
        "SEC-033" => (DesEncryptionOnly.DesKeyOnly, "Use Kerberos DES encryption types for this account"),
        _ => null,
    };
}

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
    public FindingReference? Reference { get; init; }
    public bool? CircularInventoryComplete { get; init; }

    /// <summary>Projects an original finding without retaining its detailed proof.</summary>
    public static FindingListItem FromFinding(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var membership = finding.Evidence is KerberoastableAccountEvidence account
            ? new FindingMembershipDisplay(account.ProtectionCatalogueVersion, account.DirectProtectionCatalogueEntryId,
                account.DirectProtectionName, account.MembershipRoutes)
            : null;
        return new(finding.RuleId, finding.RuleVersion, finding.Severity, finding.Subject, finding.ObjectGuid,
            finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass,
            finding.RuleId == "SEC-002" ? SavedReplicationPermission.Statement
                : finding.RuleId == "SEC-021" ? ServiceRegistrationPresentation.Why
                : finding.RuleId is "SEC-050" or "SEC-051" ? SavedGroupReview.Statement(finding.RuleId)
                : finding.RuleId == "SEC-052" ? CircularGroupMembership.Explanation
                : finding.RuleId == "SEC-060" ? SavedPermissionControl.Statement
                : finding.RuleId == "SEC-012" ? SavedDelegationConfiguration.ConstrainedStatement
                : finding.RuleId == "SEC-013" ? SavedDelegationConfiguration.ResourceStatement
                : finding.RuleId == "SEC-026" ? SavedDuplicateSpn.Statement
                : finding.RuleId == "SEC-027" ? SavedSidHistory.Statement
                : finding.RuleId == "SEC-030" ? SavedProtectionMarker.Statement
                : finding.RuleId is "SEC-031" or "SEC-032" ? SavedOwnershipAssessment.ScopeNote
                : finding.RuleId is "SEC-100" or "SEC-101" ? SavedServiceAccountContext.Statement(finding.RuleId)
                : SavedAttributeWritePermission.SupportsRule(finding.RuleId)
                    ? SavedAttributeWritePermission.ScopeNoteForRule(finding.RuleId) : finding.Detail, finding.Coverage,
            finding.PrincipalName, membership is not null ? FindingListKind.Membership
                : finding.Evidence is Tier0RouteFindingEvidence ? FindingListKind.Tier0Routes : FindingListKind.Standard,
            Complete(finding.Evidence), membership);
    }

    internal static bool Complete(FindingEvidence evidence) => evidence switch
    {
        KerberoastableAccountEvidence value => value.MembershipRoutes.IsComplete,
        BroadGroupMembershipEvidence value => value.IsComplete,
        GroupMembershipReviewEvidence value => value.IsComplete,
        CircularMembershipEvidence value => value.InventoryComplete,
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
