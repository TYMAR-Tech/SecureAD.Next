namespace SecureAD.Evidence.Findings;

/// <summary>The source-list review, distinct from membership-based authorization.</summary>
public enum GroupMembershipReviewKind
{
    /// <summary>A captured Direct count above the approved review threshold.</summary>
    PrivilegedGroupSize = 1,
    /// <summary>A group recorded directly in Domain Admins.</summary>
    GroupNestedInDomainAdmins = 2,
}

/// <summary>Saved structural totals, not a reconstructed account population or authorization answer.</summary>
public sealed record MembershipReviewKnownTotal(int KnownMembers, int UnresolvedReferences, int UnreadableReferences,
    IReadOnlyList<string> Limitations);

/// <summary>Original member values and scoped identities underlying a Low-severity membership review.</summary>
public sealed record GroupMembershipReviewEvidence(string EvidenceSeal, Guid DerivationGenerationId, string DerivationSeal,
    int PrincipalCatalogueVersion, int PolicyVersion, string? ForestRootNamingContext, string? ConfigurationNamingContext,
    GroupMembershipReviewKind ReviewKind, Guid TargetGuid, Guid? NestedGroupGuid,
    IReadOnlyList<AdministrativeMembershipIdentity> Principals, IReadOnlyList<AdministrativeMembershipIdentity> Domains,
    IReadOnlyList<AttributeValue> MemberValues, IReadOnlyList<AdministrativeMembershipLink> Links,
    int? DirectMembers, int? ReviewThreshold, MembershipReviewKnownTotal? KnownTotal,
    bool InputsComplete, IReadOnlyList<AdministrativeMembershipLimitation> Limitations) : FindingEvidence
{
    /// <summary>Captured-input and saved-total qualification, not approval of the group's membership.</summary>
    public bool IsComplete => InputsComplete && Limitations.Count == 0
        && (KnownTotal is null || KnownTotal.Limitations.Count == 0);
}
