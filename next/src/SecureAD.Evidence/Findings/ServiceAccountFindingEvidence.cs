namespace SecureAD.Evidence.Findings;

/// <summary>The captured basis for associating an account with services, not proof that a service uses it.</summary>
public enum ServiceAccountKind
{
    /// <summary>An ordinary user with at least one readable captured service principal name.</summary>
    SpnBearingUser,
    /// <summary>An account structurally identified as msDS-ManagedServiceAccount.</summary>
    StandaloneManagedServiceAccount,
    /// <summary>An account structurally identified as msDS-GroupManagedServiceAccount.</summary>
    GroupManagedServiceAccount,
}

/// <summary>Original account-class, SPN and account-control values beside their interpretation.</summary>
public sealed record ServiceAccountAssociation(Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    DateTimeOffset CapturedUtc, EvidenceCompleteness Completeness, ServiceAccountKind Kind,
    IReadOnlyList<AttributeValue> ObjectClasses, IReadOnlyList<AttributeValue> ServicePrincipalNames,
    IReadOnlyList<AttributeValue> AccountControl, uint? UserAccountControl, IReadOnlyList<string> MissingAttributes);

/// <summary>One established administrative destination, qualified from saved routes and original captured links.</summary>
public sealed record ServiceAdministrativeMembership(string EvidenceSeal, Guid DerivationGenerationId,
    string DerivationSeal, int PrincipalCatalogueVersion, int PolicyVersion,
    string? ForestRootNamingContext, Guid AccountGuid, Guid TargetGuid,
    IReadOnlyList<AdministrativeMembershipIdentity> Principals, IReadOnlyList<AdministrativeMembershipIdentity> Domains,
    IReadOnlyList<AdministrativeMembershipLink> Links, bool InputsComplete,
    MembershipRouteIncompleteReason RouteIncompleteReasons, IReadOnlyList<AdministrativeMembershipLimitation> Limitations)
{
    /// <summary>Established membership survives a partial assessment; missing destinations are not ruled out.</summary>
    public bool IsComplete => InputsComplete && RouteIncompleteReasons == MembershipRouteIncompleteReason.None && Limitations.Count == 0;
}

/// <summary>Shared typed evidence for SEC-100 membership and SEC-101's account setting.</summary>
public sealed record ServiceAccountFindingEvidence(ServiceAccountAssociation Account,
    ServiceAdministrativeMembership? AdministrativeMembership) : FindingEvidence
{
    /// <summary>Whether every input needed for this saved answer was readable and assessed.</summary>
    public bool IsComplete => Account.MissingAttributes.Count == 0 && AdministrativeMembership?.IsComplete != false;
}
