using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Selected saved SEC-021 facts; the two visibility qualifications remain independent.</summary>
public sealed record ServiceRegistrationContext(FindingReference Reference, FindingSubject Subject,
    SavedDelegationIdentity Account, string Name, string Sid, uint SavedAccountControl,
    int UnreadableServiceNames, int ProtectionCatalogueVersion, int? DirectProtectionEntryId,
    string? DirectProtectionName, MembershipRouteIncompleteReason MembershipLimits,
    long ServiceNameCount, long InitialMembershipCount, EvidenceCompleteness Coverage)
{
    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-021" && finding.RuleVersion == 2
        && finding.Severity == Severity.Critical && finding.Kind == FindingListKind.Membership
        && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Subject == finding.Subject && Subject is { Kind: FindingSubjectKind.Account }
        && Account is { IsValid: true } && Account.ObjectGuid == finding.ObjectGuid
        && Account.DistinguishedName == finding.DistinguishedName && Account.DomainFqdn == finding.DomainFqdn
        && Account.ObjectClass == finding.ObjectClass && string.Equals(Account.ObjectClass, "user", StringComparison.OrdinalIgnoreCase)
        && Name == finding.PrincipalName && !string.IsNullOrWhiteSpace(Name)
        && SecureAD.Kernel.Security.Sid.ToBytes(Sid) is not null && UnreadableServiceNames >= 0
        && ProtectionCatalogueVersion > 0 && (DirectProtectionEntryId is null) == (DirectProtectionName is null)
        && (DirectProtectionEntryId is null || DirectProtectionEntryId >= 0 && !string.IsNullOrWhiteSpace(DirectProtectionName))
        && ((int)MembershipLimits & ~KnownMembershipLimits) == 0
        && (MembershipLimits == MembershipRouteIncompleteReason.None) == finding.EvidenceIsComplete
        && ServiceNameCount is > 0 and <= int.MaxValue && InitialMembershipCount is >= 0 and <= int.MaxValue
        && Coverage == finding.Coverage && Enum.IsDefined(Coverage);

    internal static readonly int KnownMembershipLimits = Enum.GetValues<MembershipRouteIncompleteReason>().Aggregate(0, (value, reason) => value | (int)reason);
}

public readonly record struct ServiceNameMark(Guid GenerationId, long FindingId, Guid AccountGuid, int Ordinal);
public readonly record struct InitialMembershipMark(Guid GenerationId, long FindingId, Guid AccountGuid, int Ordinal);
public readonly record struct MembershipRouteMark(Guid GenerationId, long FindingId, Guid AccountGuid, int MembershipOrdinal, int Ordinal);
public readonly record struct MembershipStepMark(Guid GenerationId, long FindingId, Guid AccountGuid, int MembershipOrdinal, int RouteOrdinal, int Ordinal);

public sealed record SavedServiceName(int Ordinal, string Value);
public sealed record SavedInitialMembership(int Ordinal, MembershipRoutePrincipal Principal, bool IsPrimaryGroup, long RouteCount);
public sealed record SavedMembershipRoute(int Ordinal, int CatalogueEntryId, string RootName,
    MembershipRouteAuthorization Authorization, bool EstablishesProtection, long StepCount)
{
    public MembershipRoutePrincipal? RootPrincipal { get; init; }
}
public sealed record SavedMembershipStep(int Ordinal, MembershipRoutePrincipal Principal, bool IsPrimaryGroup);

public sealed record SavedServiceRegistrations(ServiceRegistrationContext Context, IReadOnlyList<SavedServiceName> Names, ServiceNameMark? Next)
{
    public const int PageSize = 50;
    public const string InvalidDetails = "The selected finding's saved service-registration or membership details are missing, invalid or inconsistent.";
}
public sealed record SavedInitialMemberships(ServiceRegistrationContext Context, IReadOnlyList<SavedInitialMembership> Memberships, InitialMembershipMark? Next);
public sealed record SavedMembershipRoutes(ServiceRegistrationContext Context, SavedInitialMembership Membership,
    IReadOnlyList<SavedMembershipRoute> Routes, MembershipRouteMark? Next);
public sealed record SavedMembershipSteps(ServiceRegistrationContext Context, SavedInitialMembership Membership,
    SavedMembershipRoute Route, IReadOnlyList<SavedMembershipStep> Steps, MembershipStepMark? Next);
