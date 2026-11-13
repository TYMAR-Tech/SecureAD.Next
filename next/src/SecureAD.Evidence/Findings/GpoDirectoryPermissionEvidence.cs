using SecureAD.Kernel.Schema;

namespace SecureAD.Evidence.Findings;

public enum GpoDirectoryOperation
{
    PolicyFilePath,
    FunctionalityVersion,
    EnablementFlags,
    PolicyVersion,
    ComputerExtensions,
    UserExtensions,
    WmiFilter,
    PermissionList,
    Links,
}

public enum GpoDirectoryPermissionState
{
    NotEstablished,
    Established,
    Unresolved,
}

/// <summary>A captured directory resource, never an account-only identity or an inferred policy folder.</summary>
public sealed record GpoDirectoryResource(Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    string ObjectClass, string? Name, DateTimeOffset CapturedUtc)
{
    public bool IsValid => ObjectGuid != Guid.Empty && !string.IsNullOrWhiteSpace(DistinguishedName)
        && !string.IsNullOrWhiteSpace(DomainFqdn) && !string.IsNullOrWhiteSpace(ObjectClass);
}

public sealed record GpoDirectoryEntryScope(int Ordinal, GpoDirectoryPermissionState State, string Reason);

/// <summary>One operation's saved ordered grants, blockers and scope qualifications.</summary>
public sealed record GpoDirectoryRight(GpoDirectoryOperation Operation, GpoDirectoryPermissionState State,
    IReadOnlyList<int> GrantOrdinals, IReadOnlyList<int> BlockingOrdinals,
    IReadOnlyList<GpoDirectoryEntryScope> Scopes, IReadOnlyList<string> Limitations)
{
    public bool IsComplete => State != GpoDirectoryPermissionState.Unresolved;
}

/// <summary>Original directory permissions and independently scoped administration evidence for one holder/target finding.</summary>
public sealed record GpoDirectoryPermissionEvidence(Guid GenerationId, string EvidenceSeal,
    Guid DerivationGenerationId, string DerivationSeal, int PrincipalCatalogueVersion, int EngineVersion,
    string RuleId, GpoDirectoryResource Target, IReadOnlyList<string> ObjectClasses,
    PermissionTrustee Holder, string? HolderScope, bool NamingContextRoot, ObjectPermissions Permissions,
    string? ForestFqdn, IReadOnlyDictionary<string, string?> DomainSids, MembershipRouteSummary MembershipRoutes,
    string ExpectednessReason, IReadOnlyList<SchemaGuidEntry> SchemaEntries,
    IReadOnlyDictionary<string, IReadOnlyList<string>> PropertySets, IReadOnlyList<GpoDirectoryRight> Rights,
    IReadOnlyList<string> Limitations) : FindingEvidence
{
    public bool IsComplete => Permissions.Availability == DescriptorAvailability.Read
        && Permissions.DaclCompleteness == Kernel.Security.DaclCompleteness.Complete
        && Limitations.Count == 0 && Rights.All(right => right.IsComplete);
}
