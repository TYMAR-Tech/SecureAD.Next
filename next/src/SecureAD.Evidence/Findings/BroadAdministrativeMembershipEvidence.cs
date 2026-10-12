namespace SecureAD.Evidence.Findings;

/// <summary>An original identity attribute value, retaining its captured ordinal and stored form.</summary>
public sealed record AdministrativeMembershipValue(string Attribute, int Ordinal, string Value);

/// <summary>A captured identity, with BUILTIN scope and original identity/type evidence kept separate.</summary>
public sealed record AdministrativeMembershipIdentity(Guid ObjectGuid, string DistinguishedName,
    string NamingContext, string? DomainFqdn, string Sid, string? SidScope, string ObjectClass,
    long? GroupType, DateTimeOffset CapturedUtc, EvidenceCompleteness Completeness,
    IReadOnlyList<AdministrativeMembershipValue> Values);

/// <summary>An original member or memberOf value, not a reconstructed account population.</summary>
public sealed record AdministrativeMembershipWitness(Guid SourceObjectGuid, string Attribute, int Ordinal, string Value);

/// <summary>A qualified direct link; a foreign reference remains identifiable beside its resolved principal.</summary>
public sealed record AdministrativeMembershipLink(Guid GroupGuid, Guid MemberGuid, Guid MemberReferenceGuid,
    IReadOnlyList<AdministrativeMembershipWitness> Witnesses);

/// <summary>A symbolic broad SID and its captured representations, without expanding its members.</summary>
public sealed record AdministrativeBroadSource(string Sid, string? SidScope, string Name, IReadOnlyList<Guid> IdentityGuids);

/// <summary>Captured-input gaps and unsupported analysis are distinct from a completed search.</summary>
public enum AdministrativeMembershipReason
{
    /// <summary>At least one declared capture unit was not read.</summary>
    CaptureIncomplete,
    /// <summary>A source's recorded connection completeness is limited.</summary>
    SourceIncomplete,
    /// <summary>An empty member list cannot distinguish an empty group from withheld values.</summary>
    MembershipValuesUnavailable,
    /// <summary>A membership value or its original ordinal cannot support a complete reading.</summary>
    MembershipValuesMalformed,
    /// <summary>A recorded member DN has no unique captured object.</summary>
    MemberUncaptured,
    /// <summary>The source identity, issuing domain or resource context could not be qualified.</summary>
    IdentityUnverified,
    /// <summary>The captured group type cannot establish security nesting.</summary>
    GroupTypeUnavailable,
    /// <summary>The recorded hop contradicts or exceeds supported group-scope rules.</summary>
    GroupScopeUnsupported,
    /// <summary>A foreign reference has no unique current captured principal to qualify.</summary>
    ForeignPrincipalUnresolved,
    /// <summary>The account's primary-group identifier was absent or unusable.</summary>
    PrimaryGroupUnavailable,
    /// <summary>A captured foreign reference matches SID history, which the saved routes do not resolve.</summary>
    HistoricalIdentityUnsupported,
}

/// <summary>A source-local limitation; positive links elsewhere remain evidence.</summary>
public sealed record AdministrativeMembershipLimitation(string DistinguishedName, AdministrativeMembershipReason Reason);

/// <summary>One administrative group's broad membership and compact supported links, bound to the saved inputs.</summary>
public sealed record BroadAdministrativeMembershipEvidence(string EvidenceSeal, Guid DerivationGenerationId,
    string DerivationSeal, int PrincipalCatalogueVersion, int PolicyVersion,
    string? ForestRootNamingContext, string? ConfigurationNamingContext, Guid TargetGuid,
    IReadOnlyList<AdministrativeMembershipIdentity> Principals, IReadOnlyList<AdministrativeMembershipIdentity> Domains,
    IReadOnlyList<AdministrativeBroadSource> BroadSources, IReadOnlyList<AdministrativeMembershipLink> Links,
    bool InputsComplete, IReadOnlyList<AdministrativeMembershipLimitation> Limitations) : FindingEvidence
{
    /// <summary>Completeness of this assessment, independent of its established positive membership.</summary>
    public bool IsComplete => InputsComplete && Limitations.Count == 0;
}
