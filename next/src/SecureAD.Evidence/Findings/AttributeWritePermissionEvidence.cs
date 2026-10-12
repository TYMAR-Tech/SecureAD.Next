using SecureAD.Kernel.Schema;

namespace SecureAD.Evidence.Findings;

/// <summary>The specific property-write permission, not the corresponding directory operation.</summary>
public enum AttributeWritePermissionKind
{
    /// <summary>WRITE_PROPERTY on msDS-AllowedToActOnBehalfOfOtherIdentity.</summary>
    ResourceBasedConstrainedDelegation,
    /// <summary>WRITE_PROPERTY on servicePrincipalName, not restricted validated-SPN permission.</summary>
    ServicePrincipalName,
    /// <summary>WRITE_PROPERTY on msDS-KeyCredentialLink, not the SELF-only validated computer operation.</summary>
    KeyCredentialLink,
}

/// <summary>The operation-specific scope of an original permission occurrence.</summary>
public sealed record AttributeWritePermissionScope(int Ordinal, string State, string Basis);

/// <summary>Source-bound permission proof behind SEC-014/024/025, separate from authentication and Tier 0 paths.</summary>
public sealed record AttributeWritePermissionEvidence(Guid GenerationId, string EvidenceSeal, Guid DerivationGenerationId,
    string DerivationSeal, int PrincipalCatalogueVersion, int ControlEngineVersion, AttributeWritePermissionKind PermissionKind,
    AdministrativeMembershipIdentity Target, IReadOnlyList<AdministrativeMembershipIdentity> Domains, IReadOnlyList<AttributeValue> AccountControl,
    string HolderSid, string? HolderScope, string? HolderName, string ExpectednessReason,
    SchemaGuidEntry Attribute, IReadOnlyList<SchemaGuidEntry> SchemaEntries,
    IReadOnlyDictionary<string, IReadOnlyList<string>> PropertySetMembers,
    IReadOnlyList<AttributeWritePermissionScope> Scopes, IReadOnlyList<PermissionEntry> Entries,
    string DescriptorOutcome, IReadOnlyList<string> Limitations) : FindingEvidence
{
    /// <summary>Completeness of this saved assessment, not a claim that a live operation would succeed.</summary>
    public bool IsComplete => Limitations.Count == 0;
}
