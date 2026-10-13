namespace SecureAD.Evidence.Findings;

/// <summary>One saved component or scope check, not a replication operation.</summary>
public sealed record ReplicationPermissionCheck(string Name, string State, string EvidenceSource);

/// <summary>The original domain-root permission proof behind SEC-002, without member authorization or path claims.</summary>
public sealed record ReplicationPermissionEvidence(Guid GenerationId, string EvidenceSeal, Guid DerivationGenerationId,
    string DerivationSeal, int PrincipalCatalogueVersion, int ControlEngineVersion, int TierPolicyVersion, int TierContractVersion,
    Guid RootGuid, string NamingContextRoot, string DomainFqdn, string RootClass, string Tier0Basis,
    string HolderSid, string? HolderScope, string? HolderName, string ExpectednessReason, string DescriptorOutcome,
    IReadOnlyList<ReplicationPermissionCheck> Checks, IReadOnlyList<PermissionEntry> Entries,
    IReadOnlyList<string> Limitations) : FindingEvidence
{
    /// <summary>Whether this rule's captured inputs were complete, not whether replication would succeed.</summary>
    public bool IsComplete => Limitations.Count == 0;
}
