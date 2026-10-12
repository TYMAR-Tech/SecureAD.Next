namespace SecureAD.Evidence.Findings;

/// <summary>The captured delegation setting, not permission to change it or requester authorization.</summary>
public enum DelegationConfigurationKind
{
    /// <summary>The front-end account's named service destinations.</summary>
    Constrained = 1,
    /// <summary>The resource account's captured delegation security descriptor.</summary>
    ResourceBased = 2,
}

/// <summary>Original captured account values used to identify a configuration or service resource.</summary>
public sealed record DelegationConfigurationAccount(Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    string ObjectClass, DateTimeOffset CapturedUtc, EvidenceCompleteness Completeness, IReadOnlyList<ObjectAttribute> Attributes);

/// <summary>A generation-bound reference to shared classification and relevance witnesses, not another Tier-0 definition.</summary>
public sealed record DelegationResourceScope(Guid GenerationId, Guid ResourceGuid, string TargetDn, string Fingerprint,
    bool EstablishedTier0, IReadOnlyList<string> ClassificationBases, IReadOnlyList<string> AnchorDns,
    IReadOnlyList<long> RelationIds, IReadOnlyList<string> Limitations);

/// <summary>One exact configured value and its supported captured service registration.</summary>
public sealed record DelegationServiceOccurrence(int ConfigurationOrdinal, string ConfiguredService,
    int RegistrationOrdinal, string RegisteredService);

/// <summary>Stored grant references retain entry ordinals; they never expand a group into requesters.</summary>
public sealed record ResourceDelegationGrant(string TrusteeSid, IReadOnlyList<int> EntryOrdinals, bool NullDacl);

/// <summary>Saved configuration and shared relevance binding; successful Kerberos operations remain separate.</summary>
public sealed record DelegationConfigurationEvidence(DelegationConfigurationKind ConfigurationKind,
    string EvidenceSeal, Guid DerivationGenerationId, string DerivationSeal, int PolicyVersion,
    int DescriptorParserVersion, DelegationConfigurationAccount Account, DelegationConfigurationAccount Resource,
    DelegationResourceScope Scope, IReadOnlyList<DelegationServiceOccurrence> Services,
    IReadOnlyList<ResourceDelegationGrant> Grants, bool InputsComplete, IReadOnlyList<string> Limitations) : FindingEvidence
{
    /// <summary>Qualification of this saved finding, separate from its supported positive configuration.</summary>
    public bool IsComplete => InputsComplete && Account.Completeness == EvidenceCompleteness.Complete
        && Resource.Completeness == EvidenceCompleteness.Complete && Limitations.Count == 0 && Scope.Limitations.Count == 0;
}
