using SecureAD.Kernel.Security;

namespace SecureAD.Evidence.Findings;

/// <summary>Original password-reader configuration, separate from the account's object descriptor.</summary>
public sealed record GmsaPasswordReaderSource(
    Guid ObjectGuid, string DistinguishedName, string DomainFqdn, string? AccountName,
    string? AccountSid, DateTimeOffset CapturedUtc, bool? AccountIsDisabled,
    byte[] Descriptor, DaclState DaclState, DaclCompleteness DaclCompleteness,
    bool DaclWasCanonical, IReadOnlyList<ParsedAce> Entries)
{
    public bool IsComplete => DaclCompleteness == DaclCompleteness.Complete
        && DaclState != DaclState.Unreadable && Descriptor.Length > 0;
}

/// <summary>A supported named-holder permission and captured broad-identity membership witness.</summary>
public sealed record GmsaPasswordReaderGrant(
    string HolderSid, string? HolderScope, string? HolderName,
    IReadOnlyList<PathStep> MembershipPath, bool MembershipIsComplete,
    IReadOnlyList<int> GrantOrdinals, IReadOnlyList<int> BlockingOrdinals, bool HasNullDacl)
{
    public bool IsDirect => MembershipPath.Count == 1;
    public bool IsComplete => MembershipIsComplete;
}

/// <summary>One account/broad-identity finding with original occurrences and fixed input bindings.</summary>
public sealed record GmsaPasswordReaderEvidence(
    Guid GenerationId, string EvidenceSeal, Guid DerivationGenerationId, string DerivationSeal,
    int PrincipalCatalogueVersion, int EngineVersion, GmsaPasswordReaderSource Source,
    string BroadSid, string BroadName, IReadOnlyList<GmsaPasswordReaderGrant> Grants,
    IReadOnlyList<string> Limitations) : FindingEvidence
{
    public bool IsComplete => Source.IsComplete && Limitations.Count == 0 && Grants.All(grant => grant.IsComplete);
}
