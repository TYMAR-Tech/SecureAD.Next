namespace SecureAD.Evidence.Findings;

/// <summary>Captured identity; no live service ownership or authentication is inferred.</summary>
public sealed record DuplicateSpnOwner(Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    string ObjectClass, string? AccountName);

public sealed record DuplicateSpnOccurrence(Guid OwnerGuid, int Ordinal, string Value);

/// <summary>One full-value match with all known distinct owners and original occurrences.</summary>
public sealed record DuplicateSpnMatch(string MatchKey, IReadOnlyList<DuplicateSpnOwner> Owners,
    IReadOnlyList<DuplicateSpnOccurrence> Occurrences);

/// <summary>Positive duplicates survive incomplete inventory; completeness never promises attribute visibility.</summary>
public sealed record DuplicateSpnEvidence(string EvidenceSeal, string ForestFqdn, Guid SubjectGuid,
    IReadOnlyList<DuplicateSpnMatch> Duplicates, IReadOnlyList<string> Limitations) : FindingEvidence
{
    public string Verdict => Limitations.Count == 0 ? "RecordedDuplicates" : "RecordedDuplicatesWithLimitations";
}
