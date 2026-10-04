namespace SecureAD.Evidence.Findings;

/// <summary>
/// References all qualified unexpected questions for one account in one saved calculation.
/// Concrete destinations and routes are evidence, not separate finding identities.
/// </summary>
public sealed record Tier0RouteFindingEvidence(
    Guid GenerationId, Guid? DerivationGenerationId, string EvidenceSeal,
    string CalculationFingerprint, string Anchor, Guid RequesterGuid, string RequesterSid,
    string RequesterDn, int UnexpectedChecks, string QualificationFingerprint) : FindingEvidence;
