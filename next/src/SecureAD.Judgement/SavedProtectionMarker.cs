using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>One versioned saved positive assessment, not independently captured flags or a new protection check.</summary>
public sealed record SavedProtectionMarker(FindingReference Reference, FindingSubject Subject,
    SavedDelegationIdentity Object, string Name, string Sid, EvidenceCompleteness Coverage)
{
    public const string Statement = "The saved assessment reports adminCount=1 and blocked permission inheritance on an object assessed as not currently protected by AdminSDHolder.";
    public const string AssessmentNote = "These are the conditions reported by the saved finding, not a new check of the object or a measurement of SDProp.";
    public const string ScopeNote = "This finding does not prove past privilege, who set the marker, when inheritance was disabled, an unchanged AdminSDHolder permissions copy, absence of other privileges or failure of a live protection process.";
    public const string InvalidDetails = "The selected finding's saved protection-marker details are missing, invalid or inconsistent.";

    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-030" && finding.RuleVersion == 1
        && finding.Severity == Severity.Medium && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Subject == finding.Subject && Subject is { Kind: FindingSubjectKind.Account }
        && Object is { IsValid: true } && Object.ObjectGuid == finding.ObjectGuid
        && Object.DistinguishedName == finding.DistinguishedName && Object.DomainFqdn == finding.DomainFqdn
        && Object.ObjectClass == finding.ObjectClass && !string.IsNullOrWhiteSpace(Name) && Name == finding.PrincipalName
        && SecureAD.Kernel.Security.Sid.ToBytes(Sid) is not null && Coverage == finding.Coverage && Enum.IsDefined(Coverage);
}
