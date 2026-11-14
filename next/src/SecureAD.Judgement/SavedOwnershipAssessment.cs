using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Selected saved owner facts and qualifications, not a reconstructed permission-changing proof.</summary>
public sealed record SavedOwnershipAssessment(FindingReference Reference, string RuleId, FindingSubject Subject,
    SavedDelegationIdentity Object, string Name, string OwnerSid, string? OwnerName,
    ObjectOwnerStanding Standing, bool MembershipWasComplete, EvidenceCompleteness Coverage)
{
    public const string OrdinaryTitle = "Object ownership outside the saved owner policy";
    public const string ProtectedTitle = "Protected-object ownership outside the saved owner policy";
    public const string Risk = "The saved assessment flagged the recorded owner under the product's target-scoped owner policy. Ownership can provide permission-changing authority, but not unconditionally: OWNER RIGHTS entries, separately granted permissions and applicable directory-server restrictions matter. A recorded missing owner is not an actor that can exercise rights. This is an ownership observation at capture time, not proof of full control, abuse, a successful operation, takeover or a completed Tier 0 path.";
    public const string ProtectedRisk = "The saved assessment also classified this target as AdminSDHolder-protected. This does not date an ownership change, establish that SDProp stopped or promise automatic repair within an hour.";
    public const string Action = "Confirm the intended owner and administrative responsibility for this object. When authorised, verify current ownership and relevant permission-changing rights, including OWNER RIGHTS and independent grants, before acting. If ownership is inappropriate, change it to a valid, monitored principal appropriate to this object's administrative scope, under change control, then test dependent management and services. Do not blanket-replace computer or service-account owners or delete legitimate permission entries. Changing the owner does not remove other grants or establish that all unwanted access is gone.";
    public const string MissingOwnerNote = "Verify absence against the authorised scope before treating the owner as deleted; an unresolved name alone is not enough. Other principals may still have management rights.";
    public const string ScopeNote = "Owner acceptance is a product policy, not proof that the owner lacks administrative rights. This finding does not store a detailed permission-changing proof. This window does not reassess owner authorisation, protection or live server behaviour.";
    public const string MembershipNote = "The saved owner-policy membership evidence is incomplete. Do not treat this as proof that no accepted administrative relationship exists.";
    public const string InvalidDetails = "The selected finding's saved ownership details are missing, invalid or inconsistent.";

    public bool IsProtected => RuleId == "SEC-032";
    public bool Matches(FindingListItem finding) => RuleId is "SEC-031" or "SEC-032" && finding.RuleId == RuleId
        && finding.RuleVersion == 3 && finding.Severity == (IsProtected ? Severity.Medium : Severity.Low)
        && Reference == finding.Reference && Reference.GenerationId != Guid.Empty && Reference.FindingId > 0
        && Subject == finding.Subject && Subject is { Kind: FindingSubjectKind.DirectoryObject }
        && Object is { IsValid: true } && Object.ObjectGuid == finding.ObjectGuid
        && Object.DistinguishedName == finding.DistinguishedName && Object.DomainFqdn == finding.DomainFqdn
        && Object.ObjectClass == finding.ObjectClass && !string.IsNullOrWhiteSpace(Name) && Name == finding.PrincipalName
        && Sid.ToBytes(OwnerSid) is not null && (OwnerName is null || !string.IsNullOrWhiteSpace(OwnerName))
        && Enum.IsDefined(Standing) && MembershipWasComplete == finding.EvidenceIsComplete
        && Coverage == finding.Coverage && Enum.IsDefined(Coverage);
}
