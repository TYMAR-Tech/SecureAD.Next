using SecureAD.Evidence.Findings;
using SecureAD.Judgement;

namespace SecureAD.Shell.ViewModels;

internal sealed class OwnershipAssessmentViewModel(SavedOwnershipAssessment saved)
{
    public string AffectedObject => saved.Name;
    public string ObjectType => saved.Object.ObjectClass;
    public string Domain => saved.Object.DomainFqdn;
    public string Location => saved.Object.DistinguishedName;
    public string OwnerName => saved.OwnerName ?? "Name not resolved from saved evidence.";
    public string OwnerSid => saved.OwnerSid;
    public string OwnerStatus => IsMissing ? "Recorded as missing in the saved assessment" : "Present in captured evidence";
    public string TargetClassification => saved.IsProtected ? "In the AdminSDHolder-protected set" : "Outside the AdminSDHolder-protected set";
    public string MembershipEvidence => saved.MembershipWasComplete ? "Complete" : "May be incomplete";
    public bool IsMissing => saved.Standing == ObjectOwnerStanding.DoesNotExist;
    public bool HasMembershipLimit => !saved.MembershipWasComplete;
    public string MissingOwnerNote => SavedOwnershipAssessment.MissingOwnerNote;
    public string MembershipNote => SavedOwnershipAssessment.MembershipNote;
    public string ScopeNote => SavedOwnershipAssessment.ScopeNote;
}
