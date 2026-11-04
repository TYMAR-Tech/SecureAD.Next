using SecureAD.Judgement;

namespace SecureAD.Shell.ViewModels;

internal sealed class ProtectionMarkerViewModel(SavedProtectionMarker saved)
{
    public string AffectedObject => saved.Name;
    public string ObjectType => saved.Object.ObjectClass;
    public string Domain => saved.Object.DomainFqdn;
    public string Location => saved.Object.DistinguishedName;
    public string Sid => saved.Sid;
    public string Statement => SavedProtectionMarker.Statement;
    public string ReportedAdminCount => "1";
    public string ReportedInheritance => "Disabled";
    public string SavedProtection => "Not protected";
    public string AssessmentNote => SavedProtectionMarker.AssessmentNote;
    public string ScopeNote => SavedProtectionMarker.ScopeNote;
}
