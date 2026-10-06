using System.Globalization;
using System.Resources;
using SecureAD.Evidence;
using SecureAD.Kernel.Security;

namespace SecureAD.Shell.ViewModels;

internal static class DelegationText
{
    private static readonly ResourceManager Messages = new("SecureAD.Shell.Resources.DelegationPresentation", typeof(DelegationText).Assembly);
    internal static string Get(string key) => Messages.GetString(key, CultureInfo.CurrentUICulture)
        ?? throw new MissingManifestResourceException(key);
    internal static string Format(string key, params object?[] values) =>
        string.Format(CultureInfo.CurrentCulture, Get(key), values);
    public static string Heading => Get(nameof(Heading));
    public static string Boundary => Get(nameof(Boundary));
    public static string Principal => Get(nameof(Principal));
    public static string MatchingPrincipal => Get(nameof(MatchingPrincipal));
    public static string FindPrincipal => Get(nameof(FindPrincipal));
    public static string MorePrincipals => Get(nameof(MorePrincipals));
    public static string Permission => Get(nameof(Permission));
    public static string IncludeInherited => Get(nameof(IncludeInherited));
    public static string IncludeGroups => Get(nameof(IncludeGroups));
    public static string PermissionHolder => Get(nameof(PermissionHolder));
    public static string FindDelegations => Get(nameof(FindDelegations));
    public static string Cancel => Get(nameof(Cancel));
    public static string RecordedOn => Get(nameof(RecordedOn));
    public static string Domain => Get(nameof(Domain));
    public static string AppliesTo => Get(nameof(AppliesTo));
    public static string EntryType => Get(nameof(EntryType));
    public static string Inheritance => Get(nameof(Inheritance));
    public static string InheritedNote => Get(nameof(InheritedNote));
    public static string Previous => Get(nameof(Previous));
    public static string Next => Get(nameof(Next));
    public static string OpenDetails => Get(nameof(OpenDetails));
    public static string SearchTitle => Get(nameof(SearchTitle));
    public static string PrincipalStep => Get(nameof(PrincipalStep));
    public static string PermissionStep => Get(nameof(PermissionStep));
    public static string EntriesTitle => Get(nameof(EntriesTitle));
    public static string SelectedEntryTitle => Get(nameof(SelectedEntryTitle));
    public static string OriginalEvidence => Get(nameof(OriginalEvidence));
    public static string MembershipChain => Get(nameof(MembershipChain));
}

internal sealed record DelegationPermissionChoice(DelegationPermission Value, string Name);

internal sealed record DelegationPrincipalChoice(DelegationPrincipal Principal)
{
    public string Label => $"{Principal.Name} | {Principal.DomainFqdn ?? DelegationText.Get("Unresolved")} | {Principal.Sid}";
}

internal sealed class DelegationRowViewModel(DelegationEntry source, PermissionVocabulary vocabulary,
    DelegationMembershipPresentation? membership)
{
    internal DelegationRowViewModel(DelegationEntry source, PermissionVocabulary vocabulary) : this(source, vocabulary, null) { }
    public DelegationEntry Source { get; } = source;
    public string RecordedOn => Source.DistinguishedName;
    public string Domain => Source.DomainFqdn;
    public string PermissionHeldBy => (Source.Entry.Trustee.Name ?? Source.Entry.Trustee.Sid)
        + (Source.Entry.Trustee.DomainFqdn is { } domain ? $" ({domain})" : "");
    public string Permission { get; } = vocabulary.Words.Describe(source.Entry.AccessMask, source.Entry.ObjectTypeGuid).Summary;
    public string AppliesTo { get; } = vocabulary.Scopes.Describe(source.Entry.InheritanceFlags,
        source.Entry.PropagationFlags, source.Entry.IsInherited, source.Entry.InheritedObjectTypeGuid).AppliesTo
        + (source.ScopeQualification is null ? "" : " - " + source.ScopeQualification);
    public string Inheritance => DelegationText.Get(Source.Entry.IsInherited ? "Inherited" : "Explicit");
    public string EntryType => Source.Entry.AceType switch
    {
        "AccessAllowed" or "AccessAllowedObject" => DelegationText.Get("Allow"),
        "AccessDenied" or "AccessDeniedObject" => DelegationText.Get("Deny"),
        "AccessAllowedCallback" or "AccessAllowedCallbackObject" => DelegationText.Format("Conditional", DelegationText.Get("Allow")),
        "AccessDeniedCallback" or "AccessDeniedCallbackObject" => DelegationText.Format("Conditional", DelegationText.Get("Deny")),
        _ => DelegationText.Format("Unsupported", Source.Entry.AceType),
    };
    public string MembershipDetail => Source.HolderMembershipId is { } holder
        ? membership?.Describe(holder) ?? throw new InvalidOperationException(DelegationText.Get("MembershipInvalid"))
        : DelegationText.Get("DirectEntry");
    public string OriginalDetail => DelegationText.Format("HolderDetail", PermissionHeldBy, Source.Entry.Trustee.Sid)
        + "\n" + DelegationText.Format("Detail", RecordedOn, Source.Entry.Ordinal, Source.DescriptorId,
        Source.Entry.AccessMask, Source.Entry.AceType, Source.Entry.ObjectTypeGuid ?? "-", Source.Entry.InheritedObjectTypeGuid ?? "-",
        Source.Entry.InheritanceFlags, Source.Entry.PropagationFlags, Source.DaclCompleteness, Source.ScopeQualification ?? "");
    public string Detail => MembershipDetail + "\n" + OriginalDetail;
}
