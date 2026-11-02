using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Saved qualifications, not unloaded service pages or a new assessment.</summary>
[Flags]
public enum DelegationConfigurationInputLimitations
{
    /// <summary>No saved input or assessment limitation qualifies this finding.</summary>
    None = 0,
    /// <summary>The saved capture did not read all declared scope.</summary>
    CaptureIncomplete = 1,
    /// <summary>Some configured destinations lack a supported captured match.</summary>
    UnresolvedService = 2,
    /// <summary>Some captured registrations do not identify a unique supported resource.</summary>
    AmbiguousService = 4,
    /// <summary>Some other destinations lack positively established relevance.</summary>
    UnassessedResource = 8,
    /// <summary>Additional saved source or analysis limitations remain applicable.</summary>
    Other = 16,
    /// <summary>Some saved resource-based delegation configuration was not assessed.</summary>
    ConfigurationUnassessed = 32,
}

/// <summary>The saved identity of a delegating account or its matched resource.</summary>
public sealed record SavedDelegationIdentity(Guid ObjectGuid, string DistinguishedName, string DomainFqdn, string ObjectClass)
{
    internal bool IsValid => ObjectGuid != Guid.Empty && !string.IsNullOrWhiteSpace(DistinguishedName)
        && !string.IsNullOrWhiteSpace(DomainFqdn) && !string.IsNullOrWhiteSpace(ObjectClass);
}

/// <summary>A service position bound to one finding, resource and immutable judgement.</summary>
public readonly record struct DelegationConfigurationMark(Guid GenerationId, long FindingId, Guid ResourceGuid, long Offset);

/// <summary>A saved configured holder, with an optional uniquely resolved captured name, never its expanded members.</summary>
public sealed record SavedDelegationHolder(string Sid, string? Name = null)
{
    internal bool IsValid => SecureAD.Kernel.Security.Sid.ToBytes(Sid) is not null
        && WellKnownSidCatalog.FindBySid(Sid)?.NamesAPrincipal != false && (Name is null || !string.IsNullOrWhiteSpace(Name));

    /// <summary>A missing captured name does not replace or discard its original SID.</summary>
    public string DisplayName => Name ?? "Name not resolved from captured evidence.";
}

/// <summary>Selected saved context, without original attribute snapshots or relevance traversal.</summary>
public sealed record DelegationConfigurationContext(DelegationConfigurationKind Kind, FindingReference Reference, FindingSubject Subject,
    SavedDelegationIdentity Account, SavedDelegationIdentity Resource, bool EstablishedTier0,
    bool EvidenceIsComplete, DelegationConfigurationInputLimitations Limitations, bool HasNullDacl)
{
    private const DelegationConfigurationInputLimitations AllLimitations = DelegationConfigurationInputLimitations.CaptureIncomplete
        | DelegationConfigurationInputLimitations.UnresolvedService | DelegationConfigurationInputLimitations.AmbiguousService
        | DelegationConfigurationInputLimitations.UnassessedResource | DelegationConfigurationInputLimitations.Other;

    /// <summary>Checks the displayed identity and qualification against the exact selected saved row.</summary>
    public bool Matches(FindingListItem finding) => Account is { IsValid: true } && Resource is { IsValid: true }
        && Reference.GenerationId != Guid.Empty && Reference.FindingId > 0 && Reference == finding.Reference
        && Enum.IsDefined(Kind) && finding.RuleId == (IsResourceBased ? "SEC-013" : "SEC-012")
        && finding.RuleVersion == 1 && finding.Severity == Severity.High
        && Subject is not null && Subject == finding.Subject && Subject.Kind == FindingSubjectKind.Account
        && (IsResourceBased ? Account == Resource && Subject.Key == Resource.ObjectGuid.ToString("D")
            : !HasNullDacl && Subject.Key == DelegationConfigurationRules.Key(Account.ObjectGuid, Resource.ObjectGuid))
        && Account.ObjectGuid == finding.ObjectGuid && Account.DistinguishedName == finding.DistinguishedName
        && Account.DomainFqdn == finding.DomainFqdn && Account.ObjectClass == finding.ObjectClass
        && (Limitations & ~(IsResourceBased ? ResourceLimitations : AllLimitations)) == 0
        && EvidenceIsComplete == (Limitations == DelegationConfigurationInputLimitations.None)
        && EvidenceIsComplete == finding.EvidenceIsComplete;

    private const DelegationConfigurationInputLimitations ResourceLimitations =
        DelegationConfigurationInputLimitations.CaptureIncomplete | DelegationConfigurationInputLimitations.Other
        | DelegationConfigurationInputLimitations.ConfigurationUnassessed;

    /// <summary>The saved family, not a fresh interpretation of the descriptor.</summary>
    public bool IsResourceBased => Kind == DelegationConfigurationKind.ResourceBased;

    /// <summary>Readable saved limitations; multiple underlying reasons may qualify the same statement.</summary>
    public IReadOnlyList<string> DescribeLimitations()
    {
        var result = new List<string>();
        if (IsResourceBased)
        {
            if (Limitations.HasFlag(DelegationConfigurationInputLimitations.CaptureIncomplete))
                result.Add("The capture is incomplete. The supported grants shown here remain findings.");
            if (Limitations.HasFlag(DelegationConfigurationInputLimitations.ConfigurationUnassessed))
                result.Add("Some RBCD configuration could not be assessed. Supported saved grants remain listed; unassessed entries are not treated as a clean configuration.");
            if (Limitations.HasFlag(DelegationConfigurationInputLimitations.Other))
                result.Add("Additional saved evidence limitations apply. This is not a complete delegation assessment.");
            return result;
        }
        if (Limitations.HasFlag(DelegationConfigurationInputLimitations.UnresolvedService))
            result.Add("Some configured service names could not be matched to a supported captured resource.");
        if (Limitations.HasFlag(DelegationConfigurationInputLimitations.AmbiguousService))
            result.Add("Some configured service names have ambiguous captured registrations; no destination is guessed.");
        if (Limitations.HasFlag(DelegationConfigurationInputLimitations.UnassessedResource))
            result.Add("Tier 0 relevance could not be established for some other configured destinations.");
        if (Limitations.HasFlag(DelegationConfigurationInputLimitations.CaptureIncomplete))
            result.Add("The capture is incomplete. The supported matches shown here remain findings.");
        if (Limitations.HasFlag(DelegationConfigurationInputLimitations.Other))
            result.Add("Additional saved evidence limitations apply. This is not a complete assessment of every configured destination.");
        return result;
    }
}

/// <summary>One page of original supported service occurrences, never a reconstructed complete proof.</summary>
public sealed record SavedDelegationConfiguration(DelegationConfigurationContext Context,
    IReadOnlyList<string> Services, IReadOnlyList<SavedDelegationHolder> Holders, DelegationConfigurationMark? Next)
{
    /// <summary>The display-page size, not a limit on saved or reachable occurrences.</summary>
    public const int PageSize = 50;
    /// <summary>The retained finding statement, without the old embedded service inventory.</summary>
    public const string ConstrainedStatement = ConstrainedDelegationToRelevantService.Explanation;
    /// <summary>The boundary of a positive finding for one resource.</summary>
    public const string ConstrainedScopeNote = "Only supported matches to the resource shown are listed here. Unmatched, ambiguous or unassessed destinations are not treated as safe.";
    /// <summary>The explicit refusal when selected saved facts cannot be vouched for.</summary>
    public const string ConstrainedInvalidDetails = "The selected finding's saved delegation details are missing, invalid or inconsistent.";
    /// <summary>The retained resource-based finding statement.</summary>
    public const string ResourceStatement = ResourceBasedDelegationOnRelevantResource.Explanation;
    /// <summary>Configuration grants and authorization remain different claims.</summary>
    public const string ResourceScopeNote = "These are captured RBCD configuration grants, not permission to change that configuration or authorization for a particular requester.";
    /// <summary>The explicit refusal for selected resource-based facts.</summary>
    public const string ResourceInvalidDetails = "The selected finding's saved RBCD details are missing, invalid or inconsistent.";
    /// <summary>A NULL DACL is not a fabricated explicit Everyone entry.</summary>
    public const string NullDaclNote = "The captured RBCD configuration has a NULL DACL (no discretionary access list). No access list restricts delegation in this descriptor. This is not an explicit Everyone permission entry. Review the RBCD configuration itself rather than deleting an invented Everyone entry.";

    internal static string InvalidDetailsFor(DelegationConfigurationKind kind) =>
        kind == DelegationConfigurationKind.ResourceBased ? ResourceInvalidDetails : ConstrainedInvalidDetails;

    /// <summary>Checks page shape and continuation without deriving whole-question totals from the page.</summary>
    public bool IsExpectedPage(long offset)
    {
        if (Context is null || !Enum.IsDefined(Context.Kind) || Services is null || Holders is null
            || offset < 0 || offset > long.MaxValue - PageSize || offset % PageSize != 0) return false;
        if (Context.HasNullDacl)
            return Context.IsResourceBased && offset == 0 && Services.Count == 0 && Holders.Count == 0 && Next is null;
        var count = Context.IsResourceBased ? Holders.Count : Services.Count;
        return count is > 0 and <= PageSize
            && (Context.IsResourceBased ? Services.Count == 0 && Holders.All(holder => holder is { IsValid: true })
                : Holders.Count == 0 && Services.All(value => !string.IsNullOrWhiteSpace(value)))
            && (Next is not { } next || count == PageSize && next.GenerationId == Context.Reference.GenerationId
                && next.FindingId == Context.Reference.FindingId && next.ResourceGuid == Context.Resource.ObjectGuid
                && next.Offset == offset + PageSize);
    }
}
