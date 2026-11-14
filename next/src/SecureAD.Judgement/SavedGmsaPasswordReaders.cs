using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>A selected position among one finding's saved permission holders.</summary>
public readonly record struct GmsaPasswordReaderMark(Guid GenerationId, long FindingId, Guid ObjectGuid, int Ordinal);

/// <summary>Prepared whole-finding context, independent of the loaded holder page.</summary>
public sealed record GmsaPasswordReaderContext(
    FindingReference Reference, Guid ObjectGuid, string DistinguishedName, string DomainFqdn,
    string? AccountName, bool? AccountIsDisabled, string BroadSid, string BroadName,
    bool EvidenceIsComplete, int HolderCount, int OriginalEntryCount, bool HasNullDacl,
    IReadOnlyList<string> Limitations)
{
    public bool IsComplete => EvidenceIsComplete;
    public string ServiceAccount => AccountName ?? DistinguishedName;
    public string AccountState => AccountIsDisabled is null ? "Not established from captured evidence."
        : AccountIsDisabled.Value ? "Disabled" : "Enabled";
    public string Why => GmsaPasswordReaders.Why;
    public string WhatToReview => GmsaPasswordReaders.Guidance;
    public string ScopeNote => GmsaPasswordReaders.Scope;
    public string IncompleteNote => GmsaPasswordReaders.Incomplete;
    public string NullDaclNote => "The captured password-reader descriptor has a NULL permission list. "
        + "This is not an explicit Everyone permission entry. Review the password-reader configuration rather than deleting an invented entry.";

    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-102" && finding.RuleVersion == 1
        && finding.Severity == Severity.High && finding.Reference == Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && ObjectGuid != Guid.Empty && ObjectGuid == finding.ObjectGuid
        && DistinguishedName == finding.DistinguishedName && DomainFqdn == finding.DomainFqdn
        && finding.ObjectClass == "msDS-GroupManagedServiceAccount" && BroadPrincipalCatalogue.IsBroad(BroadSid)
        && BroadName == BroadPrincipalCatalogue.NameOf(BroadSid)
        && finding.Subject == new FindingSubject(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(BroadSid))
        && EvidenceIsComplete == finding.EvidenceIsComplete && HolderCount > 0 && OriginalEntryCount >= 0
        && (!HasNullDacl || BroadSid == "S-1-1-0" && OriginalEntryCount == 0)
        && Limitations is not null && Limitations.All(value => !string.IsNullOrWhiteSpace(value))
        && EvidenceIsComplete == (Limitations.Count == 0);

    public bool SameQuestion(GmsaPasswordReaderContext other) => other.Limitations is not null
        && Limitations.SequenceEqual(other.Limitations, StringComparer.Ordinal)
        && this == (other with { Limitations = Limitations });
}

/// <summary>One saved named-holder summary; membership witnesses and original bytes remain in proof storage.</summary>
public sealed record SavedGmsaPasswordReaderHolder(int Ordinal, string Sid, string? Scope, string? Name,
    bool IncludedDirectly, int GrantCount, bool HasInheritedGrant, bool HasNullDacl, bool MembershipIsComplete)
{
    public bool IsComplete => MembershipIsComplete;
    public string PermissionHolder => Name ?? Sid;
    public string Inclusion => IncludedDirectly ? "Included directly" : "Through a group";
}

/// <summary>A bounded page of saved holders, never a repeated password or membership assessment.</summary>
public sealed record SavedGmsaPasswordReaders(GmsaPasswordReaderContext Context,
    IReadOnlyList<SavedGmsaPasswordReaderHolder> Holders, GmsaPasswordReaderMark? Next)
{
    public const int PageSize = 50;
    public const string InvalidDetails = "The selected finding's saved gMSA password-reader details are missing, invalid or inconsistent.";
    public const string IncompleteExplanation = GmsaPasswordReaders.Incomplete;
    public bool IsComplete => Context.IsComplete;

    public static string DescribeLimitation(string token)
    {
        if (token == "CaptureIncomplete") return "The capture is incomplete. Other access may exist.";
        if (token == GmsaPasswordReaders.Attribute) return "The password-reader configuration was not captured.";
        var parts = token.Split('.');
        if (parts.Length == 3 && parts[0] == "CapturedInput" && parts[1] == GmsaPasswordReaders.Attribute)
            return parts[2] switch
            {
                nameof(CapturedInputIssueKind.ZeroValue) => "No password-reader value was returned; it may be unset or unreadable.",
                nameof(CapturedInputIssueKind.UnusableValue) => "The captured password-reader value is empty or unusable.",
                nameof(CapturedInputIssueKind.UnsupportedRepresentation) => "The captured password-reader value has an unsupported representation.",
                nameof(CapturedInputIssueKind.IncompleteValue) => "The captured password-reader descriptor or its resource identity could not be read completely.",
                _ => token + ": this input could not be interpreted.",
            };
        if (parts.Length == 2 && parts[0] == nameof(DerivedFactKind.PrincipalExpansion))
            return parts[1] switch
            {
                nameof(UnresolvedReason.NotDerived) => "The saved group data could not establish this reader's membership.",
                nameof(UnresolvedReason.MembershipIncomplete) => "The captured group membership could not be followed completely. Other broad reader relationships may exist.",
                nameof(UnresolvedReason.MembershipProcessingLimit) => "The existing membership calculation reached its recorded processing limit; other reader relationships remain unassessed.",
                nameof(UnresolvedReason.MembershipScopeUnsupported) => "A captured membership relationship could not be qualified for this account's resource domain.",
                nameof(UnresolvedReason.IdentityUnreadable) => "A captured identity needed to interpret a password-reader entry is unavailable.",
                nameof(UnresolvedReason.GmsaReaderGroupTypeUnavailable) => "A group in a reader-membership route has no usable captured security-group type.",
                nameof(UnresolvedReason.GmsaReaderConditionalEntryUnsupported) => "A captured password-reader entry has an unsupported condition or entry type.",
                nameof(UnresolvedReason.GmsaReaderScopeUnsupported) => "An object-specific scope in the password-reader descriptor is not supported by this assessment.",
                nameof(UnresolvedReason.GmsaReaderDenialUnassessed) => "A denial depends on an individual requester's authorization and could not be settled from the named-holder evidence.",
                _ => "The password-reader permission could not be fully assessed: " + token + ".",
            };
        return token + ": a required captured input is unavailable.";
    }

    public bool IsExpectedPage(int after)
    {
        if (after < -1 || after >= Context.HolderCount || Holders.Count != Math.Min(PageSize, Context.HolderCount - after - 1))
            return false;
        for (var index = 0; index < Holders.Count; index++)
        {
            var holder = Holders[index];
            if (holder.Ordinal != after + index + 1 || Sid.ToBytes(holder.Sid) is null
                || (Sid.IsBuiltinDomain(holder.Sid) ? holder.Scope != Context.DomainFqdn : holder.Scope is not null)
                || holder.GrantCount < 0 || holder.HasNullDacl != Context.HasNullDacl
                || holder.HasNullDacl && (holder.Sid != "S-1-1-0" || holder.GrantCount != 0)
                || !holder.HasNullDacl && holder.GrantCount == 0
                || holder.IncludedDirectly != (holder.Sid == Context.BroadSid)) return false;
        }
        var last = after + Holders.Count;
        return last + 1 < Context.HolderCount
            ? Next == new GmsaPasswordReaderMark(Context.Reference.GenerationId, Context.Reference.FindingId, Context.ObjectGuid, last)
            : Next is null;
    }
}
