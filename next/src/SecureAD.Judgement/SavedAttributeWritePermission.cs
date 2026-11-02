using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>Original assignment breadth, not a recalculated effective permission.</summary>
public enum SavedPropertyWriteScope
{
    Attribute,
    PropertySet,
    ObjectClass,
    AllProperties,
}

/// <summary>One selected original allow/deny occurrence, without raw masks or interpretation bulk.</summary>
public sealed record SavedPropertyWriteEntry(int Ordinal, bool IsDeny, SavedPropertyWriteScope Scope,
    string? ScopeName, bool IsInherited)
{
    public string EntryType => IsDeny ? "Deny" : "Allow";
    public string Assignment => IsInherited ? "Inherited" : "Explicit";
    public string InheritanceNote => "The original source of this inherited assignment is not established by this finding.";
    public string PermissionScope => Scope switch
    {
        SavedPropertyWriteScope.Attribute => "RBCD attribute",
        SavedPropertyWriteScope.PropertySet => ScopeName is null ? "Property set (captured name unavailable)" : "Property set: " + ScopeName,
        SavedPropertyWriteScope.ObjectClass => ScopeName is null ? "Object class (captured name unavailable)" : "Object class: " + ScopeName,
        SavedPropertyWriteScope.AllProperties => "All properties",
        _ => throw new InvalidDataException(SavedAttributeWritePermission.InvalidDetails),
    };
}

/// <summary>A position in one selected finding's original shared-entry links.</summary>
public readonly record struct AttributeWritePermissionMark(Guid GenerationId, long FindingId, Guid TargetGuid, int Ordinal);

/// <summary>Saved SEC-014 context, independent of the currently loaded permission-entry page.</summary>
public sealed record AttributeWritePermissionContext(FindingReference Reference, FindingSubject Subject,
    SavedDelegationIdentity Target, string HolderSid, string? HolderScope, string? HolderName,
    string ExpectednessReason, bool? AccountIsDisabled, bool HasNullDacl, bool EvidenceIsComplete,
    bool CaptureIncomplete, bool OtherLimitations)
{
    public string PermissionHolder => HolderName ?? HolderSid;
    public string AccountState => AccountIsDisabled is null ? "Not established from captured evidence."
        : AccountIsDisabled.Value ? "Disabled" : "Enabled";
    public string Unexpectedness => ExpectednessReason switch
    {
        nameof(ControlExpectednessReason.UnexpectedBroadPrincipal) => "The holder is a broadly applicable identity.",
        nameof(ControlExpectednessReason.UnexpectedNotControlPlane) =>
            "The saved assessment does not identify this holder as an expected administrator for this target.",
        nameof(ControlExpectednessReason.UnexpectedOutsideAuthorityScope) =>
            "The holder is outside its expected administrative authority for this target in the saved assessment.",
        _ => throw new InvalidDataException(SavedAttributeWritePermission.InvalidDetails),
    };

    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-014" && finding.RuleVersion == 1
        && finding.Severity == Severity.High && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Target is { IsValid: true } && Target.ObjectGuid == finding.ObjectGuid
        && Target.DistinguishedName == finding.DistinguishedName && Target.DomainFqdn == finding.DomainFqdn
        && Target.ObjectClass == finding.ObjectClass && Subject == finding.Subject && Subject is { Kind: FindingSubjectKind.Account }
        && Sid.ToBytes(HolderSid) is not null && Subject.Key == AttributeWriteRules.Key(HolderSid, HolderScope)
        && (Sid.IsBuiltinDomain(HolderSid) ? HolderScope == Target.DomainFqdn : HolderScope is null)
        && (HolderName is null || !string.IsNullOrWhiteSpace(HolderName))
        && ExpectednessReason is nameof(ControlExpectednessReason.UnexpectedBroadPrincipal)
            or nameof(ControlExpectednessReason.UnexpectedNotControlPlane) or nameof(ControlExpectednessReason.UnexpectedOutsideAuthorityScope)
        && EvidenceIsComplete == finding.EvidenceIsComplete && EvidenceIsComplete == (!CaptureIncomplete && !OtherLimitations)
        && (!HasNullDacl || HolderSid == "S-1-1-0");

    public IReadOnlyList<string> DescribeLimitations()
    {
        var result = new List<string>();
        if (CaptureIncomplete) result.Add("The capture is incomplete. The supported permission shown here remains a finding.");
        if (OtherLimitations) result.Add("Other saved permission or holder-assessment limitations apply. This is not a complete assessment of every permission.");
        return result;
    }
}

/// <summary>A selected SEC-014 page served from original saved metadata and shared-entry links.</summary>
public sealed record SavedAttributeWritePermission(AttributeWritePermissionContext Context,
    IReadOnlyList<SavedPropertyWriteEntry> Entries, AttributeWritePermissionMark? Next)
{
    public const int PageSize = 50;
    public const string AttributeName = "msDS-AllowedToActOnBehalfOfOtherIdentity";
    public const string InvalidDetails = "The selected finding's saved RBCD-write permission details are missing, invalid or inconsistent.";
    public const string ScopeNote = "Permission to edit RBCD configuration is not an existing delegation grant. SEC-013 reports captured RBCD configuration grants.";
    public const string NullDaclNote = "The captured object security descriptor has a NULL DACL (no discretionary access list). This finding is not an explicit Everyone permission entry. Review the object's permission configuration rather than deleting an invented entry.";

    public bool IsExpectedPage(int after)
    {
        if (Context is null || Entries is null || after < -1) return false;
        if (Context.HasNullDacl) return after == -1 && Entries.Count == 0 && Next is null;
        if (Entries.Count is < 1 or > PageSize) return false;
        var previous = after;
        foreach (var entry in Entries)
        {
            if (entry is null || entry.Ordinal <= previous || !Enum.IsDefined(entry.Scope)
                || entry.ScopeName is not null && string.IsNullOrWhiteSpace(entry.ScopeName)) return false;
            previous = entry.Ordinal;
        }
        return Next is not { } next || Entries.Count == PageSize && next.GenerationId == Context.Reference.GenerationId
            && next.FindingId == Context.Reference.FindingId && next.TargetGuid == Context.Target.ObjectGuid && next.Ordinal == previous;
    }
}
