using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public readonly record struct ReplicationPermissionMark(Guid GenerationId, long FindingId, Guid RootGuid, long EdgeId, int Ordinal);

public sealed record SavedReplicationPermissionEntry(int Ordinal, string EntryType, string Sid, string? Name,
    string Scope, bool IsInherited)
{
    public string Holder => Name ?? "Name not resolved from saved evidence.";
    public string Assignment => IsInherited ? "Inherited" : "Explicit";
    public string InheritanceNote => "The original source of this inherited assignment is not established by this finding.";
}

public sealed record ReplicationPermissionContext(FindingReference Reference, FindingSubject Subject,
    SavedDelegationIdentity Root, long EdgeId, string HolderSid, string? HolderScope, string? HolderName,
    string ExpectednessReason, bool HasNullDacl, bool CaptureIncomplete, bool OtherLimitations,
    bool EvidenceIsComplete, long OriginalEntryCount)
{
    public string Holder => HolderName ?? "Name not resolved from saved evidence.";
    public string Unexpectedness => SavedPermissionReview.Describe(ExpectednessReason, SavedReplicationPermission.InvalidDetails);
    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-002" && finding.RuleVersion == 1
        && finding.Severity == Severity.Critical && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && EdgeId > 0 && Subject == finding.Subject
        && Subject is { Kind: FindingSubjectKind.DirectoryObject } && Subject.Key == UnexpectedDomainSecretReplication.Key(HolderSid, HolderScope)
        && Root is { IsValid: true } && Root.ObjectGuid == finding.ObjectGuid && Root.DistinguishedName == finding.DistinguishedName
        && Root.DomainFqdn == finding.DomainFqdn && Root.ObjectClass == finding.ObjectClass
        && string.Equals(Root.ObjectClass, "domainDNS", StringComparison.OrdinalIgnoreCase)
        && Sid.ToBytes(HolderSid) is not null && (HolderName is null || !string.IsNullOrWhiteSpace(HolderName))
        && (Sid.IsBuiltinDomain(HolderSid) ? HolderScope == Root.DomainFqdn : HolderScope is null)
        && ExpectednessReason is nameof(ControlExpectednessReason.UnexpectedBroadPrincipal)
            or nameof(ControlExpectednessReason.UnexpectedNotControlPlane) or nameof(ControlExpectednessReason.UnexpectedOutsideAuthorityScope)
        && EvidenceIsComplete == finding.EvidenceIsComplete && EvidenceIsComplete == (!CaptureIncomplete && !OtherLimitations)
        && OriginalEntryCount is >= 0 and <= int.MaxValue
        && (HasNullDacl ? HolderSid == "S-1-1-0" && OriginalEntryCount == 0 : OriginalEntryCount > 0);
}

public sealed record SavedReplicationPermission(ReplicationPermissionContext Context,
    IReadOnlyList<SavedReplicationPermissionEntry> Entries, ReplicationPermissionMark? Next, long EntriesBefore = 0)
{
    public const int PageSize = 50;
    public const string Statement = UnexpectedDomainSecretReplication.Explanation;
    public const string ScopeNote = UnexpectedDomainSecretReplication.ScopeNote;
    public const string InvalidDetails = "The selected finding's saved replication-permission details are missing, invalid or inconsistent.";
    public const string PolicyNote = "Unexpected is the product's saved review result, not proof of malicious use or that the permission is unnecessary.";
    public const string EntryNote = "These are original permission entries supporting the saved assessment, not separate findings or authorization for individual group members.";

    public bool IsExpectedPage(int after)
    {
        if (Context is null || Entries is null || after < -1) return false;
        if (Context.HasNullDacl) return after == -1 && EntriesBefore == 0 && Entries.Count == 0 && Next is null;
        if (EntriesBefore < 0 || EntriesBefore >= Context.OriginalEntryCount || EntriesBefore % PageSize != 0
            || (after == -1) != (EntriesBefore == 0)
            || Entries.Count != Math.Min(PageSize, Context.OriginalEntryCount - EntriesBefore)
            || (Context.OriginalEntryCount - EntriesBefore > PageSize) != (Next is not null)) return false;
        var previous = after;
        foreach (var entry in Entries)
        {
            if (entry is null || entry.Ordinal <= previous || Sid.ToBytes(entry.Sid) is null
                || entry.Name is not null && string.IsNullOrWhiteSpace(entry.Name)
                || entry.EntryType is not ("Allow" or "Deny" or "Other saved entry (not re-evaluated here)")
                || entry.Scope is not ("Replicating Directory Changes" or "Replicating Directory Changes All"
                    or "Replicating Directory Changes In Filtered Set" or "All extended rights" or "Other saved scope (not re-evaluated here)"))
                return false;
            previous = entry.Ordinal;
        }
        return Next is not { } mark || Entries.Count == PageSize && mark.GenerationId == Context.Reference.GenerationId
            && mark.FindingId == Context.Reference.FindingId && mark.RootGuid == Context.Root.ObjectGuid
            && mark.EdgeId == Context.EdgeId && mark.Ordinal == Entries[^1].Ordinal;
    }
}
