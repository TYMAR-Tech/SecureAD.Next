using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public sealed record SavedReviewGroup(SavedDelegationIdentity Identity, string Sid, string? SidScope, long? GroupType);
public sealed record SavedGroupReview(FindingReference Reference, string RuleId, FindingSubject Subject,
    SavedReviewGroup Affected, SavedReviewGroup Destination, int? DirectCount, int? ReviewThreshold,
    int? KnownTotal, int? UnresolvedReferences, int? UnreadableReferences, GroupMembershipLimitations TotalLimitations,
    bool InputsComplete, string InputLimitations, bool IsComplete, long ReferenceCount, bool HasForeignReference)
{
    public bool IsSizeReview => RuleId == "SEC-050";
    public const int PageSize = 50;
    public static string InvalidDetails(string rule) => rule == "SEC-050"
        ? "The selected finding's saved group-size review details are missing, invalid or inconsistent."
        : "The selected finding's saved direct-nesting details are missing, invalid or inconsistent.";
    public static string Statement(string rule) => rule == "SEC-050" ? LargePrivilegedGroupReview.Explanation
        : rule == "SEC-051" ? GroupNestedInDomainAdmins.Explanation : throw new InvalidDataException("Unsupported membership-review rule.");
    public bool Matches(FindingListItem finding) => RuleId is "SEC-050" or "SEC-051" && finding.RuleId == RuleId
        && finding.RuleVersion == 1 && finding.Severity == Severity.Low && Reference == finding.Reference
        && Reference.GenerationId != Guid.Empty && Reference.FindingId > 0 && Subject == finding.Subject
        && Subject is { Kind: FindingSubjectKind.DirectoryObject } && Affected is not null && Destination is not null
        && Affected.Identity is { IsValid: true } && Destination.Identity is { IsValid: true }
        && Affected.Identity.ObjectGuid == finding.ObjectGuid && Affected.Identity.DistinguishedName == finding.DistinguishedName
        && Affected.Identity.DomainFqdn == finding.DomainFqdn && Affected.Identity.ObjectClass == finding.ObjectClass
        && Affected.Identity.ObjectClass == "group" && Destination.Identity.ObjectClass == "group"
        && Sid.ToBytes(Affected.Sid) is not null && Sid.ToBytes(Destination.Sid) is not null
        && IsComplete == finding.EvidenceIsComplete && ReferenceCount is > 0 and <= int.MaxValue
        && (IsSizeReview ? Affected == Destination && Subject.Key == Affected.Identity.ObjectGuid.ToString("D")
            && DirectCount > ReviewThreshold && ReviewThreshold >= 0 && KnownTotal >= 0 && UnresolvedReferences >= 0 && UnreadableReferences >= 0
            : Affected.Identity.ObjectGuid != Destination.Identity.ObjectGuid
                && Subject.Key == GroupNestedInDomainAdmins.Key(Affected.Identity.ObjectGuid, Destination.Identity.ObjectGuid)
                && DirectCount is null && ReviewThreshold is null && KnownTotal is null
                && UnresolvedReferences is null && UnreadableReferences is null && TotalLimitations == GroupMembershipLimitations.None);
}
public readonly record struct GroupReviewReferenceMark(Guid GenerationId, long FindingId, Guid AffectedGuid, Guid DestinationGuid, long Offset);
public sealed record SavedGroupReference(long Position, string? DistinguishedName)
{
    public string Value => string.IsNullOrWhiteSpace(DistinguishedName) ? "Unreadable saved reference." : DistinguishedName;
}
public sealed record SavedGroupReferences(SavedGroupReview Context, IReadOnlyList<SavedGroupReference> References, GroupReviewReferenceMark? Next)
{
    public bool IsExpectedPage(GroupReviewReferenceMark? after)
    {
        if (Context is null || References is null) return false;
        var start = after?.Offset ?? 0;
        return start >= 0 && start < Context.ReferenceCount
            && (after is not { } previous || previous.GenerationId == Context.Reference.GenerationId
                && previous.FindingId == Context.Reference.FindingId && previous.AffectedGuid == Context.Affected.Identity.ObjectGuid
                && previous.DestinationGuid == Context.Destination.Identity.ObjectGuid && previous.Offset > 0 && previous.Offset % SavedGroupReview.PageSize == 0)
            && References.Count == Math.Min(SavedGroupReview.PageSize, Context.ReferenceCount - start)
            && References.Select((value, index) => value is not null && value.Position == start + index).All(value => value)
            && (Next is not null) == (start + References.Count < Context.ReferenceCount)
            && (Next is not { } mark || mark.GenerationId == Context.Reference.GenerationId && mark.FindingId == Context.Reference.FindingId
                && mark.AffectedGuid == Context.Affected.Identity.ObjectGuid && mark.DestinationGuid == Context.Destination.Identity.ObjectGuid
                && mark.Offset == start + References.Count);
    }
}
