using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public enum BroadMembershipPageKind { Sources, Links, Values, Limitations }
public sealed record SavedBroadMembershipIdentity(Guid ObjectGuid, string DistinguishedName, string NamingContext,
    string? DomainFqdn, string Sid, string? SidScope, string ObjectClass, long? GroupType)
{
    internal bool IsValid => ObjectGuid != Guid.Empty && !string.IsNullOrWhiteSpace(DistinguishedName)
        && !string.IsNullOrWhiteSpace(NamingContext) && SecureAD.Kernel.Security.Sid.ToBytes(Sid) is not null
        && GroupMembershipFindingStorage.Within(DistinguishedName, NamingContext)
        && (SecureAD.Kernel.Security.Sid.IsBuiltinDomain(Sid) ? DomainFqdn is not null
            && string.Equals(SidScope, DomainFqdn, StringComparison.OrdinalIgnoreCase) : SidScope is null)
        && (ObjectClass == "foreignSecurityPrincipal" ? GroupType is null
            : ObjectClass == "group" && GroupType is { } type && type is >= int.MinValue and <= uint.MaxValue && (type & 0x80000000L) != 0
                && (type & 0x0f) is 2 or 4 or 5 or 8
                && ((type & 0x0f) == 5) == SecureAD.Kernel.Security.Sid.IsBuiltinDomain(Sid));
}
public sealed record SavedBroadIdentity(string Sid, string? SidScope, string Name);
public sealed record SavedBroadMembershipLink(long Position, SavedBroadMembershipIdentity ContainingGroup,
    SavedBroadMembershipIdentity Member, SavedBroadMembershipIdentity RecordedThrough, long WitnessCount);
public sealed record SavedBroadMembershipWitness(SavedBroadMembershipIdentity Source, string Attribute, int OriginalOrdinal, string Value);
public sealed record SavedBroadMembershipContext(FindingReference Reference, string RuleId, FindingSubject Subject,
    SavedBroadMembershipIdentity Target, long SourceCount, long LinkCount, long LimitationCount, bool InputsComplete, bool IsComplete)
{
    public const int PageSize = 50;
    public const string InvalidDetails = "The selected finding's saved broad-membership details are missing, invalid or inconsistent.";
    public static string DescribeLimitation(AdministrativeMembershipReason reason) => CapturedGroupMembershipIndex.Describe(reason);
    public bool Matches(FindingListItem finding) => RuleId is "SEC-061" or "SEC-062" && finding.RuleId == RuleId
        && finding.RuleVersion == 1 && finding.Severity == (RuleId == "SEC-061" ? Severity.Medium : Severity.High)
        && Reference == finding.Reference && Reference.GenerationId != Guid.Empty && Reference.FindingId > 0
        && Subject == finding.Subject && Subject.Kind == FindingSubjectKind.DirectoryObject
        && Target is { IsValid: true, ObjectClass: "group" } && Target.ObjectGuid == finding.ObjectGuid
        && Target.DistinguishedName == finding.DistinguishedName && Target.DomainFqdn == finding.DomainFqdn
        && finding.ObjectClass == "group" && Subject.Key == Target.ObjectGuid.ToString("D")
        && SourceCount > 0 && LinkCount > 0 && LimitationCount >= 0
        && IsComplete == (InputsComplete && LimitationCount == 0) && IsComplete == finding.EvidenceIsComplete;
    internal bool Matches(BroadMembershipMark mark, BroadMembershipPageKind kind, long link, long total) =>
        mark.GenerationId == Reference.GenerationId && mark.FindingId == Reference.FindingId
        && mark.TargetGuid == Target.ObjectGuid && mark.Kind == kind && mark.LinkPosition == link
        && mark.Offset > 0 && mark.Offset < total && mark.Offset % PageSize == 0;
}
public readonly record struct BroadMembershipMark(Guid GenerationId, long FindingId, Guid TargetGuid,
    BroadMembershipPageKind Kind, long LinkPosition, long Offset);
public sealed record SavedBroadMembershipRow<T>(long Position, T Value);
public sealed record SavedBroadMembershipPage<T>(SavedBroadMembershipContext Context, BroadMembershipPageKind Kind,
    SavedBroadMembershipLink? SelectedLink, IReadOnlyList<SavedBroadMembershipRow<T>> Rows, BroadMembershipMark? Next)
{
    public bool IsExpectedPage(BroadMembershipMark? after)
    {
        var expected = typeof(T) == typeof(SavedBroadIdentity) ? BroadMembershipPageKind.Sources
            : typeof(T) == typeof(SavedBroadMembershipLink) ? BroadMembershipPageKind.Links
            : typeof(T) == typeof(SavedBroadMembershipWitness) ? BroadMembershipPageKind.Values
            : typeof(T) == typeof(AdministrativeMembershipLimitation) ? BroadMembershipPageKind.Limitations : (BroadMembershipPageKind?)null;
        if (Context is null || Rows is null || Kind != expected || (Kind == BroadMembershipPageKind.Values) != (SelectedLink is not null)) return false;
        var total = Kind switch { BroadMembershipPageKind.Sources => Context.SourceCount, BroadMembershipPageKind.Links => Context.LinkCount,
            BroadMembershipPageKind.Values => SelectedLink!.WitnessCount, _ => Context.LimitationCount };
        var link = SelectedLink?.Position ?? -1;
        var start = after?.Offset ?? 0;
        return start >= 0 && (start < total || start == 0 && total == 0)
            && (after is not { } previous || Context.Matches(previous, Kind, link, total))
            && Rows.Count == Math.Min(SavedBroadMembershipContext.PageSize, total - start)
            && Rows.Select((row, index) => row is not null && row.Position == start + index && ValidValue(row)).All(value => value)
            && (Next is not null) == (start + Rows.Count < total)
            && (Next is not { } next || Context.Matches(next, Kind, link, total) && next.Offset == start + Rows.Count);
    }
    private bool ValidValue(SavedBroadMembershipRow<T> row) => row.Value switch
    {
        SavedBroadIdentity source => Sid.ToBytes(source.Sid) is not null && !string.IsNullOrWhiteSpace(source.Name)
            && (Sid.IsBuiltinDomain(source.Sid) ? !string.IsNullOrWhiteSpace(source.SidScope) : source.SidScope is null),
        SavedBroadMembershipLink link => link.Position == row.Position && link.WitnessCount > 0
            && link.ContainingGroup is { IsValid: true, ObjectClass: "group" }
            && link.Member is { IsValid: true } && link.RecordedThrough is { IsValid: true }
            && string.Equals(link.Member.Sid, link.RecordedThrough.Sid, StringComparison.OrdinalIgnoreCase),
        SavedBroadMembershipWitness value => SelectedLink is { } selected && value.OriginalOrdinal >= 0
            && (value.Attribute == "member" ? value.Source == selected.ContainingGroup
                && string.Equals(value.Value, selected.RecordedThrough.DistinguishedName, StringComparison.OrdinalIgnoreCase)
                : value.Attribute == "memberOf" && value.Source == selected.RecordedThrough
                    && string.Equals(value.Value, selected.ContainingGroup.DistinguishedName, StringComparison.OrdinalIgnoreCase)),
        AdministrativeMembershipLimitation limitation => Enum.IsDefined(limitation.Reason) && !string.IsNullOrWhiteSpace(limitation.DistinguishedName),
        _ => false,
    };
}
