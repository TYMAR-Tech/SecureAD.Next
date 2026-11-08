using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public sealed record SavedCircularMembershipContext(FindingReference Reference, FindingSubject Subject,
    CircularMembershipGroup Anchor, int GroupCount, int LinkCount, bool InventoryComplete, EvidenceCompleteness CaptureCoverage)
{
    public const int PageSize = 50;
    public const string InvalidDetails = "The selected finding's saved circular-membership details are missing, invalid or inconsistent.";
    public bool Matches(FindingListItem finding) => finding.RuleId == "SEC-052" && finding.RuleVersion == 1
        && finding.Severity == Severity.Medium && Reference == finding.Reference && Reference.GenerationId != Guid.Empty
        && Reference.FindingId > 0 && Subject == finding.Subject && Subject.Kind == FindingSubjectKind.DirectoryObject
        && Subject.Key is { Length: 70 } && Subject.Key.StartsWith("cycle:", StringComparison.Ordinal)
        && ValidGroup(Anchor) && Anchor.ObjectGuid == finding.ObjectGuid && Anchor.DistinguishedName == finding.DistinguishedName
        && Anchor.DomainFqdn == finding.DomainFqdn && finding.ObjectClass == "group"
        && GroupCount > 0 && LinkCount > 0 && CaptureCoverage == finding.Coverage
        && (finding.CircularInventoryComplete is null || finding.CircularInventoryComplete == InventoryComplete);
    internal bool MatchesPosition(Guid generation, long finding, string component, long offset, long total) =>
        generation == Reference.GenerationId && finding == Reference.FindingId && component == Subject.Key
        && offset > 0 && offset < total && offset % PageSize == 0;
    internal static bool ValidGroup(CircularMembershipGroup? group) => group is not null && group.ObjectGuid != Guid.Empty
        && !string.IsNullOrWhiteSpace(group.DistinguishedName) && !string.IsNullOrWhiteSpace(group.DomainFqdn)
        && Sid.ToBytes(group.Sid) is not null && (Sid.IsBuiltinDomain(group.Sid)
            ? string.Equals(group.SidScope, group.DomainFqdn, StringComparison.OrdinalIgnoreCase) : group.SidScope is null);
}

public readonly record struct CircularMembershipGroupMark(Guid GenerationId, long FindingId, string ComponentKey, long Offset);
public readonly record struct CircularMembershipLinkMark(Guid GenerationId, long FindingId, string ComponentKey, long Offset);
public readonly record struct CircularMembershipWitnessMark(Guid GenerationId, long FindingId, string ComponentKey,
    Guid GroupGuid, Guid MemberGuid, long Offset);
public sealed record SavedCircularMembershipGroup(long Position, CircularMembershipGroup Group);
public sealed record SavedCircularMembershipLink(long Position, CircularMembershipGroup ContainingGroup,
    CircularMembershipGroup Member, int WitnessCount)
{
    public bool IsSelfMembership => ContainingGroup.ObjectGuid == Member.ObjectGuid;
}
public sealed record SavedCircularMembershipWitness(long Position, CircularMembershipGroup Source,
    string Attribute, int OriginalOrdinal, string Value);

public sealed record SavedCircularMembershipGroups(SavedCircularMembershipContext Context,
    IReadOnlyList<SavedCircularMembershipGroup> Groups, CircularMembershipGroupMark? Next)
{
    public bool IsExpectedPage(CircularMembershipGroupMark? after)
    {
        var start = after?.Offset ?? 0;
        return Context is not null && Groups is not null && start >= 0 && start < Context.GroupCount
            && (after is not { } previous || Context.MatchesPosition(previous.GenerationId, previous.FindingId, previous.ComponentKey, previous.Offset, Context.GroupCount))
            && Groups.Count == Math.Min(SavedCircularMembershipContext.PageSize, Context.GroupCount - start)
            && Groups.Select((value, index) => value is not null && value.Position == start + index
                && SavedCircularMembershipContext.ValidGroup(value.Group)).All(value => value)
            && (Next is not null) == (start + Groups.Count < Context.GroupCount)
            && (Next is not { } next || Context.MatchesPosition(next.GenerationId, next.FindingId, next.ComponentKey, next.Offset, Context.GroupCount)
                && next.Offset == start + Groups.Count);
    }
}
public sealed record SavedCircularMembershipLinks(SavedCircularMembershipContext Context,
    IReadOnlyList<SavedCircularMembershipLink> Links, CircularMembershipLinkMark? Next)
{
    public bool IsExpectedPage(CircularMembershipLinkMark? after)
    {
        var start = after?.Offset ?? 0;
        return Context is not null && Links is not null && start >= 0 && start < Context.LinkCount
            && (after is not { } previous || Context.MatchesPosition(previous.GenerationId, previous.FindingId, previous.ComponentKey, previous.Offset, Context.LinkCount))
            && Links.Count == Math.Min(SavedCircularMembershipContext.PageSize, Context.LinkCount - start)
            && Links.Select((value, index) => value is not null && value.Position == start + index && value.WitnessCount > 0
                && SavedCircularMembershipContext.ValidGroup(value.ContainingGroup) && SavedCircularMembershipContext.ValidGroup(value.Member)).All(value => value)
            && (Next is not null) == (start + Links.Count < Context.LinkCount)
            && (Next is not { } next || Context.MatchesPosition(next.GenerationId, next.FindingId, next.ComponentKey, next.Offset, Context.LinkCount)
                && next.Offset == start + Links.Count);
    }
}
public sealed record SavedCircularMembershipWitnesses(SavedCircularMembershipContext Context,
    SavedCircularMembershipLink Link, IReadOnlyList<SavedCircularMembershipWitness> Witnesses, CircularMembershipWitnessMark? Next)
{
    public bool IsExpectedPage(CircularMembershipWitnessMark? after)
    {
        var start = after?.Offset ?? 0;
        return Context is not null && Link is not null && Witnesses is not null && start >= 0 && start < Link.WitnessCount
            && (after is not { } previous || Matches(previous))
            && Witnesses.Count == Math.Min(SavedCircularMembershipContext.PageSize, Link.WitnessCount - start)
            && Witnesses.Select((value, index) => value is not null && value.Position == start + index && value.OriginalOrdinal >= 0
                && (value.Attribute == "member" ? value.Source == Link.ContainingGroup && Same(value.Value, Link.Member.DistinguishedName)
                    : value.Attribute == "memberOf" && value.Source == Link.Member && Same(value.Value, Link.ContainingGroup.DistinguishedName))).All(value => value)
            && (Next is not null) == (start + Witnesses.Count < Link.WitnessCount)
            && (Next is not { } next || Matches(next) && next.Offset == start + Witnesses.Count);
    }
    private bool Matches(CircularMembershipWitnessMark mark) =>
        Context.MatchesPosition(mark.GenerationId, mark.FindingId, mark.ComponentKey, mark.Offset, Link.WitnessCount)
        && mark.GroupGuid == Link.ContainingGroup.ObjectGuid && mark.MemberGuid == Link.Member.ObjectGuid;
    private static bool Same(string? left, string? right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
