using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

[Flags]
public enum GroupMembershipLimitations
{
    None = 0,
    CaptureIncomplete = 1,
    UnresolvedReferences = 2,
    UnreadableReferences = 4,
    SourceLimited = 8,
    ForeignPrincipal = 16,
    ObjectClassNotRecorded = 32,
}

/// <summary>Distinct captured objects reached through member values, not authorization membership.</summary>
public sealed record GroupMembershipTotal(int KnownMembers, int UnresolvedReferences, int UnreadableReferences,
    GroupMembershipLimitations Limitations)
{
    public string Verdict => Limitations == GroupMembershipLimitations.None ? "Recorded" : "Incomplete";
}

internal sealed class GroupMembershipTotals
{
    private sealed record Node(bool Group, string[] Members, int Unreadable, GroupMembershipLimitations Limitations);
    private readonly Dictionary<string, Node> _objects = new(StringComparer.OrdinalIgnoreCase);

    internal void Clear() => _objects.Clear();

    internal void Add(ObjectAttributes source)
    {
        var group = RequesterTrusteeReading.HasClass(source, "group");
        var values = group ? source.Find("member")?.Values : null;
        var members = values?.Where(value => !string.IsNullOrWhiteSpace(value.Text)).Select(value => value.Text!)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToArray() ?? [];
        var unreadable = values?.Count(value => string.IsNullOrWhiteSpace(value.Text)) ?? 0;
        var limitations = source.Completeness != EvidenceCompleteness.Complete || group && values is null
            ? GroupMembershipLimitations.SourceLimited : GroupMembershipLimitations.None;
        if (source.Find("objectClass")?.HasValue != true) limitations |= GroupMembershipLimitations.ObjectClassNotRecorded;
        if (RequesterTrusteeReading.HasClass(source, "foreignSecurityPrincipal")) limitations |= GroupMembershipLimitations.ForeignPrincipal;
        if (unreadable != 0) limitations |= GroupMembershipLimitations.UnreadableReferences;
        if (!_objects.TryAdd(source.DistinguishedName, new(group, members, unreadable, limitations)))
            throw new InvalidDataException("The membership inventory contains an ambiguous captured object name.");
    }

    internal IEnumerable<(string DistinguishedName, GroupMembershipTotal Total)> Calculate(bool captureComplete, CancellationToken token)
    {
        // Keep one walk's visited set, not a forest-sized table of every transitive pair.
        // Mark on discovery so repeated routes and cycles never multiply work within a walk.
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pending = new Stack<Node>();
        foreach (var (dn, root) in _objects)
        {
            token.ThrowIfCancellationRequested();
            if (!root.Group) continue;
            visited.Clear();
            visited.Add(dn);
            pending.Push(root);
            var known = 0;
            var unresolved = 0;
            var unreadable = 0;
            var limitations = captureComplete ? GroupMembershipLimitations.None : GroupMembershipLimitations.CaptureIncomplete;
            while (pending.TryPop(out var node))
            {
                token.ThrowIfCancellationRequested();
                limitations |= node.Limitations;
                unreadable = checked(unreadable + node.Unreadable);
                foreach (var member in node.Members)
                {
                    token.ThrowIfCancellationRequested();
                    if (!visited.Add(member)) continue;
                    if (!_objects.TryGetValue(member, out var target))
                    {
                        unresolved++;
                        limitations |= GroupMembershipLimitations.UnresolvedReferences;
                        continue;
                    }
                    known++;
                    pending.Push(target);
                }
            }
            yield return (dn, new(known, unresolved, unreadable, limitations));
        }
    }
}
