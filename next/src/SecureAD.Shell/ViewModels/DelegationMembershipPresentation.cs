using SecureAD.Evidence;

namespace SecureAD.Shell.ViewModels;

internal sealed class DelegationMembershipPresentation
{
    private readonly DelegationMembership _membership;
    private readonly Dictionary<int, DelegationMemberNode> _nodes;
    private readonly Dictionary<int, DelegationMemberLink[]> _incoming;
    private readonly Dictionary<int, DelegationMemberLink> _parent = [];

    internal DelegationMembershipPresentation(DelegationMembership membership)
    {
        _membership = membership;
        _nodes = membership.Nodes.ToDictionary(node => node.Id);
        if (!_nodes.ContainsKey(membership.RootId) || membership.Links.Any(link =>
            !_nodes.ContainsKey(link.MemberId) || !_nodes.ContainsKey(link.GroupId)))
            throw new InvalidOperationException(DelegationText.Get("MembershipInvalid"));
        _incoming = membership.Links.GroupBy(link => link.GroupId).ToDictionary(group => group.Key, group => group.ToArray());
        var outgoing = membership.Links.GroupBy(link => link.MemberId).ToDictionary(group => group.Key, group => group.ToArray());
        var seen = new HashSet<int> { membership.RootId };
        var queue = new Queue<int>();
        queue.Enqueue(membership.RootId);
        while (queue.TryDequeue(out var current))
        {
            if (!outgoing.TryGetValue(current, out var links)) continue;
            foreach (var link in links)
                if (seen.Add(link.GroupId))
                {
                    _parent.Add(link.GroupId, link);
                    queue.Enqueue(link.GroupId);
                }
        }
    }

    internal string Describe(int holder)
    {
        if (!_parent.ContainsKey(holder)) throw new InvalidOperationException(DelegationText.Get("MembershipInvalid"));
        var chain = new List<DelegationMemberLink>();
        for (var current = holder; current != _membership.RootId;)
        {
            var step = _parent[current];
            chain.Add(step);
            current = step.MemberId;
        }
        chain.Reverse();
        var text = DelegationText.Get("MembershipChain") + ": " + Name(_membership.RootId)
            + string.Concat(chain.Select(link => $" --{Kind(link)}--> {Name(link.GroupId)}"));
        var links = new HashSet<DelegationMemberLink>();
        var seen = new HashSet<int> { holder };
        var queue = new Queue<int>();
        queue.Enqueue(holder);
        while (queue.TryDequeue(out var current))
        {
            if (!_incoming.TryGetValue(current, out var incoming)) continue;
            foreach (var link in incoming)
            {
                links.Add(link);
                if (seen.Add(link.MemberId)) queue.Enqueue(link.MemberId);
            }
        }
        return text + "\n" + DelegationText.Get("OneChain") + "\n" + DelegationText.Get("SupportingLinks") + "\n"
            + string.Join("\n", links.OrderBy(link => link.MemberId).ThenBy(link => link.GroupId).ThenBy(link => link.IsPrimaryGroup)
                .Select(link => $"{Name(link.MemberId)} --{Kind(link)}--> {Name(link.GroupId)}"));
    }

    private string Name(int id)
    {
        var node = _nodes[id];
        var name = node.Principal is { } principal ? new DelegationPrincipalChoice(principal).Label : node.Sid;
        return node.IsGroup is not false && node.IsSecurityEnabled is null
            ? name + " [" + DelegationText.Get("UnknownGroupType") + "]" : name;
    }

    private static string Kind(DelegationMemberLink link) =>
        DelegationText.Get(link.IsPrimaryGroup ? "PrimaryGroupLink" : "MemberLink");
}
