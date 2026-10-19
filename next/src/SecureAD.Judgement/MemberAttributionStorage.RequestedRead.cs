using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static partial class MemberAttributionStorage
{
    private sealed record PermissionIdentity(string Target, string Holder, string Scope, string Capability,
        ControlExpectedness Expected, bool Counted, ControlEvaluationState State, bool Included);

    private static MemberAttributionDetail ReadRequested(SqliteConnection connection, RequestedDetailReader requested,
        JudgementDescription description, string sid, string? scope, string target)
    {
        var roots = RequestedProofSelectionStorage.ReadPage(requested,
            RequestedProofSelectionStorage.Question("member-holder", sid, scope ?? ""), 0, 2, out var count);
        if (count == 0) return new(true, null, []);
        if (count != 1 || roots.Count != 1) throw Invalid();
        var root = checked((int)roots[0]);
        var permissions = RequestedProofSelectionStorage.ReadPage(requested,
            RequestedProofSelectionStorage.Question("member-target", RequestedProofSelectionStorage.RootKey(root), target), 0, 1, out _);
        if (permissions.Count == 0) return new(true, null, []);
        var link = requested.ReadSingle("member_attribution_permission", permissions[0]) ?? throw Invalid();
        if (link.Integer("root_id") != root || !Same(link.CompleteText("target"), target)) throw Invalid();
        var context = link.CompleteText("context");
        var source = ReadPermissionIdentity(requested, description, permissions[0]);
        if (!Same(source.Target, target) || !Same(source.Holder, sid) || !Same(source.Scope, scope ?? "")) throw Invalid();
        ValidateLink(connection, description, permissions[0], sid, scope, target, context);
        var expansion = ReadRoot(connection, description, root);
        return new(true, expansion, ReadContext(connection, root, context, expansion));
    }

    private static MemberPermissionPage ReadRequestedReverse(SqliteConnection connection, RequestedDetailReader requested,
        JudgementDescription description, string sid, string? scope, bool includeExpected, long after)
    {
        var summary = requested.ReadSingle("detail_member_summary", 1L) ?? throw Invalid();
        var roots = requested.ReadCompleteScope("detail_member_identity",
            RequestedProofSelectionStorage.Question("member-of", sid, scope ?? ""))
            .ToDictionary(row => checked((int)row.Integer("root_id")));
        var complete = summary.Integer("roots_complete") == 1 && roots.Values.All(row => row.Integer("complete") == 1);
        long expected = 0;
        var iterators = new List<IEnumerator<long>>();
        var queue = new PriorityQueue<(int Root, IEnumerator<long> Items), long>();
        var selected = new List<(long Id, int Root)>();
        try
        {
            foreach (var (root, _) in roots)
            {
                var count = requested.ReadSingle("detail_member_root_count", root);
                expected = checked(expected + (count?.Integer("expected") ?? 0));
                var iterator = Permissions(root).GetEnumerator();
                iterators.Add(iterator);
                if (iterator.MoveNext()) queue.Enqueue((root, iterator), iterator.Current);
            }
            while (selected.Count <= 100 && queue.TryDequeue(out var entry, out var id))
            {
                var identity = ReadPermissionIdentity(requested, description, id);
                if (includeExpected || identity.Expected != ControlExpectedness.Expected) selected.Add((id, entry.Root));
                if (entry.Items.MoveNext()) queue.Enqueue(entry, entry.Items.Current);
            }
        }
        finally { foreach (var iterator in iterators) iterator.Dispose(); }
        var more = selected.Count > 100;
        if (more) selected.RemoveAt(100);
        var result = new List<MemberPermissionReference>();
        foreach (var (id, root) in selected)
        {
            var link = requested.ReadSingle("member_attribution_permission", id) ?? throw Invalid();
            if (link.Integer("root_id") != root) throw Invalid();
            var context = link.CompleteText("context");
            var target = link.CompleteText("target");
            var source = ReadPermissionIdentity(requested, description, id);
            var holder = requested.ReadSingle("member_attribution_root", root) ?? throw Invalid();
            if (!Same(holder.CompleteText("holder_sid"), source.Holder)
                || !Same(holder.CompleteText("holder_scope"), source.Scope)) throw Invalid();
            ValidateLink(connection, description, id, source.Holder, source.Scope, target, context);
            var member = roots[root];
            var identity = member.CompleteText("identity");
            var applicability = requested.ReadSingle("detail_member_resource", RequestedProofSelectionStorage.Question(
                "member-resource", RequestedProofSelectionStorage.RootKey(root), context, identity)) ?? throw Invalid();
            if (applicability.Integer("root_id") != root || applicability.CompleteText("context") != context
                || !Same(applicability.CompleteText("member"), identity)) throw Invalid();
            var state = State(applicability.CompleteText("state"));
            if (state == MemberAttributionState.Unknown) complete = false;
            result.Add(new(id, source.Holder, source.Scope.Length == 0 ? null : source.Scope, target, source.Capability,
                source.Expected, source.Counted, State(member.CompleteText("state")), state, applicability.CompleteText("reason"))
            { PermissionState = source.State, IncludedInFullControl = source.Included });
        }
        return new(true, complete, description.GenerationId, result, more, selected.Count == 0 ? after : selected[^1].Id)
        { ExpectedCount = expected };

        IEnumerable<long> Permissions(int root)
        {
            var question = RequestedProofSelectionStorage.Question(includeExpected ? "member-root" : "member-root-visible",
                RequestedProofSelectionStorage.RootKey(root));
            var page = requested.ReadPageAfter("detail_selection", question, after);
            while (true)
            {
                foreach (var row in page.Rows)
                    if (row.Integer("ordinal") > after) yield return row.Integer("source");
                if (page.Next is null) yield break;
                page = requested.ReadPage("detail_selection", question, page.Next);
            }
        }
    }

    private static PermissionIdentity ReadPermissionIdentity(RequestedDetailReader requested, JudgementDescription description, long display)
    {
        if (display <= 0) throw Invalid();
        var direct = display % 2 == 0;
        var row = requested.ReadSingle(direct ? "control_edge" : "full_control_assessment",
            direct ? display / 2 : (display + 1) / 2) ?? throw Invalid();
        if (row.CompleteText("generation") != description.GenerationId.ToString("D")
            || (row.IsNull("derivation_generation") ? null : row.CompleteText("derivation_generation"))
                != description.DerivationGenerationId?.ToString("D")) throw Invalid();
        var state = Enum.Parse<ControlEvaluationState>(row.CompleteText("evaluation"));
        var expected = Enum.Parse<ControlExpectedness>(row.CompleteText("expectedness"));
        if (!Enum.IsDefined(state) || !Enum.IsDefined(expected)) throw Invalid();
        var included = direct && requested.ReadSingle("detail_control_support", display / 2) is not null;
        return new(row.CompleteText("target"), row.CompleteText("holder_sid"),
            row.IsNull("holder_scope") ? "" : row.CompleteText("holder_scope"),
            direct ? row.CompleteText("capability") : "HasFullControl", expected,
            direct ? row.Integer("counted") == 1 && !included : state == ControlEvaluationState.Established, state, included);
    }

    private static MemberAttributionState State(string value) =>
        Enum.TryParse<MemberAttributionState>(value, out var result) && Enum.IsDefined(result) ? result : throw Invalid();
}
