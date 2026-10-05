using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Derivation;

internal static class ContainingGroupReader
{
    internal static string ParentSql => """
        SELECT group_sid_id, 0 FROM nesting_edge INDEXED BY ix_nesting_edge_member WHERE member_sid_id=$member
        UNION ALL
        SELECT primary_group_sid_id, 1 FROM principal WHERE sid_id=$member AND primary_group_sid_id IS NOT NULL
        ORDER BY 1, 2
        """;

    internal static DelegationMembership Read(SqliteConnection connection, DerivationDescription description,
        int rootId, CancellationToken token)
    {
        var warnings = new HashSet<string>(StringComparer.Ordinal);
        var nodes = new Dictionary<int, DelegationMemberNode>();
        var links = new HashSet<DelegationMemberLink>();
        var queue = new Queue<int>();
        var root = ReadNode(connection, rootId);
        nodes.Add(rootId, root);
        if (root.IsGroup is true && root.IsSecurityEnabled is false)
            warnings.Add("The selected group is a distribution group; its containing groups are not presented as usable security-group routes.");
        else queue.Enqueue(rootId);
        if (root.IsGroup is not false && root.IsSecurityEnabled is null)
            warnings.Add("The selected principal's group type was not captured; group-held membership results are uncertain.");
        using (var capture = connection.CreateCommand())
        {
            capture.CommandText = "SELECT capture_complete FROM membership_input_manifest WHERE id=1";
            var complete = capture.ExecuteScalar();
            if (complete is null) throw new InvalidDataException("The saved membership capture manifest is missing.");
            if (Convert.ToInt64(complete, System.Globalization.CultureInfo.InvariantCulture) == 0)
                warnings.Add("Membership capture did not cover all declared scope; additional containing groups may be missing.");
        }
        using var parents = connection.CreateCommand();
        parents.CommandText = ParentSql;
        parents.Parameters.Add("$member", SqliteType.Integer);
        using var unresolved = connection.CreateCommand();
        unresolved.CommandText = """
            SELECT distinguished_name FROM nesting_unresolved_link
            WHERE sid_id=$member AND direction='ContainingGroup' ORDER BY distinguished_name
            """;
        unresolved.Parameters.Add("$member", SqliteType.Integer);
        while (queue.TryDequeue(out var current))
        {
            token.ThrowIfCancellationRequested();
            unresolved.Parameters[0].Value = current;
            using (var gaps = unresolved.ExecuteReader())
                while (gaps.Read())
                {
                    token.ThrowIfCancellationRequested();
                    warnings.Add($"A containing group was not captured: {gaps.GetString(0)}.");
                }
            parents.Parameters[0].Value = current;
            var found = new List<(int Id, bool Primary)>();
            using (var read = parents.ExecuteReader())
                while (read.Read()) found.Add((read.GetInt32(0), read.GetBoolean(1)));
            foreach (var (id, primary) in found)
            {
                token.ThrowIfCancellationRequested();
                links.Add(new(current, id, primary));
                if (nodes.ContainsKey(id)) continue;
                var group = ReadNode(connection, id);
                nodes.Add(id, group);
                if (group.IsGroup is false)
                {
                    warnings.Add($"A saved containing-group link names a non-group identity: {group.Sid}. This link is not followed.");
                    continue;
                }
                if (group.IsSecurityEnabled is false)
                {
                    warnings.Add($"A distribution-group route stops at {group.Sid}; it is not a usable security-group route.");
                    continue;
                }
                if (group.IsGroup is null || group.IsSecurityEnabled is null)
                    warnings.Add($"Group type or identity was not captured for {group.Sid}; membership through it is uncertain.");
                queue.Enqueue(id);
            }
        }
        return new(description.GenerationId, description.EvidenceSeal, rootId,
            nodes.Values.OrderBy(node => node.Id).ToArray(),
            links.OrderBy(link => link.MemberId).ThenBy(link => link.GroupId).ThenBy(link => link.IsPrimaryGroup).ToArray(),
            warnings.Order(StringComparer.Ordinal).ToArray());
    }

    private static DelegationMemberNode ReadNode(SqliteConnection connection, int id)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT s.sid, s.scope, p.object_guid, p.is_group, p.group_type
            FROM sid AS s LEFT JOIN principal AS p ON p.sid_id=s.sid_id WHERE s.sid_id=$id
            """;
        command.Parameters.AddWithValue("$id", id);
        using var read = command.ExecuteReader();
        if (!read.Read()) throw new InvalidDataException("A saved membership link names a missing SID.");
        return new(id, read.GetString(0), read.GetString(1),
            read.IsDBNull(2) ? null : Guid.Parse(read.GetString(2)),
            read.IsDBNull(3) ? null : read.GetBoolean(3),
            MembershipNestingPass.IsSecurityEnabled(read.IsDBNull(4) ? null : read.GetInt32(4)));
    }
}
