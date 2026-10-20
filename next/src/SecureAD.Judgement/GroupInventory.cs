using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Kernel.Naming;

namespace SecureAD.Judgement;

public enum GroupInventoryScope { All, Global, Universal, DomainLocal }
public enum GroupInventoryKind { All, Security, Distribution }
public enum GroupInventorySort { Name, NameDescending, Direct, DirectDescending }

/// <summary>Filters captured groups; null container means all recorded groups in this generation.</summary>
public sealed record GroupInventoryQuery(string? Container, ListingScope Scope, string Search,
    GroupInventoryScope GroupScope, GroupInventoryKind Kind, bool CyclesOnly, GroupInventorySort Sort);

/// <summary>A keyset continuation bound to the submitted question and saved generation.</summary>
public sealed record GroupInventoryMark(Guid GenerationId, string Question, string Name, int Direct, string DistinguishedName);

/// <summary>Captured identity and direct member references; cycle status is a separate saved rule answer.</summary>
public sealed record GroupInventoryRow(Guid? ObjectGuid, string DistinguishedName, string Name, string? AccountName,
    string? DomainFqdn, long? GroupType, int DirectMembers, int UnreadableReferences, bool? HasCycle, string? Description,
    GroupMembershipTotal MembershipTotal);

/// <summary>Whole-question count and one page; neither unloaded pages nor unavailable nested totals are capture gaps.</summary>
public sealed record GroupInventoryPage(Guid GenerationId, string EvidenceSeal, IReadOnlyList<GroupInventoryRow> Groups,
    int Total, GroupInventoryMark? Next, ListingCoverage Coverage, string? CycleQualification)
{
    public string Verdict => Coverage.IsComplete ? "Recorded" : "CaptureIncomplete";
}

internal static class GroupInventoryStorage
{
    internal const int PageSize = 50;

    internal static int DirectCount(IReadOnlyList<AttributeValue> values) => values
        .Where(value => !string.IsNullOrWhiteSpace(value.Text)).Select(value => value.Text!)
        .Distinct(StringComparer.OrdinalIgnoreCase).Count();

    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.group_inventory_product (id INTEGER PRIMARY KEY CHECK(id=1), generation TEXT NOT NULL,
                capture_complete INTEGER NOT NULL, completed INTEGER NOT NULL CHECK(completed IN (0,1)));
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.group_inventory (distinguished_name TEXT PRIMARY KEY COLLATE NOCASE, object_guid TEXT NULL,
                name TEXT NOT NULL, account_name TEXT NULL, domain_fqdn TEXT NULL, group_type INTEGER NULL,
                direct_members INTEGER NOT NULL CHECK(direct_members>=0), unreadable_references INTEGER NOT NULL CHECK(unreadable_references>=0),
                description TEXT NULL, parent_dn TEXT NULL, dn_reversed TEXT NOT NULL,
                known_total INTEGER NULL CHECK(known_total>=0),
                unresolved_members INTEGER NULL CHECK(unresolved_members>=0),
                unreadable_members INTEGER NULL CHECK(unreadable_members>=0),
                membership_limitations INTEGER NULL CHECK(membership_limitations BETWEEN 0 AND 63));
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.ix_group_inventory_name ON group_inventory(name COLLATE NOCASE,distinguished_name);
            CREATE INDEX {JudgementStoreLayout.Schema(connection, StoreSegmentRole.Judgement)}.ix_group_inventory_direct ON group_inventory(direct_members,distinguished_name);
            """;
        command.ExecuteNonQuery();
    }

    internal static void Start(SqliteConnection connection, Guid generation, bool captureComplete)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO group_inventory_product VALUES(1,$generation,$complete,0)";
        command.Parameters.AddWithValue("$generation", generation.ToString("D"));
        command.Parameters.AddWithValue("$complete", captureComplete);
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, ObjectAttributes subject,
        PreparedStatements statements)
    {
        if (!RequesterTrusteeReading.HasClass(subject, "group")) return;
        var members = subject.Find("member")?.Values;
        var direct = DirectCount(members ?? []);
        var unreadable = members?.Count(value => string.IsNullOrWhiteSpace(value.Text)) ?? 0;
        var command = statements.Bind("INSERT INTO group_inventory VALUES($dn,$guid,$name,$account,$domain,$type,$direct,$unreadable,$description,$parent,$reversed,NULL,NULL,NULL,NULL)",
            transaction, ("$dn", subject.DistinguishedName), ("$guid", subject.ObjectGuid?.ToString("D")),
            ("$name", DnHelper.ExtractNameFromDn(subject.DistinguishedName)),
            ("$account", subject.Find("sAMAccountName")?.OnlyValue?.Text), ("$domain", subject.DomainFqdn),
            ("$type", RequesterTrusteeReading.Number(subject, "groupType")), ("$direct", direct), ("$unreadable", unreadable),
            ("$description", subject.Find("description")?.OnlyValue?.Text),
            ("$parent", DnHelper.GetParentDn(subject.DistinguishedName)), ("$reversed", DnHelper.ReverseDn(subject.DistinguishedName)));
        if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
    }

    internal static void Complete(SqliteConnection connection, GroupMembershipTotals totals, CancellationToken token)
    {
        bool captureComplete;
        using (var header = connection.CreateCommand())
        {
            header.CommandText = "SELECT capture_complete FROM group_inventory_product WHERE id=1 AND completed=0";
            captureComplete = header.ExecuteScalar() is long value ? value == 1 : throw Tier0PathStorage.InvalidProof();
        }
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            UPDATE group_inventory SET known_total=$total,unresolved_members=$unresolved,
                unreadable_members=$unreadable,membership_limitations=$limitations WHERE distinguished_name=$dn
            """;
        var dn = command.Parameters.Add("$dn", SqliteType.Text);
        var total = command.Parameters.Add("$total", SqliteType.Integer);
        var unresolved = command.Parameters.Add("$unresolved", SqliteType.Integer);
        var unreadable = command.Parameters.Add("$unreadable", SqliteType.Integer);
        var limitations = command.Parameters.Add("$limitations", SqliteType.Integer);
        foreach (var result in totals.Calculate(captureComplete, token))
        {
            dn.Value = result.DistinguishedName;
            total.Value = result.Total.KnownMembers;
            unresolved.Value = result.Total.UnresolvedReferences;
            unreadable.Value = result.Total.UnreadableReferences;
            limitations.Value = (int)result.Total.Limitations;
            if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
        }
        token.ThrowIfCancellationRequested();
        command.Parameters.Clear();
        command.CommandText = "UPDATE group_inventory_product SET completed=1 WHERE id=1";
        if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
        RequirePublishable(connection, transaction);
        transaction.Commit();
    }

    internal static void RequirePublishable(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM group_inventory),
                   (SELECT COUNT(*) FROM group_inventory_product WHERE completed=1),
                   (SELECT COUNT(*) FROM group_inventory_product WHERE completed<>1),
                   (SELECT COUNT(*) FROM group_inventory WHERE known_total IS NULL OR unresolved_members IS NULL
                       OR unreadable_members IS NULL OR membership_limitations IS NULL)
            """;
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetInt64(2) != 0 || row.GetInt64(3) != 0 || row.GetInt64(0) != 0 && row.GetInt64(1) != 1)
            throw Tier0PathStorage.InvalidProof();
    }

    internal static GroupInventoryPage Read(SqliteConnection connection, JudgementDescription description,
        GroupInventoryQuery query, GroupInventoryMark? after, CancellationToken token,
        IDictionary<GroupInventoryQuery, int> savedCounts)
    {
        ArgumentNullException.ThrowIfNull(savedCounts);
        token.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(query.Scope) || !Enum.IsDefined(query.GroupScope) || !Enum.IsDefined(query.Kind)
            || !Enum.IsDefined(query.Sort) || query.Search is null) throw new ArgumentException("Invalid group inventory filters.", nameof(query));
        var question = Tier0PathCalculation.Fingerprint(query);
        if (after is not null && (after.GenerationId != description.GenerationId || after.Question != question
            || after.Direct < 0 || string.IsNullOrWhiteSpace(after.DistinguishedName) || after.Name is null))
            throw new ArgumentException("The group page belongs to another selection or generation.", nameof(after));
        bool complete;
        string? cycleOutcome;
        using (var header = connection.CreateCommand())
        {
            header.CommandText = """
                SELECT p.generation,p.capture_complete,p.completed,
                    (SELECT outcome FROM rule_execution WHERE rule_id='SEC-052')
                FROM group_inventory_product p WHERE p.id=1
                """;
            using var row = header.ExecuteReader();
            if (!row.Read()) throw new InvalidDataException("The saved group inventory is unavailable. Judge this sealed capture to produce it.");
            if (row.GetString(0) != description.GenerationId.ToString("D") || !row.GetBoolean(2))
                throw Tier0PathStorage.InvalidProof();
            complete = row.GetBoolean(1);
            cycleOutcome = row.IsDBNull(3) ? null : row.GetString(3);
        }
        var cycleComplete = cycleOutcome == "Succeeded";
        var cyclesRead = cycleOutcome is "Succeeded" or "Indeterminate";
        var cycleQualification = cycleOutcome switch
        {
            "Succeeded" => null,
            "Indeterminate" => "Cycle assessment is incomplete. Known cycles are shown; other groups remain unassessed.",
            null or "DidNotRun" => "SEC-052 has not run in this saved judgement. Cycle status is not assessed.",
            "Error" => "SEC-052 failed in this saved judgement. Open Rules for its recorded error; no cycle status is assumed.",
            _ => throw new InvalidDataException("The saved SEC-052 outcome is not recognized."),
        };
        if (query.CyclesOnly && !cyclesRead)
            throw new InvalidOperationException("No saved SEC-052 assessment is available for the cycles-only filter. Clear the filter to browse captured groups.");
        const string cycle = "EXISTS(SELECT 1 FROM finding_circular_group cg JOIN finding f ON f.finding_id=cg.finding_id WHERE f.rule_id='SEC-052' AND cg.distinguished_name=g.distinguished_name COLLATE NOCASE)";
        var location = query.Container is null ? "1" : query.Scope switch
        {
            ListingScope.Base => "g.distinguished_name=$container COLLATE NOCASE",
            ListingScope.OneLevel => "(g.distinguished_name=$container COLLATE NOCASE OR g.parent_dn=$container COLLATE NOCASE)",
            ListingScope.Subtree => "(g.dn_reversed=$reversed OR g.dn_reversed LIKE $prefix ESCAPE '\\')",
            _ => throw new ArgumentOutOfRangeException(nameof(query)),
        };
        var where = $"""
            {location}
            AND ($search='' OR instr(lower(g.name),lower($search))>0 OR instr(lower(g.account_name),lower($search))>0)
            AND ($scope=0 OR (g.group_type & 15)=$scope OR ($scope=4 AND (g.group_type & 15)=5))
            AND ($kind=0 OR ($kind=1 AND (g.group_type & 2147483648)<>0) OR ($kind=2 AND (g.group_type & 2147483648)=0))
            AND ($cycles=0 OR {cycle})
            """;
        using var command = connection.CreateCommand();
        command.Parameters.AddWithValue("$container", (object?)query.Container ?? DBNull.Value);
        var reversed = query.Container is null ? "" : DnHelper.ReverseDn(query.Container);
        command.Parameters.AddWithValue("$reversed", reversed);
        command.Parameters.AddWithValue("$prefix", reversed.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + ",%");
        command.Parameters.AddWithValue("$search", query.Search.Trim());
        command.Parameters.AddWithValue("$scope", query.GroupScope switch { GroupInventoryScope.Global => 2, GroupInventoryScope.Universal => 8, GroupInventoryScope.DomainLocal => 4, _ => 0 });
        command.Parameters.AddWithValue("$kind", (int)query.Kind);
        command.Parameters.AddWithValue("$cycles", query.CyclesOnly);
        var countQuestion = query with { Sort = GroupInventorySort.Name };
        int total;
        lock (savedCounts)
        {
            if (!savedCounts.TryGetValue(countQuestion, out total))
            {
                command.CommandText = $"SELECT COUNT(*) FROM group_inventory g WHERE {where}";
                total = checked((int)(long)command.ExecuteScalar()!);
                savedCounts.Add(countQuestion, total);
            }
        }
        var numeric = query.Sort is GroupInventorySort.Direct or GroupInventorySort.DirectDescending;
        var descending = query.Sort is GroupInventorySort.NameDescending or GroupInventorySort.DirectDescending;
        var key = numeric ? "g.direct_members" : "g.name COLLATE NOCASE";
        var comparator = descending ? "<" : ">";
        var continuation = after is null ? "1" : $"({key}{comparator}$after OR ({key}=$after AND g.distinguished_name>$afterDn COLLATE NOCASE))";
        command.CommandText = $"""
            SELECT g.object_guid,g.distinguished_name,g.name,g.account_name,g.domain_fqdn,g.group_type,
                   g.direct_members,g.unreadable_references,g.description,{cycle},
                   g.known_total,g.unresolved_members,g.unreadable_members,g.membership_limitations
            FROM group_inventory g WHERE {where} AND {continuation}
            ORDER BY {key} {(descending ? "DESC" : "ASC")},g.distinguished_name COLLATE NOCASE
            LIMIT $take
            """;
        command.Parameters.AddWithValue("$after", after is null ? DBNull.Value : numeric ? (object)after.Direct : after.Name);
        command.Parameters.AddWithValue("$afterDn", (object?)after?.DistinguishedName ?? DBNull.Value);
        command.Parameters.AddWithValue("$take", PageSize + 1);
        var groups = new List<GroupInventoryRow>();
        GroupInventoryMark? next = null;
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            if (groups.Count == PageSize)
            {
                var last = groups[^1];
                next = new(description.GenerationId, question, last.Name, last.DirectMembers, last.DistinguishedName);
                break;
            }
            groups.Add(new(read.IsDBNull(0) ? null : Guid.Parse(read.GetString(0)), read.GetString(1), read.GetString(2),
                read.IsDBNull(3) ? null : read.GetString(3), read.IsDBNull(4) ? null : read.GetString(4),
                read.IsDBNull(5) ? null : read.GetInt64(5), read.GetInt32(6), read.GetInt32(7),
                cyclesRead && read.GetBoolean(9) ? true : cycleComplete ? false : null, read.IsDBNull(8) ? null : read.GetString(8),
                ReadTotal(read, complete)));
        }
        return new(description.GenerationId, description.EvidenceSeal, groups, total, next,
            new(complete, complete ? null : "This run has capture gaps. The group list covers recorded objects, not the whole forest."),
            cycleQualification);
    }

    private static GroupMembershipTotal ReadTotal(SqliteDataReader row, bool captureComplete)
    {
        for (var column = 10; column <= 13; column++)
            if (row.IsDBNull(column) || row.GetInt64(column) < 0 || row.GetInt64(column) > int.MaxValue)
                throw Tier0PathStorage.InvalidProof();
        var limitations = (GroupMembershipLimitations)row.GetInt32(13);
        if ((int)limitations > 63
            || limitations.HasFlag(GroupMembershipLimitations.CaptureIncomplete) == captureComplete
            || limitations.HasFlag(GroupMembershipLimitations.UnresolvedReferences) != (row.GetInt32(11) != 0)
            || limitations.HasFlag(GroupMembershipLimitations.UnreadableReferences) != (row.GetInt32(12) != 0))
            throw Tier0PathStorage.InvalidProof();
        return new(row.GetInt32(10), row.GetInt32(11), row.GetInt32(12), limitations);
    }
}
