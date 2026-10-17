using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class RequestedProofSelectionStorage
{
    internal static string Question(string family, string? first = null, string? second = null, string? third = null)
    {
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(
            new[] { family, Fold(first), Fold(second), Fold(third) })));

        static string? Fold(string? value) => value is null ? null : string.Create(value.Length, value, (target, source) =>
        {
            for (var index = 0; index < source.Length; index++)
                target[index] = source[index] is >= 'A' and <= 'Z' ? (char)(source[index] + ('a' - 'A')) : source[index];
        });
    }

    internal static string ControlQuestion(string? target, string? holder, string? scope, bool? includeExpected = null) =>
        Question("control-" + (target is not null ? "target" : holder is not null ? "holder" : "all")
            + (includeExpected is null ? "" : includeExpected.Value ? "-all" : "-visible"),
            target ?? holder, target is null && holder is not null ? scope ?? "" : null);

    internal static void Prepare(SqliteConnection connection, JudgementDescription description, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        SQLitePCL.raw.sqlite3_progress_handler(connection.Handle ?? throw new InvalidOperationException(),
            1000, _ => token.IsCancellationRequested ? 1 : 0, null);
        try { PrepareCore(connection, description, token); }
        catch (SqliteException error) when (token.IsCancellationRequested)
        {
            throw new OperationCanceledException("Requested proof selection preparation was cancelled.", error, token);
        }
        finally { SQLitePCL.raw.sqlite3_progress_handler(connection.Handle, 0, null, null); }
    }

    private static void PrepareCore(SqliteConnection connection, JudgementDescription description, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        connection.CreateFunction<string, string?, string?, string?, string>("detail_question", Question, isDeterministic: true);
        var selfSummary = SelfMembershipCoverageStorage.Read(connection, description);
        using var transaction = connection.BeginTransaction();
        foreach (var role in new[] { StoreSegmentRole.PermissionProof, StoreSegmentRole.PathProof })
            Execute($"""
                CREATE TABLE "{role}".detail_selection (
                    question TEXT NOT NULL, ordinal INTEGER NOT NULL, source INTEGER NOT NULL,
                    PRIMARY KEY(question,ordinal)) WITHOUT ROWID;
                """);
        PrepareControl();
        PreparePaths();
        PrepareSelfMembership();
        MemberAttributionStorage.PrepareRequested(connection, transaction, description, token);
        Execute("DROP TABLE temp.detail_control_source");
        token.ThrowIfCancellationRequested();
        transaction.Commit();

        void PrepareControl()
        {
            Execute($"""
                CREATE TEMP TABLE detail_control_source AS {MemberAttributionStorage.SourceSql};
                CREATE INDEX temp.ix_detail_control_target ON detail_control_source(target COLLATE NOCASE);
                CREATE TABLE PermissionProof.detail_control_count (
                    question TEXT PRIMARY KEY, unexpected INTEGER NOT NULL, unknown INTEGER NOT NULL,
                    expected INTEGER NOT NULL, incomplete INTEGER NOT NULL);
                INSERT INTO PermissionProof.detail_control_count
                SELECT detail_question('control-target',o.target,NULL,NULL),
                    COALESCE(SUM(s.counted AND s.expectedness='Unexpected'),0),
                    COALESCE(SUM(s.counted AND s.expectedness='Unknown'),0),
                    COALESCE(SUM(s.counted AND s.expectedness='Expected'),0),1-o.is_complete
                FROM control_object o LEFT JOIN temp.detail_control_source s ON s.target=o.target COLLATE NOCASE
                GROUP BY o.target COLLATE NOCASE;
                INSERT INTO PermissionProof.detail_control_count
                SELECT detail_question('control-holder',holder_sid,holder_scope,NULL),
                    SUM(counted AND expectedness='Unexpected'),SUM(counted AND expectedness='Unknown'),
                    SUM(counted AND expectedness='Expected'),(SELECT COUNT(*) FROM control_object WHERE is_complete=0)
                FROM temp.detail_control_source GROUP BY holder_sid COLLATE NOCASE,holder_scope COLLATE NOCASE;
                INSERT INTO PermissionProof.detail_control_count
                SELECT detail_question('control-all',NULL,NULL,NULL),
                    COALESCE(SUM(counted AND expectedness='Unexpected'),0),COALESCE(SUM(counted AND expectedness='Unknown'),0),
                    COALESCE(SUM(counted AND expectedness='Expected'),0),(SELECT COUNT(*) FROM control_object WHERE is_complete=0)
                FROM temp.detail_control_source;
                CREATE TABLE PermissionProof.detail_control_support (edge_id INTEGER PRIMARY KEY, assessment_id INTEGER NOT NULL);
                INSERT INTO PermissionProof.detail_control_support SELECT edge_id,assessment_id FROM full_control_support;
                """);
            foreach (var (family, first, second) in new[]
            {
                ("control-target", "target", "NULL"), ("control-holder", "holder_sid", "holder_scope"),
                ("control-all", "NULL", "NULL"),
            })
                foreach (var includeExpected in new[] { true, false })
                    Execute($"""
                        INSERT INTO PermissionProof.detail_selection
                        SELECT detail_question('{family}-{(includeExpected ? "all" : "visible")}',{first},{second},NULL),
                            display_id,display_id
                        FROM temp.detail_control_source{(includeExpected ? "" : " WHERE expectedness<>'Expected'")};
                        """);
        }

        void PreparePaths()
        {
            Execute("""
                CREATE TABLE PathProof.detail_path_count (
                    requester TEXT PRIMARY KEY COLLATE NOCASE, unexpected INTEGER NOT NULL, expected INTEGER NOT NULL,
                    not_established INTEGER NOT NULL, unknown INTEGER NOT NULL);
                INSERT INTO PathProof.detail_path_count
                SELECT requester,SUM(verdict='UnexpectedRoute'),SUM(verdict='ExpectedRoute'),
                    SUM(verdict='NotEstablished'),SUM(verdict='Unknown')
                FROM path_requester_risk GROUP BY requester COLLATE NOCASE;
                INSERT INTO PathProof.detail_selection
                SELECT detail_question('path-risk',requester,verdict,NULL),id,id FROM path_requester_risk;
                INSERT INTO PathProof.detail_selection
                SELECT detail_question('path-question',requester,question_key,NULL),id,id FROM path_requester_risk;
                """);
        }

        void PrepareSelfMembership()
        {
            Execute("""
                CREATE TABLE PathProof.detail_self_summary(singleton INTEGER PRIMARY KEY CHECK(singleton=1),payload TEXT NOT NULL);
                INSERT INTO PathProof.detail_selection
                SELECT question,ROW_NUMBER() OVER(PARTITION BY question ORDER BY requester_dn COLLATE NOCASE,
                    target_dn COLLATE NOCASE,operation,COALESCE(member_dn,'') COLLATE NOCASE),id
                FROM (
                    SELECT detail_question('self-all',NULL,NULL,NULL) AS question,id,requester_dn,target_dn,operation,member_dn FROM self_membership_assessment
                    UNION ALL SELECT detail_question('self-target',target_dn,NULL,NULL),id,requester_dn,target_dn,operation,member_dn FROM self_membership_assessment
                    UNION ALL SELECT detail_question('self-requester',requester_dn,NULL,NULL),id,requester_dn,target_dn,operation,member_dn FROM self_membership_assessment
                    UNION ALL SELECT detail_question('self-both',target_dn,requester_dn,NULL),id,requester_dn,target_dn,operation,member_dn FROM self_membership_assessment
                );
                """);
            if (selfSummary is null) return;
            using var save = connection.CreateCommand();
            save.Transaction = transaction;
            save.CommandText = "INSERT INTO PathProof.detail_self_summary VALUES(1,$payload)";
            save.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(selfSummary, ProofSerialization.Options));
            save.ExecuteNonQuery();
        }

        void Execute(string sql)
        {
            token.ThrowIfCancellationRequested();
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            command.ExecuteNonQuery();
            token.ThrowIfCancellationRequested();
        }
    }

    internal static IReadOnlyList<long> ReadPage(RequestedDetailReader reader, string question, long after, int size,
        out long total)
    {
        var result = new List<long>(size);
        var page = reader.ReadPageAfter("detail_selection", question, after);
        total = page.TotalRows;
        while (true)
        {
            foreach (var row in page.Rows)
            {
                if (row.Integer("ordinal") <= after) continue;
                result.Add(row.Integer("source"));
                if (result.Count == size) return result;
            }
            if (page.Next is null) return result;
            page = reader.ReadPage("detail_selection", question, page.Next);
        }
    }

    internal static string RootKey(long id) => id.ToString(CultureInfo.InvariantCulture);

}
