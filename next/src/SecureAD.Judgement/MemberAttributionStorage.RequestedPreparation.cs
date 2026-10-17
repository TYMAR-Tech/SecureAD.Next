using Microsoft.Data.Sqlite;

namespace SecureAD.Judgement;

internal static partial class MemberAttributionStorage
{
    internal static void PrepareRequested(SqliteConnection connection, SqliteTransaction transaction,
        JudgementDescription description, CancellationToken token)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE PermissionProof.detail_member_summary(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                roots_complete INTEGER NOT NULL CHECK(roots_complete IN (0,1)));
            CREATE TABLE PermissionProof.detail_member_root_count(root_id INTEGER PRIMARY KEY,expected INTEGER NOT NULL);
            CREATE TABLE PermissionProof.detail_member_identity(
                question TEXT NOT NULL,root_id INTEGER NOT NULL,identity TEXT NOT NULL,state TEXT NOT NULL,
                complete INTEGER NOT NULL CHECK(complete IN (0,1)),PRIMARY KEY(question,root_id)) WITHOUT ROWID;
            CREATE TABLE PermissionProof.detail_member_resource(question TEXT PRIMARY KEY,root_id INTEGER NOT NULL,
                context TEXT NOT NULL,member TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL);
            INSERT INTO PermissionProof.detail_member_root_count
            SELECT p.root_id,SUM(s.expectedness='Expected' AND s.counted)
            FROM member_attribution_permission p JOIN temp.detail_control_source s USING(display_id) GROUP BY p.root_id;
            INSERT INTO PermissionProof.detail_selection
            SELECT detail_question('member-holder',holder_sid,holder_scope,NULL),id,id FROM member_attribution_root;
            INSERT INTO PermissionProof.detail_selection
            SELECT detail_question('member-root',CAST(root_id AS TEXT),NULL,NULL),display_id,display_id FROM member_attribution_permission;
            INSERT INTO PermissionProof.detail_selection
            SELECT detail_question('member-root-visible',CAST(p.root_id AS TEXT),NULL,NULL),p.display_id,p.display_id
            FROM member_attribution_permission p JOIN temp.detail_control_source s USING(display_id) WHERE s.expectedness<>'Expected';
            INSERT INTO PermissionProof.detail_selection
            SELECT detail_question('member-target',CAST(root_id AS TEXT),target,NULL),display_id,display_id FROM member_attribution_permission;
            """;
        command.ExecuteNonQuery();
        if (!ReadManifest(connection, transaction)) return;
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM member_attribution_permission)
                <> (SELECT COUNT(*) FROM member_attribution_permission JOIN temp.detail_control_source USING(display_id))
            """;
        if ((long)command.ExecuteScalar()! != 0) throw Invalid();
        command.CommandText = "SELECT id FROM member_attribution_root ORDER BY id";
        var roots = new List<int>();
        using (var read = command.ExecuteReader()) while (read.Read()) roots.Add(read.GetInt32(0));
        var allComplete = true;
        using var resource = connection.CreateCommand();
        resource.Transaction = transaction;
        resource.CommandText = "INSERT INTO PermissionProof.detail_member_resource VALUES($question,$root,$context,$member,$state,$reason)";
        foreach (var name in new[] { "$question", "$root", "$context", "$member", "$state", "$reason" })
            resource.Parameters.AddWithValue(name, DBNull.Value);
        resource.Prepare();
        using var member = connection.CreateCommand();
        member.Transaction = transaction;
        member.CommandText = "INSERT INTO PermissionProof.detail_member_identity VALUES($question,$root,$identity,$state,$complete)";
        foreach (var name in new[] { "$question", "$root", "$identity", "$state", "$complete" })
            member.Parameters.AddWithValue(name, DBNull.Value);
        member.Prepare();
        foreach (var id in roots)
        {
            token.ThrowIfCancellationRequested();
            var root = ReadRoot(connection, description, id, transaction);
            allComplete &= root.IsComplete;
            var byMember = root.Members.ToDictionary(value => value.Identity, StringComparer.OrdinalIgnoreCase);
            var complete = byMember.Keys.ToDictionary(identity => identity, _ => true, StringComparer.OrdinalIgnoreCase);
            command.Parameters.Clear();
            command.CommandText = "SELECT DISTINCT context FROM member_attribution_permission WHERE root_id=$id ORDER BY context";
            command.Parameters.AddWithValue("$id", id);
            var contexts = new List<string>();
            using (var read = command.ExecuteReader()) while (read.Read()) contexts.Add(read.GetString(0));
            foreach (var context in contexts)
            {
                token.ThrowIfCancellationRequested();
                foreach (var value in ReadContext(connection, id, context, root, transaction))
                {
                    token.ThrowIfCancellationRequested();
                    complete[value.Member] &= value.State is MemberAttributionState.Established or MemberAttributionState.NotEstablished;
                    resource.Parameters["$question"].Value = RequestedProofSelectionStorage.Question(
                        "member-resource", RequestedProofSelectionStorage.RootKey(id), context, value.Member);
                    resource.Parameters["$root"].Value = id;
                    resource.Parameters["$context"].Value = context;
                    resource.Parameters["$member"].Value = value.Member;
                    resource.Parameters["$state"].Value = value.State.ToString();
                    resource.Parameters["$reason"].Value = value.Reason;
                    if (resource.ExecuteNonQuery() != 1) throw Invalid();
                }
            }
            command.CommandText = """
                SELECT sid,scope,identity,MIN(identity) OVER(PARTITION BY sid COLLATE NOCASE,scope COLLATE NOCASE)
                FROM member_attribution_member WHERE root_id=$id AND sid IS NOT NULL
                """;
            var questions = new Dictionary<string, (string Identity, bool Complete)>(StringComparer.Ordinal);
            using (var identities = command.ExecuteReader())
                while (identities.Read())
                {
                    token.ThrowIfCancellationRequested();
                    var question = RequestedProofSelectionStorage.Question("member-of", identities.GetString(0), identities.GetString(1));
                    var valid = complete[identities.GetString(2)];
                    questions[question] = (identities.GetString(3), valid && (!questions.TryGetValue(question, out var previous) || previous.Complete));
                }
            foreach (var (question, value) in questions)
            {
                token.ThrowIfCancellationRequested();
                if (!byMember.TryGetValue(value.Identity, out var original)) throw Invalid();
                member.Parameters["$question"].Value = question;
                member.Parameters["$root"].Value = id;
                member.Parameters["$identity"].Value = value.Identity;
                member.Parameters["$state"].Value = original.State.ToString();
                member.Parameters["$complete"].Value = value.Complete;
                if (member.ExecuteNonQuery() != 1) throw Invalid();
            }
        }
        command.Parameters.Clear();
        command.CommandText = "INSERT INTO PermissionProof.detail_member_summary VALUES(1,$complete)";
        command.Parameters.AddWithValue("$complete", allComplete);
        command.ExecuteNonQuery();
    }
}
