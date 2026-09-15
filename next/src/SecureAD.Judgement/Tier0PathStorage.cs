using System.Resources;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class Tier0PathStorage
{
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.Tier0Path", typeof(Tier0PathStorage).Assembly);
    private sealed record Header(int Version, Guid Generation, string InputFingerprint, int NodeCount);

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE tier0_path_calculation (id INTEGER PRIMARY KEY CHECK(id=1), proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE tier0_path_node (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_target(target),
            outcome TEXT NOT NULL, proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        """);

    internal static void Write(SqliteConnection connection, JudgementDescription description, string directory,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var inputs = PathInputStorage.Read(connection, description, directory);
        IReadOnlyList<Tier0PathNode> nodes = [];
        if (inputs.Availability == PathInputAvailability.Recorded)
        {
            var opened = BundleReader.Open(directory);
            if (!opened.IsSuccess) throw InvalidProof();
            using var bundle = opened.Value;
            var contexts = bundle.ReadNamingContexts();
            if (!contexts.IsSuccess) throw InvalidProof();
            nodes = Tier0PathCalculation.Calculate(inputs, OwnershipAuditStorage.Targets(connection).Select(row => row.Identity).ToArray(),
                TerminalPermissions(connection, description), bundle.ReadObjectAttributes, contexts.Value, cancellationToken);
        }
        using var transaction = connection.BeginTransaction();
        foreach (var node in nodes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var json = JsonSerializer.Serialize(node, ProofSerialization.Options);
            Execute(connection, transaction, "INSERT INTO tier0_path_node VALUES ($target,$outcome,$proof,$hash)",
                ("$target", node.Subject.DistinguishedName), ("$outcome", node.Reachability.ToString()),
                ("$proof", json), ("$hash", OwnershipAuditStorage.Hash(json)));
        }
        var header = JsonSerializer.Serialize(new Header(Tier0PathCalculation.Version, description.GenerationId,
            Tier0PathCalculation.Fingerprint(inputs), nodes.Count), ProofSerialization.Options);
        Execute(connection, transaction, "INSERT INTO tier0_path_calculation VALUES (1,$proof,$hash)",
            ("$proof", header), ("$hash", OwnershipAuditStorage.Hash(header)));
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    internal static Tier0PathResult Read(SqliteConnection connection, JudgementDescription description, string directory, string subjectDn)
    {
        var inputs = PathInputStorage.Read(connection, description, directory);
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT proof,fingerprint FROM tier0_path_calculation WHERE id=1";
        Header? header;
        using (var read = query.ExecuteReader()) header = read.Read() ? Decode<Header>(read.GetString(0), (byte[])read.GetValue(1)) : null;
        var nodes = ReadNodes(connection);
        if (header is null)
        {
            if (inputs.Availability == PathInputAvailability.Recorded || nodes.Count != 0) throw InvalidProof();
            return new(inputs, null, Tier0Reachability.Unknown, null, []);
        }
        if (header.Version != Tier0PathCalculation.Version || header.Generation != description.GenerationId
            || header.InputFingerprint != Tier0PathCalculation.Fingerprint(inputs) || header.NodeCount != nodes.Count) throw InvalidProof();
        if (inputs.Availability != PathInputAvailability.Recorded)
        {
            if (nodes.Count != 0) throw InvalidProof();
            return new(inputs, null, Tier0Reachability.Unknown, null, []);
        }
        Validate(connection, description, directory, inputs, nodes);
        if (!nodes.TryGetValue(subjectDn, out var subject)) return new(inputs, null, Tier0Reachability.Unknown, null, []);
        var steps = new List<Tier0PathStep>();
        if (subject.MembershipDistance != 0 && subject.Terminal is { } terminal)
            steps.Add(terminal);
        else
        {
            var current = subject;
            while (current.MembershipNext is { } step)
            {
                steps.Add(step);
                current = nodes[step.To.DistinguishedName];
            }
        }
        return new(inputs, subject.Subject, subject.Reachability,
            subject.Reachability == Tier0Reachability.Reachable ? steps.Count : null, steps);
    }

    private static Dictionary<string, Tier0PathNode> ReadNodes(SqliteConnection connection)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT target,outcome,proof,fingerprint FROM tier0_path_node ORDER BY target";
        using var read = query.ExecuteReader();
        var nodes = new Dictionary<string, Tier0PathNode>(StringComparer.OrdinalIgnoreCase);
        while (read.Read())
        {
            var node = Decode<Tier0PathNode>(read.GetString(2), (byte[])read.GetValue(3));
            if (node.Subject is null || node.Subject.DistinguishedName != read.GetString(0)
                || node.Reachability.ToString() != read.GetString(1)) throw InvalidProof();
            nodes.Add(read.GetString(0), node);
        }
        return nodes;
    }

    private static void Validate(SqliteConnection connection, JudgementDescription description, string directory,
        PathInputs inputs, IReadOnlyDictionary<string, Tier0PathNode> nodes)
    {
        var targets = OwnershipAuditStorage.Targets(connection).Select(row => row.Identity).ToArray();
        if (targets.Length != nodes.Count || targets.Any(target => !nodes.TryGetValue(target.DistinguishedName, out var node)
            || node.Subject != target)) throw InvalidProof();
        var anchors = inputs.FixedTargets.ToDictionary(target => target.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        var membership = Tier0PathCalculation.MembershipSteps(inputs, CancellationToken.None).ToHashSet();
        foreach (var node in nodes.Values)
        {
            var fixedTarget = anchors.ContainsKey(node.Subject.DistinguishedName);
            if (fixedTarget != (node.MembershipDistance == 0) || node.MembershipDistance < 0) throw InvalidProof();
            if (node.MembershipDistance is null or 0)
            {
                if (node.MembershipNext is not null) throw InvalidProof();
            }
            else if (node.MembershipNext is not { } next || next.From != node.Subject || !membership.Contains(next)
                || !nodes.TryGetValue(next.To.DistinguishedName, out var parent)
                || parent.Subject != next.To || parent.MembershipDistance != node.MembershipDistance - 1) throw InvalidProof();
            if (node.Terminal is null && node.PermissionFingerprint is not null) throw InvalidProof();
        }
        // These inequalities validate the saved shortest-distance certificate. No queue, discovery,
        // permission evaluation or replacement path is run while reading a result.
        foreach (var step in membership)
        {
            if (!nodes.TryGetValue(step.From.DistinguishedName, out var from) || !nodes.TryGetValue(step.To.DistinguishedName, out var to))
                throw InvalidProof();
            if (to.MembershipDistance is { } distance && (from.MembershipDistance is null || from.MembershipDistance > distance + 1))
                throw InvalidProof();
        }
        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess) throw InvalidProof();
        using var bundle = opened.Value;
        var contexts = bundle.ReadNamingContexts();
        if (!contexts.IsSuccess) throw InvalidProof();
        var holders = targets.Where(target => target.Sid is not null)
            .GroupBy(target => Tier0PathCalculation.HolderKey(target.Sid!, target.SidScope), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() == 1).ToDictionary(group => group.Key, group => group.Single(), StringComparer.OrdinalIgnoreCase);
        var supportedTerminals = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var edge in TerminalPermissions(connection, description))
        {
            var step = Tier0PathCalculation.TerminalStep(edge, inputs, anchors, holders, bundle.ReadObjectAttributes, contexts.Value);
            if (step is null || !supportedTerminals.Add(step.From.DistinguishedName)) continue;
            var node = nodes[step.From.DistinguishedName];
            if (node.Terminal != step || node.PermissionFingerprint != Tier0PathCalculation.Fingerprint(edge)) throw InvalidProof();
        }
        if (nodes.Values.Any(node => node.Terminal is not null && !supportedTerminals.Contains(node.Subject.DistinguishedName))) throw InvalidProof();
    }

    private static IEnumerable<ControlEdge> TerminalPermissions(SqliteConnection connection, JudgementDescription description)
    {
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT e.id FROM control_edge e JOIN path_anchor a ON a.target=e.target COLLATE NOCASE
            WHERE e.capability IN ('CanWriteDacl','IsOwnerAndCanRewriteDacl')
            ORDER BY e.target COLLATE NOCASE, CASE e.capability WHEN 'CanWriteDacl' THEN 0 ELSE 1 END, e.id
            """;
        var ids = new List<long>();
        using (var read = query.ExecuteReader()) while (read.Read()) ids.Add(read.GetInt64(0));
        foreach (var edge in ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id))
            .OrderBy(edge => edge.Target, StringComparer.OrdinalIgnoreCase).ThenBy(edge => edge.Capability).ThenBy(edge => edge.Id))
            yield return edge;
    }

    private static T Decode<T>(string json, byte[] fingerprint)
    {
        if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual(fingerprint)) throw InvalidProof();
        return JsonSerializer.Deserialize<T>(json, ProofSerialization.Options) ?? throw InvalidProof();
    }

    internal static InvalidDataException InvalidProof() => new(Resources.GetString("InvalidProof", System.Globalization.CultureInfo.CurrentUICulture));

    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
