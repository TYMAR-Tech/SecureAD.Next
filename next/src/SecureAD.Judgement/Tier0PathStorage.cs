using System.Resources;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class Tier0PathStorage
{
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.Tier0Path", typeof(Tier0PathStorage).Assembly);
    private sealed record Header(int Version, Guid Generation, string InputFingerprint, int NodeCount,
        IReadOnlyList<SavedRequesterDaclProof> Requesters, IReadOnlyList<SavedOwnAccountMembershipProof> OwnAccounts,
        IReadOnlyList<SavedMembershipDaclProof> MembershipDacls, bool OfflineSelection, PathRequesterSelection? Selection);

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE tier0_path_calculation (id INTEGER PRIMARY KEY CHECK(id=1), proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE tier0_path_node (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_target(target),
            outcome TEXT NOT NULL, proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        """);

    internal static void Write(SqliteConnection connection, JudgementDescription description, string directory,
        IReadOnlyList<RequesterDaclRequest> requests, IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        CancellationToken cancellationToken, IReadOnlyList<MembershipDaclRequest> membershipDaclRequests, bool offlineSelection,
        Action<PathRequesterWorkPhase> beginPhase)
    {
        cancellationToken.ThrowIfCancellationRequested();
        beginPhase(PathRequesterWorkPhase.PreparingPaths);
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
        PathRequesterSelection? selection = null;
        if (offlineSelection)
        {
            beginPhase(PathRequesterWorkPhase.SelectingQuestions);
            using var bundle = OpenSelectionBundle(directory);
            selection = Selector(bundle, inputs, nodes, cancellationToken).Select();
            requests = PathRequesterSelector.Requests(selection);
            ownAccountRequests = PathRequesterSelector.OwnAccounts(selection);
            membershipDaclRequests = PathRequesterSelector.MembershipDacls(selection);
        }
        beginPhase(PathRequesterWorkPhase.RequesterDacl);
        var requesters = RequesterDaclProofs.Create(connection, description, directory, inputs, requests, cancellationToken, obtainedMembership: null);
        nodes = nodes.Select(node => node with { RequesterRoute = RequesterDaclProofs.Best(node, requesters) }).ToArray();
        beginPhase(PathRequesterWorkPhase.OwnAccountMembership);
        var ownAccounts = OwnAccountMembershipProofs.Create(connection, description, directory, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), ownAccountRequests, cancellationToken);
        nodes = nodes.Select(node => node with { OwnAccountRoute = OwnAccountMembershipProofs.Best(node, ownAccounts, requesters) }).ToArray();
        beginPhase(PathRequesterWorkPhase.MembershipDacl);
        var membershipDacls = MembershipDaclProofs.Create(connection, description, directory, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), membershipDaclRequests, cancellationToken);
        nodes = nodes.Select(node => node with
            { MembershipDaclRoute = MembershipDaclProofs.Best(node, membershipDacls, requesters, ownAccounts) }).ToArray();
        beginPhase(PathRequesterWorkPhase.WritingProofs);
        Reconcile(selection, requesters, ownAccounts, membershipDacls);
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
            Tier0PathCalculation.Fingerprint(inputs), nodes.Count, requesters, ownAccounts, membershipDacls, offlineSelection, selection), ProofSerialization.Options);
        Execute(connection, transaction, "INSERT INTO tier0_path_calculation VALUES (1,$proof,$hash)",
            ("$proof", header), ("$hash", OwnershipAuditStorage.Hash(header)));
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    private static (PathInputs Inputs, Header? Header, Dictionary<string, Tier0PathNode> Nodes) ReadValidated(
        SqliteConnection connection, JudgementDescription description, string directory)
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
            return (inputs, null, nodes);
        }
        if (header.Version != Tier0PathCalculation.Version || header.Generation != description.GenerationId
            || header.InputFingerprint != Tier0PathCalculation.Fingerprint(inputs) || header.NodeCount != nodes.Count
            || header.Requesters is null || header.OwnAccounts is null || header.MembershipDacls is null
            || header.OfflineSelection != (header.Selection is not null)) throw InvalidProof();
        RequesterDaclProofs.Validate(connection, description, directory, inputs, header.Requesters);
        if (inputs.Availability == PathInputAvailability.Recorded) Validate(connection, description, directory, inputs, nodes);
        OwnAccountMembershipProofs.Validate(connection, description, directory, inputs, nodes, header.OwnAccounts);
        MembershipDaclProofs.Validate(connection, description, directory, inputs, nodes, header.MembershipDacls);
        if (header.Selection is { } selection)
        {
            using var bundle = OpenSelectionBundle(directory);
            Selector(bundle, inputs, nodes.Values.ToArray(), CancellationToken.None).Validate(selection,
                header.Requesters.Select(value => value.Assessment.Request).ToArray(),
                header.OwnAccounts.Select(value => value.Assessment.Request).ToArray(),
                header.MembershipDacls.Select(value => value.Assessment.Request).ToArray());
        }
        Reconcile(header.Selection, header.Requesters, header.OwnAccounts, header.MembershipDacls);
        if (nodes.Values.Any(node => node.RequesterRoute != RequesterDaclProofs.Best(node, header.Requesters))) throw InvalidProof();
        if (nodes.Values.Any(node => node.OwnAccountRoute != OwnAccountMembershipProofs.Best(node, header.OwnAccounts, header.Requesters))) throw InvalidProof();
        if (nodes.Values.Any(node => node.MembershipDaclRoute != MembershipDaclProofs.Best(node, header.MembershipDacls, header.Requesters, header.OwnAccounts))) throw InvalidProof();
        return (inputs, header, nodes);
    }

    internal static Tier0PathResult Read(SqliteConnection connection, JudgementDescription description, string directory, string subjectDn)
    {
        var (inputs, header, nodes) = ReadValidated(connection, description, directory);
        if (header is null) return new(inputs, null, Tier0Reachability.Unknown, null, []);
        var assessments = header.Requesters.Select(proof => proof.Assessment)
            .Where(value => string.Equals(value.Request.RequesterDn, subjectDn, StringComparison.OrdinalIgnoreCase)).ToArray();
        var ownAssessments = header.OwnAccounts.Select(proof => proof.Assessment)
            .Where(value => string.Equals(value.Request.RequesterDn, subjectDn, StringComparison.OrdinalIgnoreCase)).ToArray();
        var membershipDaclAssessments = header.MembershipDacls.Select(proof => proof.Assessment)
            .Where(value => string.Equals(value.Request.RequesterDn, subjectDn, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (inputs.Availability != PathInputAvailability.Recorded)
        {
            if (nodes.Count != 0) throw InvalidProof();
            return new(inputs, null, Tier0Reachability.Unknown, null, [])
                { RequesterAssessments = assessments, OwnAccountAssessments = ownAssessments, MembershipDaclAssessments = membershipDaclAssessments, RequesterSelection = header.Selection };
        }
        if (!nodes.TryGetValue(subjectDn, out var subject))
            return new(inputs, null, Tier0Reachability.Unknown, null, [])
                { RequesterAssessments = assessments, OwnAccountAssessments = ownAssessments, MembershipDaclAssessments = membershipDaclAssessments, RequesterSelection = header.Selection };
        var steps = new List<Tier0PathStep>();
        if (subject.MembershipDaclRoute is { } membershipDaclRequest)
            steps.AddRange(header.MembershipDacls.Single(proof => proof.Assessment.Request == membershipDaclRequest).Assessment.Steps);
        else if (subject.OwnAccountRoute is { } ownRequest)
            steps.AddRange(header.OwnAccounts.Single(proof => proof.Assessment.Request == ownRequest).Steps);
        else if (subject.RequesterRoute is { } request)
            steps.AddRange(assessments.Single(value => value.Request == request).Steps);
        else if (subject.MembershipDistance != 0 && subject.Terminal is { } terminal)
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
            subject.Reachability == Tier0Reachability.Reachable ? steps.Count : null, steps)
        { RequesterAssessments = assessments, OwnAccountAssessments = ownAssessments, MembershipDaclAssessments = membershipDaclAssessments, RequesterSelection = header.Selection };
    }

    internal static PathRequesterCoverage ReadCoverage(SqliteConnection connection, JudgementDescription description, string directory)
    {
        var (inputs, header, _) = ReadValidated(connection, description, directory);
        var selection = header?.Selection;
        var requesters = header?.Requesters ?? [];
        var ownAccounts = header?.OwnAccounts ?? [];
        var membershipDacls = header?.MembershipDacls ?? [];
        int Selected(PathRequesterFamily family) => selection?.Candidates.Count(value => value.Family == family) ?? 0;
        return new(description.EvidenceSeal, description.DerivationGenerationId, inputs, selection?.Version, selection?.InputScanCompleted ?? false,
        [
            new(PathRequesterFamily.RequesterDacl, Selected(PathRequesterFamily.RequesterDacl), requesters.Count,
                requesters.Count(value => value.Assessment.Authorization == ControlEvaluationState.Unknown), 0, 0),
            new(PathRequesterFamily.OwnAccountMembership, Selected(PathRequesterFamily.OwnAccountMembership), ownAccounts.Count,
                ownAccounts.Count(value => value.Assessment.Obtainability == ControlEvaluationState.Unknown),
                ownAccounts.Count(value => value.Assessment.Permission.MemberPresent is null),
                ownAccounts.Count(value => value.Assessment.Permission.Readiness == ControlEvaluationState.Unknown)),
            new(PathRequesterFamily.MembershipDacl, Selected(PathRequesterFamily.MembershipDacl), membershipDacls.Count,
                membershipDacls.Count(value => value.Assessment.Authorization == ControlEvaluationState.Unknown),
                membershipDacls.Count(value => value.Assessment.Membership.Permission.MemberPresent is null),
                membershipDacls.Count(value => value.Assessment.Membership.Permission.Readiness == ControlEvaluationState.Unknown)),
        ], selection?.Limitations ?? []);
    }

    private static void Reconcile(PathRequesterSelection? selection, IReadOnlyList<SavedRequesterDaclProof> requesters,
        IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts, IReadOnlyList<SavedMembershipDaclProof> membershipDacls)
    {
        if (selection is null) return;
        RequireSameQuestions(PathRequesterSelector.Requests(selection).Select(RequesterDaclProofs.Key),
            requesters.Select(value => RequesterDaclProofs.Key(value.Assessment.Request)));
        RequireSameQuestions(PathRequesterSelector.OwnAccounts(selection).Select(OwnAccountMembershipProofs.Key),
            ownAccounts.Select(value => OwnAccountMembershipProofs.Key(value.Assessment.Request)));
        RequireSameQuestions(PathRequesterSelector.MembershipDacls(selection).Select(MembershipDaclProofs.Key),
            membershipDacls.Select(value => MembershipDaclProofs.Key(value.Assessment.Request)));
    }

    private static void RequireSameQuestions(IEnumerable<string> selected, IEnumerable<string> evaluated)
    {
        var expected = selected.Order(StringComparer.Ordinal).ToArray();
        var actual = evaluated.Order(StringComparer.Ordinal).ToArray();
        // Equal totals can conceal a missing question replaced by a duplicate or a different target.
        if (expected.Distinct(StringComparer.Ordinal).Count() != expected.Length
            || !expected.SequenceEqual(actual, StringComparer.Ordinal)) throw InvalidProof();
    }

    private static BundleReader OpenSelectionBundle(string directory)
    {
        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess) throw InvalidProof();
        return opened.Value;
    }

    private static PathRequesterSelector Selector(BundleReader bundle, PathInputs inputs, IReadOnlyList<Tier0PathNode> nodes,
        CancellationToken cancellationToken)
    {
        var contexts = bundle.ReadNamingContexts();
        if (!contexts.IsSuccess) throw InvalidProof();
        return new(bundle, inputs, nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            contexts.Value, cancellationToken);
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
        try
        {
            return JsonSerializer.Deserialize<T>(json, ProofSerialization.Options) ?? throw InvalidProof();
        }
        catch (JsonException)
        {
            throw InvalidProof();
        }
    }

    internal static InvalidDataException InvalidProof() => new(Resources.GetString("InvalidProof", System.Globalization.CultureInfo.CurrentUICulture));

    internal static string InvalidRequestMessage() => Resources.GetString("InvalidRequest", System.Globalization.CultureInfo.CurrentUICulture)!;

    internal static string InvalidOwnAccountRequestMessage() => Resources.GetString("InvalidOwnAccountRequest", System.Globalization.CultureInfo.CurrentUICulture)!;

    internal static string InvalidMembershipDaclRequestMessage() => Resources.GetString("InvalidMembershipDaclRequest", System.Globalization.CultureInfo.CurrentUICulture)!;

    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var parameter in parameters) command.Parameters.AddWithValue(parameter.Name, parameter.Value ?? DBNull.Value);
        command.ExecuteNonQuery();
    }
}
