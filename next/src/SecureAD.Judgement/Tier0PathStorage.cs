using System.Collections.Immutable;
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
        IReadOnlyList<SavedMembershipDaclProof> MembershipDacls, bool OfflineSelection,
        PathRequesterSelection? Selection, SavedPathInputs Inputs);

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE tier0_path_calculation (id INTEGER PRIMARY KEY CHECK(id=1), proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE tier0_path_node (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_target(target),
            outcome TEXT NOT NULL, proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        """);

    internal static void Write(SqliteConnection connection, JudgementDescription description, JudgingInputs sources,
        IReadOnlyList<RequesterDaclRequest> requests, IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        CancellationToken cancellationToken, IReadOnlyList<MembershipDaclRequest> membershipDaclRequests, bool offlineSelection,
        Action<PathRequesterWorkPhase> beginPhase)
    {
        cancellationToken.ThrowIfCancellationRequested();
        beginPhase(PathRequesterWorkPhase.PreparingPaths);
        var inputs = PathInputStorage.Read(connection, description, out var ownership, cancellationToken);
        PathInputStorage.ValidateSources(connection, description, sources, ownership, inputs, cancellationToken);
        IReadOnlyList<Tier0PathNode> nodes = [];
        if (inputs.Availability == PathInputAvailability.Recorded)
        {
            var bundle = sources.Bundle;
            var contexts = sources.ReadNamingContexts();
            if (!contexts.IsSuccess) throw InvalidProof();
            if (ownership is null) throw InvalidProof();
            ownership.RequireFor(connection, description);
            nodes = Tier0PathCalculation.Calculate(inputs, ownership.Targets.Select(row => row.Identity).ToArray(),
                TerminalPermissions(connection, description), bundle.ReadObjectAttributes, contexts.Value, cancellationToken);
        }
        PathRequesterSelection? selection = null;
        if (offlineSelection)
        {
            beginPhase(PathRequesterWorkPhase.SelectingQuestions);
            selection = Selector(sources, inputs, nodes, cancellationToken).Select();
            requests = PathRequesterSelector.Requests(selection);
            ownAccountRequests = PathRequesterSelector.OwnAccounts(selection);
            membershipDaclRequests = PathRequesterSelector.MembershipDacls(selection);
        }
        IReadOnlyDictionary<string, Tier0Target> identities = ImmutableDictionary<string, Tier0Target>.Empty;
        if (requests.Count != 0 || ownAccountRequests.Count != 0 || membershipDaclRequests.Count != 0)
        {
            // Explicit questions can exist without complete path inputs; keep their captured
            // identities without constructing a finished ownership snapshot for unavailable work.
            var targets = ownership is null ? OwnershipAuditStorage.Targets(connection, cancellationToken) : ownership.Targets;
            identities = targets.ToDictionary(row => row.Identity.DistinguishedName, row => row.Identity, StringComparer.OrdinalIgnoreCase);
        }
        beginPhase(PathRequesterWorkPhase.RequesterDacl);
        var requesters = RequesterDaclProofs.Create(connection, description, sources, identities, inputs, requests, cancellationToken, obtainedMembership: null);
        if (requesters.Count != 0)
            nodes = nodes.Select(node => node with { RequesterRoute = RequesterDaclProofs.Best(node, requesters) }).ToArray();
        beginPhase(PathRequesterWorkPhase.OwnAccountMembership);
        IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts = ownAccountRequests.Count == 0 ? []
            : OwnAccountMembershipProofs.Create(connection, description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), ownAccountRequests, cancellationToken);
        if (ownAccounts.Count != 0)
            nodes = nodes.Select(node => node with { OwnAccountRoute = OwnAccountMembershipProofs.Best(node, ownAccounts, requesters) }).ToArray();
        beginPhase(PathRequesterWorkPhase.MembershipDacl);
        IReadOnlyList<SavedMembershipDaclProof> membershipDacls = membershipDaclRequests.Count == 0 ? []
            : MembershipDaclProofs.Create(connection, description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), membershipDaclRequests, cancellationToken);
        if (membershipDacls.Count != 0)
            nodes = nodes.Select(node => node with
                { MembershipDaclRoute = MembershipDaclProofs.Best(node, membershipDacls, requesters, ownAccounts) }).ToArray();
        beginPhase(PathRequesterWorkPhase.WritingProofs);
        sources.RequireFor(description);
        ownership?.RequireFor(connection, description);
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
            Tier0PathCalculation.Fingerprint(inputs), nodes.Count, requesters, ownAccounts, membershipDacls,
            offlineSelection, selection, SavedPathInputs.From(inputs)), ProofSerialization.Options);
        Execute(connection, transaction, "INSERT INTO tier0_path_calculation VALUES (1,$proof,$hash)",
            ("$proof", header), ("$hash", OwnershipAuditStorage.Hash(header)));
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    private static (SavedPathInputs Inputs, Header? Header) ReadSaved(
        SqliteConnection connection, JudgementDescription description, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT proof,fingerprint FROM tier0_path_calculation WHERE id=1";
        Header? header;
        using (var read = query.ExecuteReader()) header = read.Read() ? Decode<Header>(read.GetString(0), (byte[])read.GetValue(1)) : null;
        if (header is null)
        {
            var completeInputs = PathInputStorage.Read(connection, description, cancellationToken);
            if (completeInputs.Availability == PathInputAvailability.Recorded) throw InvalidProof();
            return (SavedPathInputs.From(completeInputs), null);
        }
        if (header.Version != Tier0PathCalculation.Version || header.Generation != description.GenerationId
            || header.InputFingerprint is not { Length: 64 } || header.NodeCount < 0
            || header.Requesters is null || header.OwnAccounts is null || header.MembershipDacls is null
            || header.OfflineSelection != (header.Selection is not null) || header.Inputs is null
            || header.Inputs.JudgementGenerationId != description.GenerationId
            || header.Inputs.FixedTargets is null || header.Inputs.UncertaintyRegions is null) throw InvalidProof();
        var inputs = header.Inputs;
        cancellationToken.ThrowIfCancellationRequested();
        foreach (var proof in header.Requesters)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (proof?.Assessment is not { } value || value.Request is null || value.Steps is null
                || string.IsNullOrWhiteSpace(value.Request.RequesterDn) || string.IsNullOrWhiteSpace(value.Request.TargetDn)
                || !Enum.IsDefined(value.Authorization)) throw InvalidProof();
            RequireBinding(description, value.GenerationId, value.DerivationGenerationId, value.EvidenceSeal);
        }
        foreach (var proof in header.OwnAccounts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (proof?.Assessment is not { } value || proof.Steps is null) throw InvalidProof();
            RequireOwnAccount(description, value);
        }
        foreach (var proof in header.MembershipDacls)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (proof?.Assessment is not { } value || !MembershipDaclProofs.Valid(value.Request)
                || value.Membership is null || value.Steps is null || !Enum.IsDefined(value.Authorization)
                || value.AuthorizationContext != MembershipDaclAssessment.Context) throw InvalidProof();
            RequireOwnAccount(description, value.Membership);
            if (value.Dacl is { } dacl)
                RequireBinding(description, dacl.GenerationId, dacl.DerivationGenerationId, dacl.EvidenceSeal);
        }
        if (header.Selection is { } selection)
        {
            if (selection.Version != PathRequesterSelector.Version || selection.JudgementGenerationId != description.GenerationId
                || selection.InputFingerprint != header.InputFingerprint
                || selection.InputScanCompleted != (inputs.Availability == PathInputAvailability.Recorded)
                || selection.Candidates is null || selection.Sources is null || selection.Limitations is null
                || selection.Candidates.Any(value => value is null || !Enum.IsDefined(value.Family)
                    || string.IsNullOrWhiteSpace(value.RequesterDn) || string.IsNullOrWhiteSpace(value.TargetDn)
                    || value.Witnesses is not { Count: > 0 })
                || selection.Limitations.Any(value => value is null || !Enum.IsDefined(value.Reason))) throw InvalidProof();
        }
        Reconcile(header.Selection, header.Requesters, header.OwnAccounts, header.MembershipDacls);
        cancellationToken.ThrowIfCancellationRequested();
        return (inputs, header);
    }

    private static void RequireOwnAccount(JudgementDescription description, OwnAccountMembershipAssessment value)
    {
        if (value.Request is null || string.IsNullOrWhiteSpace(value.Request.RequesterDn)
            || string.IsNullOrWhiteSpace(value.Request.TargetDn) || !Enum.IsDefined(value.Request.PermissionKind)
            || !Enum.IsDefined(value.Obtainability) || value.Permission is null) throw InvalidProof();
        RequireBinding(description, value.GenerationId, value.DerivationGenerationId, value.EvidenceSeal);
        RequireBinding(description, value.Permission.GenerationId, value.Permission.DerivationGenerationId, value.Permission.EvidenceSeal);
    }

    private static void RequireBinding(JudgementDescription description, Guid generation, Guid? derivation, string evidenceSeal)
    {
        if (generation != description.GenerationId || derivation != description.DerivationGenerationId
            || evidenceSeal != description.EvidenceSeal) throw InvalidProof();
    }

    internal static Tier0PathResult Read(SqliteConnection connection, JudgementDescription description, string subjectDn)
    {
        var (inputs, header) = ReadSaved(connection, description);
        return PathOf(connection, inputs, header, subjectDn, CancellationToken.None);
    }

    internal static (Tier0PathResult Path, PathRequesterCoverage Coverage) ReadWithCoverage(
        SqliteConnection connection, JudgementDescription description, string subjectDn, CancellationToken cancellationToken)
    {
        var (inputs, header) = ReadSaved(connection, description, cancellationToken);
        var path = PathOf(connection, inputs, header, subjectDn, cancellationToken);
        var coverage = CoverageOf(description, inputs, header);
        cancellationToken.ThrowIfCancellationRequested();
        return (path, coverage);
    }

    private static Tier0PathResult PathOf(SqliteConnection connection, SavedPathInputs inputs, Header? header,
        string subjectDn, CancellationToken cancellationToken)
    {
        if (header is null) return new(inputs, null, Tier0Reachability.Unknown, null, []);
        var assessments = header.Requesters.Select(proof => proof.Assessment)
            .Where(value => string.Equals(value.Request.RequesterDn, subjectDn, StringComparison.OrdinalIgnoreCase)).ToArray();
        var ownAssessments = header.OwnAccounts.Select(proof => proof.Assessment)
            .Where(value => string.Equals(value.Request.RequesterDn, subjectDn, StringComparison.OrdinalIgnoreCase)).ToArray();
        var membershipDaclAssessments = header.MembershipDacls.Select(proof => proof.Assessment)
            .Where(value => string.Equals(value.Request.RequesterDn, subjectDn, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (inputs.Availability != PathInputAvailability.Recorded)
        {
            if (header.NodeCount != 0) throw InvalidProof();
            return new(inputs, null, Tier0Reachability.Unknown, null, [])
                { RequesterAssessments = assessments, OwnAccountAssessments = ownAssessments, MembershipDaclAssessments = membershipDaclAssessments, RequesterSelection = header.Selection };
        }
        var subject = ReadNode(connection, subjectDn, cancellationToken);
        if (subject is null)
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
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { subject.Subject.DistinguishedName };
            while (current.MembershipNext is { } step)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (step.From != current.Subject || step.To is null || !visited.Add(step.To.DistinguishedName)) throw InvalidProof();
                steps.Add(step);
                var next = ReadNode(connection, step.To.DistinguishedName, cancellationToken) ?? throw InvalidProof();
                if (next.Subject != step.To || current.MembershipDistance is not > 0
                    || next.MembershipDistance != current.MembershipDistance - 1) throw InvalidProof();
                current = next;
            }
            if (subject.Reachability == Tier0Reachability.Reachable && current.MembershipDistance != 0) throw InvalidProof();
        }
        var end = subject.Subject;
        foreach (var step in steps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (step.From != end || step.To is null || !Enum.IsDefined(step.Kind) || step.PermissionId <= 0) throw InvalidProof();
            end = step.To;
        }
        if (subject.Reachability == Tier0Reachability.Reachable && !inputs.FixedTargets.Contains(end)) throw InvalidProof();
        return new(inputs, subject.Subject, subject.Reachability,
            subject.Reachability == Tier0Reachability.Reachable ? steps.Count : null, steps)
        { RequesterAssessments = assessments, OwnAccountAssessments = ownAssessments, MembershipDaclAssessments = membershipDaclAssessments, RequesterSelection = header.Selection };
    }

    internal static PathRequesterCoverage ReadCoverage(SqliteConnection connection, JudgementDescription description)
    {
        var (inputs, header) = ReadSaved(connection, description);
        return CoverageOf(description, inputs, header);
    }

    private static PathRequesterCoverage CoverageOf(JudgementDescription description, SavedPathInputs inputs, Header? header)
    {
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

    private static PathRequesterSelector Selector(JudgingInputs sources, PathInputs inputs, IReadOnlyList<Tier0PathNode> nodes,
        CancellationToken cancellationToken)
    {
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw InvalidProof();
        return new(sources.Bundle, inputs, nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            contexts.Value, cancellationToken);
    }

    private static Tier0PathNode? ReadNode(SqliteConnection connection, string target, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT target,outcome,proof,fingerprint FROM tier0_path_node WHERE target=$target COLLATE NOCASE";
        query.Parameters.AddWithValue("$target", target);
        using var read = query.ExecuteReader();
        if (!read.Read()) return null;
        var node = Decode<Tier0PathNode>(read.GetString(2), (byte[])read.GetValue(3));
        if (node.Subject is null || node.Subject.DistinguishedName != read.GetString(0)
            || node.Reachability.ToString() != read.GetString(1) || node.MembershipDistance < 0
            || node.MembershipDistance is null or 0 && node.MembershipNext is not null) throw InvalidProof();
        return node;
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
