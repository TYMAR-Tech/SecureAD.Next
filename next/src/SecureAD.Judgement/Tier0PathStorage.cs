using System.Collections.Immutable;
using System.Resources;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class Tier0PathStorage
{
    private static readonly ResourceManager Resources = new("SecureAD.Judgement.Resources.Tier0Path", typeof(Tier0PathStorage).Assembly);
    private sealed record Header(PathCalculationStorage.Manifest Manifest, PathRequesterSelection? Selection,
        PathRequesterProofs Proofs)
    {
        internal int NodeCount => Manifest.NodeCount;
        internal IReadOnlyList<SavedRequesterDaclProof> Requesters => Proofs.Requesters;
        internal IReadOnlyList<SavedOwnAccountMembershipProof> OwnAccounts => Proofs.OwnAccounts;
        internal IReadOnlyList<SavedMembershipDaclProof> MembershipDacls => Proofs.MembershipDacls;
    }

    internal static void CreateTables(SqliteConnection connection)
    {
        PathProofStorage.CreateTables(connection);
        PathSharedProofStorage.CreateTables(connection);
        Tier0DistanceStorage.CreateTables(connection);
        BestSupportedRouteStorage.CreateTables(connection);
        Execute(connection, null, """
        CREATE TABLE tier0_path_calculation (id INTEGER PRIMARY KEY CHECK(id=1), proof INTEGER NOT NULL REFERENCES path_proof(id),
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE tier0_path_node (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_target(target),
            outcome TEXT NOT NULL, proof INTEGER NOT NULL REFERENCES path_proof(id), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        """);
        PathCalculationStorage.CreateTables(connection);
    }

    internal static void Write(SqliteConnection connection, JudgementDescription description, JudgingInputs sources,
        IReadOnlyList<RequesterDaclRequest> requests, IReadOnlyList<OwnAccountMembershipRequest> ownAccountRequests,
        CancellationToken cancellationToken, IReadOnlyList<MembershipDaclRequest> membershipDaclRequests, bool offlineSelection,
        Action<PathRequesterWorkPhase> beginPhase, JudgingStatus? status, PreparedStatements statements)
    {
        cancellationToken.ThrowIfCancellationRequested();
        beginPhase(PathRequesterWorkPhase.PreparingPaths);
        var inputs = PathInputStorage.Read(connection, description, out var ownership, cancellationToken);
        PathInputStorage.ValidateSources(connection, description, sources, ownership, inputs, cancellationToken);
        IReadOnlyList<OwnershipAuditStorage.TargetRow> recorded = ownership is null
            ? OwnershipAuditStorage.Targets(connection, cancellationToken) : ownership.Targets;
        IReadOnlyList<Tier0PathNode> nodes = [];
        var bestRoutes = new BestSupportedRouteSelection(connection, description, inputs, cancellationToken);
        if (inputs.Availability == PathInputAvailability.Recorded)
        {
            var bundle = sources.Bundle;
            var contexts = sources.ReadNamingContexts();
            if (!contexts.IsSuccess) throw InvalidProof();
            if (ownership is null) throw InvalidProof();
            ownership.RequireFor(connection, description);
            nodes = Tier0PathCalculation.Calculate(inputs, ownership.Targets.Select(row => row.Identity).ToArray(),
                TerminalPermissions(connection, description), bundle.ReadObjectAttributes, contexts.Value, cancellationToken, bestRoutes.Terminal);
            bestRoutes.Memberships(nodes);
        }
        IReadOnlyDictionary<string, Tier0Target> identities = nodes.ToDictionary(node => node.Subject.DistinguishedName,
            node => node.Subject, StringComparer.OrdinalIgnoreCase);
        if (nodes.Count == 0 && (requests.Count != 0 || ownAccountRequests.Count != 0 || membershipDaclRequests.Count != 0))
        {
            identities = recorded.ToDictionary(row => row.Identity.DistinguishedName, row => row.Identity, StringComparer.OrdinalIgnoreCase);
        }
        var memberships = offlineSelection || requests.Count != 0 || membershipDaclRequests.Count != 0
            ? RequesterMembershipContext.Create(sources, identities, inputs, cancellationToken) : null;
        PathRequesterSelection? selection = null;
        if (offlineSelection)
        {
            beginPhase(PathRequesterWorkPhase.SelectingQuestions);
            selection = WithDiagnostic("Selecting account checks", diagnostic =>
                Selector(sources, inputs, nodes, cancellationToken, diagnostic, memberships).Select());
            requests = PathRequesterSelector.Requests(selection);
            ownAccountRequests = PathRequesterSelector.OwnAccounts(selection);
            membershipDaclRequests = PathRequesterSelector.MembershipDacls(selection);
        }
        beginPhase(PathRequesterWorkPhase.RequesterDacl);
        var requesterQuestions = requests.OrderBy(RequesterDaclProofs.Key, StringComparer.Ordinal)
            .Select(request => new RequesterDaclProofs.Question(request, null)).ToArray();
        var requesters = RequesterDaclProofs.Create(connection, description, sources, identities, inputs, requesterQuestions,
            cancellationToken, memberships);
        var routeIndex = new PathRequesterRouteIndex();
        if (requesters.Count != 0)
            Match("requester-permission", requesters.Count,
                diagnostic => routeIndex.AddRequesters(requesters, cancellationToken, diagnostic),
                node => node with { RequesterRoute = routeIndex.Requester(node) });
        beginPhase(PathRequesterWorkPhase.OwnAccountMembership);
        var prerequisites = new OwnAccountMembershipProofs(connection, description, sources, identities, inputs, cancellationToken);
        IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts = ownAccountRequests.Count == 0 ? []
            : prerequisites.Create(nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), ownAccountRequests);
        if (ownAccounts.Count != 0)
            Match("own-account-membership", ownAccounts.Count,
                diagnostic => routeIndex.AddOwnAccounts(ownAccounts, cancellationToken, diagnostic),
                node => node with { OwnAccountRoute = routeIndex.OwnAccount(node) });
        beginPhase(PathRequesterWorkPhase.MembershipDacl);
        IReadOnlyList<SavedMembershipDaclProof> membershipDacls = membershipDaclRequests.Count == 0 ? []
            : MembershipDaclProofs.Create(connection, description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), membershipDaclRequests, cancellationToken, memberships, prerequisites);
        if (membershipDacls.Count != 0)
            Match("membership-permission", membershipDacls.Count,
                diagnostic => routeIndex.AddMembershipDacls(membershipDacls, cancellationToken, diagnostic),
                node => node with { MembershipDaclRoute = routeIndex.MembershipDacl(node) });
        beginPhase(PathRequesterWorkPhase.WritingProofs);
        sources.RequireFor(description);
        ownership?.RequireFor(connection, description);
        Reconcile(selection, requesters, ownAccounts, membershipDacls);
        using var transaction = connection.BeginTransaction();
        using var proofs = new PathProofStorage.Writer(connection, transaction, cancellationToken);
        var shared = new PathSharedProofStorage(connection, description, cancellationToken, proofs, transaction, statements);
        foreach (var node in nodes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var proof = proofs.Write(node);
            if (statements.Bind("INSERT INTO tier0_path_node VALUES ($target,$outcome,$proof,$hash)", transaction,
                ("$target", node.Subject.DistinguishedName), ("$outcome", node.Reachability.ToString()),
                ("$proof", proof.Id), ("$hash", proof.Fingerprint)).ExecuteNonQuery() != 1) throw InvalidProof();
        }
        var sourceReferences = PathRequesterRiskStorage.WriteSources(shared, requesters, ownAccounts, membershipDacls, cancellationToken);
        var header = PathCalculationStorage.Write(connection, transaction, description, inputs, nodes.Count, selection,
            requesters, ownAccounts, membershipDacls, sourceReferences, proofs, shared, cancellationToken);
        Execute(connection, transaction, "INSERT INTO tier0_path_calculation VALUES (1,$proof,$hash)",
            ("$proof", header.Id), ("$hash", header.Fingerprint));
        PathRequesterRiskStorage.Write(connection, transaction, description, sources, inputs, offlineSelection,
            requesters, ownAccounts, membershipDacls, Convert.ToHexString(header.Fingerprint), proofs, cancellationToken, bestRoutes, sourceReferences);
        Tier0DistanceStorage.Write(connection, transaction, description, inputs, Convert.ToHexString(header.Fingerprint),
            recorded, nodes, routeIndex, selection, requesters.Select(value => value.Assessment.Request.RequesterDn)
                .Concat(ownAccounts.Select(value => value.Assessment.Request.RequesterDn))
                .Concat(membershipDacls.Select(value => value.Assessment.Request.RequesterDn)), cancellationToken);
        BestSupportedRouteStorage.Write(connection, transaction, proofs,
            bestRoutes.Results(recorded, Convert.ToHexString(header.Fingerprint)), cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        transaction.Commit();

        T WithDiagnostic<T>(string stage, Func<PostPassDiagnostics?, T> action)
        {
            using var diagnostic = status?.BeginPostPass(stage, description.GenerationId);
            try
            {
                var result = action(diagnostic);
                cancellationToken.ThrowIfCancellationRequested();
                diagnostic?.Complete();
                return result;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                diagnostic?.Interrupted(cancelled: true);
                throw;
            }
            catch
            {
                diagnostic?.Interrupted(cancelled: false);
                throw;
            }
        }

        void Match(string family, int count, Action<PostPassDiagnostics?> index, Func<Tier0PathNode, Tier0PathNode> match)
        {
            nodes = WithDiagnostic("Matching saved answers", diagnostic =>
            {
                diagnostic?.Part(family + "-index");
                diagnostic?.Counter("answersTotal", count);
                diagnostic?.Counter("answersProcessed", 0);
                index(diagnostic);
                diagnostic?.Part(family + "-matching");
                diagnostic?.Counter("objectsTotal", nodes.Count);
                var processed = 0L;
                var result = new Tier0PathNode[nodes.Count];
                for (var i = 0; i < nodes.Count; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    result[i] = match(nodes[i]);
                    diagnostic?.Counter("objectsProcessed", ++processed);
                }
                return result;
            });
        }
    }

    private static (SavedPathInputs Inputs, Header? Header) ReadSaved(
        SqliteConnection connection, JudgementDescription description, string subjectDn, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var manifest = PathCalculationStorage.Read(connection, description, cancellationToken);
        if (manifest is null)
        {
            var completeInputs = PathInputStorage.Read(connection, description, cancellationToken);
            if (completeInputs.Availability == PathInputAvailability.Recorded) throw InvalidProof();
            return (SavedPathInputs.From(completeInputs), null);
        }
        var proofs = PathRequesterRiskStorage.ReadProofs(connection, description, cancellationToken, subjectDn);
        var inputs = PathCalculationStorage.ReadInputs(connection, description, manifest, cancellationToken);
        var header = new Header(manifest, PathCalculationStorage.ReadSelection(connection, description, manifest, cancellationToken), proofs);
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
                || selection.InputFingerprint != manifest.InputFingerprint
                || selection.InputScanCompleted != (inputs.Availability == PathInputAvailability.Recorded)
                || selection.Candidates is null || selection.Sources is null || selection.Limitations is null
                || selection.Candidates.Any(value => value is null || !Enum.IsDefined(value.Family)
                    || string.IsNullOrWhiteSpace(value.RequesterDn) || string.IsNullOrWhiteSpace(value.TargetDn)
                    || value.Witnesses is not { Count: > 0 })
                || selection.Limitations.Any(value => value is null || !Enum.IsDefined(value.Reason))) throw InvalidProof();
        }
        Reconcile(header.Selection is { } selected ? selected with
        {
            Candidates = selected.Candidates.Where(candidate => string.Equals(candidate.RequesterDn, subjectDn,
                StringComparison.OrdinalIgnoreCase)).ToArray(),
        } : null, header.Requesters, header.OwnAccounts, header.MembershipDacls);
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
        var (inputs, header) = ReadSaved(connection, description, subjectDn);
        return PathOf(connection, inputs, header, subjectDn, CancellationToken.None);
    }

    internal static (Tier0PathResult Path, PathRequesterCoverage Coverage) ReadWithCoverage(
        SqliteConnection connection, JudgementDescription description, string subjectDn, CancellationToken cancellationToken)
    {
        var (inputs, header) = ReadSaved(connection, description, subjectDn, cancellationToken);
        var path = PathOf(connection, inputs, header, subjectDn, cancellationToken);
        var coverage = CoverageOf(description, inputs, header?.Manifest, header?.Selection?.Limitations ?? []);
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
        var manifest = PathCalculationStorage.Read(connection, description, CancellationToken.None);
        var inputs = manifest is null ? SavedPathInputs.From(PathInputStorage.Read(connection, description))
            : PathCalculationStorage.ReadInputs(connection, description, manifest, CancellationToken.None);
        if (manifest is null && inputs.Availability == PathInputAvailability.Recorded) throw InvalidProof();
        var limitations = manifest is null ? [] :
            PathCalculationStorage.ReadSelection(connection, description, manifest, CancellationToken.None)?.Limitations ?? [];
        if (manifest is not null) PathRequesterRiskStorage.ValidateProofs(connection, description, CancellationToken.None);
        return CoverageOf(description, inputs, manifest, limitations);
    }

    internal static PathRequesterSummary ReadSummary(SqliteConnection connection, JudgementDescription description, CancellationToken token)
    {
        var manifest = PathCalculationStorage.Read(connection, description, token);
        if (manifest is not null) return PathCalculationStorage.Summary(description, manifest);
        var inputs = PathInputStorage.Read(connection, description, token);
        if (inputs.Availability == PathInputAvailability.Recorded) throw InvalidProof();
        return new(description.EvidenceSeal, description.DerivationGenerationId, description.GenerationId, inputs.Availability,
            null, false, EmptyFamilies(), inputs.UncertaintyRegions.Count, 0);
    }

    private static PathRequesterCoverage CoverageOf(JudgementDescription description, SavedPathInputs inputs,
        PathCalculationStorage.Manifest? manifest, IReadOnlyList<PathRequesterSelectionLimitation> limitations) =>
        new(description.EvidenceSeal, description.DerivationGenerationId, inputs, manifest?.Selection?.Version,
            manifest?.Selection?.InputScanCompleted ?? false, manifest?.Families ?? EmptyFamilies(), limitations);

    private static PathRequesterFamilyCoverage[] EmptyFamilies() => Enum.GetValues<PathRequesterFamily>()
        .Select(family => new PathRequesterFamilyCoverage(family, 0, 0, 0, 0, 0)).ToArray();

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
        CancellationToken cancellationToken, PostPassDiagnostics? diagnostic, RequesterMembershipContext? memberships)
    {
        sources.RequireCurrent();
        var contexts = sources.ReadNamingContexts();
        if (!contexts.IsSuccess) throw InvalidProof();
        return new(sources.Bundle, inputs, nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            contexts.Value, cancellationToken, diagnostic) { Memberships = memberships };
    }

    internal static Tier0PathNode? ReadNode(SqliteConnection connection, string target, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT target,outcome,proof,fingerprint FROM tier0_path_node WHERE target=$target COLLATE NOCASE";
        query.Parameters.AddWithValue("$target", target);
        using var read = query.ExecuteReader();
        if (!read.Read()) return null;
        var node = PathProofStorage.Read<Tier0PathNode>(connection, read.GetInt64(2),
            Convert.ToHexString((byte[])read.GetValue(3)), cancellationToken);
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
