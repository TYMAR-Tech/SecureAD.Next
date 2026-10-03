using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

internal static class PathRequesterRiskStorage
{
    internal const int Version = 1;

    internal static void CreateTables(SqliteConnection connection) => Execute(connection, null, """
        CREATE TABLE path_risk_product (id INTEGER PRIMARY KEY CHECK(id=1), proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE TABLE path_requester_risk (id INTEGER PRIMARY KEY, requester TEXT NOT NULL COLLATE NOCASE,
            question_key TEXT NOT NULL UNIQUE, proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE INDEX ix_path_risk_requester ON path_requester_risk(requester,id);
        """);

    private sealed record Question(PathRequesterFamily Family, string RequesterDn, string TargetDn,
        string? GroupDn, OwnAccountMembershipPermissionKind? PermissionKind, Tier0Target? Requester,
        ControlEvaluationState Authorization, IReadOnlyList<Tier0PathStep> Steps, string Fingerprint,
        ControlEvaluationState? Readiness, bool? MemberPresent);

    private sealed record Authority(MembershipRouteSummary Routes, PathRiskAuthorityEvidence Evidence);

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction,
        JudgementDescription description, JudgingInputs sources, PathInputs inputs, bool selectionRequested,
        IReadOnlyList<SavedRequesterDaclProof> requesters, IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts,
        IReadOnlyList<SavedMembershipDaclProof> membershipDacls, string calculationFingerprint,
        CancellationToken cancellationToken)
    {
        sources.RequireFor(description);
        var authorities = new Dictionary<string, Authority>(StringComparer.OrdinalIgnoreCase);
        var targets = new Dictionary<string, ObjectAttributes>(StringComparer.OrdinalIgnoreCase);
        var counts = Enum.GetValues<PathRequesterFamily>().ToDictionary(family => family, _ => new int[4]);
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO path_requester_risk(requester,question_key,proof,fingerprint) VALUES ($requester,$key,$proof,$hash)";
        var requesterParameter = insert.Parameters.Add("$requester", SqliteType.Text);
        var keyParameter = insert.Parameters.Add("$key", SqliteType.Text);
        var proofParameter = insert.Parameters.Add("$proof", SqliteType.Text);
        var hashParameter = insert.Parameters.Add("$hash", SqliteType.Blob);
        insert.Prepare();
        foreach (var question in Questions(requesters, ownAccounts, membershipDacls))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var answer = Qualify(question);
            counts[question.Family][(int)answer.Verdict]++;
            var json = JsonSerializer.Serialize(answer, ProofSerialization.Options);
            requesterParameter.Value = answer.RequesterDn;
            keyParameter.Value = Key(answer);
            proofParameter.Value = json;
            hashParameter.Value = OwnershipAuditStorage.Hash(json);
            if (insert.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
        }
        var families = counts.Select(pair => new PathRiskFamilyCoverage(pair.Key, pair.Value.Sum(),
            pair.Value[0], pair.Value[1], pair.Value[2], pair.Value[3])).ToArray();
        var requested = selectionRequested || families.Any(family => family.Questions != 0);
        var coverage = new PathRiskCoverage(Version, description.GenerationId, description.DerivationGenerationId,
            description.EvidenceSeal, inputs.Input?.DerivationSeal, calculationFingerprint, PrincipalClassificationRegistry.Version,
            !requested ? PathRiskAvailability.NotRequested : inputs.Availability == PathInputAvailability.Recorded
                ? PathRiskAvailability.Recorded : PathRiskAvailability.InputsUnavailable,
            selectionRequested, inputs.Coverage, families);
        var header = JsonSerializer.Serialize(coverage, ProofSerialization.Options);
        Execute(connection, transaction, "INSERT INTO path_risk_product VALUES (1,$proof,$hash)",
            ("$proof", header), ("$hash", OwnershipAuditStorage.Hash(header)));
        cancellationToken.ThrowIfCancellationRequested();
        RequireCount(connection, transaction, requesters.Count + ownAccounts.Count + membershipDacls.Count);
        sources.RequireFor(description);

        PathRequesterRiskAssessment Qualify(Question question)
        {
            var result = new PathRequesterRiskAssessment(description.GenerationId, description.DerivationGenerationId,
                description.EvidenceSeal, calculationFingerprint, question.Fingerprint, question.Family,
                question.RequesterDn, question.TargetDn, question.GroupDn, question.PermissionKind, null,
                question.Authorization, PathRiskVerdict.Unknown, null, null, null, null, question.Readiness, question.MemberPresent);
            if (inputs.Availability != PathInputAvailability.Recorded)
                return result with { Issue = PathRiskIssue.InputsUnavailable };
            if (question.Authorization == ControlEvaluationState.NotEstablished)
                return result with { Verdict = PathRiskVerdict.NotEstablished, Issue = PathRiskIssue.AuthorizationNotEstablished };
            if (question.Authorization != ControlEvaluationState.Established)
                return result with { Issue = PathRiskIssue.AuthorizationUnknown };
            if (question.Requester is not { IsValid: true, ObjectGuid: not null, Sid: not null } principal)
                return result with { Issue = PathRiskIssue.RequesterUnresolved };
            if (question.Steps.Count == 0)
                return result with { Issue = PathRiskIssue.ContinuationUnavailable };
            var reached = principal;
            foreach (var step in question.Steps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (step.From != reached) throw Tier0PathStorage.InvalidProof();
                reached = step.To;
            }
            if (!inputs.FixedTargets.Contains(reached)) throw Tier0PathStorage.InvalidProof();
            if (!targets.TryGetValue(reached.DistinguishedName, out var target))
            {
                target = sources.Bundle.ReadObjectAttributes(reached.DistinguishedName) ?? throw Tier0PathStorage.InvalidProof();
                if (Tier0Target.From(target, reached.NamingContext) != reached) throw Tier0PathStorage.InvalidProof();
                targets.Add(reached.DistinguishedName, target);
            }
            if (!authorities.TryGetValue(principal.DistinguishedName, out var authority))
            {
                var protection = sources.Facts.ProtectedPrincipals.Value;
                var fact = protection?.Lookup(principal.Sid, principal.SidScope);
                var routes = fact?.MembershipRoutes ?? MembershipRouteSummary.NotDerived;
                var binding = inputs.Input ?? throw Tier0PathStorage.InvalidProof();
                var roots = routes.Memberships.SelectMany(group => group.Routes)
                    .Where(route => route.Authorization == MembershipRouteAuthorization.SecurityEnabled
                        && route.Steps.Count != 0 && route.Steps[0].Principal.Sid == principal.Sid)
                    .Select(route => route.Steps[^1].Principal)
                    .Where(root => PrincipalClassificationRegistry.For(root.Sid).ControlPlaneScope != PrincipalAuthorityScope.None)
                    .Distinct().OrderBy(root => root.Sid, StringComparer.Ordinal).ThenBy(root => root.Scope, StringComparer.Ordinal).ToArray();
                authority = new(routes, new(principal, binding.DerivationGenerationId, binding.DerivationSeal,
                    protection?.CatalogueVersion ?? 0, fact is not null, Tier0PathCalculation.Fingerprint(routes),
                    routes.IncompleteReasons, roots));
                authorities.Add(principal.DistinguishedName, authority);
            }
            // Expectedness belongs to the captured requester and actual endpoint, not to a granting
            // group or a membership the route proposes obtaining.
            var holder = new PermissionTrustee(principal.Sid, null, principal.DistinguishedName,
                principal.DomainFqdn, null, null, null);
            var expected = ControlEdgeDeriver.Expected(holder, target, sources.Bundle.Description.ForestFqdn,
                authority.Routes, descriptorComplete: true, effectiveDirectAce: false, sources.ReadDomainSid);
            return result with
            {
                ReachedTarget = reached, CurrentAuthority = authority.Evidence, Expectedness = expected.State,
                ExpectednessReason = expected.Reason,
                Verdict = expected.State switch
                {
                    ControlExpectedness.Unexpected => PathRiskVerdict.UnexpectedRoute,
                    ControlExpectedness.Expected => PathRiskVerdict.ExpectedRoute,
                    _ => PathRiskVerdict.Unknown,
                },
                Issue = expected.State == ControlExpectedness.Unknown ? PathRiskIssue.AuthorityUnknown : null,
            };
        }
    }

    private static IEnumerable<Question> Questions(IReadOnlyList<SavedRequesterDaclProof> requesters,
        IReadOnlyList<SavedOwnAccountMembershipProof> ownAccounts, IReadOnlyList<SavedMembershipDaclProof> membershipDacls)
    {
        foreach (var proof in requesters)
        {
            var value = proof.Assessment;
            yield return new(PathRequesterFamily.RequesterDacl, value.Request.RequesterDn, value.Request.TargetDn,
                null, null, value.Requester, value.Authorization, value.Steps, Tier0PathCalculation.Fingerprint(proof), null, null);
        }
        foreach (var proof in ownAccounts)
        {
            var value = proof.Assessment;
            yield return new(PathRequesterFamily.OwnAccountMembership, value.Request.RequesterDn, value.Request.TargetDn,
                null, value.Request.PermissionKind, value.Requester, value.Obtainability, proof.Steps,
                Tier0PathCalculation.Fingerprint(proof), value.Permission.Readiness, value.Permission.MemberPresent);
        }
        foreach (var proof in membershipDacls)
        {
            var value = proof.Assessment;
            yield return new(PathRequesterFamily.MembershipDacl, value.Request.RequesterDn, value.Request.TargetDn,
                value.Request.GroupDn, value.Request.PermissionKind, value.Membership.Requester, value.Authorization,
                value.Steps, Tier0PathCalculation.Fingerprint(proof), value.Membership.Permission.Readiness, value.Membership.Permission.MemberPresent);
        }
    }

    internal static PathRiskCoverage ReadCoverage(SqliteConnection connection, JudgementDescription description,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT r.proof,r.fingerprint,p.fingerprint FROM path_risk_product r
            JOIN tier0_path_calculation p ON p.id=r.id WHERE r.id=1
            """;
        using var read = command.ExecuteReader();
        if (!read.Read()) throw Tier0PathStorage.InvalidProof();
        var result = Decode<PathRiskCoverage>(read.GetString(0), (byte[])read.GetValue(1));
        if (result.Version != Version || result.GenerationId != description.GenerationId
            || result.EvidenceSeal != description.EvidenceSeal || result.DerivationGenerationId != description.DerivationGenerationId
            || result.ControlPolicyVersion != PrincipalClassificationRegistry.Version || !Enum.IsDefined(result.Availability)
            || result.CalculationFingerprint != Convert.ToHexString((byte[])read.GetValue(2))
            || result.Availability == PathRiskAvailability.Recorded && result.DerivationSeal is not { Length: 64 }
            || result.PathCoverage is null || result.Families is not { Count: 3 }
            || !result.Families.Select(family => family.Family).SequenceEqual(Enum.GetValues<PathRequesterFamily>())
            || result.Families.Any(family => family.Questions < 0 || family.UnexpectedRoutes < 0 || family.ExpectedRoutes < 0
                || family.NotEstablished < 0 || family.Unknown < 0 || (long)family.Questions != (long)family.UnexpectedRoutes
                    + family.ExpectedRoutes + family.NotEstablished + family.Unknown)
            || result.Availability == PathRiskAvailability.NotRequested
                && (result.AutomaticSelectionRequested || result.Families.Any(family => family.Questions != 0)))
            throw Tier0PathStorage.InvalidProof();
        return result;
    }

    internal static PathRequesterRiskSet Read(SqliteConnection connection, JudgementDescription description,
        string requesterDn, CancellationToken cancellationToken)
    {
        var coverage = ReadCoverage(connection, description, cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT requester,question_key,proof,fingerprint FROM path_requester_risk WHERE requester=$requester ORDER BY id";
        command.Parameters.AddWithValue("$requester", requesterDn);
        using var read = command.ExecuteReader();
        var values = new List<PathRequesterRiskAssessment>();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = Decode<PathRequesterRiskAssessment>(read.GetString(2), (byte[])read.GetValue(3));
            if (value.GenerationId != description.GenerationId || value.DerivationGenerationId != description.DerivationGenerationId
                || value.EvidenceSeal != description.EvidenceSeal || value.CalculationFingerprint != coverage.CalculationFingerprint
                || value.RequesterDn != read.GetString(0) || string.IsNullOrWhiteSpace(value.TargetDn)
                || !Enum.IsDefined(value.Family) || !Enum.IsDefined(value.Verdict) || !Enum.IsDefined(value.Authorization)
                || value.Issue is { } issue && !Enum.IsDefined(issue)
                || value.Expectedness is { } expectedness && !Enum.IsDefined(expectedness)
                || value.ExpectednessReason is { } expectednessReason && !Enum.IsDefined(expectednessReason)
                || value.Family == PathRequesterFamily.RequesterDacl && (value.GroupDn is not null || value.PermissionKind is not null)
                || value.Family != PathRequesterFamily.RequesterDacl && (value.PermissionKind is not { } kind || !Enum.IsDefined(kind))
                || value.Family == PathRequesterFamily.MembershipDacl && string.IsNullOrWhiteSpace(value.GroupDn)
                || value.SourceProofFingerprint is not { Length: 64 } || Key(value) != read.GetString(1)
                || value.Verdict is PathRiskVerdict.ExpectedRoute or PathRiskVerdict.UnexpectedRoute
                    && (value.Authorization != ControlEvaluationState.Established || value.ReachedTarget is null
                        || value.CurrentAuthority is null || value.Issue is not null
                        || value.ExpectednessReason is null
                        || value.Expectedness != (value.Verdict == PathRiskVerdict.ExpectedRoute
                            ? ControlExpectedness.Expected : ControlExpectedness.Unexpected))
                || value.Verdict == PathRiskVerdict.NotEstablished
                    && (value.Authorization != ControlEvaluationState.NotEstablished || value.Issue != PathRiskIssue.AuthorizationNotEstablished)
                || value.Verdict == PathRiskVerdict.Unknown && value.Issue is null)
                throw Tier0PathStorage.InvalidProof();
            if (value.CurrentAuthority is { } authority && (authority.DerivationGenerationId != description.DerivationGenerationId
                || authority.Principal is not { IsValid: true }
                || !string.Equals(authority.Principal.DistinguishedName, value.RequesterDn, StringComparison.OrdinalIgnoreCase)
                || authority.DerivationSeal != coverage.DerivationSeal || authority.MembershipFingerprint is not { Length: 64 }
                || authority.CapturedAuthorityRoots is null))
                throw Tier0PathStorage.InvalidProof();
            values.Add(value);
        }
        return new(coverage, values);
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM tier0_path_calculation),
                   (SELECT COUNT(*) FROM path_risk_product),
                   (SELECT COUNT(*) FROM path_requester_risk),
                   COALESCE((SELECT SUM(json_extract(f.value,'$.Questions'))
                       FROM path_risk_product p,json_each(p.proof,'$.Families') f),0)
            """;
        using var read = command.ExecuteReader();
        if (!read.Read() || read.GetInt64(0) != read.GetInt64(1)
            || read.GetInt64(2) != read.GetInt64(3)
            || read.GetInt64(0) == 0 && read.GetInt64(2) != 0) throw Tier0PathStorage.InvalidProof();
    }

    private static void RequireCount(SqliteConnection connection, SqliteTransaction transaction, int expected)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM path_requester_risk";
        if ((long)command.ExecuteScalar()! != expected) throw Tier0PathStorage.InvalidProof();
    }

    private static string Key(PathRequesterRiskAssessment value) => string.Join('\0', value.Family.ToString(),
        value.RequesterDn.ToUpperInvariant(), value.TargetDn.ToUpperInvariant(), value.GroupDn?.ToUpperInvariant(), value.PermissionKind?.ToString());

    private static T Decode<T>(string json, byte[] fingerprint)
    {
        if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual(fingerprint)) throw Tier0PathStorage.InvalidProof();
        return JsonSerializer.Deserialize<T>(json, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
    }

    private static void Execute(SqliteConnection connection, SqliteTransaction? transaction, string sql,
        params (string Name, object Value)[] parameters)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        command.ExecuteNonQuery();
    }
}
