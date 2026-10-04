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
            question_key TEXT NOT NULL UNIQUE, verdict TEXT NOT NULL, source_proof TEXT NOT NULL, proof TEXT NOT NULL,
            fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
        CREATE INDEX ix_path_risk_requester ON path_requester_risk(requester,id);
        CREATE INDEX ix_path_risk_group ON path_requester_risk(requester,verdict,id);
        """);

    private sealed record Question(PathRequesterFamily Family, string RequesterDn, string TargetDn,
        string? GroupDn, OwnAccountMembershipPermissionKind? PermissionKind, Tier0Target? Requester,
        ControlEvaluationState Authorization, IReadOnlyList<Tier0PathStep> Steps, string Fingerprint,
        ControlEvaluationState? Readiness, bool? MemberPresent, string SourceJson);

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
        insert.CommandText = "INSERT INTO path_requester_risk(requester,question_key,verdict,source_proof,proof,fingerprint) VALUES ($requester,$key,$verdict,$source,$proof,$hash)";
        var requesterParameter = insert.Parameters.Add("$requester", SqliteType.Text);
        var keyParameter = insert.Parameters.Add("$key", SqliteType.Text);
        var verdictParameter = insert.Parameters.Add("$verdict", SqliteType.Text);
        var sourceParameter = insert.Parameters.Add("$source", SqliteType.Text);
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
            verdictParameter.Value = answer.Verdict.ToString();
            sourceParameter.Value = question.SourceJson;
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
                null, null, value.Requester, value.Authorization, value.Steps, Tier0PathCalculation.Fingerprint(proof), null, null,
                JsonSerializer.Serialize(proof, ProofSerialization.Options));
        }
        foreach (var proof in ownAccounts)
        {
            var value = proof.Assessment;
            yield return new(PathRequesterFamily.OwnAccountMembership, value.Request.RequesterDn, value.Request.TargetDn,
                null, value.Request.PermissionKind, value.Requester, value.Obtainability, proof.Steps,
                Tier0PathCalculation.Fingerprint(proof), value.Permission.Readiness, value.Permission.MemberPresent,
                JsonSerializer.Serialize(proof, ProofSerialization.Options));
        }
        foreach (var proof in membershipDacls)
        {
            var value = proof.Assessment;
            yield return new(PathRequesterFamily.MembershipDacl, value.Request.RequesterDn, value.Request.TargetDn,
                value.Request.GroupDn, value.Request.PermissionKind, value.Membership.Requester, value.Authorization,
                value.Steps, Tier0PathCalculation.Fingerprint(proof), value.Membership.Permission.Readiness, value.Membership.Permission.MemberPresent,
                JsonSerializer.Serialize(proof, ProofSerialization.Options));
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
        return new(coverage, ReadAssessments(connection, description, coverage, requesterDn, cancellationToken).ToArray());
    }

    internal static IEnumerable<PathRequesterRiskAssessment> ReadAssessments(SqliteConnection connection,
        JudgementDescription description, PathRiskCoverage coverage, string? requesterDn, CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT requester,question_key,proof,fingerprint,verdict FROM path_requester_risk "
            + (requesterDn is null ? "ORDER BY requester,id" : "WHERE requester=$requester ORDER BY id");
        if (requesterDn is not null) command.Parameters.AddWithValue("$requester", requesterDn);
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return ReadAssessment(read, description, coverage);
        }
    }

    private static PathRequesterRiskAssessment ReadAssessment(SqliteDataReader read,
        JudgementDescription description, PathRiskCoverage coverage)
    {
        var value = Decode<PathRequesterRiskAssessment>(read.GetString(2), (byte[])read.GetValue(3));
            if (value.GenerationId != description.GenerationId || value.DerivationGenerationId != description.DerivationGenerationId
                || value.EvidenceSeal != description.EvidenceSeal || value.CalculationFingerprint != coverage.CalculationFingerprint
                || value.RequesterDn != read.GetString(0) || string.IsNullOrWhiteSpace(value.TargetDn)
                || !Enum.IsDefined(value.Family) || !Enum.IsDefined(value.Verdict) || !Enum.IsDefined(value.Authorization)
                || value.Verdict.ToString() != read.GetString(4)
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
        return value;
    }

    internal static PathRiskPage ReadPage(SqliteConnection connection, JudgementDescription description,
        string requesterDn, PathRiskVerdict verdict, PathRiskPageMark? after, CancellationToken cancellationToken)
    {
        if (!Enum.IsDefined(verdict)) throw new ArgumentOutOfRangeException(nameof(verdict));
        if (after is not null && (after.GenerationId != description.GenerationId || after.Verdict != verdict
            || !string.Equals(after.RequesterDn, requesterDn, StringComparison.OrdinalIgnoreCase) || after.AfterId <= 0))
            throw Tier0PathStorage.InvalidProof();
        var coverage = ReadCoverage(connection, description, cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT verdict,COUNT(*) FROM path_requester_risk WHERE requester=$requester GROUP BY verdict";
        command.Parameters.AddWithValue("$requester", requesterDn);
        var counts = new int[4];
        using (var read = command.ExecuteReader())
            while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Enum.TryParse<PathRiskVerdict>(read.GetString(0), out var group) || !Enum.IsDefined(group))
                    throw Tier0PathStorage.InvalidProof();
                counts[(int)group] = checked((int)read.GetInt64(1));
            }
        var questions = new List<PathRiskQuestion>();
        PathRiskPageMark? next = null;
        command.CommandText = """
            SELECT requester,question_key,proof,fingerprint,verdict,source_proof,id
            FROM path_requester_risk WHERE requester=$requester AND verdict=$verdict AND id>$after
            ORDER BY id LIMIT $limit
            """;
        command.Parameters.AddWithValue("$verdict", verdict.ToString());
        command.Parameters.AddWithValue("$after", after?.AfterId ?? 0);
        command.Parameters.AddWithValue("$limit", PathRiskPage.PageSize + 1);
        using (var read = command.ExecuteReader())
            while (read.Read())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (questions.Count == PathRiskPage.PageSize)
                {
                    next = new(description.GenerationId, requesterDn, verdict, questions[^1].Id);
                    break;
                }
                var risk = ReadAssessment(read, description, coverage);
                questions.Add(ReadQuestion(read.GetInt64(6), risk, read.GetString(5), cancellationToken));
            }
        command.Parameters.Clear();
        command.CommandText = "SELECT COUNT(*) FROM path_anchor WHERE target=$target";
        command.Parameters.AddWithValue("$target", requesterDn);
        var fixedTarget = (long)command.ExecuteScalar()! == 1;
        cancellationToken.ThrowIfCancellationRequested();
        return new(coverage, requesterDn, verdict, new(counts[0], counts[1], counts[2], counts[3]), questions, next, fixedTarget);
    }

    private static PathRiskQuestion ReadQuestion(long id, PathRequesterRiskAssessment risk, string json, CancellationToken cancellationToken)
    {
        if (Convert.ToHexString(OwnershipAuditStorage.Hash(json)) != risk.SourceProofFingerprint)
            throw Tier0PathStorage.InvalidProof();
        PathRiskQuestion question;
        Guid generation;
        Guid? derivation;
        string seal;
        string requester;
        string target;
        Tier0Target? principal;
        ControlEvaluationState authorization;
        ControlEvaluationState? readiness = null;
        bool? memberPresent = null;
        string? group = null;
        OwnAccountMembershipPermissionKind? kind = null;
        switch (risk.Family)
        {
            case PathRequesterFamily.RequesterDacl:
                var direct = JsonSerializer.Deserialize<SavedRequesterDaclProof>(json, ProofSerialization.Options)
                    ?? throw Tier0PathStorage.InvalidProof();
                var dacl = direct.Assessment;
                if (dacl?.Request is null) throw Tier0PathStorage.InvalidProof();
                RequesterDaclProofs.RequireMembershipEvidence(dacl, cancellationToken);
                question = new(id, risk, direct.SourceFingerprint, dacl.Steps, dacl, null, null);
                principal = dacl.Requester;
                authorization = dacl.Authorization;
                (generation, derivation, seal, requester, target) = (dacl.GenerationId, dacl.DerivationGenerationId,
                    dacl.EvidenceSeal, dacl.Request.RequesterDn, dacl.Request.TargetDn);
                break;
            case PathRequesterFamily.OwnAccountMembership:
                var own = JsonSerializer.Deserialize<SavedOwnAccountMembershipProof>(json, ProofSerialization.Options)
                    ?? throw Tier0PathStorage.InvalidProof();
                var membership = own.Assessment;
                if (membership?.Request is null || membership.Permission is null) throw Tier0PathStorage.InvalidProof();
                question = new(id, risk, own.SourceFingerprint, own.Steps, null, membership, null);
                principal = membership.Requester;
                authorization = membership.Obtainability;
                readiness = membership.Permission.Readiness;
                memberPresent = membership.Permission.MemberPresent;
                (generation, derivation, seal, requester, target) = (membership.GenerationId, membership.DerivationGenerationId,
                    membership.EvidenceSeal, membership.Request.RequesterDn, membership.Request.TargetDn);
                kind = membership.Request.PermissionKind;
                break;
            case PathRequesterFamily.MembershipDacl:
                var combined = JsonSerializer.Deserialize<SavedMembershipDaclProof>(json, ProofSerialization.Options)
                    ?? throw Tier0PathStorage.InvalidProof();
                var value = combined.Assessment;
                if (value?.Request is null || value.Membership?.Permission is null) throw Tier0PathStorage.InvalidProof();
                if (value.Dacl is { } combinedDacl)
                {
                    RequesterDaclProofs.RequireMembershipEvidence(combinedDacl, value.Membership, cancellationToken);
                    if (value.Authorization != combinedDacl.Authorization || value.Request.RequesterDn != combinedDacl.Request.RequesterDn
                        || value.Request.TargetDn != combinedDacl.Request.TargetDn || value.Request.GroupDn != value.Membership.Request.TargetDn
                        || value.Request.PermissionKind != value.Membership.Request.PermissionKind
                        || value.Authorization == ControlEvaluationState.Established
                            && !value.Steps.SequenceEqual(MembershipDaclProofs.Steps(combinedDacl, value.Membership.Request, value.Request)))
                        throw Tier0PathStorage.InvalidProof();
                }
                question = new(id, risk, combined.SourceFingerprint, value.Steps, null, null, value);
                principal = value.Membership.Requester;
                authorization = value.Authorization;
                readiness = value.Membership.Permission.Readiness;
                memberPresent = value.Membership.Permission.MemberPresent;
                (generation, derivation, seal, requester, target) = (value.GenerationId, value.DerivationGenerationId,
                    value.EvidenceSeal, value.Request.RequesterDn, value.Request.TargetDn);
                group = value.Request.GroupDn;
                kind = value.Request.PermissionKind;
                break;
            default: throw Tier0PathStorage.InvalidProof();
        }
        if (generation != risk.GenerationId || derivation != risk.DerivationGenerationId || seal != risk.EvidenceSeal
            || requester != risk.RequesterDn || target != risk.TargetDn || group != risk.GroupDn || kind != risk.PermissionKind
            || question.SourceFingerprint is not { Length: 64 } || question.Steps is null
            || authorization != risk.Authorization || readiness != risk.OrdinaryAddReadiness || memberPresent != risk.CapturedMemberPresent
            || risk.CurrentAuthority is { } authority && authority.Principal != principal)
            throw Tier0PathStorage.InvalidProof();
        if (risk.ReachedTarget is { } reached)
        {
            var current = principal;
            foreach (var step in question.Steps)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (step.From != current || !Enum.IsDefined(step.Kind)) throw Tier0PathStorage.InvalidProof();
                current = step.To;
            }
            if (question.Steps.Count == 0 || current != reached) throw Tier0PathStorage.InvalidProof();
        }
        return question;
    }

    internal static PathRequesterProofs ReadProofs(SqliteConnection connection, JudgementDescription description,
        CancellationToken cancellationToken)
    {
        var coverage = ReadCoverage(connection, description, cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT requester,question_key,proof,fingerprint,verdict,source_proof,id FROM path_requester_risk ORDER BY id";
        using var read = command.ExecuteReader();
        var requesters = new List<SavedRequesterDaclProof>();
        var ownAccounts = new List<SavedOwnAccountMembershipProof>();
        var membershipDacls = new List<SavedMembershipDaclProof>();
        while (read.Read())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = ReadQuestion(read.GetInt64(6), ReadAssessment(read, description, coverage), read.GetString(5), cancellationToken);
            if (value.Requester is { } requester) requesters.Add(new(requester, value.SourceFingerprint));
            else if (value.OwnAccount is { } own) ownAccounts.Add(new(own, value.SourceFingerprint, value.Steps));
            else if (value.Membership is { } membership) membershipDacls.Add(new(membership, value.SourceFingerprint));
            else throw Tier0PathStorage.InvalidProof();
        }
        return new(requesters, ownAccounts, membershipDacls);
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
