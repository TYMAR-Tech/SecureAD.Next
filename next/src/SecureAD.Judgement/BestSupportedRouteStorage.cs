using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

internal static class BestSupportedRouteStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            CREATE TABLE {JudgementStoreLayout.Schema(connection, StoreSegmentRole.PathProof)}.tier0_best_route (target TEXT PRIMARY KEY COLLATE NOCASE,
                proof INTEGER NOT NULL REFERENCES path_proof(id), fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, PathProofStorage.Writer proofs,
        IEnumerable<BestRouteSelection> selections, CancellationToken cancellationToken)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "INSERT INTO tier0_best_route VALUES ($target,$proof,$hash)";
        command.Parameters.Add("$target", SqliteType.Text);
        command.Parameters.Add("$proof", SqliteType.Integer);
        command.Parameters.Add("$hash", SqliteType.Blob);
        foreach (var selection in selections)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Validate(selection);
            var proof = proofs.Write(selection);
            command.Parameters["$target"].Value = selection.Subject.DistinguishedName;
            command.Parameters["$proof"].Value = proof.Id;
            command.Parameters["$hash"].Value = proof.Fingerprint;
            if (command.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
        }
    }

    internal static SavedBestSupportedRoute? Read(SqliteConnection connection, JudgementDescription description,
        string target, CancellationToken cancellationToken)
    {
        var distance = Tier0DistanceStorage.ReadObject(connection, description, target, cancellationToken);
        if (distance is null) return null;
        var selection = ReadSelection(connection, description, distance, cancellationToken);
        return ReadRoute(connection, description, distance, selection, cancellationToken);
    }

    internal static BestRouteSelection ReadSelection(SqliteConnection connection, JudgementDescription description,
        Tier0ObjectDistance distance, CancellationToken cancellationToken)
    {
        BestRouteSelection selection;
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT proof,fingerprint FROM tier0_best_route WHERE target=$target COLLATE NOCASE";
            command.Parameters.AddWithValue("$target", distance.Subject.DistinguishedName);
            using var row = command.ExecuteReader();
            if (!row.Read()) throw Tier0PathStorage.InvalidProof();
            selection = PathProofStorage.Read<BestRouteSelection>(connection, row.GetInt64(0),
                Convert.ToHexString((byte[])row.GetValue(1)), cancellationToken);
        }
        Validate(selection);
        if (selection.GenerationId != description.GenerationId || selection.DerivationGenerationId != description.DerivationGenerationId
            || selection.EvidenceSeal != description.EvidenceSeal || selection.CalculationFingerprint != distance.CalculationFingerprint
            || selection.Subject != distance.Subject) throw Tier0PathStorage.InvalidProof();
        return selection;
    }

    private static SavedBestSupportedRoute ReadRoute(SqliteConnection connection, JudgementDescription description,
        Tier0ObjectDistance distance, BestRouteSelection selection, CancellationToken cancellationToken)
    {
        if (selection.Best is not { } best)
            return new(selection, [], distance.Coverage);
        IReadOnlyList<Tier0PathStep> steps;
        var proofs = new PathSharedProofStorage(connection, description, cancellationToken);
        switch (best.Source)
        {
            case RouteSourceKind.FixedTarget:
                steps = [];
                break;
            case RouteSourceKind.Membership:
                var chain = new List<Tier0PathStep>();
                var current = selection.Subject;
                var seen = new HashSet<Tier0Target> { current };
                for (var i = 0; i < best.Grade.Length; i++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var node = Tier0PathStorage.ReadNode(connection, current.DistinguishedName, cancellationToken);
                    if (node?.Subject != current || node.MembershipNext is not { } step || step.From != current
                        || step.Kind != Tier0PathStepKind.Membership || !seen.Add(step.To)) throw Tier0PathStorage.InvalidProof();
                    chain.Add(step);
                    current = step.To;
                }
                steps = chain;
                break;
            case RouteSourceKind.Terminal:
                var terminal = best.Terminal ?? throw Tier0PathStorage.InvalidProof();
                var edge = ControlEdgeStorage.ReadEdge(connection, description, terminal.PermissionId ?? throw Tier0PathStorage.InvalidProof());
                if (edge.Target != terminal.To.DistinguishedName || edge.HolderSid != terminal.From.Sid
                    || edge.HolderScope != terminal.From.SidScope || edge.EvaluationState != ControlEvaluationState.Established
                    || edge.Uncertainty != ControlUncertainty.None || Tier0PathCalculation.Fingerprint(edge) != best.ProofFingerprint)
                    throw Tier0PathStorage.InvalidProof();
                steps = [terminal];
                break;
            case RouteSourceKind.Requester:
                var requester = proofs.Read<SavedRequesterDaclProof>(best.ProofId!.Value, best.ProofFingerprint!).Assessment;
                RequireProof(description, selection.Subject, requester.Requester, requester.GenerationId,
                    requester.DerivationGenerationId, requester.EvidenceSeal, requester.Authorization);
                RequesterDaclProofs.RequireMembershipEvidence(requester, cancellationToken);
                steps = requester.Steps;
                break;
            case RouteSourceKind.OwnAccount:
                var own = proofs.Read<SavedOwnAccountMembershipProof>(best.ProofId!.Value, best.ProofFingerprint!);
                RequireProof(description, selection.Subject, own.Assessment.Requester, own.Assessment.GenerationId,
                    own.Assessment.DerivationGenerationId, own.Assessment.EvidenceSeal, own.Assessment.Obtainability);
                RequireConditions(best, own.Assessment);
                steps = own.Steps;
                break;
            case RouteSourceKind.MembershipDacl:
                var combined = proofs.Read<SavedMembershipDaclProof>(best.ProofId!.Value, best.ProofFingerprint!).Assessment;
                RequireProof(description, selection.Subject, combined.Membership.Requester, combined.GenerationId,
                    combined.DerivationGenerationId, combined.EvidenceSeal, combined.Authorization);
                if (combined.Dacl is null || combined.Membership.Obtainability != ControlEvaluationState.Established)
                    throw Tier0PathStorage.InvalidProof();
                RequesterDaclProofs.RequireMembershipEvidence(combined.Dacl, combined.Membership, cancellationToken);
                if (!combined.Steps.SequenceEqual(MembershipDaclProofs.Steps(combined.Dacl, combined.Membership.Request, combined.Request)))
                    throw Tier0PathStorage.InvalidProof();
                RequireConditions(best, combined.Membership);
                steps = combined.Steps;
                break;
            default: throw Tier0PathStorage.InvalidProof();
        }
        var endpoint = selection.Subject;
        foreach (var step in steps)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (step.From != endpoint || !Enum.IsDefined(step.Kind)) throw Tier0PathStorage.InvalidProof();
            endpoint = step.To;
        }
        if (endpoint != best.ReachedTarget || steps.Count != best.Grade.Length
            || (steps.Any(step => step.Kind == Tier0PathStepKind.OwnAccountMembership)
                ? best.Grade.Feasibility != RouteFeasibility.Conditional
                : best.Grade.Feasibility != RouteFeasibility.Direct)) throw Tier0PathStorage.InvalidProof();
        using var anchor = connection.CreateCommand();
        anchor.CommandText = "SELECT COUNT(*) FROM path_anchor WHERE target=$target COLLATE NOCASE";
        anchor.Parameters.AddWithValue("$target", endpoint.DistinguishedName);
        if ((long)anchor.ExecuteScalar()! != 1) throw Tier0PathStorage.InvalidProof();
        return new(selection, steps, distance.Coverage);
    }

    private static void RequireProof(JudgementDescription description, Tier0Target subject, Tier0Target? actual,
        Guid generation, Guid? derivation, string evidence, ControlEvaluationState state)
    {
        if (actual != subject || generation != description.GenerationId || derivation != description.DerivationGenerationId
            || evidence != description.EvidenceSeal || state != ControlEvaluationState.Established) throw Tier0PathStorage.InvalidProof();
    }

    private static void RequireConditions(BestRouteCandidate best, OwnAccountMembershipAssessment own)
    {
        var expected = new List<RouteCondition>();
        if (own.Basis == OwnAccountMembershipBasis.ExistingOrAuthorizedAdd)
        {
            if (own.Requester is null || own.Target is null) throw Tier0PathStorage.InvalidProof();
            expected.Add(new("MembershipOutcome", own.Requester, own.Target, null));
            if (best.Source == RouteSourceKind.MembershipDacl)
                expected.Add(new("MembershipEnabledForAuthorization", own.Requester, own.Target, best.ReachedTarget.NamingContext));
        }
        if (!expected.OrderBy(SupportedRouteGrade.ConditionKey, StringComparer.Ordinal).SequenceEqual(best.Grade.UnmetConditions))
            throw Tier0PathStorage.InvalidProof();
    }

    internal static void RequirePublishable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT (SELECT COUNT(*) FROM tier0_best_route),(SELECT COUNT(*) FROM tier0_distance),
                   (SELECT COUNT(*) FROM tier0_best_route b LEFT JOIN tier0_distance d ON d.target=b.target WHERE d.target IS NULL)
            """;
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetInt64(0) != row.GetInt64(1) || row.GetInt64(2) != 0) throw Tier0PathStorage.InvalidProof();
    }

    private static void Validate(BestRouteSelection value)
    {
        if (value.Version != 1 || value.Subject is null || value.CalculationFingerprint is not { Length: 64 }
            || value.CompleteCandidates < 0 || value.UngradedCandidates < 0 || value.UngradedCandidates > value.CompleteCandidates
            || value.GradingLimitations is null || value.GradingLimitations.Any(reason => !Enum.IsDefined(reason))
            || (value.UngradedCandidates == 0) != (value.GradingLimitations.Count == 0)
            || (value.Best is null) != (value.CompleteCandidates == value.UngradedCandidates)) throw Tier0PathStorage.InvalidProof();
        if (value.Best is not { } best) return;
        var grade = best.Grade;
        if (best.Subject != value.Subject || best.ReachedTarget is not { IsValid: true } || !Enum.IsDefined(best.Source)
            || grade is null || grade.Evidence != RouteEvidenceClass.Definite || !Enum.IsDefined(grade.Feasibility)
            || !Enum.IsDefined(grade.Confidence) || grade.Length < 0 || grade.StableSignature is not { Length: 64 }
            || grade.UnmetConditions is null || grade.UnmetConditions.Any(condition => condition is null
                || condition.Requester != best.Subject || condition.Group is not { IsValid: true })
            || grade.UnmetConditions.Select(SupportedRouteGrade.ConditionKey).Distinct(StringComparer.Ordinal).Count() != grade.UnmetConditions.Count
            || (grade.Feasibility == RouteFeasibility.Direct) != (grade.UnmetConditions.Count == 0)
            || (best.Source == RouteSourceKind.FixedTarget) != (grade.Length == 0)
            || (best.Source is RouteSourceKind.Requester or RouteSourceKind.OwnAccount or RouteSourceKind.MembershipDacl
                ? best.ProofId is null or <= 0 || best.ProofFingerprint is not { Length: 64 } || best.Terminal is not null
                : best.ProofId is not null)
            || (best.Source == RouteSourceKind.Terminal) != (best.Terminal is not null))
            throw Tier0PathStorage.InvalidProof();
    }
}
