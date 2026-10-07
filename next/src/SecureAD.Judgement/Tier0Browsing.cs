using SecureAD.Derivation;
using Microsoft.Data.Sqlite;

namespace SecureAD.Judgement;

public sealed record Tier0OverviewMark(Guid GenerationId, string CalculationFingerprint, string AfterDn);
public sealed record Tier0OverviewRow(Tier0Target Subject, Tier0DistanceFacts Distance, SupportedRouteGrade? BestGrade);
public sealed record Tier0OverviewPage(Tier0RunSummary Summary, IReadOnlyList<Tier0OverviewRow> Objects, Tier0OverviewMark? Next)
{
    public Tier0Coverage Coverage => Summary.Coverage;
}

/// <summary>Selected saved proofs only; no requester discovery or path calculation occurs on read.</summary>
public sealed record Tier0RouteDetails(Guid GenerationId, Guid? DerivationGenerationId, string EvidenceSeal,
    string CalculationFingerprint, Tier0Target Subject, Tier0DistanceFacts Distance, SupportedRouteGrade? BestGrade,
    int CompleteCandidates, int UngradedCandidates, IReadOnlyList<RouteGradingLimitation> GradingLimitations,
    IReadOnlyList<Tier0PathStep> BestSteps, IReadOnlyList<Tier0PathStep> ShortestSteps,
    IReadOnlyList<ControlEdge> Permissions, Tier0Coverage Coverage);

internal static class Tier0Browsing
{
    internal static Tier0OverviewPage? ReadPage(SqliteConnection connection, JudgementDescription description,
        Tier0OverviewMark? after, CancellationToken token)
    {
        var summary = Tier0DistanceStorage.ReadSummary(connection, description, token);
        if (summary is null) return null;
        if (after is not null && (after.GenerationId != description.GenerationId
            || after.CalculationFingerprint != summary.CalculationFingerprint || string.IsNullOrWhiteSpace(after.AfterDn)))
            throw new ArgumentException("The Tier 0 page belongs to another saved calculation.", nameof(after));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT target FROM tier0_distance WHERE target>$after COLLATE NOCASE ORDER BY target COLLATE NOCASE LIMIT 51";
        command.Parameters.AddWithValue("$after", after?.AfterDn ?? "");
        var names = new List<string>();
        using (var read = command.ExecuteReader())
            while (read.Read()) { token.ThrowIfCancellationRequested(); names.Add(read.GetString(0)); }
        var rows = new List<Tier0OverviewRow>();
        foreach (var name in names.Take(50))
        {
            var distance = Tier0DistanceStorage.ReadObject(connection, description, name, token) ?? throw Tier0PathStorage.InvalidProof();
            var best = BestSupportedRouteStorage.ReadSelection(connection, description, distance, token);
            rows.Add(new(distance.Subject, distance.Facts, best.Best?.Grade));
        }
        return new(summary, rows, names.Count > 50 ? new(description.GenerationId, summary.CalculationFingerprint, rows[^1].Subject.DistinguishedName) : null);
    }

    internal static Tier0RouteDetails? ReadObject(SqliteConnection connection, JudgementDescription description,
        string target, CancellationToken token)
    {
        var distance = Tier0DistanceStorage.ReadObject(connection, description, target, token);
        if (distance is null) return null;
        var best = BestSupportedRouteStorage.Read(connection, description, target, token) ?? throw Tier0PathStorage.InvalidProof();
        var shortest = Shortest(connection, description, distance, token);
        var permissions = best.Steps.Concat(shortest).Where(step => step.PermissionId is not null)
            .DistinctBy(step => step.PermissionId).Select(step =>
            {
                token.ThrowIfCancellationRequested();
                var edge = ControlEdgeStorage.ReadEdge(connection, description, step.PermissionId!.Value);
                if (edge.Target != step.To.DistinguishedName) throw Tier0PathStorage.InvalidProof();
                return edge;
            }).ToArray();
        return new(description.GenerationId, description.DerivationGenerationId, description.EvidenceSeal,
            distance.CalculationFingerprint, distance.Subject, distance.Facts, best.Selection.Best?.Grade,
            best.Selection.CompleteCandidates, best.Selection.UngradedCandidates, best.Selection.GradingLimitations,
            best.Steps, shortest, permissions, distance.Coverage);
    }

    private static IReadOnlyList<Tier0PathStep> Shortest(SqliteConnection connection, JudgementDescription description,
        Tier0ObjectDistance distance, CancellationToken token)
    {
        if (distance.Facts.SupportedDistance is not { } length) return [];
        var node = Tier0PathStorage.ReadNode(connection, distance.Subject.DistinguishedName, token);
        if (node?.Subject != distance.Subject) throw Tier0PathStorage.InvalidProof();
        IReadOnlyList<Tier0PathStep> steps;
        if (node.MembershipDaclRoute is { } combined)
            steps = PathRequesterRiskStorage.ReadSelectedQuestion(connection, description, combined.RequesterDn,
                PathRequesterFamily.MembershipDacl, combined.TargetDn, combined.GroupDn, combined.PermissionKind, token).Steps;
        else if (node.OwnAccountRoute is { } own)
            steps = PathRequesterRiskStorage.ReadSelectedQuestion(connection, description, own.RequesterDn,
                PathRequesterFamily.OwnAccountMembership, own.TargetDn, null, own.PermissionKind, token).Steps;
        else if (node.RequesterRoute is { } requester)
            steps = PathRequesterRiskStorage.ReadSelectedQuestion(connection, description, requester.RequesterDn,
                PathRequesterFamily.RequesterDacl, requester.TargetDn, null, null, token).Steps;
        else if (length != 0 && node.Terminal is { } terminal)
            steps = [terminal];
        else
        {
            var chain = new List<Tier0PathStep>();
            var current = node;
            var seen = new HashSet<Tier0Target> { node.Subject };
            while (current.MembershipNext is { } step)
            {
                token.ThrowIfCancellationRequested();
                if (step.From != current.Subject || !seen.Add(step.To) || chain.Count >= length) throw Tier0PathStorage.InvalidProof();
                chain.Add(step);
                current = Tier0PathStorage.ReadNode(connection, step.To.DistinguishedName, token) ?? throw Tier0PathStorage.InvalidProof();
                if (current.Subject != step.To) throw Tier0PathStorage.InvalidProof();
            }
            steps = chain;
        }
        var endpoint = distance.Subject;
        foreach (var step in steps)
        {
            token.ThrowIfCancellationRequested();
            if (step.From != endpoint || !Enum.IsDefined(step.Kind)) throw Tier0PathStorage.InvalidProof();
            endpoint = step.To;
        }
        using var anchor = connection.CreateCommand();
        anchor.CommandText = "SELECT COUNT(*) FROM path_anchor WHERE target=$target";
        anchor.Parameters.AddWithValue("$target", endpoint.DistinguishedName);
        if (steps.Count != length || (long)anchor.ExecuteScalar()! != 1) throw Tier0PathStorage.InvalidProof();
        return steps;
    }
}
