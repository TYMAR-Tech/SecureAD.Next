using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;

namespace SecureAD.Judgement;

/// <summary>The saved calculation's answer, never a whole-forest negative reachability claim.</summary>
public enum Tier0DistanceVerdict { FixedTarget, SupportedRoute, Unresolved, NotAssessed }

/// <summary>Distance and classification are independent; requester checks are a separate assessment axis.</summary>
public sealed record Tier0DistanceFacts(Tier0DistanceVerdict Verdict, Tier0State Classification,
    int? SupportedDistance, bool IsMinimumEstablished, bool HasRequesterChecks);

/// <summary>One recorded object's saved answer, bound to the same evidence and calculation as its run summary.</summary>
internal sealed record Tier0ObjectDistance(Guid GenerationId, Guid? DerivationGenerationId, string EvidenceSeal,
    string CalculationFingerprint, Tier0Target Subject, Tier0DistanceFacts Facts, Tier0Coverage Coverage);

/// <summary>
/// Whole-generation counts over recorded identities, including declared but uncaptured roots,
/// not captured inventory, pages, paths, questions or findings.
/// Classified objects overlap supported-route counts; other supported reachers are not promoted to Tier 0.
/// </summary>
public sealed record Tier0RunSummary(int Version, Guid GenerationId, Guid? DerivationGenerationId, string EvidenceSeal,
    string CalculationFingerprint, PathInputAvailability Availability, Tier0Coverage Coverage,
    bool AutomaticRequesterSelectionRequested, bool RequesterInputScanCompleted,
    int RecordedSubjects, int ClassifiedTier0Objects, int FixedTargets, int ObjectsWithSupportedRoute,
    int OtherObjectsWithSupportedRoute, int UnresolvedObjects, int UnassessedObjects, int ObjectsWithRequesterChecks);

internal static class Tier0DistanceStorage
{
    internal static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE tier0_distance_product (id INTEGER PRIMARY KEY CHECK(id=1),
                proof TEXT NOT NULL, fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            CREATE TABLE tier0_distance (target TEXT PRIMARY KEY COLLATE NOCASE REFERENCES ownership_target(target),
                verdict TEXT NOT NULL, classification TEXT NOT NULL, supported_distance INTEGER NULL,
                minimum_established INTEGER NOT NULL CHECK(minimum_established IN (0,1)),
                requester_checked INTEGER NOT NULL CHECK(requester_checked IN (0,1)),
                fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32));
            """;
        command.ExecuteNonQuery();
    }

    internal static void Write(SqliteConnection connection, SqliteTransaction transaction, JudgementDescription description,
        PathInputs inputs, string calculationFingerprint, IReadOnlyList<OwnershipAuditStorage.TargetRow> recorded,
        IReadOnlyList<Tier0PathNode> nodes, PathRequesterRouteIndex routes, PathCalculationStorage.Selection? selection,
        IEnumerable<string> checkedRequesters, CancellationToken cancellationToken)
    {
        var byDn = nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        if (inputs.Availability == PathInputAvailability.Recorded ? nodes.Count != recorded.Count : nodes.Count != 0)
            throw Tier0PathStorage.InvalidProof();
        var classified = inputs.Classifications.Where(value => value.State == Tier0State.Established)
            .Select(value => value.Target).ToHashSet();
        var fixedTargets = inputs.FixedTargets.ToHashSet();
        var checkedObjects = checkedRequesters.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var classifiedCount = 0;
        var fixedCount = 0;
        var supported = 0;
        var otherSupported = 0;
        var unresolved = 0;
        var unassessed = 0;
        var checkedCount = 0;
        using var insert = connection.CreateCommand();
        insert.Transaction = transaction;
        insert.CommandText = "INSERT INTO tier0_distance VALUES ($target,$verdict,$classification,$distance,$minimum,$checked,$hash)";
        foreach (var name in new[] { "$target", "$verdict", "$classification", "$distance", "$minimum", "$checked", "$hash" })
            insert.Parameters.Add(new SqliteParameter(name, DBNull.Value));
        foreach (var row in recorded)
        {
            cancellationToken.ThrowIfCancellationRequested();
            byDn.TryGetValue(row.Identity.DistinguishedName, out var node);
            if (node is not null && node.Subject != row.Identity) throw Tier0PathStorage.InvalidProof();
            var distance = node is null ? null : routes.SupportedDistance(node);
            var isFixed = fixedTargets.Contains(row.Identity);
            var isClassified = classified.Contains(row.Identity);
            var facts = new Tier0DistanceFacts(node is null ? Tier0DistanceVerdict.NotAssessed
                    : isFixed ? Tier0DistanceVerdict.FixedTarget
                    : distance is not null ? Tier0DistanceVerdict.SupportedRoute : Tier0DistanceVerdict.Unresolved,
                isClassified ? Tier0State.Established : Tier0State.Unknown,
                distance, isFixed && distance == 0, checkedObjects.Contains(row.Identity.DistinguishedName));
            Validate(facts);
            if (isClassified) classifiedCount++;
            if (isFixed) fixedCount++;
            if (distance is not null) { supported++; if (!isClassified) otherSupported++; }
            if (facts.Verdict == Tier0DistanceVerdict.Unresolved) unresolved++;
            if (facts.Verdict == Tier0DistanceVerdict.NotAssessed) unassessed++;
            if (facts.HasRequesterChecks) checkedCount++;
            insert.Parameters["$target"].Value = row.Identity.DistinguishedName;
            insert.Parameters["$verdict"].Value = facts.Verdict.ToString();
            insert.Parameters["$classification"].Value = facts.Classification.ToString();
            insert.Parameters["$distance"].Value = (object?)distance ?? DBNull.Value;
            insert.Parameters["$minimum"].Value = facts.IsMinimumEstablished;
            insert.Parameters["$checked"].Value = facts.HasRequesterChecks;
            insert.Parameters["$hash"].Value = Fingerprint(calculationFingerprint, row.Identity.DistinguishedName, facts);
            if (insert.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
        }
        var summary = new Tier0RunSummary(1, description.GenerationId, description.DerivationGenerationId,
            description.EvidenceSeal, calculationFingerprint, inputs.Availability, inputs.Coverage,
            selection is not null, selection?.InputScanCompleted == true, recorded.Count, classifiedCount, fixedCount,
            supported, otherSupported, unresolved, unassessed, checkedCount);
        Validate(summary);
        var json = JsonSerializer.Serialize(summary, ProofSerialization.Options);
        using var save = connection.CreateCommand();
        save.Transaction = transaction;
        save.CommandText = "INSERT INTO tier0_distance_product VALUES (1,$proof,$hash)";
        save.Parameters.AddWithValue("$proof", json);
        save.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
        if (save.ExecuteNonQuery() != 1) throw Tier0PathStorage.InvalidProof();
    }

    internal static Tier0RunSummary? ReadSummary(SqliteConnection connection, JudgementDescription description,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT p.proof,p.fingerprint,c.fingerprint FROM (SELECT 1 AS id) root
            LEFT JOIN tier0_distance_product p ON p.id=root.id
            LEFT JOIN tier0_path_calculation c ON c.id=root.id
            """;
        using var read = command.ExecuteReader();
        if (!read.Read()) throw Tier0PathStorage.InvalidProof();
        if (read.IsDBNull(0) && read.IsDBNull(2)) return null;
        if (read.IsDBNull(0) || read.IsDBNull(2)) throw Tier0PathStorage.InvalidProof();
        var json = read.GetString(0);
        if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual((byte[])read.GetValue(1)))
            throw Tier0PathStorage.InvalidProof();
        var value = JsonSerializer.Deserialize<Tier0RunSummary>(json, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
        Validate(value);
        if (value.GenerationId != description.GenerationId || value.DerivationGenerationId != description.DerivationGenerationId
            || value.EvidenceSeal != description.EvidenceSeal
            || value.CalculationFingerprint != Convert.ToHexString((byte[])read.GetValue(2))) throw Tier0PathStorage.InvalidProof();
        cancellationToken.ThrowIfCancellationRequested();
        return value;
    }

    internal static Tier0ObjectDistance? ReadObject(SqliteConnection connection, JudgementDescription description,
        string target, CancellationToken cancellationToken)
    {
        var summary = ReadSummary(connection, description, cancellationToken);
        if (summary is null) return null;
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT o.identity_json,o.fingerprint,d.target,d.verdict,d.classification,d.supported_distance,
                   d.minimum_established,d.requester_checked,d.fingerprint
            FROM ownership_target o LEFT JOIN tier0_distance d ON d.target=o.target
            WHERE o.target=$target COLLATE NOCASE
            """;
        command.Parameters.AddWithValue("$target", target);
        using var read = command.ExecuteReader();
        if (!read.Read()) return null;
        if (read.IsDBNull(2)) throw Tier0PathStorage.InvalidProof();
        var identityJson = read.GetString(0);
        if (!OwnershipAuditStorage.Hash(identityJson).AsSpan().SequenceEqual((byte[])read.GetValue(1)))
            throw Tier0PathStorage.InvalidProof();
        var subject = JsonSerializer.Deserialize<Tier0Target>(identityJson, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
        if (subject.DistinguishedName != read.GetString(2) || read.GetInt32(6) is not (0 or 1) || read.GetInt32(7) is not (0 or 1))
            throw Tier0PathStorage.InvalidProof();
        var facts = new Tier0DistanceFacts(Enum.Parse<Tier0DistanceVerdict>(read.GetString(3)),
            Enum.Parse<Tier0State>(read.GetString(4)), read.IsDBNull(5) ? null : read.GetInt32(5),
            read.GetBoolean(6), read.GetBoolean(7));
        Validate(facts);
        if (!Fingerprint(summary.CalculationFingerprint, subject.DistinguishedName, facts).AsSpan().SequenceEqual((byte[])read.GetValue(8)))
            throw Tier0PathStorage.InvalidProof();
        cancellationToken.ThrowIfCancellationRequested();
        return new(description.GenerationId, description.DerivationGenerationId, description.EvidenceSeal,
            summary.CalculationFingerprint, subject, facts, summary.Coverage);
    }

    internal static void RequirePublishable(SqliteConnection connection, JudgementDescription? description,
        CancellationToken cancellationToken)
    {
        var summary = description is null ? null : ReadSummary(connection, description, cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*),COALESCE(SUM(classification='Established'),0),COALESCE(SUM(verdict='FixedTarget'),0),
                   COALESCE(SUM(supported_distance IS NOT NULL),0),
                   COALESCE(SUM(supported_distance IS NOT NULL AND classification='Unknown'),0),
                   COALESCE(SUM(verdict='Unresolved'),0),COALESCE(SUM(verdict='NotAssessed'),0),
                   COALESCE(SUM(requester_checked),0),(SELECT COUNT(*) FROM ownership_target),
                   (SELECT COUNT(*) FROM tier0_distance_product),(SELECT COUNT(*) FROM tier0_path_calculation)
            FROM tier0_distance
            """;
        using var read = command.ExecuteReader();
        if (!read.Read()) throw Tier0PathStorage.InvalidProof();
        if (summary is null)
        {
            if (read.GetInt64(0) != 0 || read.GetInt64(9) != 0 || read.GetInt64(10) != 0) throw Tier0PathStorage.InvalidProof();
            return;
        }
        var expected = new[] { summary.RecordedSubjects, summary.ClassifiedTier0Objects, summary.FixedTargets,
            summary.ObjectsWithSupportedRoute, summary.OtherObjectsWithSupportedRoute, summary.UnresolvedObjects,
            summary.UnassessedObjects, summary.ObjectsWithRequesterChecks, summary.RecordedSubjects };
        for (var i = 0; i < expected.Length; i++)
            if (read.GetInt64(i) != expected[i]) throw Tier0PathStorage.InvalidProof();
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static byte[] Fingerprint(string calculation, string target, Tier0DistanceFacts facts) =>
        OwnershipAuditStorage.Hash(calculation + "\0" + target + "\0" + JsonSerializer.Serialize(facts, ProofSerialization.Options));

    private static void Validate(Tier0DistanceFacts value)
    {
        if (!Enum.IsDefined(value.Verdict) || value.Classification is not (Tier0State.Established or Tier0State.Unknown)
            || value.SupportedDistance < 0 || value.IsMinimumEstablished != (value.Verdict == Tier0DistanceVerdict.FixedTarget)
            || (value.Verdict switch
            {
                Tier0DistanceVerdict.FixedTarget => value.SupportedDistance != 0 || value.Classification != Tier0State.Established,
                Tier0DistanceVerdict.SupportedRoute => value.SupportedDistance is null or <= 0,
                _ => value.SupportedDistance is not null,
            })) throw Tier0PathStorage.InvalidProof();
    }

    private static void Validate(Tier0RunSummary value)
    {
        if (value.Version != 1 || !Enum.IsDefined(value.Availability) || value.Coverage is null
            || value.CalculationFingerprint is not { Length: 64 }
            || value.RecordedSubjects < 0 || value.ClassifiedTier0Objects < 0 || value.FixedTargets < 0
            || value.ObjectsWithSupportedRoute < 0 || value.OtherObjectsWithSupportedRoute < 0
            || value.UnresolvedObjects < 0 || value.UnassessedObjects < 0 || value.ObjectsWithRequesterChecks < 0
            || (long)value.ObjectsWithSupportedRoute + value.UnresolvedObjects + value.UnassessedObjects != value.RecordedSubjects
            || value.ClassifiedTier0Objects > value.RecordedSubjects || value.FixedTargets > value.ClassifiedTier0Objects
            || value.FixedTargets > value.ObjectsWithSupportedRoute || value.OtherObjectsWithSupportedRoute > value.ObjectsWithSupportedRoute
            || value.ObjectsWithSupportedRoute - value.OtherObjectsWithSupportedRoute > value.ClassifiedTier0Objects
            || value.ObjectsWithRequesterChecks > value.RecordedSubjects
            || value.RequesterInputScanCompleted && (!value.AutomaticRequesterSelectionRequested || value.Availability != PathInputAvailability.Recorded)
            || (value.Availability == PathInputAvailability.Recorded ? value.UnassessedObjects != 0 : value.UnassessedObjects != value.RecordedSubjects))
            throw Tier0PathStorage.InvalidProof();
    }
}
