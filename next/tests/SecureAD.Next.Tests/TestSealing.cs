using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests;

internal static partial class TestSealing
{
    internal static string AnalysisInputPath(string directory, AnalysisStoreKind kind, Guid generation) =>
        kind == AnalysisStoreKind.Derivation ? AnalysisStoreLifecycle.StagingPath(directory, kind)
            : BundleLayout.AnalysisGenerationDataPath(directory, kind, generation);

    internal static AnalysisStoreGeneration PendingJudgementGeneration(string directory)
    {
        var pending = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement) + ".partial";
        var root = JsonSerializer.Deserialize<StoreRootManifest>(File.ReadAllText(pending));
        if (root is null || root.GenerationId == Guid.Empty)
            throw new InvalidDataException("The fixture has no identified pending judgement generation.");
        return new(AnalysisStoreKind.Judgement, root.GenerationId);
    }

    internal static string PendingJudgementPath(string directory) =>
        BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement,
            PendingJudgementGeneration(directory).GenerationId);

    internal static void ResealCapture(string directory)
    {
        var path = BundleLayout.EvidencePath(directory);
        BundleSealing.Seal(path, BundleLayout.SealPath(directory));
        Rebind(directory, BundleLayout.CaptureManifestPath(directory), path);
    }

    internal static void ResealAnalysis(string directory, AnalysisStoreGeneration generation)
    {
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, generation.Kind);
        var root = JsonSerializer.Deserialize<StoreRootManifest>(File.ReadAllText(manifest))
            ?? throw new InvalidDataException("The fixture has no publication root.");
        var segments = root.Segments.Select(segment =>
        {
            var path = BundleLayout.AnalysisSegmentDataPath(directory, generation, segment.Role);
            if (segment.RequestedDetails is not null)
            {
                using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                {
                    DataSource = path, Mode = SqliteOpenMode.ReadWrite, Pooling = false,
                }.ToString());
                connection.Open();
                foreach (var payload in JudgementStoreLayout.RequestedPayloads(segment.Role))
                {
                    // These alterations re-authenticate the fixture to test proof semantics,
                    // not rejection caused only by a stale payload-piece fingerprint.
                    using var read = connection.CreateCommand();
                    read.CommandText = $"SELECT rowid FROM \"{payload.Table}\" ORDER BY rowid";
                    var ids = new List<long>();
                    using (var rows = read.ExecuteReader())
                        while (rows.Read()) ids.Add(rows.GetInt64(0));
                    read.CommandText = $"SELECT \"{payload.Data}\" FROM \"{payload.Table}\" WHERE rowid=$id";
                    read.Parameters.Add("$id", SqliteType.Integer);
                    using var update = connection.CreateCommand();
                    update.CommandText = $"UPDATE \"{payload.Table}\" SET \"{payload.Fingerprint}\"=$hash WHERE rowid=$id";
                    update.Parameters.Add("$hash", SqliteType.Blob);
                    update.Parameters.Add("$id", SqliteType.Integer);
                    foreach (var id in ids)
                    {
                        read.Parameters["$id"].Value = id;
                        var bytes = read.ExecuteScalar() as byte[]
                            ?? throw new InvalidDataException("A fixture payload piece is missing.");
                        update.Parameters["$hash"].Value = SHA256.HashData(bytes);
                        update.Parameters["$id"].Value = id;
                        if (update.ExecuteNonQuery() != 1) throw new InvalidDataException("A fixture payload piece was not re-authenticated.");
                    }
                }
                using (var drop = connection.CreateCommand())
                {
                    drop.CommandText = "DROP TABLE requested_detail_node";
                    drop.ExecuteNonQuery();
                }
                segment = segment with { RequestedDetails = RequestedDetailIndex.Prepare(connection, "main",
                    segment.Role, segment.SchemaVersion, root.GenerationId, root.EvidenceSeal, CancellationToken.None,
                    JudgementStoreLayout.RequestedPayloads(segment.Role)) };
            }
            BundleSealing.Seal(path, path + ".seal");
            return segment with { Hash = BundleSealing.ReadSeal(path + ".seal")!.Hash, ByteLength = new FileInfo(path).Length };
        }).ToArray();
        root = root with { Segments = segments };
        File.WriteAllText(manifest, JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
    }

    internal static void AttachJudgementParts(SqliteConnection connection, string directory, Guid generation, bool staged = false)
    {
        var selected = staged ? PendingJudgementGeneration(directory)
            : new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, generation);
        foreach (var role in BundleLayout.JudgementParts)
        {
            var path = BundleLayout.AnalysisSegmentDataPath(directory, selected, role);
            if (!File.Exists(path)) throw new FileNotFoundException("The generated test fixture is missing a proof part.", path);
            using var attach = connection.CreateCommand();
            attach.CommandText = $"ATTACH DATABASE $path AS \"{role}\"";
            attach.Parameters.AddWithValue("$path", path);
            attach.ExecuteNonQuery();
        }
        JudgementStoreLayout.RegisterReader(connection, _ => { });
        if (new SqliteConnectionStringBuilder(connection.ConnectionString).Mode != SqliteOpenMode.ReadOnly)
        {
            using var cascade = connection.CreateCommand();
            cascade.CommandText = """
                CREATE TEMP TRIGGER copied_calculation_delete AFTER DELETE ON main.tier0_path_calculation
                BEGIN
                    DELETE FROM path_calculation_record WHERE calculation=OLD.id;
                    DELETE FROM path_requester_work WHERE calculation=OLD.id;
                END;
                """;
            cascade.ExecuteNonQuery();
        }
    }

    internal static string CopyJudgement(string directory, Guid generation, string name)
    {
        var copy = TempDirectories.Create(name);
        var selected = new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, generation);
        foreach (var role in BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement))
        {
            var source = BundleLayout.AnalysisSegmentDataPath(directory, selected, role);
            File.Copy(source, Path.Combine(copy, Path.GetFileName(source)));
            File.Copy(source + ".seal", Path.Combine(copy, Path.GetFileName(source) + ".seal"));
        }
        File.Copy(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement),
            AnalysisStoreLifecycle.ManifestPath(copy, AnalysisStoreKind.Judgement));
        return copy;
    }

    internal static string CopyStagedJudgement(string directory, string name)
    {
        var copy = TempDirectories.Create(name);
        var generation = PendingJudgementGeneration(directory);
        foreach (var role in BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement))
            File.Copy(BundleLayout.AnalysisSegmentDataPath(directory, generation, role),
                BundleLayout.AnalysisSegmentDataPath(copy, generation, role));
        File.Copy(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement) + ".partial",
            AnalysisStoreLifecycle.ManifestPath(copy, AnalysisStoreKind.Judgement) + ".partial");
        return copy;
    }

    private static void Rebind(string directory, string manifest, string path)
    {
        var root = JsonSerializer.Deserialize<StoreRootManifest>(File.ReadAllText(manifest))
            ?? throw new InvalidDataException("The fixture has no publication root.");
        var hash = BundleSealing.ReadSeal(path + ".seal")!.Hash;
        root = root with { EvidenceSeal = path == BundleLayout.EvidencePath(directory) ? hash : root.EvidenceSeal,
            Segments = root.Segments.Select(segment =>
            segment.FileName == Path.GetFileName(path) ? segment with { Hash = hash, ByteLength = new FileInfo(path).Length } : segment).ToArray() };
        File.WriteAllText(manifest, JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
    }
}
