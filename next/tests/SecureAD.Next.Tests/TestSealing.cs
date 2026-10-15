using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests;

internal static class TestSealing
{
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
            BundleSealing.Seal(path, path + ".seal");
            return segment with { Hash = BundleSealing.ReadSeal(path + ".seal")!.Hash, ByteLength = new FileInfo(path).Length };
        }).ToArray();
        root = root with { Segments = segments };
        File.WriteAllText(manifest, JsonSerializer.Serialize(root with { Hash = root.ComputeHash() }));
    }

    internal static void AttachJudgementParts(SqliteConnection connection, string directory, Guid generation, bool staged = false)
    {
        var selected = new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, generation);
        foreach (var role in BundleLayout.JudgementParts)
        {
            var path = staged ? BundleLayout.JudgementPartStagingPath(directory, role)
                : BundleLayout.AnalysisSegmentDataPath(directory, selected, role);
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
        File.Copy(BundleLayout.JudgementPartialPath(directory), BundleLayout.JudgementPartialPath(copy));
        foreach (var role in BundleLayout.JudgementParts)
            File.Copy(BundleLayout.JudgementPartStagingPath(directory, role), BundleLayout.JudgementPartStagingPath(copy, role));
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
