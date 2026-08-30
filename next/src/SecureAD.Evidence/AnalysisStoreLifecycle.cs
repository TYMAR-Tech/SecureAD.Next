using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>The disposable analysis store whose generation is being written or resolved.</summary>
public enum AnalysisStoreKind
{
    /// <summary>Reusable facts derived from sealed Evidence.</summary>
    Derivation,

    /// <summary>Rule executions and findings produced from validated inputs.</summary>
    Judgement,
}

/// <summary>One immutable generation selected by an analysis-store manifest.</summary>
/// <param name="Kind">Which disposable store the generation belongs to.</param>
/// <param name="GenerationId">The identifier from which <see cref="BundleLayout"/> derives its paths.</param>
public sealed record AnalysisStoreGeneration(AnalysisStoreKind Kind, Guid GenerationId);

/// <summary>
/// Stages and atomically publishes immutable Derivation and Judgement generations.
/// </summary>
/// <remarks>
/// A database and seal are two files and cannot be replaced atomically as a pair. They are therefore
/// written under generation-specific names. A small manifest is the only mutable name and publishing
/// it is the single operation that makes a generation current. Failure before publication leaves the
/// previous manifest and generation untouched.
/// </remarks>
public static class AnalysisStoreLifecycle
{
    private sealed record Manifest(int Version, string GenerationId);

    private const int ManifestVersion = 1;

    /// <summary>Returns the private staging database path used while a generation is being written.</summary>
    public static string StagingPath(string bundleDirectory, AnalysisStoreKind kind)
    {
        return BundleLayout.AnalysisStagingPath(bundleDirectory, kind);
    }

    /// <summary>Returns the manifest path whose contents select the current complete generation.</summary>
    public static string ManifestPath(string bundleDirectory, AnalysisStoreKind kind)
    {
        return BundleLayout.AnalysisManifestPath(bundleDirectory, kind);
    }

    /// <summary>Returns the immutable paths for <paramref name="generationId"/>.</summary>
    public static AnalysisStoreGeneration Generation(
        string bundleDirectory,
        AnalysisStoreKind kind,
        Guid generationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        return new AnalysisStoreGeneration(kind, generationId);
    }

    /// <summary>
    /// Seals and publishes a staged database as the current immutable generation.
    /// </summary>
    /// <param name="bundleDirectory">The bundle containing the analysis store.</param>
    /// <param name="kind">Which disposable store is being published.</param>
    /// <param name="generationId">The generation written into the staged database.</param>
    public static AnalysisStoreGeneration Publish(
        string bundleDirectory,
        AnalysisStoreKind kind,
        Guid generationId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var stagingPath = StagingPath(bundleDirectory, kind);
        if (!File.Exists(stagingPath))
        {
            throw new FileNotFoundException(
                $"The staged {Prefix(kind)} database does not exist.", stagingPath);
        }

        var generation = Generation(bundleDirectory, kind, generationId);
        var dataPath = BundleLayout.AnalysisGenerationDataPath(bundleDirectory, kind, generationId);
        var sealPath = BundleLayout.AnalysisGenerationSealPath(bundleDirectory, kind, generationId);
        if (File.Exists(dataPath) || File.Exists(sealPath))
        {
            throw new InvalidOperationException(
                $"Analysis generation '{generationId:D}' already exists. Generation identifiers "
                + "are immutable and cannot be published twice.");
        }

        File.Move(stagingPath, dataPath);
        BundleSealing.Seal(dataPath, sealPath);

        var manifestPath = ManifestPath(bundleDirectory, kind);
        var stagedManifestPath = manifestPath + ".partial";
        var manifest = JsonSerializer.Serialize(new Manifest(ManifestVersion, generationId.ToString("D")));

        using (var stream = new FileStream(
            stagedManifestPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.WriteThrough))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(manifest);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }

        File.Move(stagedManifestPath, manifestPath, overwrite: true);
        return generation;
    }

    /// <summary>Resolves the complete generation selected by the current manifest.</summary>
    public static Result<AnalysisStoreGeneration> Resolve(
        string bundleDirectory,
        AnalysisStoreKind kind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var manifestPath = ManifestPath(bundleDirectory, kind);
        if (!File.Exists(manifestPath))
        {
            return Failure(
                kind,
                "ManifestAbsent",
                $"There is no current {Prefix(kind)} generation manifest at '{manifestPath}'.",
                manifestPath);
        }

        try
        {
            var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(manifestPath));
            if (manifest is null || manifest.Version != ManifestVersion
                || !Guid.TryParse(manifest.GenerationId, out var generationId))
            {
                return Failure(
                    kind,
                    "ManifestUnreadable",
                    $"The current {Prefix(kind)} generation manifest at '{manifestPath}' does not "
                    + "name a supported generation.",
                    manifestPath);
            }

            var generation = Generation(bundleDirectory, kind, generationId);
            var dataPath = BundleLayout.AnalysisGenerationDataPath(
                bundleDirectory, kind, generationId);
            var sealPath = BundleLayout.AnalysisGenerationSealPath(
                bundleDirectory, kind, generationId);
            if (!File.Exists(dataPath) || !File.Exists(sealPath))
            {
                return Failure(
                    kind,
                    "GenerationIncomplete",
                    $"The current {Prefix(kind)} manifest names generation '{generationId:D}', but "
                    + "its database and seal are not both present.",
                    manifestPath);
            }

            return generation;
        }
        catch (Exception error) when (
            error is JsonException or IOException or UnauthorizedAccessException)
        {
            return Failure(
                kind,
                "ManifestUnreadable",
                $"The current {Prefix(kind)} generation manifest at '{manifestPath}' could not be "
                + $"read: {error.Message}",
                manifestPath);
        }
    }

    private static string Prefix(AnalysisStoreKind kind) => kind switch
    {
        AnalysisStoreKind.Derivation => "derivation",
        AnalysisStoreKind.Judgement => "judgement",
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown analysis store kind."),
    };

    private static Result<AnalysisStoreGeneration> Failure(
        AnalysisStoreKind kind,
        string reason,
        string description,
        string context) =>
        Result<AnalysisStoreGeneration>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence,
                Prefix(kind) + reason,
                ErrorSeverity.Failed,
                description,
                context));
}
