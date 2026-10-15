using System.Text.Json;
using SecureAD.Evidence.Inventory;
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

internal enum AnalysisPublicationPart
{
    WritePendingManifest,
    MoveData,
    SealData,
    SelectManifest,
}

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
    /// <summary>Excludes another judgement writer or an explicitly requested discard in this bundle.</summary>
    public static IDisposable LockJudgementWrites(string bundleDirectory) =>
        new FileStream(BundleLayout.JudgementWriteLockPath(bundleDirectory), FileMode.OpenOrCreate,
            FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);

    /// <summary>Discards only saved judgement generations after the operator has confirmed their loss.</summary>
    public static AnalysisStoreGeneration DiscardJudgement(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        using var writing = LockJudgementWrites(bundleDirectory);
        if (HasUnpublishedChanges(bundleDirectory, AnalysisStoreKind.Judgement)
            || HasUnpublishedChanges(bundleDirectory, AnalysisStoreKind.Derivation))
            throw new InvalidOperationException("This run has an unfinished analysis attempt; its judgement was not discarded.");
        var current = Resolve(bundleDirectory, AnalysisStoreKind.Judgement);
        if (!current.IsSuccess) throw new InvalidOperationException(current.Error.Description);
        var derivation = Resolve(bundleDirectory, AnalysisStoreKind.Derivation);
        if (!derivation.IsSuccess) throw new InvalidOperationException(derivation.Error.Description);

        var manifest = ManifestPath(bundleDirectory, AnalysisStoreKind.Judgement);
        var files = Directory.EnumerateFiles(bundleDirectory)
            .Where(IsJudgementGenerationFile).Prepend(manifest).ToArray();
        var protectedFiles = new List<FileStream>();
        try
        {
            foreach (var path in files)
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException($"The judgement file '{path}' is a link and was not discarded.");
                protectedFiles.Add(new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Delete));
            }

            // Refuse new readers before unselecting the old result. A failed deletion stays visibly unfinished.
            BeginAttempt(bundleDirectory, AnalysisStoreKind.Judgement);
            foreach (var path in files) File.Delete(path);
            File.Delete(manifest + ".partial");
            return current.Value;
        }
        finally
        {
            foreach (var file in protectedFiles) file.Dispose();
        }
    }

    private static bool IsJudgementGenerationFile(string path)
    {
        var name = Path.GetFileName(path);
        var prefix = Prefix(AnalysisStoreKind.Judgement) + ".";
        if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            || name.Length < prefix.Length + 32
            || !Guid.TryParseExact(name.AsSpan(prefix.Length, 32), "N", out var generation))
            return false;
        var selected = new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, generation);
        return BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement).Any(role =>
        {
            var dataName = Path.GetFileName(BundleLayout.AnalysisSegmentDataPath(".", selected, role));
            return name.Equals(dataName, StringComparison.OrdinalIgnoreCase)
                || name.Equals(dataName + ".seal", StringComparison.OrdinalIgnoreCase)
                || name.Equals(dataName + "-wal", StringComparison.OrdinalIgnoreCase)
                || name.Equals(dataName + "-shm", StringComparison.OrdinalIgnoreCase)
                || name.Equals(dataName + "-journal", StringComparison.OrdinalIgnoreCase);
        });
    }

    /// <summary>Marks a new attempt before replacing its staging file; failure leaves the attempt visible.</summary>
    public static void BeginAttempt(string bundleDirectory, AnalysisStoreKind kind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        WritePendingManifest(ManifestPath(bundleDirectory, kind) + ".partial",
            new StoreRootManifest(StoreRootManifest.CurrentVersion, Guid.Empty, "", [], null, ""));
    }

    /// <summary>Whether a newer attempt is unfinished, including the interval after its database was renamed.</summary>
    public static bool HasUnpublishedChanges(string bundleDirectory, AnalysisStoreKind kind) =>
        Exists(StagingPath(bundleDirectory, kind)) || Exists(ManifestPath(bundleDirectory, kind) + ".partial");

    private static bool Exists(string path)
    {
        try { _ = File.GetAttributes(path); return true; }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

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
    /// <param name="cancellationToken">Stops before the atomic manifest replacement; already-written generation files remain unselected.</param>
    public static AnalysisStoreGeneration Publish(
        string bundleDirectory,
        AnalysisStoreKind kind,
        Guid generationId,
        CancellationToken cancellationToken = default) =>
        Publish(bundleDirectory, kind, generationId, cancellationToken, null);

    /// <summary>Publishes with aggregate file-sealing diagnostics, preserving the existing publication boundary.</summary>
    /// <param name="bundleDirectory">The bundle containing the analysis store.</param>
    /// <param name="kind">The analysis store being published.</param>
    /// <param name="generationId">The immutable generation being selected.</param>
    /// <param name="cancellationToken">The existing pre-publication cancellation boundary.</param>
    /// <param name="log">The run log receiving aggregate sealing diagnostics.</param>
    public static AnalysisStoreGeneration PublishWithDiagnostics(string bundleDirectory, AnalysisStoreKind kind,
        Guid generationId, CancellationToken cancellationToken, IRunLog log)
    {
        ArgumentNullException.ThrowIfNull(log);
        return Publish(bundleDirectory, kind, generationId, cancellationToken, null, log);
    }

    internal static AnalysisStoreGeneration Publish(string bundleDirectory, AnalysisStoreKind kind,
        Guid generationId, CancellationToken cancellationToken, Action<AnalysisPublicationPart>? beginPart) =>
        Publish(bundleDirectory, kind, generationId, cancellationToken, beginPart, null);

    internal static AnalysisStoreGeneration Publish(string bundleDirectory, AnalysisStoreKind kind,
        Guid generationId, CancellationToken cancellationToken, Action<AnalysisPublicationPart>? beginPart, IRunLog? log)
        => Publish(bundleDirectory, kind, generationId, cancellationToken, beginPart, log, 1, "", null, null);

    /// <summary>Publishes one analysis product and its small, generation-bound browse summary.</summary>
    public static AnalysisStoreGeneration PublishBound(string bundleDirectory, AnalysisStoreKind kind,
        Guid generationId, int schemaVersion, string evidenceSeal, DerivationBrowseSummary? summary,
        CancellationToken cancellationToken, IRunLog? log) =>
        Publish(bundleDirectory, kind, generationId, cancellationToken, null, log, schemaVersion, evidenceSeal, summary, null);

    internal static AnalysisStoreGeneration Publish(string bundleDirectory, AnalysisStoreKind kind,
        Guid generationId, CancellationToken cancellationToken, Action<AnalysisPublicationPart>? beginPart,
        IRunLog? log, int schemaVersion, string evidenceSeal, DerivationBrowseSummary? summary,
        IReadOnlyList<StoreSegmentRole>? additionalParts)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        cancellationToken.ThrowIfCancellationRequested();

        var stagingPath = StagingPath(bundleDirectory, kind);
        if (!File.Exists(stagingPath))
        {
            throw new FileNotFoundException(
                $"The staged {Prefix(kind)} database does not exist.", stagingPath);
        }

        var generation = Generation(bundleDirectory, kind, generationId);
        var role = kind == AnalysisStoreKind.Derivation ? StoreSegmentRole.Derivation : StoreSegmentRole.Judgement;
        if (additionalParts is not null && (kind != AnalysisStoreKind.Judgement
            || !additionalParts.SequenceEqual(BundleLayout.JudgementParts)))
            throw new ArgumentException("A judgement must publish all of its declared parts together.", nameof(additionalParts));
        var roles = (additionalParts ?? []).Prepend(role).ToArray();
        var products = roles.Select(product => (
            Role: product,
            Staging: product == role ? stagingPath : BundleLayout.JudgementPartStagingPath(bundleDirectory, product),
            Data: BundleLayout.AnalysisSegmentDataPath(bundleDirectory, generation, product))).ToArray();
        if (products.Any(product => File.Exists(product.Data) || File.Exists(product.Data + ".seal")))
        {
            throw new InvalidOperationException(
                $"Analysis generation '{generationId:D}' already exists. Generation identifiers "
                + "are immutable and cannot be published twice.");
        }
        foreach (var product in products)
            if (!File.Exists(product.Staging))
                throw new FileNotFoundException("A staged analysis product is missing.", product.Staging);

        var manifestPath = ManifestPath(bundleDirectory, kind);
        var stagedManifestPath = manifestPath + ".partial";
        // The staging database disappears during sealing. Keep the unfinished attempt visible
        // until the single atomic operation that makes its sealed generation current.
        beginPart?.Invoke(AnalysisPublicationPart.WritePendingManifest);
        WritePendingManifest(stagedManifestPath,
            new StoreRootManifest(StoreRootManifest.CurrentVersion, generationId, evidenceSeal, [], summary, ""));

        beginPart?.Invoke(AnalysisPublicationPart.MoveData);
        var protection = new List<FileStream>();
        try
        {
            foreach (var product in products)
            {
                File.Move(product.Staging, product.Data);
                protection.Add(new FileStream(product.Data, FileMode.Open, FileAccess.Read, FileShare.Read));
            }
            beginPart?.Invoke(AnalysisPublicationPart.SealData);
            var segments = new List<SealedStoreSegment>();
            foreach (var product in products)
            {
                // Only the final root selects these files; a failed seal must leave the previous selection intact.
                if (log is null) BundleSealing.Seal(product.Data, product.Data + ".seal");
                else BundleSealing.SealWithDiagnostics(product.Data, product.Data + ".seal", CancellationToken.None, log, kind, generationId);
                segments.Add(SealedSegment(product.Data, product.Data + ".seal", product.Role, schemaVersion, generationId));
            }
            var root = new StoreRootManifest(StoreRootManifest.CurrentVersion, generationId, evidenceSeal, segments, summary, "");
            WritePendingManifest(stagedManifestPath, root with { Hash = root.ComputeHash() });
            beginPart?.Invoke(AnalysisPublicationPart.SelectManifest);
            cancellationToken.ThrowIfCancellationRequested();
            File.Move(stagedManifestPath, manifestPath, overwrite: true);
            return generation;
        }
        finally { foreach (var file in protection) file.Dispose(); }
    }

    private static void WritePendingManifest(string path, StoreRootManifest manifest)
    {
        using (var stream = new FileStream(
            path,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.WriteThrough))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(JsonSerializer.Serialize(manifest));
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }
    }

    /// <summary>Resolves the complete generation selected by the current manifest.</summary>
    public static Result<AnalysisStoreGeneration> Resolve(
        string bundleDirectory,
        AnalysisStoreKind kind)
    {
        var root = ResolveRoot(bundleDirectory, kind);
        return root.IsSuccess ? Generation(bundleDirectory, kind, root.Value.GenerationId)
            : Result<AnalysisStoreGeneration>.Failure(root.Error);
    }

    /// <summary>Reads the small, self-fingerprinted root without verifying unselected database bytes.</summary>
    public static Result<StoreRootManifest> ResolveRoot(string bundleDirectory, AnalysisStoreKind kind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var manifestPath = ManifestPath(bundleDirectory, kind);
        if (!File.Exists(manifestPath))
        {
            return RootFailure(
                kind,
                "ManifestAbsent",
                $"There is no current {Prefix(kind)} generation manifest at '{manifestPath}'.",
                manifestPath);
        }

        try
        {
            // Publication replaces this name atomically. A short metadata read must not block
            // that replacement; its handle still describes the complete old or new manifest.
            using var stream = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            var manifest = JsonSerializer.Deserialize<StoreRootManifest>(stream);
            var role = kind == AnalysisStoreKind.Derivation ? StoreSegmentRole.Derivation : StoreSegmentRole.Judgement;
            var roles = kind == AnalysisStoreKind.Judgement && manifest?.Segments is { Count: > 1 }
                ? BundleLayout.JudgementParts.Prepend(role).ToArray() : new[] { role };
            if (!ValidRoot(manifest, roles))
            {
                return RootFailure(
                    kind,
                    "ManifestUnreadable",
                    $"The current {Prefix(kind)} generation manifest at '{manifestPath}' does not "
                    + "name a supported generation.",
                    manifestPath);
            }

            var generationId = manifest!.GenerationId;
            var generation = new AnalysisStoreGeneration(kind, generationId);
            foreach (var product in roles)
            {
                var dataPath = BundleLayout.AnalysisSegmentDataPath(bundleDirectory, generation, product);
                if (!File.Exists(dataPath) || !File.Exists(dataPath + ".seal"))
                {
                    return RootFailure(
                        kind,
                        "GenerationIncomplete",
                        $"The current {Prefix(kind)} manifest names generation '{generationId:D}', but "
                        + "its database and seal are not both present.",
                        manifestPath);
                }
                RequireDeclaration(manifest.Segment(product), dataPath);
            }
            return manifest with { Segments = Array.AsReadOnly(manifest.Segments.ToArray()) };
        }
        catch (Exception error) when (
            error is JsonException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return RootFailure(
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

    private static Result<StoreRootManifest> RootFailure(
        AnalysisStoreKind kind,
        string reason,
        string description,
        string context) =>
        Result<StoreRootManifest>.Failure(
            AuditError.Create(
                ErrorCategory.Evidence,
                Prefix(kind) + reason,
                ErrorSeverity.Failed,
                description,
                context));

    internal static StoreRootManifest PublishCapture(string directory, string stagedEvidence, Guid generation, long objects, CancellationToken token,
        Action<string, string, CancellationToken> seal, Action claimPublication)
    {
        var manifestPath = BundleLayout.CaptureManifestPath(directory);
        if (File.Exists(manifestPath)) throw new InvalidOperationException("Captured generations are never replaced.");
        WritePendingManifest(manifestPath + ".partial",
            new(StoreRootManifest.CurrentVersion, generation, "", [], null, ""));
        var navigation = BundleLayout.NavigationPath(directory, generation);
        var overview = BundleLayout.OverviewPath(directory, generation);
        if (File.Exists(navigation) || File.Exists(navigation + ".seal")
            || File.Exists(overview) || File.Exists(overview + ".seal"))
            throw new InvalidOperationException("A captured browse generation already exists.");
        var evidence = BundleLayout.EvidencePath(directory);
        var stagedNavigation = BundleLayout.NavigationPartialPath(directory);
        var stagedOverview = BundleLayout.OverviewPartialPath(directory);
        using var protectedEvidence = new FileStream(stagedEvidence, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        using var protectedNavigation = new FileStream(stagedNavigation, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        using var protectedOverview = new FileStream(stagedOverview, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        token.ThrowIfCancellationRequested();
        seal(stagedEvidence, BundleLayout.SealPath(directory), token);
        token.ThrowIfCancellationRequested();
        seal(stagedNavigation, navigation + ".seal", token);
        token.ThrowIfCancellationRequested();
        seal(stagedOverview, overview + ".seal", token);
        var captured = SealedSegment(stagedEvidence, BundleLayout.SealPath(directory),
            StoreSegmentRole.Evidence, BundleSchema.Version, generation) with { FileName = Path.GetFileName(evidence) };
        var browse = SealedSegment(stagedNavigation, navigation + ".seal",
            StoreSegmentRole.Navigation, NavigationStorage.Version, generation) with { FileName = Path.GetFileName(navigation) };
        var dashboard = SealedSegment(stagedOverview, overview + ".seal",
            StoreSegmentRole.Overview, DashboardOverviewStorage.Version, generation) with { FileName = Path.GetFileName(overview) };
        var root = new StoreRootManifest(StoreRootManifest.CurrentVersion, generation, captured.Hash,
            [captured, browse, dashboard], null, "") { CapturedObjects = objects };
        root = root with { Hash = root.ComputeHash() };
        WritePendingManifest(manifestPath + ".partial", root);
        token.ThrowIfCancellationRequested();
        claimPublication();
        File.Move(stagedNavigation, navigation);
        File.Move(stagedOverview, overview);
        File.Move(stagedEvidence, evidence);
        File.Move(manifestPath + ".partial", manifestPath);
        return root;
    }

    /// <summary>Resolves a complete capture without hashing unselected products.</summary>
    public static Result<StoreRootManifest> ResolveCapture(string directory)
    {
        var path = BundleLayout.CaptureManifestPath(directory);
        try
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("The capture root is a link.");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            var root = JsonSerializer.Deserialize<StoreRootManifest>(stream);
            if (!ValidRoot(root, [StoreSegmentRole.Evidence, StoreSegmentRole.Navigation, StoreSegmentRole.Overview])
                || root!.EvidenceSeal != root.Segment(StoreSegmentRole.Evidence).Hash || root.DerivationSummary is not null
                || root.CapturedObjects is not >= 0)
                throw new InvalidDataException("The capture root has unsupported or contradictory declarations.");
            RequireDeclaration(root.Segment(StoreSegmentRole.Evidence), BundleLayout.EvidencePath(directory));
            RequireDeclaration(root.Segment(StoreSegmentRole.Navigation), BundleLayout.NavigationPath(directory, root.GenerationId));
            RequireDeclaration(root.Segment(StoreSegmentRole.Overview), BundleLayout.OverviewPath(directory, root.GenerationId));
            foreach (var segment in root.Segments)
            {
                var dataPath = Path.Combine(directory, segment.FileName);
                if (!File.Exists(dataPath) || !File.Exists(dataPath + ".seal"))
                    throw new FileNotFoundException("A selected capture segment or its seal is missing.", dataPath);
            }
            return root with { Segments = Array.AsReadOnly(root.Segments.ToArray()) };
        }
        catch (Exception error) when (error is JsonException or InvalidDataException or IOException or UnauthorizedAccessException)
        {
            return Result<StoreRootManifest>.Failure(AuditError.Create(ErrorCategory.Evidence, "CaptureManifestUnreadable",
                ErrorSeverity.Failed, $"The captured generation could not be selected: {error.Message}", path));
        }
    }

    private static bool ValidRoot(StoreRootManifest? root, StoreSegmentRole[] roles) =>
        root is { Version: StoreRootManifest.CurrentVersion } && root.GenerationId != Guid.Empty
        && root.EvidenceSeal is not null && root.Segments is not null && root.Segments.All(segment => segment is not null)
        && root.Segments.Select(segment => segment.Role).SequenceEqual(roles)
        && IsHash(root.Hash) && root.Hash == root.ComputeHash()
        && root.Segments.All(segment => segment.GenerationId == root.GenerationId && segment.SchemaVersion > 0
            && segment.ByteLength >= 0 && IsHash(segment.Hash));

    private static void RequireDeclaration(SealedStoreSegment segment, string expectedPath)
    {
        if (segment.FileName != Path.GetFileName(expectedPath))
            throw new InvalidDataException("A segment role has an invalid file name.");
    }

    private static SealedStoreSegment SealedSegment(string dataPath, string sealPath, StoreSegmentRole role,
        int version, Guid generation)
    {
        var seal = BundleSealing.ReadSeal(sealPath);
        if (seal?.Algorithm != BundleSealing.Algorithm || !IsHash(seal.Hash))
            throw new InvalidDataException("A newly published segment has an unreadable seal.");
        return new(role, version, generation, Path.GetFileName(dataPath), new FileInfo(dataPath).Length, seal.Hash);
    }

    private static bool IsHash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
}
