using System.Diagnostics.Metrics;
using System.Security.Cryptography;
using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Evidence;

/// <summary>
/// What verifying a bundle's seal concluded.
/// </summary>
/// <remarks>
/// Four states rather than three, and the fourth is the correction. The implementation being
/// replaced folded an unreadable signature file into "unsigned", which renders <i>something
/// happened to the seal</i> as <i>nobody ever sealed this</i> - a failure presented as a benign
/// absence, which is the one shape of defect an audit tool cannot have. See
/// <c>docs/decisions/0019</c>.
/// </remarks>
public enum SealState
{
    /// <summary>A seal is present, readable, and matches the evidence file.</summary>
    Intact,

    /// <summary>
    /// There is no seal file.
    /// </summary>
    /// <remarks>
    /// Unreachable for a bundle produced by this product, because sealing happens before the
    /// rename that gives the evidence file the name a reader asks for. Seeing it means the
    /// directory was assembled by hand.
    /// </remarks>
    Absent,

    /// <summary>
    /// A seal file exists and cannot be read. Not the same as <see cref="Absent"/>: the one thing
    /// that certainly happened is that something happened to the seal.
    /// </summary>
    Unreadable,

    /// <summary>The seal was read and the evidence file does not match it.</summary>
    Mismatch,
}

/// <summary>
/// The result of verifying a bundle's seal: what was concluded, and enough detail to say why.
/// </summary>
/// <param name="State">What was concluded.</param>
/// <param name="Detail">
/// What was observed, in terms a person can act on. Never empty, including when the state is
/// <see cref="SealState.Intact"/>, so that a caller rendering the detail never renders a blank.
/// </param>
public sealed record SealVerdict(SealState State, string Detail)
{
    /// <summary>
    /// Whether this bundle may be opened. Only <see cref="SealState.Intact"/> may.
    /// </summary>
    /// <remarks>
    /// Stated as one property rather than left to each caller, because a rule spelled out at
    /// thirty call sites is a rule that is wrong at one of them. This is the mechanism
    /// <c>docs/decisions/0003</c> rests on, generalised from re-analysis to every open.
    /// </remarks>
    public bool MayBeOpened => State == SealState.Intact;
}

/// <summary>
/// What a bundle's seal file records.
/// </summary>
/// <param name="Algorithm">The hash algorithm, named rather than assumed.</param>
/// <param name="Hash">The hash of the evidence file, lowercase hexadecimal.</param>
public sealed record BundleSealContents(string Algorithm, string Hash);

/// <summary>
/// Sealing a bundle, and checking a seal.
/// </summary>
/// <remarks>
/// <para>
/// <b>What the seal proves:</b> the bytes of the evidence file are the bytes that were there when
/// the run declared itself finished.
/// </para>
/// <para>
/// <b>What it does not prove.</b> It is not a signature and is deliberately not called one. There
/// is no key anywhere in this product, so anyone who can rewrite the evidence file can rewrite
/// the seal beside it - this catches corruption, truncation and casual editing, and not a
/// determined party. It says nothing about whether the capture was <i>complete</i>: that is a
/// claim the bundle makes in its own tables, and the seal only proves the claim has not been
/// edited since it was made. And it says nothing about whether the capture was correct.
/// </para>
/// <para>
/// There is no cached verdict. Reopening a large bundle re-hashes it, which costs real time on a
/// bundle of some gigabytes. That cost is accepted deliberately: a cache whose function is to
/// avoid performing an integrity check is a way for that check to silently never run.
/// </para>
/// </remarks>
public static class BundleSealing
{
    private static readonly Meter ReadbackMeter = new("SecureAD.Evidence.Readback");
    private static readonly Counter<long> Verifications = ReadbackMeter.CreateCounter<long>("store.verifications");

    /// <summary>The algorithm named in every seal this product writes.</summary>
    public const string Algorithm = "SHA-256";

    /// <summary>
    /// Hashes a file, lowercase hexadecimal.
    /// </summary>
    /// <param name="filePath">The file to hash.</param>
    public static string HashFile(string filePath) => HashFile(filePath, CancellationToken.None);

    /// <summary>Hashes a file cooperatively, without leaving a reader running after cancellation.</summary>
    /// <param name="filePath">The file to hash.</param>
    /// <param name="cancellationToken">Cancellation checked between reads.</param>
    public static string HashFile(string filePath, CancellationToken cancellationToken) =>
        HashFile(filePath, cancellationToken, null);

    private static string HashFile(string filePath, CancellationToken cancellationToken, FileSealWork? work)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        cancellationToken.ThrowIfCancellationRequested();

        FileStream? stream = null;
        try
        {
            work?.Begin(FileSealPart.OpenData);
            stream = File.OpenRead(filePath);
            work?.End();
            return HashStream(stream, cancellationToken, work);
        }
        catch
        {
            work?.RecordInterruptedPart();
            throw;
        }
        finally
        {
            if (stream is not null)
            {
                work?.Begin(FileSealPart.CloseData);
                try { stream.Dispose(); work?.End(); }
                catch { work?.RecordInterruptedPart(); throw; }
            }
        }
    }

    /// <summary>Hashes the remaining stream contents, leaving the caller-owned stream open.</summary>
    /// <param name="stream">The evidence bytes to hash.</param>
    /// <param name="cancellationToken">Cancellation checked before and after each read, including EOF.</param>
    public static string HashStream(Stream stream, CancellationToken cancellationToken) =>
        HashStream(stream, cancellationToken, null);

    internal static string HashStream(Stream stream, CancellationToken cancellationToken, FileSealWork? work)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                work?.Begin(FileSealPart.ReadData);
                work?.Reading();
                var read = stream.Read(buffer, 0, buffer.Length);
                work?.Read(read);
                work?.End();
                cancellationToken.ThrowIfCancellationRequested();
                if (read == 0)
                {
                    work?.Begin(FileSealPart.FinishHash);
                    var result = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
                    work?.End();
                    return result;
                }
                work?.Begin(FileSealPart.HashData);
                hash.AppendData(buffer, 0, read);
                work?.Hashed(read);
                work?.End();
            }
        }
        catch
        {
            work?.RecordInterruptedPart();
            throw;
        }
    }

    /// <summary>
    /// Writes a seal covering <paramref name="evidenceFilePath"/> to <paramref name="sealFilePath"/>.
    /// </summary>
    /// <param name="evidenceFilePath">The evidence file being sealed.</param>
    /// <param name="sealFilePath">Where the seal is written.</param>
    public static void Seal(string evidenceFilePath, string sealFilePath) =>
        Seal(evidenceFilePath, sealFilePath, CancellationToken.None);

    /// <summary>Prepares a seal without publishing the evidence file.</summary>
    /// <param name="evidenceFilePath">The evidence file being sealed.</param>
    /// <param name="sealFilePath">Where the seal is written.</param>
    /// <param name="cancellationToken">Cancellation during hashing and before writing the seal.</param>
    public static void Seal(string evidenceFilePath, string sealFilePath, CancellationToken cancellationToken) =>
        Seal(evidenceFilePath, sealFilePath, cancellationToken, null);

    /// <summary>Seals normally and records aggregate file-operation timings without directory-object data.</summary>
    /// <param name="evidenceFilePath">The file to seal.</param>
    /// <param name="sealFilePath">The unchanged seal-file destination.</param>
    /// <param name="cancellationToken">The caller's existing sealing cancellation boundary.</param>
    /// <param name="log">The run log receiving one aggregate record, including interrupted attempts.</param>
    /// <param name="kind">The analysis store, or null for captured evidence.</param>
    /// <param name="generation">The analysis generation, or null for captured evidence.</param>
    public static void SealWithDiagnostics(string evidenceFilePath, string sealFilePath, CancellationToken cancellationToken,
        IRunLog log, AnalysisStoreKind? kind, Guid? generation)
    {
        ArgumentNullException.ThrowIfNull(log);
        if (kind is { } value && !Enum.IsDefined(value) || kind.HasValue != generation.HasValue)
            throw new ArgumentException("Sealing diagnostics must identify either evidence or one analysis generation.", nameof(kind));
        var work = new FileSealWork(TimeProvider.System);
        var outcome = "Failed";
        try
        {
            Seal(evidenceFilePath, sealFilePath, cancellationToken, work);
            outcome = "Completed";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            outcome = "Cancelled";
            throw;
        }
        finally
        {
            var name = Path.GetFileName(evidenceFilePath);
            var artifact = kind is not null ? null
                : name.StartsWith("navigation.", StringComparison.Ordinal) ? "Navigation"
                : name.StartsWith("overview.", StringComparison.Ordinal) ? "Overview" : null;
            work.Report(log, kind, generation, outcome, artifact);
        }
    }

    internal static void Seal(string evidenceFilePath, string sealFilePath, CancellationToken cancellationToken, FileSealWork? work)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sealFilePath);

        try
        {
            var contents = new BundleSealContents(Algorithm, HashFile(evidenceFilePath, cancellationToken, work));
            cancellationToken.ThrowIfCancellationRequested();
            work?.Begin(FileSealPart.EncodeSeal);
            var json = JsonSerializer.Serialize(contents, ProofSerialization.Options);
            work?.End();
            work?.Begin(FileSealPart.WriteSeal);
            File.WriteAllText(sealFilePath, json);
            work?.End();
        }
        catch
        {
            work?.RecordInterruptedPart();
            throw;
        }
    }

    /// <summary>
    /// Verifies the seal on a bundle directory.
    /// </summary>
    /// <remarks>
    /// Every path out of here names one of the four states. There is no path that returns
    /// "probably fine", and none that treats a failure to read as a failure to find.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static SealVerdict Verify(string bundleDirectory) => Verify(bundleDirectory, CancellationToken.None);

    /// <summary>Verifies evidence with cancellation between file reads.</summary>
    public static SealVerdict Verify(string bundleDirectory, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        return Verify(
            BundleLayout.EvidencePath(bundleDirectory),
            BundleLayout.SealPath(bundleDirectory),
            "evidence file",
            "Every bundle this product writes is sealed before its evidence file is given the name "
            + "a reader asks for, so a bundle with no seal was assembled by something other than a "
            + "capture.",
            "It does not prove the capture was complete, which is a claim the bundle makes in its "
            + "own tables.", cancellationToken);
    }

    internal static SealVerdict VerifySegment(string dataPath, string sealPath, string artifact, CancellationToken token) =>
        Verify(dataPath, sealPath, artifact, "A selected immutable product must have its matching seal.",
            "The seal does not establish capture or analysis completeness.", token);

    /// <summary>
    /// Verifies the seal on a bundle's judgement store.
    /// </summary>
    /// <remarks>
    /// <b>This is a different question from <see cref="Verify(string)"/> and the two can disagree.</b>
    /// They cover different artefacts made at different times: the evidence is sealed when capture
    /// ends, the judgement when judging ends, and a bundle may hold intact evidence beside a
    /// judgement that does not verify. Anything showing both to an operator has to say which is
    /// which.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static SealVerdict VerifyJudgement(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var resolved = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Judgement);
        if (!resolved.IsSuccess)
            return new SealVerdict(SealState.Absent, resolved.Error!.Description);

        return VerifyAnalysisGeneration(
            bundleDirectory,
            resolved.Value!,
            "judgement store",
            "It does not prove every scheduled rule reached a verdict, which is a claim the store "
            + "makes in its own tables.");
    }

    /// <summary>
    /// Verifies the seal on a bundle's derived facts.
    /// </summary>
    /// <remarks>
    /// A third question, independent of <see cref="Verify(string)"/> and
    /// <see cref="VerifyJudgement(string)"/>. A bundle may hold intact evidence, a judgement that
    /// verifies, and derived facts that do not - or derived facts alone, because deriving and
    /// judging are separate acts and a bundle may have had one without the other.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static SealVerdict VerifyDerivation(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        var resolved = AnalysisStoreLifecycle.Resolve(bundleDirectory, AnalysisStoreKind.Derivation);
        if (!resolved.IsSuccess)
            return new SealVerdict(SealState.Absent, resolved.Error!.Description);

        return VerifyAnalysisGeneration(
            bundleDirectory,
            resolved.Value!,
            "derived facts",
            "It does not prove every closure is complete, which is a claim the store makes in its own tables.");
    }

    /// <summary>Verifies one immutable analysis generation against its matching seal.</summary>
    /// <param name="bundleDirectory">The directory containing the generation.</param>
    /// <param name="generation">The database and seal paths selected by a manifest.</param>
    /// <param name="artefact">The operator-facing name of the store.</param>
    /// <param name="intactCaveat">What an intact seal does not establish.</param>
    public static SealVerdict VerifyAnalysisGeneration(
        string bundleDirectory,
        AnalysisStoreGeneration generation,
        string artefact,
        string intactCaveat) => VerifyAnalysisGeneration(bundleDirectory, generation, artefact, intactCaveat, CancellationToken.None);

    /// <summary>Verifies an analysis generation with cancellation between file reads.</summary>
    public static SealVerdict VerifyAnalysisGeneration(string bundleDirectory, AnalysisStoreGeneration generation,
        string artefact, string intactCaveat, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        ArgumentNullException.ThrowIfNull(generation);
        ArgumentException.ThrowIfNullOrWhiteSpace(artefact);
        ArgumentException.ThrowIfNullOrWhiteSpace(intactCaveat);

        if (generation.Kind == AnalysisStoreKind.Judgement)
        {
            var selected = AnalysisStoreLifecycle.ResolveRoot(bundleDirectory, generation.Kind);
            if (!selected.IsSuccess) return new(SealState.Unreadable, selected.Error.Description);
            if (selected.Value.GenerationId != generation.GenerationId)
                return new(SealState.Mismatch, "The judgement generation changed before its complete verification.");
            var files = new List<ProtectedStoreFile>();
            try
            {
                foreach (var segment in selected.Value.Segments)
                {
                    var opened = ProtectedStoreFile.OpenAnalysisSegment(bundleDirectory, generation, segment.Role, cancellationToken);
                    if (!opened.IsSuccess)
                    {
                        var state = opened.Error.Code switch
                        {
                            "Evidence.ProtectedStoreAbsent" => SealState.Absent,
                            "Evidence.ProtectedStoreMismatch" => SealState.Mismatch,
                            _ => SealState.Unreadable,
                        };
                        return new(state, opened.Error.Description);
                    }
                    files.Add(opened.Value);
                    if (opened.Value.Root.Hash != selected.Value.Hash)
                        return new(SealState.Mismatch, "The judgement root changed during its complete verification.");
                }
                return new(SealState.Intact, $"The {artefact} matches its seal ({Algorithm}). This proves the bytes are "
                    + "unchanged since it was written. " + intactCaveat);
            }
            finally { foreach (var file in files) file.Dispose(); }
        }

        return Verify(
            BundleLayout.AnalysisGenerationDataPath(
                bundleDirectory, generation.Kind, generation.GenerationId),
            BundleLayout.AnalysisGenerationSealPath(
                bundleDirectory, generation.Kind, generation.GenerationId),
            artefact,
            "A manifest-selected generation must always have its matching seal.",
            intactCaveat, cancellationToken);
    }

    /// <summary>
    /// What a seal file records, or null if it is absent or does not parse.
    /// </summary>
    /// <remarks>
    /// Exposed so a judgement can name the capture it was made against. It returns null for two
    /// different reasons and a caller that needs to tell them apart wants
    /// <see cref="Verify(string)"/> instead - this is for the caller that already knows the seal is
    /// intact and wants the value out of it.
    /// </remarks>
    /// <param name="sealFilePath">The seal file.</param>
    public static BundleSealContents? ReadSeal(string sealFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sealFilePath);

        if (!File.Exists(sealFilePath))
            return null;

        try
        {
            return JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(sealFilePath), ProofSerialization.Options);
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static SealVerdict Verify(
        string dataPath, string sealPath, string artefact, string absentCaveat, string intactCaveat,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(sealPath))
        {
            return new SealVerdict(
                SealState.Absent,
                $"No seal file at '{sealPath}'. " + absentCaveat);
        }

        if (!File.Exists(dataPath))
        {
            return new SealVerdict(
                SealState.Mismatch,
                $"A seal is present at '{sealPath}' and there is no {artefact} at "
                + $"'{dataPath}' for it to cover.");
        }

        BundleSealContents? contents;
        try
        {
            contents = JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(sealPath), ProofSerialization.Options);
        }
        catch (Exception error) when (error is JsonException or IOException or UnauthorizedAccessException)
        {
            return new SealVerdict(
                SealState.Unreadable,
                $"The seal at '{sealPath}' could not be read: {error.Message}. This is not the "
                + "same as an absent seal - something happened to it.");
        }

        if (contents is null || string.IsNullOrWhiteSpace(contents.Hash))
        {
            return new SealVerdict(
                SealState.Unreadable,
                $"The seal at '{sealPath}' parsed but records no hash. This is not the same as an "
                + "absent seal - something happened to it.");
        }

        if (!string.Equals(contents.Algorithm, Algorithm, StringComparison.Ordinal))
        {
            return new SealVerdict(
                SealState.Unreadable,
                $"The seal at '{sealPath}' names algorithm '{contents.Algorithm}', which this "
                + $"build cannot compute. It expects '{Algorithm}'. The seal is not being read as "
                + "absent, and not as a mismatch either, because nothing was compared.");
        }

        string actual;
        try
        {
            Verifications.Add(1, new KeyValuePair<string, object?>("file", Path.GetFullPath(dataPath)));
            actual = HashFile(dataPath, cancellationToken);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            return new SealVerdict(
                SealState.Unreadable,
                $"The {artefact} at '{dataPath}' could not be hashed: {error.Message}. The seal "
                + "cannot be called intact or mismatched because no comparison was completed.");
        }

        return string.Equals(actual, contents.Hash, StringComparison.Ordinal)
            ? new SealVerdict(
                SealState.Intact,
                $"The {artefact} matches its seal ({Algorithm}). This proves the bytes are "
                + "unchanged since it was written. " + intactCaveat)
            : new SealVerdict(
                SealState.Mismatch,
                $"The {artefact} at '{dataPath}' does not match its seal. The seal records "
                + $"{contents.Hash} and the file hashes to {actual}.");
    }
}
