using System.Security.Cryptography;
using System.Text.Json;

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
    /// <summary>The algorithm named in every seal this product writes.</summary>
    public const string Algorithm = "SHA-256";

    /// <summary>
    /// Hashes a file, lowercase hexadecimal.
    /// </summary>
    /// <param name="filePath">The file to hash.</param>
    public static string HashFile(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        using var stream = File.OpenRead(filePath);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    /// <summary>
    /// Writes a seal covering <paramref name="evidenceFilePath"/> to <paramref name="sealFilePath"/>.
    /// </summary>
    /// <param name="evidenceFilePath">The evidence file being sealed.</param>
    /// <param name="sealFilePath">Where the seal is written.</param>
    public static void Seal(string evidenceFilePath, string sealFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(evidenceFilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sealFilePath);

        var contents = new BundleSealContents(Algorithm, HashFile(evidenceFilePath));
        File.WriteAllText(sealFilePath, JsonSerializer.Serialize(contents));
    }

    /// <summary>
    /// Verifies the seal on a bundle directory.
    /// </summary>
    /// <remarks>
    /// Every path out of here names one of the four states. There is no path that returns
    /// "probably fine", and none that treats a failure to read as a failure to find.
    /// </remarks>
    /// <param name="bundleDirectory">The bundle's directory.</param>
    public static SealVerdict Verify(string bundleDirectory)
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
            + "own tables.");
    }

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

        return Verify(
            BundleLayout.JudgementPath(bundleDirectory),
            BundleLayout.JudgementSealPath(bundleDirectory),
            "judgement store",
            "A judgement is sealed before it is given the name a reader asks for, so a store with "
            + "no seal was assembled by something other than a judging run.",
            "It does not prove every scheduled rule reached a verdict, which is a claim the store "
            + "makes in its own tables.");
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
            return JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(sealFilePath));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static SealVerdict Verify(
        string dataPath, string sealPath, string artefact, string absentCaveat, string intactCaveat)
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
            contents = JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(sealPath));
        }
        catch (JsonException error)
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

        var actual = HashFile(dataPath);

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
