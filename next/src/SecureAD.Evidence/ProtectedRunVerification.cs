namespace SecureAD.Evidence;

/// <summary>How one product's whole-file check ended.</summary>
public enum ProtectedFileCheckOutcome
{
    /// <summary>This pass verified the file's bytes.</summary>
    Verified,

    /// <summary>The file was already verified (carried over from capture, or checked by an earlier request), so this pass cost nothing.</summary>
    AlreadyVerified,

    /// <summary>The file did not verify, or could not be read.</summary>
    Failed,
}

/// <summary>What opening one product of a saved run cost.</summary>
/// <param name="Role">Which product.</param>
/// <param name="FileName">The product's file, relative to the run's folder.</param>
/// <param name="Bytes">The size of the file.</param>
/// <param name="Hashed">How long this pass spent verifying its bytes, or null when it verified nothing because the file was already verified.</param>
/// <param name="Started">When the pass began waiting for this product, measured from the pass's start.</param>
/// <param name="Finished">When the product's outcome was known, measured from the pass's start.</param>
/// <param name="Outcome">How the check ended.</param>
/// <param name="Failure">Why it failed, when it did.</param>
public sealed record ProtectedFileCheck(StoreSegmentRole Role, string FileName, long Bytes, TimeSpan? Hashed,
    TimeSpan Started, TimeSpan Finished, ProtectedFileCheckOutcome Outcome, string? Failure);

/// <summary>What opening a whole saved run cost, in total.</summary>
/// <param name="Files">How many products the run has.</param>
/// <param name="Verified">How many this pass verified.</param>
/// <param name="Unverified">How many did not verify, because they were damaged or could not be read.</param>
/// <param name="Bytes">The bytes of every product.</param>
/// <param name="Elapsed">Wall-clock time for the whole pass; the checks overlap, so this is far less than their sum.</param>
/// <param name="Hashed">The sum of the time this pass spent verifying the files it verified.</param>
/// <param name="Problems">Roots that could not be selected, which no check could report.</param>
public sealed record ProtectedRunVerification(int Files, int Verified, int Unverified, long Bytes, TimeSpan Elapsed,
    TimeSpan Hashed, IReadOnlyList<string> Problems);
