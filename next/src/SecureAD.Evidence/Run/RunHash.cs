using System.Security.Cryptography;
using System.Text;

namespace SecureAD.Evidence.Run;

/// <summary>
/// The one way a run identity turns its inputs into a value.
/// </summary>
/// <remarks>
/// <para>
/// Internal, and shared by <see cref="ProfileId"/> and <see cref="CoverageId"/> so that the width
/// and alphabet of an identity cannot drift between the two. They appear side by side in folder
/// names and in the run library, and two identities of different shapes would look like a defect
/// to an operator long before anyone noticed it was one.
/// </para>
/// <para>
/// Truncated to eight bytes deliberately. This is a grouping key, not a security control: it
/// decides which runs are shown together, and nothing rests on the difficulty of contriving a
/// collision. It is stated here so that nobody later reads a SHA-256 in the source and infers a
/// guarantee that was never claimed - the mistake <c>0020</c> exists to undo one layer up, where
/// the seal was described as detecting tampering.
/// </para>
/// </remarks>
internal static class RunHash
{
    /// <summary>Hashes <paramref name="input"/> to sixteen lowercase hex characters.</summary>
    /// <param name="input">
    /// The already-normalised text to hash. Normalisation is each identity's own business,
    /// because what counts as the same input differs between them.
    /// </param>
    internal static string Of(string input)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
    }
}
