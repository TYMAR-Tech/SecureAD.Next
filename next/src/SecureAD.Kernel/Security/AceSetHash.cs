using System.Security.Cryptography;
using System.Text;

namespace SecureAD.Kernel.Security;

/// <summary>
/// The hash of a whole set of access control entries, as one value.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it is for.</b> Comparing two runs of the same forest. Asking whether an object's
/// permissions changed by reading every entry of every object is the query that makes comparison
/// too slow to use, and comparison is the only verification path this product has since live
/// verification was removed. One value per object turns that question into an equality test.
/// </para>
/// <para>
/// It is required by <c>docs/decisions/0015</c>, which also says why it is being taken on now
/// rather than later: it is cheap while the schema is being designed and expensive afterwards.
/// </para>
/// <para>
/// <b>Determinism.</b> The entries are hashed in the order given, which is safe because the order
/// given is already canonical - <see cref="AceNormalizer"/> orders by content, so two descriptors
/// with the same entries produce the same sequence regardless of the order the directory returned
/// them in. Hashing the sequence rather than a sorted copy is therefore equally deterministic and
/// keeps ordering inside the answer, which matters because deny entries sorting before allow
/// entries is not decoration.
/// </para>
/// <para>
/// <b>An empty set has a hash.</b> It is not an empty string and not null, so a reader never has
/// to decide what a missing value means. Whether an empty set means <i>this object grants
/// nothing</i> or <i>this object grants everyone everything</i> is not this value's question -
/// that is what the DACL state beside it answers.
/// </para>
/// </remarks>
public static class AceSetHash
{
    /// <summary>
    /// The hash of a set of canonical entries, lowercase hexadecimal.
    /// </summary>
    /// <param name="aces">The entries, in canonical order.</param>
    public static string Compute(IReadOnlyList<CanonicalAce> aces)
    {
        ArgumentNullException.ThrowIfNull(aces);

        // The version is inside the hash so that two values produced by different canonicalisation
        // pipelines can never compare equal by coincidence. A comparison that reported "unchanged"
        // across a pipeline change would be the product saying something false.
        var builder = new StringBuilder()
            .Append(AceCanonicalization.Version)
            .Append('\u001f');

        foreach (var ace in aces)
            builder.Append(ace.AceHash).Append('\u001f');

        return Convert
            .ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())))
            .ToLowerInvariant();
    }
}
