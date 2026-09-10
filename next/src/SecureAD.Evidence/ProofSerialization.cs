using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureAD.Evidence;

/// <summary>
/// The one serialisation shape for anything a store keeps as a proof, so what is written and what
/// is read back are the same by construction.
/// </summary>
/// <remarks>
/// <para>
/// <b>Enum names, never ordinals, and this is the whole point.</b> <c>System.Text.Json</c> writes
/// an enum as its numeric value by default, so <c>MembershipEvidenceIncomplete</c> is stored as
/// <c>2</c> - a number that means what it means only because of the order somebody typed the
/// members in. Reordering an enum, or removing a member from the middle of one, then changes the
/// meaning of data already written without changing a line of the code that reads it.
/// </para>
/// <para>
/// <b>A <c>[Flags]</c> enum makes that sharper than a wrong comparison.</b> Inserting a member
/// into <see cref="Findings.MembershipRouteIncompleteReason"/> does not shift later values by one;
/// it renumbers their bits. A stored route recording <i>membership evidence was incomplete</i>
/// would read back as a different limitation entirely - parsing cleanly, reporting confidently,
/// and being wrong. That is the failure this repository puts first: a check that passes while
/// measuring something other than what it claims.
/// </para>
/// <para>
/// <b>Written and read with the same options, deliberately.</b> Two stores previously kept
/// <c>ReadOptions</c> used on the way in and nothing on the way out, which happens to work while
/// the two defaults agree and stops working silently the moment they do not. One instance used by
/// both directions cannot drift.
/// </para>
/// <para>
/// <b>This is not a general-purpose serialiser.</b> It is for stored proofs: values hashed into a
/// fingerprint, or written to a store and rehydrated later. Display, settings files and log output
/// have no such requirement and should not reach for it.
/// </para>
/// </remarks>
public static class ProofSerialization
{
    /// <summary>The options every stored-proof read and write uses.</summary>
    public static JsonSerializerOptions Options { get; } = new()
    {
        Converters = { new JsonStringEnumConverter() },
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
    };
}
