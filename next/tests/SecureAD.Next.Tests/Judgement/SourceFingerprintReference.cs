using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

internal static class SourceFingerprintReference
{
    // Reassemble the complete format-52 source first, then independently partition its fields.
    internal static string FromLegacy(PathSourceFamily family, JudgementDescription description, PathInputs inputs, object source)
    {
        // JsonElement would re-escape typed timestamp '+' bytes; preserve the original CLR values.
        object? Field(string name) => (source.GetType().GetProperty(name)
            ?? throw new MissingMemberException(source.GetType().FullName, name)).GetValue(source);
        object shared = family == PathSourceFamily.OwnAccountMembership ? new
        {
            Roots = Field("Roots"), Schema = Field("Schema"),
            Catalogue = Field("Catalogue"), Contexts = Field("Contexts"), Forest = Field("Forest"),
        } : new { Forest = Field("Forest"), Contexts = Field("Contexts") };
        var common = Hash(new
        {
            Version = 1, Family = family.ToString(), Generation = description.GenerationId, Derivation = description.DerivationGenerationId,
            Evidence = description.EvidenceSeal, Inputs = inputs.Input, inputs.Availability, Shared = shared,
        });
        var target = Hash(new
        {
            Target = Field("Target"), Permissions = Field("Permissions"), Holders = Field("Holders"),
        });
        var requester = Hash(Field("Requester"));
        if (family == PathSourceFamily.OwnAccountMembership)
            return Hash(new { Version = 1, Shared = common, Target = target, Requester = requester });
        var obtained = Field("ObtainedMembership");
        return Hash(new
        {
            Version = 1, Shared = common, Target = target, Requester = requester,
            ObtainedMembership = obtained is null ? null : Hash(obtained),
            Membership = Field("Membership"), ObtainedGroupMembership = Field("ObtainedGroupMembership"),
            ResourceContext = Field("ResourceContext"),
        });
    }

    private static string Hash<T>(T value) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value, ProofSerialization.Options))));
}
