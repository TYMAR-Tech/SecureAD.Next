using SecureAD.Evidence;

namespace SecureAD.Derivation;

/// <summary>Source-linked membership inputs from one sealed capture and selected derivation.</summary>
/// <param name="DerivationGenerationId">The immutable derivation that collected these sources.</param>
/// <param name="IsComplete">Whether all declared capture units were read; not an attribute-visibility guarantee.</param>
/// <param name="Objects">Captured principal identities and membership attributes, including unresolved DN values.</param>
public sealed record CapturedMembershipInput(
    Guid DerivationGenerationId,
    bool IsComplete,
    IReadOnlyList<ObjectAttributes> Objects)
{
    internal static readonly string[] AttributeNames =
    [
        "objectSid", "objectClass", "groupType", "primaryGroupID", "member", "memberOf",
        "sIDHistory", "userAccountControl", "isDeleted", "sAMAccountName",
    ];

    internal static ObjectAttributes? Project(ObjectAttributes source)
    {
        var classes = source.Find("objectClass")?.Values;

        // Naming-context heads are retained even though they are not principals. A partition root
        // holds no SID and no membership, so every other test here rejects it, but decision 0117
        // makes it a Tier-0 seed in its own right and the classifier cannot qualify what the index
        // does not contain. Its objectClass is the qualifying witness and is already projected.
        if (classes?.Any(value => value.Text is "domainDNS" or "configuration" or "dMD") == true) return Projected(source);
        if (source.Find("objectSid")?.HasValue != true
            && classes?.Any(value => value.Text is "group" or "user" or "computer" or "foreignSecurityPrincipal") != true
            && source.Find("member")?.HasValue != true && source.Find("memberOf")?.HasValue != true)
            return null;
        return Projected(source);
    }

    private static ObjectAttributes Projected(ObjectAttributes source) => source with
    {
        Attributes = source.Attributes.Where(attribute => AttributeNames.Contains(attribute.LdapDisplayName,
            StringComparer.OrdinalIgnoreCase)).ToArray(),
    };
}
