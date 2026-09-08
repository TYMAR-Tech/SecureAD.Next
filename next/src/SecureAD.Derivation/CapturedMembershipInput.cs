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
        if (source.Find("objectSid")?.HasValue != true
            && classes?.Any(value => value.Text is "group" or "user" or "computer" or "foreignSecurityPrincipal") != true
            && source.Find("member")?.HasValue != true && source.Find("memberOf")?.HasValue != true)
            return null;
        return source with
        {
            Attributes = source.Attributes.Where(attribute => AttributeNames.Contains(attribute.LdapDisplayName,
                StringComparer.OrdinalIgnoreCase)).ToArray(),
        };
    }
}
