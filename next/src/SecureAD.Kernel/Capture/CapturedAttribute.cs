namespace SecureAD.Kernel.Capture;

/// <summary>
/// One attribute the product asks a domain controller for.
/// </summary>
/// <remarks>
/// <para>
/// Everything the product can ever say about a forest is bounded by this list. An attribute that is
/// not requested is not in the bundle, is in no report, and cannot be added afterwards without
/// capturing the forest again - and nobody can go back and re-read last quarter. So the entry
/// carries only what a reader of the values needs, and <b>who reads it</b> lives in
/// docs/layers/audit/the-attribute-catalogue.md beside the reason, bound by
/// <c>CapturedAttributeCatalogDocumentationTests</c>.
/// </para>
/// <para>
/// <b>Absence is not a fact about the forest.</b> An attribute marked confidential in the schema is
/// withheld from a caller who lacks <c>CONTROL_ACCESS</c> on it, and it is withheld silently - the
/// value is simply not in the entry, exactly as though it had never been set
/// (<see href="https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential">Mark
/// an attribute as confidential</see>,
/// <see href="https://learn.microsoft.com/windows/win32/adschema/a-searchflags">Search-Flags</see>
/// bit 128). <c>docs/decisions/0002</c> requires those two to be told apart, so the catalogue does
/// not guess which attributes could be withheld: capture reads <c>searchFlags</c> and
/// <c>systemFlags</c> from that forest's own schema and answers it per forest. The distinction is
/// real - bit 128 is ignored for base-schema attributes, which are the ones carrying
/// <c>systemFlags</c> 0x10 - so the answer is derivable rather than assumed.
/// </para>
/// </remarks>
/// <param name="LdapDisplayName">
/// The name the attribute is requested by, spelled as the schema spells it. Requests are
/// case-insensitive; the spelling is for a human reading the request.
/// </param>
/// <param name="Cardinality">
/// Whether the attribute is range-liable. See <see cref="AttributeCardinality"/>.
/// </param>
/// <param name="Storage">Whether the value is text or bytes. See <see cref="AttributeStorage"/>.</param>
public sealed record CapturedAttribute(
    string LdapDisplayName,
    AttributeCardinality Cardinality,
    AttributeStorage Storage);
