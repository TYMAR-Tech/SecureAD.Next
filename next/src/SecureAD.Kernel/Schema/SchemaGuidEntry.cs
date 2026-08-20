namespace SecureAD.Kernel.Schema;

/// <summary>
/// One row of the schema-GUID catalogue: an opaque directory GUID and what it is called.
/// </summary>
/// <remarks>
/// The entry carries identity and provenance, and nothing else. Whether the right this GUID names
/// is dangerous is not recorded here: that is a judgement the product makes about a permission, it
/// depends on the access mask and the ACE type as well as the GUID, and it belongs to the
/// classifier rather than to the table. No friendly display label is recorded either - not because
/// a label is unwanted, but because the directory holds the authoritative one and capture reads it,
/// per <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c>.
/// </remarks>
/// <param name="Guid">The <c>rightsGuid</c> or <c>schemaIDGUID</c>, lowercase and without braces.</param>
/// <param name="LdapName">The name Microsoft's AD schema gives it, such as <c>userAccountControl</c>.</param>
/// <param name="Kind">What this GUID names.</param>
/// <param name="Source">Whether this name was shipped with the product or read from a forest.</param>
public sealed record SchemaGuidEntry(
    string Guid,
    string LdapName,
    SchemaGuidKind Kind,
    SchemaGuidSource Source);
