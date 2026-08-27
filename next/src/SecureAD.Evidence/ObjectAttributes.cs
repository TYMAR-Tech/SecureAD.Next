using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Capture;

namespace SecureAD.Evidence;

/// <summary>
/// One value of one attribute, as the bundle stored it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing here is worded.</b> A <c>userAccountControl</c> of <c>514</c> arrives as the four
/// characters the directory sent, and whatever turns that into <i>Disabled</i> does so somewhere
/// a reader can see both. The stored form is kept beside the worded one on screen for the same
/// reason the mask is kept beside its wording: a wording this build gets wrong is invisible
/// otherwise.
/// </para>
/// <para>
/// Text and bytes are kept apart all the way out, as <see cref="EvidenceValue"/> keeps them apart
/// on the way in. <see cref="Stored"/> is the one place bytes become characters, and it says so by
/// being hexadecimal rather than something that could be mistaken for a value the directory holds.
/// </para>
/// </remarks>
/// <param name="Ordinal">
/// Where the value sits in the order the controller sent it, counting from zero. Always zero for a
/// single-valued attribute.
/// </param>
/// <param name="Text">The value as text, or null when this is a byte value.</param>
/// <param name="Bytes">The value as bytes, or null when this is a text value.</param>
public sealed record AttributeValue(int Ordinal, string? Text, byte[]? Bytes)
{
    /// <summary>
    /// The value as it is stored: the text itself, or the bytes in hexadecimal.
    /// </summary>
    public string Stored => Text ?? Convert.ToHexString(Bytes ?? []);
}

/// <summary>
/// One attribute of one object: what the catalogue asked for, and what the bundle holds for it.
/// </summary>
/// <remarks>
/// <b>An attribute with no values is not an attribute that was not asked for.</b> Capture requests
/// every catalogued attribute of every object whatever its class, so this exists for every
/// catalogued attribute whether or not a value arrived - and an empty <see cref="Values"/> means
/// the object has no value or the reader was refused it, which the directory does not tell apart.
/// See <c>docs/decisions/0022</c>.
/// </remarks>
/// <param name="LdapDisplayName">The attribute, under the name the catalogue asked for.</param>
/// <param name="Cardinality">Whether the directory allows this attribute more than one value.</param>
/// <param name="Values">The values, in the order the controller sent them. Possibly none.</param>
public sealed record ObjectAttribute(
    string LdapDisplayName,
    AttributeCardinality Cardinality,
    IReadOnlyList<AttributeValue> Values)
{
    /// <summary>Whether the bundle holds any value at all for this attribute.</summary>
    public bool HasValue => Values.Count > 0;

    /// <summary>
    /// The one value, for an attribute that has one, or null when none arrived.
    /// </summary>
    /// <remarks>
    /// Defined for a multi-valued attribute too, where it is the first of them. A caller that
    /// wants the first of many should say so by reading <see cref="Values"/>.
    /// </remarks>
    public AttributeValue? OnlyValue => Values.Count > 0 ? Values[0] : null;
}

/// <summary>
/// Every attribute value this bundle holds for one object.
/// </summary>
/// <remarks>
/// <b>The whole catalogue, not the part that arrived.</b> Handing back only the attributes with
/// values would make a section have to guess why it has nothing to show, and would leave
/// <i>we were refused this</i> looking the same as <i>this build never asked</i>.
/// </remarks>
/// <param name="DistinguishedName">The object, as the controller named it.</param>
/// <param name="CapturedUtc">
/// When the run read this object. Carried because a timestamp is only meaningful beside it: a
/// password last set six days before a capture is a fact about that forest and stays one, where
/// the same value measured against a reader's own clock says something different every morning.
/// </param>
/// <param name="Completeness">
/// Whether the connection this object was read over could have been served confidential attributes
/// at all.
/// <para>
/// <b>It does not say every attribute is here</b>, and the member is not named as though it does.
/// Nothing read from a directory can say that: a controller omits a value the caller may not read
/// in exactly the way it omits one that was never set, so a claim of completeness would be a claim
/// about a distinction the protocol does not provide (<c>docs/decisions/0022</c>). This says the
/// narrower thing that is observable, and it is the same statement
/// <see cref="EvidenceObject.Completeness"/> makes about the same object on the way in.
/// </para>
/// </param>
/// <param name="ObjectGuid">
/// Which object this is, immutably.
/// <para>
/// Typed here rather than left to be parsed out of the <c>objectGUID</c> attribute, because this is
/// what a finding's identity rests on and what two bundles are joined on. It survives both rename
/// and move, which the distinguished name does not. Null is possible and meaningful: an object the
/// controller returned without one cannot be identified across runs at all, so nothing may be
/// attached to it that has to outlive this bundle.
/// </para>
/// </param>
/// <summary>
/// Every object a bundle holds, beside whether the run that captured them read everything it set
/// out to.
/// </summary>
/// <remarks>
/// <para>
/// <b>The flag is why this is a type rather than a sequence.</b> A caller that walked every object
/// in a bundle has walked every object <i>that was captured</i>, which is a different claim from
/// having walked the forest. A run that reached one domain of nine seals a perfectly valid bundle,
/// and conclusions drawn from it are a floor rather than a total. Handing back a bare sequence
/// would let a caller walk it, find nothing wrong, and say so.
/// </para>
/// <para>
/// <b><see cref="IsComplete"/> is capture's claim, not a reader's.</b> It says every unit the run
/// declared was recorded as read. It does not say the forest holds nothing else, and it says
/// nothing about whether individual attributes were withheld - that is per object, and each one
/// carries its own answer.
/// </para>
/// </remarks>
/// <param name="IsComplete">Whether the run recorded every declared unit as read.</param>
/// <param name="Objects">The objects, streamed in stored order.</param>
public sealed record BundleObjects(bool IsComplete, IEnumerable<ObjectAttributes> Objects);

/// <param name="Attributes">
/// Every attribute the catalogue names, in the order the catalogue names them.
/// </param>
/// <param name="DomainFqdn">
/// The domain this object was captured from, or null where the bundle did not record one.
/// </param>
/// <remarks>
/// <b><paramref name="DomainFqdn"/> is part of a principal's identity, not decoration.</b> A SID is
/// unique within its scope rather than within a forest: <c>S-1-5-32-544</c> is
/// <c>BUILTIN\Administrators</c> in every domain, and those are different groups holding different
/// members. A derivation that keys principals by SID alone merges them. See
/// <c>docs/decisions/0087-a-sid-is-unique-within-its-scope.md</c>.
/// </remarks>
public sealed record ObjectAttributes(
    string DistinguishedName,
    Guid? ObjectGuid,
    DateTimeOffset CapturedUtc,
    EvidenceCompleteness Completeness,
    IReadOnlyList<ObjectAttribute> Attributes,
    string? DomainFqdn)
{
    /// <summary>
    /// The attribute <paramref name="ldapDisplayName"/> names, or null when the catalogue does not
    /// name it - which is a fact about this build and not about the object.
    /// </summary>
    /// <param name="ldapDisplayName">The attribute, as the catalogue names it.</param>
    public ObjectAttribute? Find(string ldapDisplayName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ldapDisplayName);

        return Attributes.FirstOrDefault(
            a => string.Equals(a.LdapDisplayName, ldapDisplayName, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Reads the attribute values a bundle holds for one object.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every table this reads is named by the catalogue, never by a caller.</b> The column and table
/// names are derived through <see cref="BundleSchema.ColumnNameFor"/> from the same list the
/// schema was written from, so there is no identifier here that a caller could choose and nothing
/// to interpolate but names this build owns. The distinguished name, which does come from outside,
/// is a parameter.
/// </para>
/// <para>
/// One query for the single-valued attributes and one per multi-valued table. The alternative - a
/// single union over every value table - would be one round trip instead of a dozen against a
/// local file that is already in the page cache, and would put every attribute's values through
/// one column of one type, which is exactly the text-and-bytes confusion the schema keeps apart.
/// </para>
/// </remarks>
internal static class ObjectAttributesReader
{
    public static ObjectAttributes? Read(SqliteConnection connection, string distinguishedName)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        var stored = SingleValuedOf(connection, distinguishedName);
        if (stored is null)
            return null;

        var (objectId, dn, objectGuid, captured, completeness, attributes) = stored.Value;

        foreach (var attribute in BundleSchema.MultiValuedTables)
        {
            attributes.Add(new ObjectAttribute(
                attribute.LdapDisplayName,
                AttributeCardinality.MultiValued,
                StoredValuesFor(connection, attribute, objectId)));
        }

        return new ObjectAttributes(
            dn,
            objectGuid,
            captured,
            completeness,
            [.. attributes.OrderBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)],
            // This reads one object by name for a screen to show. Nothing here keys a principal, so
            // the domain is not fetched rather than being fetched and ignored - and it is stated
            // here so a caller that later needs it changes this deliberately.
            DomainFqdn: null);
    }

    /// <summary>
    /// The object's row, turned into one attribute per column - including the two the schema
    /// stores under a name of its own.
    /// </summary>
    /// <remarks>
    /// <b>The coverage row is joined rather than looked up separately.</b> An object and the rung
    /// it was read over are one fact, and fetching them in two queries would allow a caller to hold
    /// an object beside somebody else's coverage. <c>connection_security</c> is selected after the
    /// attribute columns so that adding a catalogued attribute does not move it.
    /// </remarks>
    private static (long ObjectId, string Dn, Guid? ObjectGuid, DateTimeOffset Captured, EvidenceCompleteness Completeness, List<ObjectAttribute> Attributes)? SingleValuedOf(
        SqliteConnection connection, string distinguishedName)
    {
        var columns = BundleSchema.SingleValuedColumns;

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT o.object_id, o.distinguished_name, o.object_guid, o.captured_utc"
            + string.Concat(
                columns.Select(a => ", o." + BundleSchema.ColumnNameFor(a.LdapDisplayName)))
            + ", c.connection_security"
            + " FROM captured_object AS o"
            + " JOIN partition_coverage AS c ON c.coverage_id = o.coverage_id"
            + " WHERE o.distinguished_name = $dn COLLATE NOCASE LIMIT 1";
        command.Parameters.AddWithValue("$dn", distinguishedName);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;

        var objectId = reader.GetInt64(0);
        var dn = reader.GetString(1);
        var storedGuid = reader.IsDBNull(2) ? null : reader.GetString(2);
        var captured = DateTimeOffset.Parse(
            reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture);

        var attributes = new List<ObjectAttribute>
        {
            Structural("distinguishedName", dn),
            Structural("objectGUID", storedGuid),
        };

        for (var i = 0; i < columns.Count; i++)
        {
            var attribute = columns[i];
            var ordinal = i + 4;

            attributes.Add(new ObjectAttribute(
                attribute.LdapDisplayName,
                AttributeCardinality.SingleValued,
                reader.IsDBNull(ordinal) ? [] : [ValueAt(reader, ordinal, attribute.Storage, 0)]));
        }

        var completeness = ReadCoverage.Over(
            Enum.Parse<ConnectionSecurityLevel>(reader.GetString(4 + columns.Count)));

        return (
            objectId,
            dn,
            storedGuid is null ? null : Guid.Parse(storedGuid),
            captured,
            completeness,
            attributes);
    }

    /// <summary>
    /// An attribute the schema holds as identity rather than as a derived column.
    /// </summary>
    /// <remarks>
    /// Both are text here whatever the catalogue says their storage is: <c>objectGUID</c> is
    /// stored in its canonical spelling rather than as bytes, because it is what two bundles are
    /// joined on. Handing back the canonical form is handing back what the bundle stored.
    /// </remarks>
    private static ObjectAttribute Structural(string ldapDisplayName, string? text) =>
        new(
            ldapDisplayName,
            AttributeCardinality.SingleValued,
            text is null ? [] : [new AttributeValue(0, text, null)]);

    private static List<AttributeValue> StoredValuesFor(
        SqliteConnection connection, CapturedAttribute attribute, long objectId)
    {
        var values = new List<AttributeValue>();

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT ordinal, value FROM "
            + BundleSchema.ValueTableNameFor(attribute.LdapDisplayName)
            + " WHERE object_id = $object ORDER BY ordinal";
        command.Parameters.AddWithValue("$object", objectId);

        using var reader = command.ExecuteReader();
        while (reader.Read())
            values.Add(ValueAt(reader, 1, attribute.Storage, reader.GetInt32(0)));

        return values;
    }

    internal static AttributeValue ValueAt(
        SqliteDataReader reader, int ordinal, AttributeStorage storage, int valueOrdinal) =>
        storage == AttributeStorage.Binary
            ? new AttributeValue(valueOrdinal, null, reader.GetFieldValue<byte[]>(ordinal))
            : new AttributeValue(valueOrdinal, reader.GetString(ordinal), null);
}
