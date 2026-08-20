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
/// <param name="AttributesAreComplete">
public sealed record ObjectAttributes(
    string DistinguishedName,
    DateTimeOffset CapturedUtc,
    bool AttributesAreComplete,
    IReadOnlyList<ObjectAttribute> Attributes)
{
/// Whether every attribute the catalogue names is here. False would mean a section finding nothing
/// is looking at a list this build shortened, which reads identically to an object that holds no
/// value - so the statement is carried rather than assumed.
/// </param>
/// <param name="Attributes">
/// Every attribute the catalogue names, in the order the catalogue names them.
/// </param>
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

        var (objectId, dn, captured, attributes) = stored.Value;

        foreach (var attribute in BundleSchema.MultiValuedTables)
        {
            attributes.Add(new ObjectAttribute(
                attribute.LdapDisplayName,
                AttributeCardinality.MultiValued,
                StoredValuesFor(connection, attribute, objectId)));
        }

        return new ObjectAttributes(
            dn,
            captured,
            attributes.Count == CapturedAttributeCatalog.All.Count,
            [.. attributes.OrderBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)]);
    }

    /// <summary>
    /// The object's row, turned into one attribute per column - including the two the schema
    /// stores under a name of its own.
    /// </summary>
    private static (long ObjectId, string Dn, DateTimeOffset Captured, List<ObjectAttribute> Attributes)? SingleValuedOf(
        SqliteConnection connection, string distinguishedName)
    {
        var columns = BundleSchema.SingleValuedColumns;

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT object_id, distinguished_name, object_guid, captured_utc"
            + string.Concat(columns.Select(a => ", " + BundleSchema.ColumnNameFor(a.LdapDisplayName)))
            + " FROM captured_object WHERE distinguished_name = $dn COLLATE NOCASE LIMIT 1";
        command.Parameters.AddWithValue("$dn", distinguishedName);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return null;

        var objectId = reader.GetInt64(0);
        var dn = reader.GetString(1);
        var captured = DateTimeOffset.Parse(
            reader.GetString(3), System.Globalization.CultureInfo.InvariantCulture);

        var attributes = new List<ObjectAttribute>
        {
            Structural("distinguishedName", dn),
            Structural("objectGUID", reader.IsDBNull(2) ? null : reader.GetString(2)),
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

        return (objectId, dn, captured, attributes);
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

    private static AttributeValue ValueAt(
        SqliteDataReader reader, int ordinal, AttributeStorage storage, int valueOrdinal) =>
        storage == AttributeStorage.Binary
            ? new AttributeValue(valueOrdinal, null, reader.GetFieldValue<byte[]>(ordinal))
            : new AttributeValue(valueOrdinal, reader.GetString(ordinal), null);
}
