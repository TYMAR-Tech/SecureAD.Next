using Microsoft.Data.Sqlite;

namespace SecureAD.Evidence;

/// <summary>
/// One attribute definition from the forest's schema partition, as far as visibility goes.
/// </summary>
/// <remarks>
/// <b>The raw flags, not the answer.</b> Whether the forest withholds this attribute is computed
/// from these two values by <c>SchemaAttributeFlags.IsConfidential</c>. Storing the conclusion here
/// as well would be a second copy of one fact that can disagree with the first, which is the reason
/// the delegation and pre-authentication finding tables leave their computed answers out.
/// </remarks>
/// <param name="LdapDisplayName">The attribute's <c>lDAPDisplayName</c>.</param>
/// <param name="SearchFlags">Its <c>searchFlags</c>, or null where the capture holds no value.</param>
/// <param name="SystemFlags">Its <c>systemFlags</c>, or null where the capture holds no value.</param>
public sealed record SchemaAttributeDefinition(
    string LdapDisplayName,
    int? SearchFlags,
    int? SystemFlags);

/// <summary>
/// The schema partition's attribute definitions, with whether the question was put at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>Gate 4 refuses a bare list here, and it is right to.</b> An empty list means either <i>this
/// forest defines no attributes</i> - which is impossible - or <i>this run was never given the
/// schema partition</i>, and a caller handed only the list would read the second as the first. The
/// consequence is not academic: a rule would treat every LAPS attribute as absent-and-readable and
/// report an entire estate.
/// </para>
/// <para>
/// <b>The voucher is inferred from the count, and that is stated rather than hidden.</b> The only
/// signal available at this level is how many definitions came back. No Active Directory forest has
/// zero <c>attributeSchema</c> objects - the base schema alone runs to hundreds - so zero means
/// nobody looked. A stronger answer would come from the run's own partition coverage, and this is
/// the weaker one said plainly rather than a stronger one implied.
/// </para>
/// </remarks>
/// <param name="Attributes">Every schema definition captured.</param>
public sealed record SchemaAttributeReading(IReadOnlyList<SchemaAttributeDefinition> Attributes)
{
    /// <summary>Whether this capture was given the schema partition at all.</summary>
    public bool SchemaAttributesWereAsked => Attributes.Count > 0;
}

/// <summary>
/// Reads the schema partition's attribute definitions out of sealed evidence.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing here contacts a directory.</b> Capture already read the schema partition -
/// <c>CapturedAttributeCatalog.SchemaPartition</c> requests <c>searchFlags</c> and
/// <c>systemFlags</c> for every <c>attributeSchema</c> object - so these rows are inside the seal
/// and this is a query over a file, per <c>docs/decisions/0008</c>.
/// </para>
/// <para>
/// <b>Discriminated by <c>schemaIDGUID</c> rather than by <c>objectClass</c></b>, for the reason
/// <see cref="CapturedSchemaGuidReader"/> gives: <c>objectClass</c> is multi-valued and lives in its
/// own table, while an object holding a <c>schemaIDGUID</c> is a schema definition whatever else its
/// class list says.
/// </para>
/// <para>
/// <b><c>classSchema</c> rows come back too, and that is harmless.</b> A class carries no
/// <c>searchFlags</c>, so it arrives with nulls and is answered as <i>the flags were never
/// captured</i> rather than as <i>readable</i>. Nothing asks this reader about a class, and if
/// anything ever does it gets the cautious answer rather than a confident wrong one.
/// </para>
/// </remarks>
public static class CapturedSchemaAttributeReader
{
    /// <summary>
    /// Reads every schema definition this bundle captured.
    /// </summary>
    /// <remarks>
    /// An empty list means the run was refused the schema partition, not that the forest has no
    /// attributes. No Active Directory forest has zero <c>attributeSchema</c> objects, so the
    /// caller reads emptiness as <i>nobody looked</i> - which is the distinction
    /// <c>docs/decisions/0002</c> exists to keep.
    /// </remarks>
    /// <param name="connection">An open connection to the evidence.</param>
    public static SchemaAttributeReading Read(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var definitions = new List<SchemaAttributeDefinition>();

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT "
            + BundleSchema.ColumnNameFor("lDAPDisplayName") + ", "
            + BundleSchema.ColumnNameFor("searchFlags") + ", "
            + BundleSchema.ColumnNameFor("systemFlags")
            + " FROM captured_object"
            + " WHERE " + BundleSchema.ColumnNameFor("schemaIDGUID") + " IS NOT NULL"
            + " AND " + BundleSchema.ColumnNameFor("lDAPDisplayName") + " IS NOT NULL";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            definitions.Add(new SchemaAttributeDefinition(
                reader.GetString(0),
                FlagsAt(reader, 1),
                FlagsAt(reader, 2)));
        }

        return new SchemaAttributeReading(definitions);
    }

    /// <summary>
    /// Reads one flags word, which the catalogue stores as text.
    /// </summary>
    /// <remarks>
    /// <b>A value that will not parse is null rather than zero.</b> Zero is a real answer meaning
    /// <i>this forest withholds nothing</i>, and handing it back for something unreadable would
    /// turn a gap in the evidence into a statement about the forest.
    /// </remarks>
    private static int? FlagsAt(SqliteDataReader reader, int ordinal) =>
        !reader.IsDBNull(ordinal)
        && int.TryParse(
            reader.GetString(ordinal),
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out var flags)
            ? flags
            : null;
}
