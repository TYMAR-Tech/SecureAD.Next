using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Schema;

namespace SecureAD.Evidence;

/// <summary>
/// What a run read of its forest's schema: what each GUID means, and what each property set holds.
/// </summary>
/// <param name="Entries">Every schema GUID the forest defined, with the name it gave it.</param>
/// <param name="PropertySetMembers">
/// The LDAP names of the attributes in each property set, keyed by the set's GUID. A set the
/// forest defined but put nothing in is absent rather than empty, and a set that is absent is
/// <i>not assessed</i> rather than <i>holds nothing dangerous</i>.
/// </param>
internal sealed record CapturedSchema(
    IReadOnlyList<SchemaGuidEntry> Entries,
    IReadOnlyDictionary<string, IReadOnlyList<string>> PropertySetMembers);

/// <summary>
/// The schema-GUID catalogue a run actually read, recovered from the bundle it wrote.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this had to exist.</b>
/// <c>docs/decisions/0014-capture-reads-the-schema-partition.md</c> says the catalogue is one
/// lookup over two layers - shipped and captured - and that every answer states which. Capture
/// built the second layer and nothing read it back, so every name the product showed came from the
/// hundred-odd entries hard-coded in <see cref="SchemaGuidCatalog.Embedded"/> and every GUID
/// outside that list rendered raw. <c>inetOrgPerson</c> is a stock class and was one of them.
/// </para>
/// <para>
/// <b>It is worse than a missing name.</b> A forest's own schema extensions can never be in a
/// shipped table, so the attributes a customer added - the ones most likely to be delegated
/// carelessly and least likely to be understood - were exactly the ones shown as GUIDs. And
/// <see cref="SchemaGuidSource.Captured"/> was never produced anywhere, so the product could not
/// tell <i>Microsoft publishes this</i> from <i>your forest says this</i>, which is the distinction
/// <c>0014</c> exists to preserve.
/// </para>
/// <para>
/// <b>Nothing here needs a new capture.</b> The rows were always being written; this reads what is
/// already in every bundle.
/// </para>
/// </remarks>
internal static class CapturedSchemaGuidReader
{
    /// <summary>
    /// <c>validAccesses</c> on a <c>controlAccessRight</c>, the normative field for which of three
    /// kinds it is.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Extended rights, property sets and validated writes all live in the extended-rights
    /// container - Microsoft says outright that the last two are there "for convenience" despite
    /// not being extended rights. A reader that assumed the container held only extended rights
    /// would mislabel every property set in the forest.
    /// </para>
    /// <para>
    /// <b>Normative is not the same as present and correct.</b> It is what a forest is supposed to
    /// publish, not a guarantee that every forest does; a value can be absent or unreadable, and
    /// <see cref="SchemaGuidKind.Unclassified"/> exists for that gap rather than a guess filling
    /// it. Softened from "the only thing that says which" per <c>S-57</c> finding <c>#13</c>.
    /// </para>
    /// </remarks>
    private const int ExtendedRightAccess = 256;

    private const int PropertySetAccess = 48;

    private const int ValidatedWriteAccess = 8;

    /// <summary>
    /// Every schema GUID the run captured, with the name the forest gave it, and which attributes
    /// each property set contains.
    /// </summary>
    /// <param name="connection">An open connection to the bundle.</param>
    /// <returns>
    /// The entries and the property-set membership. Both are empty when the run did not read the
    /// schema partition. Empty is not an error and it is not the same as a forest with no schema:
    /// the caller keeps the two apart by noticing that a catalogue with no captured layer resolves
    /// nothing a forest added.
    /// </returns>
    public static CapturedSchema Read(SqliteConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);

        var entries = new List<SchemaGuidEntry>();
        var membership = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        using var command = connection.CreateCommand();

        // Discriminated by which GUID column carries a value rather than by objectClass, because
        // objectClass is multi-valued and lives in its own table: an object holding a schemaIDGUID
        // is a schema definition and one holding a rightsGuid is a control access right, whatever
        // else its class list says.
        command.CommandText =
            "SELECT "
            + BundleSchema.ColumnNameFor("lDAPDisplayName") + ", "
            + BundleSchema.ColumnNameFor("cn") + ", "
            + BundleSchema.ColumnNameFor("schemaIDGUID") + ", "
            + BundleSchema.ColumnNameFor("rightsGuid") + ", "
            + BundleSchema.ColumnNameFor("validAccesses") + ", "
            + BundleSchema.ColumnNameFor("isSingleValued") + ", "
            + BundleSchema.ColumnNameFor("attributeSecurityGUID")
            + " FROM captured_object"
            + " WHERE " + BundleSchema.ColumnNameFor("schemaIDGUID") + " IS NOT NULL"
            + " OR " + BundleSchema.ColumnNameFor("rightsGuid") + " IS NOT NULL";

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var entry = EntryFrom(reader);

            if (entry is not null)
                entries.Add(entry);

            RecordMembership(reader, entry, membership);
        }

        return new CapturedSchema(
            entries,
            membership.ToDictionary(
                p => p.Key,
                p => (IReadOnlyList<string>)p.Value,
                StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Files an attribute under the property set it belongs to, when it names one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The join Microsoft documents, in the direction it actually runs.</b> A property set is a
    /// <c>controlAccessRight</c> object and it names none of its members; each attribute instead
    /// points back at the set through <c>attributeSecurityGUID</c>
    /// (<see href="https://learn.microsoft.com/windows/win32/ad/creating-a-control-access-right">Creating
    /// a Control Access Right</see>). So membership can only be built by reading every attribute,
    /// never by reading the sets.
    /// </para>
    /// <para>
    /// <b>The two ends are the same GUID in two different representations.</b>
    /// <c>attributeSecurityGUID</c> is an octet string and <c>rightsGuid</c> is a 36-character
    /// string; compared as they arrive they never match, and a join that never matches produces an
    /// empty property set rather than an error.
    /// </para>
    /// </remarks>
    private static void RecordMembership(
        SqliteDataReader reader,
        SchemaGuidEntry? entry,
        Dictionary<string, List<string>> membership)
    {
        if (entry is null || entry.Kind != SchemaGuidKind.Attribute || reader.IsDBNull(6))
            return;

        var setGuid = GuidFrom((byte[])reader[6]);

        if (setGuid is null)
            return;

        if (!membership.TryGetValue(setGuid, out var members))
            membership[setGuid] = members = [];

        members.Add(entry.LdapName);
    }

    private static SchemaGuidEntry? EntryFrom(SqliteDataReader reader)
    {
        var ldapName = reader.IsDBNull(0) ? null : reader.GetString(0);
        var commonName = reader.IsDBNull(1) ? null : reader.GetString(1);

        // A GUID with no name resolves nothing, and an entry naming it "" would render as a blank
        // where a GUID at least tells an operator what to search for.
        var name = string.IsNullOrWhiteSpace(ldapName) ? commonName : ldapName;

        if (string.IsNullOrWhiteSpace(name))
            return null;

        if (!reader.IsDBNull(3))
        {
            var rightsGuid = reader.GetString(3);

            return Guid.TryParse(rightsGuid, out var parsed)
                ? new SchemaGuidEntry(
                    parsed.ToString("D"), name, KindOfRight(reader), SchemaGuidSource.Captured)
                : null;
        }

        if (reader.IsDBNull(2))
            return null;

        var schemaIdGuid = GuidFrom((byte[])reader[2]);

        if (schemaIdGuid is null)
            return null;

        // Only attributeSchema carries isSingleValued, and the schema makes it mandatory there, so
        // its presence separates an attribute definition from a class definition without a join.
        var kind = reader.IsDBNull(5)
            ? SchemaGuidKind.ObjectClass
            : SchemaGuidKind.Attribute;

        return new SchemaGuidEntry(schemaIdGuid, name, kind, SchemaGuidSource.Captured);
    }

    /// <summary>
    /// Which of the three kinds sharing the extended-rights container this right is, or
    /// <see cref="SchemaGuidKind.Unclassified"/> when the forest did not say.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>There were three ways to guess here, not one.</b> A missing <c>validAccesses</c>, a
    /// value that would not parse, and a value this build does not recognise all returned
    /// <see cref="SchemaGuidKind.ExtendedRight"/> - the third by falling out of the switch, and the
    /// second by laundering the literal 256 through it, which is why it read as arithmetic rather
    /// than as a decision. <c>S-57</c>'s verdict on <c>#13</c> names only the second and third.
    /// </para>
    /// <para>
    /// <b>Why none of them guesses now.</b> The retired reasoning was that an unrecognised value is
    /// an extended right because that is the reading which grants the most. It is the right
    /// instinct on the wrong axis: this field decides what kind of thing a GUID is, and per
    /// <c>S-56</c> R3 and R4 that is a factual classification rather than a severity call.
    /// Mislabelling a property set as an extended right does not overstate it, it sends
    /// <c>DangerousPermissionClassifier.ClassifyScoped</c> down the wrong branch, where the verdict
    /// is computed by a rule that was never about this right. <c>S-53</c> recorded the original
    /// decision and now carries the amendment.
    /// </para>
    /// </remarks>
    private static SchemaGuidKind KindOfRight(SqliteDataReader reader)
    {
        if (reader.IsDBNull(4))
            return SchemaGuidKind.Unclassified;

        if (reader.GetFieldType(4) != typeof(string))
            return KindOf(reader.GetInt32(4));

        return int.TryParse(reader.GetString(4), out var parsed)
            ? KindOf(parsed)
            : SchemaGuidKind.Unclassified;
    }

    /// <summary>
    /// The kind a <c>validAccesses</c> value names, on the exact values Microsoft documents.
    /// </summary>
    /// <remarks>
    /// Matched exactly rather than by mask test, because these are the whole published values for
    /// each kind and a combination is not a fourth kind - it is a value this build cannot read,
    /// which is what <see cref="SchemaGuidKind.Unclassified"/> says.
    /// </remarks>
    private static SchemaGuidKind KindOf(int validAccesses) => validAccesses switch
    {
        ExtendedRightAccess => SchemaGuidKind.ExtendedRight,
        PropertySetAccess => SchemaGuidKind.PropertySet,
        ValidatedWriteAccess => SchemaGuidKind.ValidatedWrite,
        _ => SchemaGuidKind.Unclassified,
    };

    /// <summary>
    /// A <c>schemaIDGUID</c> octet string as the GUID it stands for.
    /// </summary>
    /// <remarks>
    /// <b>The byte order is the trap.</b> Active Directory stores this as a GUID in its native
    /// little-endian layout, which is what <see cref="Guid(byte[])"/> expects - reading it as a
    /// big-endian sequence produces a well-formed GUID that matches nothing, and a lookup that
    /// silently finds nothing looks exactly like a forest that never defined the attribute.
    /// </remarks>
    private static string? GuidFrom(byte[] bytes) =>
        bytes.Length == 16 ? new Guid(bytes).ToString("D") : null;
}
