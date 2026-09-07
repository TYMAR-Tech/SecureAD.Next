using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Capture;

namespace SecureAD.Evidence;

/// <summary>
/// Every object in a bundle, in one pass, for a caller that has to look at all of them.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because <see cref="ObjectAttributesReader"/> is the wrong shape for bulk.</b> That
/// reader fetches the object row and its batched multi-valued attributes for a single object.
/// Judging a forest must not repeat those queries for every object when it can walk each table once.
/// </para>
/// <para>
/// <b>So the whole bundle is read as sequential passes instead: one over
/// <c>captured_object</c>, and one over each multi-valued value table.</b> Every single-valued
/// attribute is already a column on the object row, so 59 of the catalogue's attributes arrive with
/// no join at all. Each value table is walked in <c>object_id</c> order beside the object scan and
/// merged as it goes, so nothing is held but the object being assembled.
/// </para>
/// <para>
/// <b>Every multi-valued table is read, including ones no caller asked for.</b> Reading only the
/// attributes a rule declared would be faster and would make an undeclared read indistinguishable
/// from an attribute the directory did not hold - a silent wrong answer, which is the one shape of
/// defect this product may not have. The cost of never being wrong here is thirteen extra passes
/// over narrow, sparse tables, beside one pass over the wide table that dominates either way.
/// </para>
/// <para>
/// <b>It streams.</b> A forest is millions of objects, and materialising them would cost gigabytes
/// to hand a caller something it consumes one at a time. Nothing here holds more than the object
/// being built.
/// </para>
/// </remarks>
internal static class ObjectStreamReader
{
    /// <summary>
    /// Every object the bundle holds, in <c>object_id</c> order, with every catalogued attribute.
    /// </summary>
    /// <param name="connection">An open connection to the evidence database.</param>
    /// <param name="rememberIdentity">Retains only the current row's identity for the owning reader.</param>
    public static IEnumerable<ObjectAttributes> Stream(
        SqliteConnection connection, Action<long, string> rememberIdentity)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(rememberIdentity);

        var columns = BundleSchema.SingleValuedColumns;

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT o.object_id, o.distinguished_name, o.object_guid, o.captured_utc"
            + string.Concat(
                columns.Select(a => ", o." + BundleSchema.ColumnNameFor(a.LdapDisplayName)))
            + ", c.connection_security, o.domain_fqdn"
            + " FROM captured_object AS o"
            + " JOIN partition_coverage AS c ON c.coverage_id = o.coverage_id"
            + " ORDER BY o.object_id";

        using var objects = command.ExecuteReader();

        var sidecars = BundleSchema.MultiValuedTables
            .Select(a => new ValueTableCursor(connection, a))
            .ToList();

        try
        {
            while (objects.Read())
            {
                var objectId = objects.GetInt64(0);
                var dn = objects.GetString(1);
                var storedGuid = objects.IsDBNull(2) ? null : objects.GetString(2);

                var attributes = new List<ObjectAttribute>
                {
                    Structural("distinguishedName", dn),
                    Structural("objectGUID", storedGuid),
                };

                for (var i = 0; i < columns.Count; i++)
                {
                    var ordinal = i + 4;

                    attributes.Add(new ObjectAttribute(
                        columns[i].LdapDisplayName,
                        AttributeCardinality.SingleValued,
                        objects.IsDBNull(ordinal)
                            ? []
                            : [ObjectAttributesReader.ValueAt(objects, ordinal, columns[i].Storage, 0)]));
                }

                foreach (var sidecar in sidecars)
                {
                    attributes.Add(new ObjectAttribute(
                        sidecar.Attribute.LdapDisplayName,
                        AttributeCardinality.MultiValued,
                        sidecar.ValuesFor(objectId)));
                }

                rememberIdentity(objectId, dn);
                yield return new ObjectAttributes(
                    dn,
                    storedGuid is null ? null : Guid.Parse(storedGuid),
                    DateTimeOffset.Parse(
                        objects.GetString(3), System.Globalization.CultureInfo.InvariantCulture),
                    ReadCoverage.Over(
                        Enum.Parse<ConnectionSecurityLevel>(
                            objects.GetString(4 + columns.Count))),
                    [.. attributes.OrderBy(a => a.LdapDisplayName, StringComparer.OrdinalIgnoreCase)],
                    objects.IsDBNull(5 + columns.Count)
                        ? null
                        : objects.GetString(5 + columns.Count));
            }
        }
        finally
        {
            foreach (var sidecar in sidecars)
                sidecar.Dispose();
        }
    }

    private static ObjectAttribute Structural(string ldapDisplayName, string? text) =>
        new(
            ldapDisplayName,
            AttributeCardinality.SingleValued,
            text is null ? [] : [new AttributeValue(0, text, null)]);

    /// <summary>
    /// One multi-valued table, walked in step with the object scan.
    /// </summary>
    /// <remarks>
    /// <b>It only ever moves forward.</b> Both this and the object scan are ordered by
    /// <c>object_id</c>, so the values for an object are always at or ahead of the cursor: rows for
    /// objects already passed are discarded, and the cursor stops as soon as it reaches an object
    /// beyond the one being asked about. That makes the whole table one sequential read for the
    /// entire bundle rather than a query per object.
    /// </remarks>
    private sealed class ValueTableCursor : IDisposable
    {
        private readonly SqliteCommand _command;
        private readonly SqliteDataReader _reader;
        private readonly CapturedAttribute _attribute;

        private bool _exhausted;
        private long _pendingObjectId;
        private AttributeValue? _pending;

        public ValueTableCursor(SqliteConnection connection, CapturedAttribute attribute)
        {
            _attribute = attribute;

            _command = connection.CreateCommand();
            _command.CommandText =
                $"SELECT object_id, ordinal, value FROM {BundleSchema.ValueTableNameFor(attribute.LdapDisplayName)} "
                + "ORDER BY object_id, ordinal";

            _reader = _command.ExecuteReader();
            Advance();
        }

        public CapturedAttribute Attribute => _attribute;

        /// <summary>
        /// The values this table holds for <paramref name="objectId"/>, which may be none.
        /// </summary>
        /// <param name="objectId">The object being assembled.</param>
        public List<AttributeValue> ValuesFor(long objectId)
        {
            // Rows for objects the scan has already passed. Reachable when a value table holds an
            // object the outer query did not return, which the schema does not permit - but
            // discarding rather than assuming keeps this cursor honest about its own ordering.
            while (!_exhausted && _pendingObjectId < objectId)
                Advance();

            var values = new List<AttributeValue>();

            while (!_exhausted && _pendingObjectId == objectId)
            {
                values.Add(_pending!);
                Advance();
            }

            return values;
        }

        public void Dispose()
        {
            _reader.Dispose();
            _command.Dispose();
        }

        private void Advance()
        {
            if (!_reader.Read())
            {
                _exhausted = true;
                _pending = null;
                return;
            }

            _pendingObjectId = _reader.GetInt64(0);
            _pending = ObjectAttributesReader.ValueAt(
                _reader, 2, _attribute.Storage, _reader.GetInt32(1));
        }
    }
}
