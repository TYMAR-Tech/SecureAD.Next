using System.Globalization;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;

namespace SecureAD.Evidence;

public sealed partial class RequestedDetailLease
{
    private bool _captureValidated;

    private void RequireCaptureHeader()
    {
        if (_captureValidated) return;
        if (Reader.Manifest.Role != StoreSegmentRole.Evidence
            || Root.Segment(StoreSegmentRole.Evidence).SchemaVersion != BundleSchema.Version)
            throw new InvalidDataException("The captured requested-detail format is unsupported.");
        var page = Reader.ReadPage("bundle", 1L);
        if (page.Rows.Count != 1 || page.TotalRows != 1 || page.Next is not null) throw RequestedDetailMap.Invalid();
        var header = page.Rows[0];
        if (header.Integer("schema_version") != BundleSchema.Version
            || header.Integer("captured_attribute_catalog_version") != CapturedAttributeCatalog.Version
            || header.Integer("schema_guid_catalog_version") != SchemaGuidCatalog.Version
            || header.Integer("security_descriptor_parser_version") != SecurityDescriptorParser.Version
            || header.CompleteText("capture_generation_id") != Root.GenerationId.ToString("D")
            || header.CompleteText("coverage_id") != Root.LibraryHeader?.CoverageId)
            throw new InvalidDataException("The captured requested-detail format, semantic versions or source identity are unsupported.");
        _captureValidated = true;
    }

    private RequestedDetailRow? CapturedObject(string distinguishedName)
    {
        RequireCaptureHeader();
        var id = Reader.ResolveObject(distinguishedName);
        if (id is null) return null;
        var page = Reader.ReadPage("captured_object", id);
        if (!page.Exists || page.Rows.Count != 1 || page.TotalRows != 1 || page.Next is not null)
            throw RequestedDetailMap.Invalid();
        return page.Rows[0];
    }

    /// <summary>The evidence-owned descriptor association, without reading the descriptor.</summary>
    public long? ReadDescriptorId(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        var captured = CapturedObject(distinguishedName);
        if (captured is null) return null;
        var page = Reader.ReadPage("object_security_descriptor", captured.Integer("object_id"));
        if (!page.Exists) return null;
        if (page.Rows.Count != 1 || page.TotalRows != 1 || page.Next is not null) throw RequestedDetailMap.Invalid();
        return page.Rows[0].Integer("descriptor_id");
    }

    /// <summary>Reads the selected object's complete original DACL, never its canonical projection.</summary>
    public ObjectPermissions? ReadPermissions(string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        var captured = CapturedObject(distinguishedName);
        return captured is null ? null : ObjectPermissionsReader.ReadAt(Reader,
            captured.Integer("object_id"), captured.CompleteText("distinguished_name"));
    }

    /// <summary>Reads only selected catalogue fields; each requested whole attribute remains complete.</summary>
    public ObjectAttributes? ReadObjectAttributes(string distinguishedName, IReadOnlyCollection<string> attributes)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        ArgumentNullException.ThrowIfNull(attributes);
        var names = attributes.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (names.Any(name => !CapturedAttributeCatalog.All.Any(attribute =>
            attribute.LdapDisplayName.Equals(name, StringComparison.OrdinalIgnoreCase))))
            throw new ArgumentException("A selected attribute is not part of the captured catalogue.", nameof(attributes));
        var captured = CapturedObject(distinguishedName);
        if (captured is null) return null;
        var id = captured.Integer("object_id");
        var dn = captured.CompleteText("distinguished_name");
        var guid = captured.IsNull("object_guid") ? null : captured.CompleteText("object_guid");
        var coverage = Reader.ReadPage("partition_coverage", captured.Integer("coverage_id"));
        if (coverage.Rows.Count != 1 || coverage.TotalRows != 1) throw RequestedDetailMap.Invalid();
        var completeness = ReadCoverage.Over(Enum.Parse<ConnectionSecurityLevel>(
            coverage.Rows[0].CompleteText("connection_security")));
        var result = new List<ObjectAttribute>();
        foreach (var definition in CapturedAttributeCatalog.All.Where(attribute => names.Contains(attribute.LdapDisplayName)))
        {
            if (BundleSchema.StructurallyStoredAttributes.Contains(definition.LdapDisplayName, StringComparer.OrdinalIgnoreCase))
            {
                var value = definition.LdapDisplayName.Equals("distinguishedName", StringComparison.OrdinalIgnoreCase) ? dn : guid;
                result.Add(new(definition.LdapDisplayName, definition.Cardinality,
                    value is null ? [] : [new(0, value, null)]));
            }
            else if (definition.Cardinality == AttributeCardinality.SingleValued)
            {
                var column = BundleSchema.ColumnNameFor(definition.LdapDisplayName);
                result.Add(new(definition.LdapDisplayName, definition.Cardinality,
                    captured.IsNull(column) ? [] : [Value(captured, column, 0, definition.Storage)]));
            }
            else
            {
                var values = Reader.ReadCompleteScope(BundleSchema.ValueTableNameFor(definition.LdapDisplayName), id)
                    .Select(row => Value(row, "value", checked((int)row.Integer("ordinal")), definition.Storage)).ToArray();
                result.Add(new(definition.LdapDisplayName, definition.Cardinality, values));
            }
        }
        return new(dn, guid is null ? null : Guid.Parse(guid),
            DateTimeOffset.Parse(captured.CompleteText("captured_utc"), CultureInfo.InvariantCulture),
            completeness, [.. result.OrderBy(attribute => attribute.LdapDisplayName, StringComparer.OrdinalIgnoreCase)],
            captured.IsNull("domain_fqdn") ? null : captured.CompleteText("domain_fqdn"));
    }

    /// <summary>Reads the existing 50-value original membership page without reconstructing the collection.</summary>
    public CapturedMembershipPage? ReadCapturedMembership(string distinguishedName, bool parents, CapturedMembershipMark? after)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        if (after is not null && (after.Fingerprint != Root.EvidenceSeal || after.DistinguishedName != distinguishedName
            || after.Parents != parents || after.Ordinal < 0 || after.RequestedPage is null || after.RequestedRow < 0))
            throw new ArgumentException("This membership page belongs to another capture, object or attribute.", nameof(after));
        var captured = CapturedObject(distinguishedName);
        if (captured is null) return null;
        var table = BundleSchema.ValueTableNameFor(parents ? "memberOf" : "member");
        var id = captured.Integer("object_id");
        var mark = after?.RequestedPage;
        var skip = after?.RequestedRow ?? 0;
        var values = new List<AttributeValue>();
        var primary = captured.IsNull("primarygroupid") ? null : captured.CompleteText("primarygroupid");
        long total = -1;
        do
        {
            var page = Reader.ReadPage(table, id, mark);
            if (total < 0) total = page.TotalRows;
            if (page.TotalRows != total || skip > page.Rows.Count) throw RequestedDetailMap.Invalid();
            for (var position = skip; position < page.Rows.Count; position++)
            {
                var row = page.Rows[position];
                var ordinal = checked((int)row.Integer("ordinal"));
                if (after is not null && ordinal <= after.Ordinal) throw RequestedDetailMap.Invalid();
                values.Add(new(ordinal, row.CompleteText("value"), null));
                if (values.Count != 50) continue;
                RequestedDetailMark? next;
                var nextRow = 0;
                if (position + 1 < page.Rows.Count)
                {
                    var scope = RequestedDetailIndex.ScopeKey(table, RequestedDetailMap.Key(new RequestedDetailIndex.KeyValue(1, id)));
                    next = new(Reader.Manifest.Root, scope, mark?.Page ?? 0);
                    nextRow = position + 1;
                }
                else next = page.Next;
                return new(values, checked((int)total), primary,
                    next is null ? null : new CapturedMembershipMark(Root.EvidenceSeal, distinguishedName, parents, ordinal)
                    { RequestedPage = next, RequestedRow = nextRow });
            }
            mark = page.Next;
            skip = 0;
        } while (mark is not null);
        return new(values, checked((int)total), primary, null);
    }

    private static AttributeValue Value(RequestedDetailRow row, string column, int ordinal, AttributeStorage storage) =>
        storage == AttributeStorage.Binary ? new(ordinal, null, row.CompleteBytes(column))
            : new(ordinal, row.CompleteText(column), null);
}
