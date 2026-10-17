using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

public sealed record CapturedMemberReference(string RecordedName, Guid? ObjectGuid, string? DistinguishedName,
    string? Name, string? ObjectClass, string? DomainFqdn);

/// <summary>A bounded identity lookup, not group expansion; unresolved references remain in place.</summary>
public sealed record CapturedMemberReferences(IReadOnlyList<CapturedMemberReference> References)
{
    public bool IsComplete => References.All(reference => reference.DistinguishedName is not null);
}

/// <summary>A position in one original ordered member/memberOf attribute, bound to its protected evidence.</summary>
public sealed record CapturedMembershipMark(string Fingerprint, string DistinguishedName, bool Parents, int Ordinal)
{
    /// <summary>The next authenticated native page, when read through the requested-detail boundary.</summary>
    public RequestedDetailMark? RequestedPage { get; init; }
    /// <summary>The next row within that bounded native page.</summary>
    public int RequestedRow { get; init; }
}

/// <summary>An independently counted page of original values; unloaded values are not missing captured evidence.</summary>
public sealed record CapturedMembershipPage(IReadOnlyList<AttributeValue> Values, int Total,
    string? PrimaryGroupId, CapturedMembershipMark? Next);

internal static class CapturedMembershipReferences
{
    internal static CapturedMemberReferences Read(SqliteConnection connection, IReadOnlyList<string> names,
        CancellationToken token, bool navigation = false)
    {
        if (names.Count > 50) throw new ArgumentException("Membership identity lookups are limited to one 50-row page.", nameof(names));
        token.ThrowIfCancellationRequested();
        if (names.Count == 0) return new([]);
        using var command = connection.CreateCommand();
        var parameters = names.Select((_, index) => "$n" + index).ToArray();
        var objectClass = navigation ? "o.most_specific_class"
            : "(SELECT v.value FROM objectclass_value v WHERE v.object_id=o.object_id ORDER BY v.ordinal DESC LIMIT 1)";
        command.CommandText = $"""
            SELECT o.distinguished_name,o.object_guid,o.domain_fqdn,
                {objectClass}
            FROM captured_object o WHERE o.distinguished_name COLLATE NOCASE IN ({string.Join(",", parameters)})
            """;
        for (var i = 0; i < names.Count; i++) command.Parameters.AddWithValue(parameters[i], names[i]);
        var found = new Dictionary<string, List<CapturedMemberReference>>(StringComparer.OrdinalIgnoreCase);
        using (var read = command.ExecuteReader())
            while (read.Read())
            {
                token.ThrowIfCancellationRequested();
                var dn = read.GetString(0);
                if (!found.TryGetValue(dn, out var rows)) found[dn] = rows = [];
                rows.Add(new(dn, read.IsDBNull(1) ? null : Guid.Parse(read.GetString(1)), dn, DnHelper.ExtractNameFromDn(dn),
                    read.IsDBNull(3) ? null : read.GetString(3), read.IsDBNull(2) ? null : read.GetString(2)));
            }
        return new(names.Select(name => found.TryGetValue(name, out var rows) && rows.Count == 1
            ? rows[0] with { RecordedName = name }
            : new CapturedMemberReference(name, null, null, null, null, null)).ToArray());
    }

    internal static CapturedMembershipPage? ReadPage(SqliteConnection connection, string fingerprint,
        string distinguishedName, bool parents, CapturedMembershipMark? after, CancellationToken token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);
        token.ThrowIfCancellationRequested();
        if (after is not null && (after.Fingerprint != fingerprint || after.DistinguishedName != distinguishedName
            || after.Parents != parents || after.Ordinal < 0))
            throw new ArgumentException("This membership page belongs to another capture, object or attribute.", nameof(after));
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT object_id,primarygroupid FROM captured_object WHERE distinguished_name=$dn COLLATE NOCASE LIMIT 1";
        command.Parameters.AddWithValue("$dn", distinguishedName);
        long id;
        string? primary;
        using (var row = command.ExecuteReader())
        {
            if (!row.Read()) return null;
            id = row.GetInt64(0);
            primary = row.IsDBNull(1) ? null : row.GetString(1);
        }
        var table = BundleSchema.ValueTableNameFor(parents ? "memberOf" : "member");
        command.Parameters.Clear();
        command.Parameters.AddWithValue("$object", id);
        command.CommandText = $"SELECT COUNT(*) FROM {table} WHERE object_id=$object";
        var total = Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
        command.CommandText = $"""
            SELECT ordinal,value FROM {table}
            WHERE object_id=$object AND ordinal>$after ORDER BY ordinal LIMIT 51
            """;
        command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
        var values = new List<AttributeValue>();
        CapturedMembershipMark? next = null;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            token.ThrowIfCancellationRequested();
            if (values.Count == 50) return new(values, total, primary, next);
            var ordinal = rows.GetInt32(0);
            values.Add(new(ordinal, rows.GetString(1), null));
            next = new(fingerprint, distinguishedName, parents, ordinal);
        }
        return new(values, total, primary, null);
    }
}
