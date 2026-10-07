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

internal static class CapturedMembershipReferences
{
    internal static CapturedMemberReferences Read(SqliteConnection connection, IReadOnlyList<string> names, CancellationToken token)
    {
        if (names.Count > 50) throw new ArgumentException("Membership identity lookups are limited to one 50-row page.", nameof(names));
        token.ThrowIfCancellationRequested();
        if (names.Count == 0) return new([]);
        using var command = connection.CreateCommand();
        var parameters = names.Select((_, index) => "$n" + index).ToArray();
        command.CommandText = $"""
            SELECT o.distinguished_name,o.object_guid,o.domain_fqdn,
                (SELECT v.value FROM objectclass_value v WHERE v.object_id=o.object_id ORDER BY v.ordinal DESC LIMIT 1)
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
}
