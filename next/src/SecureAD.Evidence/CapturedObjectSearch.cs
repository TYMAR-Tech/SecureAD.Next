using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

/// <summary>A search continuation bound to the exact protected capture and submitted text.</summary>
public sealed record ObjectSearchMark(string EvidenceFingerprint, string Search, long ObjectId);

/// <summary>One bounded page of captured matches; unrequested pages are not a capture shortfall.</summary>
public sealed record ObjectSearchPage(IReadOnlyList<ListedObject> Objects, ObjectSearchMark? Next, ListingCoverage Coverage);

internal static class CapturedObjectSearch
{
    internal const int PageSize = ObjectListingReader.PageSize;
    internal static string QuerySql => Query(navigation: false);

    private static string Query(bool navigation) => $"""
        SELECT o.object_id, o.distinguished_name, o.object_guid, o.parent_dn, o.domain_fqdn,
               {(navigation ? "o.most_specific_class" : "(SELECT c.value FROM objectclass_value AS c WHERE c.object_id=o.object_id ORDER BY c.ordinal DESC LIMIT 1)")}
        FROM captured_object AS o
        WHERE o.object_id > $after
          AND (instr(lower(o.distinguished_name), lower($search)) > 0
               OR instr(lower(o.samaccountname), lower($search)) > 0)
        ORDER BY o.object_id LIMIT $take
        """;

    internal static ObjectSearchPage Read(SqliteConnection connection, string fingerprint, BundleDescription description,
        string search, ObjectSearchMark? after, CancellationToken token, bool navigation = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(search);
        search = search.Trim();
        token.ThrowIfCancellationRequested();
        if (after is not null && (after.EvidenceFingerprint != fingerprint || after.Search != search || after.ObjectId <= 0))
            throw new ArgumentException("This object-search page belongs to another capture or search.", nameof(after));
        using var command = connection.CreateCommand();
        command.CommandText = Query(navigation);
        command.Parameters.AddWithValue("$after", after?.ObjectId ?? 0);
        command.Parameters.AddWithValue("$search", search);
        command.Parameters.AddWithValue("$take", PageSize + 1);
        var objects = new List<ListedObject>();
        var lastId = 0L;
        var more = false;
        using var read = command.ExecuteReader();
        while (read.Read())
        {
            token.ThrowIfCancellationRequested();
            if (objects.Count == PageSize) { more = true; break; }
            lastId = read.GetInt64(0);
            var dn = read.GetString(1);
            objects.Add(new(dn, DnHelper.ExtractFirstRdn(dn),
                read.IsDBNull(2) ? null : Guid.Parse(read.GetString(2)),
                read.IsDBNull(5) ? null : read.GetString(5),
                read.IsDBNull(3) ? null : read.GetString(3))
            { DomainFqdn = read.GetString(4) });
        }
        return new(objects, more ? new(fingerprint, search, lastId) : null,
            new(description.EveryDeclaredUnitRecordedAsRead, description.EveryDeclaredUnitRecordedAsRead ? null
                : "This capture did not read all declared scope. Matching objects may be missing; see Capture coverage."));
    }
}
