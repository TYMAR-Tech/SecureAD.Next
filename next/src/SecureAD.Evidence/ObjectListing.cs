using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

/// <summary>
/// How much of the directory beneath a container a listing covers.
/// </summary>
/// <remarks>
/// Active Directory's own three search scopes, under the names an administrator already uses.
/// <b>The selected object is included at every level</b>, which is how the directory defines them
/// and what an operator selecting a container expects to see listed.
/// </remarks>
public enum ListingScope
{
    /// <summary>The selected object alone.</summary>
    Base,

    /// <summary>The selected object and the objects directly inside it.</summary>
    OneLevel,

    /// <summary>The selected object and everything beneath it, however deep.</summary>
    Subtree,
}

/// <summary>
/// One object as a listing shows it.
/// </summary>
/// <param name="DistinguishedName">The object's name, as the controller gave it.</param>
/// <param name="Name">The first relative name, for showing.</param>
/// <param name="ObjectGuid">
/// The identity that survives a rename or a move, or null when it did not arrive.
/// </param>
/// <param name="ObjectClass">
/// The most specific class the controller named - <c>user</c>, <c>group</c>, <c>builtinDomain</c>.
/// Null when the object's class did not arrive, rather than guessed from anything else.
/// </param>
/// <param name="ParentDistinguishedName">The container it sits in, or null at a partition root.</param>
public sealed record ListedObject(
    string DistinguishedName,
    string Name,
    Guid? ObjectGuid,
    string? ObjectClass,
    string? ParentDistinguishedName);

/// <summary>
/// One page of objects, and what is true about the whole listing they came from.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Total"/> is the whole listing, not this page.</b> A pager that counts only what it
/// fetched can say "1-100 of 100" about a container holding forty thousand objects.
/// </para>
/// <para>
/// <b><see cref="ObjectsAreComplete"/> is why this is a type and not a list.</b> Widen the scope
/// over a branch the run could not read and the answer is short by an unknown amount - and a
/// shorter list is indistinguishable from a smaller directory. Per
/// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> that shortfall is stated rather
/// than left to be inferred, and gate 4 requires this type to carry the statement rather than hand
/// back a bare collection.
/// </para>
/// </remarks>
/// <param name="Objects">The objects on this page, ordered by name.</param>
/// <param name="Total">How many objects the whole listing holds.</param>
/// <param name="ObjectsAreComplete">
/// Whether every part of the directory this listing covers was read in full. False means the list
/// is short by an unknown amount. Named for its subject rather than for the type, as
/// <see cref="PartitionCoverage.ContinuationReferencesAreComplete"/> is, so that the collection
/// and the statement about it cannot be read apart.
/// </param>
/// <param name="Shortfall">
/// What was not read, in terms an operator can act on, or null when
/// <paramref name="ObjectsAreComplete"/> is true.
/// </param>
public sealed record ObjectPage(
    IReadOnlyList<ListedObject> Objects,
    int Total,
    bool ObjectsAreComplete,
    string? Shortfall);

/// <summary>
/// Lists the objects a bundle captured beneath one container.
/// </summary>
/// <remarks>
/// <para>
/// <b>Ordered and paged in the database, never in memory.</b> Fetching a container's objects to
/// sort them in the shell would read a whole forest to show a hundred rows, and the first page
/// would be the first hundred the database happened to return rather than the first hundred by
/// name.
/// </para>
/// <para>
/// <b>The subtree case is a prefix scan on <c>dn_reversed</c>.</b> A distinguished name is written
/// leaf first, so everything under a container shares a suffix, and no index can serve a search
/// for a suffix. Reversed, that suffix becomes a prefix and the index built for it applies. That
/// column has been in the schema since the beginning for this purpose and nothing used it until
/// now.
/// </para>
/// </remarks>
internal static class ObjectListingReader
{
    /// <summary>How many objects one page holds.</summary>
    internal const int PageSize = 100;

    /// <summary>
    /// The order a listing is read in: by the object's own name, which is what an operator sees in
    /// the Name column.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Not by distinguished name</b>, which sorts by naming attribute first and so lists every
    /// <c>CN=</c> object before every <c>OU=</c> one. The predecessor sorted by name - its Builtin
    /// listing has the container itself sitting alphabetically among the groups - and that is what
    /// an administrator expects.
    /// </para>
    /// <para>
    /// <b>Computed rather than read from a column, because there is no column to read.</b> The
    /// catalogue captures <c>cn</c>, which an organisational unit does not have, and does not
    /// capture <c>name</c> at all - so ordering by a stored attribute would put every OU together
    /// under a null. Taking what follows the first <c>=</c> gives the name for every class without
    /// a capture change. Objects sharing a parent then differ only in that name, and anything left
    /// tied falls back to the rest of the distinguished name, so the order is total and a page
    /// boundary is stable.
    /// </para>
    /// <para>
    /// It is an expression and therefore not served by an index. That is a real cost on a large
    /// forest and is recorded as a finding rather than guessed at here; it needs a bundle of some
    /// millions of objects to measure against, and one does not exist yet.
    /// </para>
    /// </remarks>
    private const string NameOrder =
        "SUBSTR(o.distinguished_name, INSTR(o.distinguished_name, '=') + 1)";

    /// <summary>
    /// Lists one page of the objects in <paramref name="containerDn"/> at
    /// <paramref name="scope"/>.
    /// </summary>
    /// <param name="connection">The open evidence database.</param>
    /// <param name="containerDn">The container the operator selected.</param>
    /// <param name="scope">How much of what is beneath it to include.</param>
    /// <param name="pageNumber">The page to fetch, counting from one.</param>
    public static ObjectPage Read(
        SqliteConnection connection, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);
        ArgumentOutOfRangeException.ThrowIfLessThan(pageNumber, 1);

        var where = WhereFor(scope);
        var total = CountOf(connection, where, containerDn);
        var objects = PageOf(connection, where, containerDn, pageNumber);
        var (complete, shortfall) = CoverageOf(connection, containerDn, scope);

        return new ObjectPage(objects, total, complete, shortfall);
    }

    /// <summary>
    /// The condition selecting one scope, written once so the count and the page can never
    /// disagree about which objects they are talking about.
    /// </summary>
    private static string WhereFor(ListingScope scope) => scope switch
    {
        ListingScope.Base => "distinguished_name = $dn COLLATE NOCASE",
        ListingScope.OneLevel =>
            "(distinguished_name = $dn COLLATE NOCASE OR parent_dn = $dn COLLATE NOCASE)",

        // The object itself, plus everything whose reversed name begins with the reversed name of
        // the container and a comma. ESCAPE is not optional: a distinguished name may contain '_'
        // and '%', both of which are LIKE wildcards, and 'CN=IIS_IUSRS' is a real container in
        // every forest. Without it, a listing would quietly include objects from elsewhere.
        ListingScope.Subtree =>
            "(dn_reversed = $reversed OR dn_reversed LIKE $prefix ESCAPE '\\')",
        _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown listing scope."),
    };

    private static void Bind(SqliteCommand command, string containerDn)
    {
        var reversed = DnHelper.ReverseDn(containerDn);

        command.Parameters.AddWithValue("$dn", containerDn);
        command.Parameters.AddWithValue("$reversed", reversed);
        command.Parameters.AddWithValue("$prefix", EscapeForLike(reversed) + ",%");
    }

    /// <summary>
    /// Renders a value harmless to <c>LIKE</c>, so that only the wildcard this reader adds is one.
    /// </summary>
    private static string EscapeForLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

    private static int CountOf(SqliteConnection connection, string where, string containerDn)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT COUNT(*) FROM captured_object WHERE {where}";
        Bind(command, containerDn);

        return Convert.ToInt32(command.ExecuteScalar());
    }

    private static List<ListedObject> PageOf(
        SqliteConnection connection, string where, string containerDn, int pageNumber)
    {
        var objects = new List<ListedObject>();

        using var command = connection.CreateCommand();

        // The most specific class the controller sent is the last one it sent: objectClass arrives
        // least specific first - top, person, organizationalPerson, user - and the values are
        // stored in that order. Taking the highest ordinal is therefore 'user' rather than 'top',
        // which is the word an administrator recognises the object by.
        command.CommandText =
            $"""
            SELECT o.distinguished_name, o.object_guid, o.parent_dn,
                   (SELECT v.value
                    FROM objectclass_value AS v
                    WHERE v.object_id = o.object_id
                    ORDER BY v.ordinal DESC
                    LIMIT 1)
            FROM captured_object AS o
            WHERE {where}
            ORDER BY {NameOrder} COLLATE NOCASE
            LIMIT $take OFFSET $skip
            """;

        Bind(command, containerDn);
        command.Parameters.AddWithValue("$take", PageSize);
        command.Parameters.AddWithValue("$skip", (pageNumber - 1) * PageSize);

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var dn = reader.GetString(0);
            objects.Add(new ListedObject(
                dn,
                DnHelper.ExtractFirstRdn(dn),
                reader.IsDBNull(1) ? null : Guid.Parse(reader.GetString(1)),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(2) ? null : reader.GetString(2)));
        }

        return objects;
    }

    /// <summary>
    /// Whether everything this listing covers was read in full.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Answered from what the run recorded about the domain the container belongs to, rather than
    /// from the shape of the answer. A listing cannot tell from its own rows that objects are
    /// missing - that is the whole difficulty, and it is why the run's own account of its coverage
    /// has to be consulted instead.
    /// </para>
    /// <para>
    /// <b>Only a widened scope can be short.</b> At <see cref="ListingScope.Base"/> the object is
    /// either in the evidence or it is not, and nothing about a domain's coverage changes that.
    /// </para>
    /// </remarks>
    private static (bool Complete, string? Shortfall) CoverageOf(
        SqliteConnection connection, string containerDn, ListingScope scope)
    {
        if (scope == ListingScope.Base)
            return (true, null);

        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT d.domain_fqdn, d.outcome, d.reason
            FROM domain_coverage AS d
            WHERE d.outcome <> 'Read'
              AND EXISTS (
                  SELECT 1 FROM captured_object AS o
                  WHERE o.domain_fqdn = d.domain_fqdn
                    AND o.distinguished_name = $dn COLLATE NOCASE)
            """;

        command.Parameters.AddWithValue("$dn", containerDn);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return (true, null);

        var domain = reader.GetString(0);
        var outcome = reader.GetString(1);
        var why = reader.IsDBNull(2) ? null : reader.GetString(2);

        return (
            false,
            $"'{domain}' was recorded as {outcome}, so this list is short by an unknown number of "
            + "objects." + (why is null ? string.Empty : " " + why));
    }
}
