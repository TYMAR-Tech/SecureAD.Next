using Microsoft.Data.Sqlite;
using SecureAD.Kernel.Naming;

namespace SecureAD.Evidence;

/// <summary>
/// Lists the computers a bundle captured beneath one container, with their LAPS state.
/// </summary>
/// <remarks>
/// <para>
/// <b>It reads sealed evidence and not the findings store, and that is the point of it.</b>
/// <i>Which machines have modern, which have legacy, which have none</i> includes the healthy ones,
/// and a findings store holds only what a rule reported. The evidence already carries every
/// computer, both timestamps and the operating system, so this is a query over a file.
/// </para>
/// <para>
/// <b>Scoped and paged exactly as <see cref="ObjectListingReader"/> is</b>, including the reversed
/// distinguished name for the subtree case and the <c>LIKE</c> escaping that a container such as
/// <c>CN=IIS_IUSRS</c> makes necessary. One mechanism, so a container that lists 40 objects cannot
/// list 38 machines for a different reason.
/// </para>
/// <para>
/// <b>The counts are computed over the whole listing and the classification is done here, not in
/// SQL.</b> Expressing <i>managed</i>, <i>capable</i> or <i>domain controller</i> as a <c>CASE</c>
/// would put a second copy of each rule's logic in a query, where nothing tests it against the
/// rule. So the count pass reads every in-scope computer's classifying columns and counts them in
/// memory. That is a scan per listing, and it is a real cost on a large estate - stated here rather
/// than discovered later, and bounded by the fact that computers are a small fraction of a
/// directory.
/// </para>
/// </remarks>
internal static class LapsInventoryReader
{
    /// <summary>How many computers one page holds.</summary>
    internal const int PageSize = 100;

    /// <summary>
    /// The order a listing is read in, matching the object listing so the two agree.
    /// </summary>
    private const string NameOrder =
        "SUBSTR(o.distinguished_name, INSTR(o.distinguished_name, '=') + 1)";

    /// <summary>
    /// The columns a row is built from, named once so the count pass and the page pass cannot
    /// disagree about what they are reading.
    /// </summary>
    private static readonly string Columns =
        "o.distinguished_name, o.object_guid, o.domain_fqdn, "
        + $"o.{BundleSchema.ColumnNameFor("msLAPS-PasswordExpirationTime")}, "
        + $"o.{BundleSchema.ColumnNameFor("ms-Mcs-AdmPwdExpirationTime")}, "
        + $"o.{BundleSchema.ColumnNameFor("operatingSystem")}, "
        + $"o.{BundleSchema.ColumnNameFor("operatingSystemVersion")}, "
        + $"o.{BundleSchema.ColumnNameFor("userAccountControl")}, "
        + $"o.{BundleSchema.ColumnNameFor("primaryGroupID")}";

    /// <summary>
    /// The computer test, and it is the object's <b>most derived</b> class.
    /// </summary>
    /// <remarks>
    /// <b>A group managed service account's <c>objectClass</c> chain contains <c>computer</c>.</b>
    /// Judged against <c>ad.lab</c> on 2026-09-03, asking whether <c>computer</c> was merely present
    /// would have listed three of them as machines with no local administrator password to manage.
    /// Both rules test the most derived class, and so does this.
    /// </remarks>
    private const string IsComputer =
        """
        (SELECT v.value FROM objectclass_value AS v
         WHERE v.object_id = o.object_id
         ORDER BY v.ordinal DESC LIMIT 1) = 'computer' COLLATE NOCASE
        """;

    /// <summary>
    /// Lists one page of the computers in <paramref name="containerDn"/> at
    /// <paramref name="scope"/>, with the counts for the whole listing.
    /// </summary>
    /// <param name="connection">The open evidence database.</param>
    /// <param name="containerDn">The container the operator selected.</param>
    /// <param name="scope">How much of what is beneath it to include.</param>
    /// <param name="pageNumber">The page to fetch, counting from one.</param>
    public static LapsPage Read(
        SqliteConnection connection, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);
        ArgumentOutOfRangeException.ThrowIfLessThan(pageNumber, 1);

        var where = WhereFor(scope);
        var all = ReadRows(connection, where, containerDn, pageNumber: null);
        var page = ReadRows(connection, where, containerDn, pageNumber);
        var (complete, shortfall) = ObjectListingReader.CoverageOf(connection, containerDn, scope);

        var counts = all.CountBy(computer => computer.Management).ToDictionary();

        return new LapsPage(page, all.Count, counts, complete, shortfall);
    }

    /// <summary>
    /// The condition selecting one scope, written once so the count and the page can never
    /// disagree about which computers they are talking about.
    /// </summary>
    private static string WhereFor(ListingScope scope) => scope switch
    {
        ListingScope.Base => "o.distinguished_name = $dn COLLATE NOCASE",
        ListingScope.OneLevel =>
            "(o.distinguished_name = $dn COLLATE NOCASE OR o.parent_dn = $dn COLLATE NOCASE)",

        // The container itself, plus everything whose reversed name begins with the reversed name
        // of the container and a comma. ESCAPE is not optional: a distinguished name may contain
        // '_' and '%', both of which are LIKE wildcards.
        ListingScope.Subtree =>
            "(o.dn_reversed = $reversed OR o.dn_reversed LIKE $prefix ESCAPE '\\')",
        _ => throw new ArgumentOutOfRangeException(nameof(scope), scope, "Unknown listing scope."),
    };

    /// <summary>
    /// Reads rows, either all of them for the counts or one page of them for the grid.
    /// </summary>
    /// <param name="pageNumber">The page to fetch, or null for every row in scope.</param>
    private static List<LapsComputer> ReadRows(
        SqliteConnection connection, string where, string containerDn, int? pageNumber)
    {
        var computers = new List<LapsComputer>();

        using var command = connection.CreateCommand();

        command.CommandText =
            $"""
            SELECT {Columns}
            FROM captured_object AS o
            WHERE {where} AND {IsComputer}
            ORDER BY {NameOrder} COLLATE NOCASE
            """
            + (pageNumber is null ? string.Empty : " LIMIT $take OFFSET $skip");

        Bind(command, containerDn);

        if (pageNumber is { } number)
        {
            command.Parameters.AddWithValue("$take", PageSize);
            command.Parameters.AddWithValue("$skip", (number - 1) * PageSize);
        }

        using var reader = command.ExecuteReader();

        while (reader.Read())
        {
            var dn = reader.GetString(0);

            computers.Add(new LapsComputer(
                dn,
                DnHelper.ExtractFirstRdn(dn),
                reader.IsDBNull(1) ? null : Guid.Parse(reader.GetString(1)),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                TextAt(reader, 3),
                TextAt(reader, 4),
                TextAt(reader, 5),
                TextAt(reader, 6),
                UnsignedAt(reader, 7),
                SignedAt(reader, 8)));
        }

        return computers;
    }

    private static string? TextAt(SqliteDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    /// <summary>
    /// Reads a flags word, which the catalogue stores as text.
    /// </summary>
    /// <remarks>
    /// <b>A value that will not parse is null rather than zero.</b> Zero is a real answer - an
    /// account with no flags set - and handing it back for something unreadable would turn a gap in
    /// the evidence into a statement about the machine, which is what decides whether it is shown
    /// as a domain controller or as an ordinary member server.
    /// </remarks>
    private static uint? UnsignedAt(SqliteDataReader reader, int ordinal) =>
        !reader.IsDBNull(ordinal)
        && uint.TryParse(
            reader.GetString(ordinal),
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out var value)
            ? value
            : null;

    private static int? SignedAt(SqliteDataReader reader, int ordinal) =>
        !reader.IsDBNull(ordinal)
        && int.TryParse(
            reader.GetString(ordinal),
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out var value)
            ? value
            : null;

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
}
