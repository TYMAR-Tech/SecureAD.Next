using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Binds <c>docs/next/S-16-the-bundle.md</c> to the schema the code actually creates, per
/// <c>docs/next/README.md</c> §When a document counts as documentation.
///
/// <para>
/// <b>The comparison is against a real database, not against a list in the code.</b> Comparing the
/// document to <see cref="BundleSchema.TableNames"/> would prove the two lists agree and say
/// nothing about whether either describes what a bundle contains - both could be wrong in the same
/// way. So the schema is created in a temporary file and the tables are read back out of
/// <c>sqlite_master</c>, which is SQLite's own account of what exists.
/// </para>
/// <para>
/// This is the shape the previous tree's <c>DataModelDocSyncTests</c> used, and it is used again
/// for the same reason: a table added to the code and not to the document is how a data model
/// stops being documentation and becomes a description of what somebody once intended.
/// </para>
/// </summary>
public sealed class BundleDocumentationTests : IDisposable
{
    private const string Slice = "S-16-the-bundle.md";
    private const string TableBegin = "<!-- TABLES:BEGIN -->";
    private const string TableEnd = "<!-- TABLES:END -->";

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "securead-schema-" + Guid.NewGuid().ToString("N"));

    /// <summary>
    /// Every table the schema creates is named in the document.
    /// </summary>
    [Fact]
    public void EveryTableTheSchemaCreatesIsDocumented()
    {
        var documented = DocumentedTables();
        var undocumented = TablesInARealDatabase().Where(t => !documented.Contains(t)).ToList();

        Assert.True(
            undocumented.Count == 0,
            $"The schema creates tables that {Slice} does not name: "
            + string.Join(", ", undocumented)
            + ". An undocumented table is a piece of the only thing this product reads from that "
            + "nobody has explained.");
    }

    /// <summary>
    /// And the other direction: every table the document names really exists. Without this, the
    /// document could describe a bundle nobody writes.
    /// </summary>
    [Fact]
    public void EveryTableTheDocumentNamesExists()
    {
        var actual = TablesInARealDatabase();
        var invented = DocumentedTables().Where(t => !actual.Contains(t)).ToList();

        Assert.True(
            invented.Count == 0,
            $"{Slice} names tables the schema does not create: " + string.Join(", ", invented));
    }

    /// <summary>
    /// The document says what the absence of a row means, for every table. That is the whole
    /// reason this schema is shaped the way it is, per <c>docs/decisions/0002</c>, and a table
    /// listed with a blank there is a table whose emptiness nobody has interpreted.
    /// </summary>
    [Fact]
    public void EveryTableSaysWhatItsAbsenceMeans()
    {
        var silent = DocumentedRows()
            .Where(r => r.Value.Length < 30)
            .Select(r => $"  {r.Key}: '{r.Value}'")
            .ToList();

        Assert.True(
            silent.Count == 0,
            $"{Slice} lists tables without saying what a missing row means:"
            + Environment.NewLine + string.Join(Environment.NewLine, silent));
    }

    /// <summary>
    /// The scanner self-test. Without it both directions above pass by comparing an empty document
    /// against an empty database and finding nothing wrong with either - which is the failure this
    /// repository has committed three times.
    /// </summary>
    [Fact]
    public void TheCheckReadsBothTheDocumentAndARealDatabase()
    {
        var actual = TablesInARealDatabase();
        var documented = DocumentedTables();

        Assert.True(actual.Count >= 10, $"Read only {actual.Count} tables from a real database.");
        Assert.Equal(actual.Count, documented.Count);

        // A named table, so a scan that returned an empty set of names would fail here rather than
        // passing by matching nothing against nothing.
        Assert.Contains("partition_coverage", actual);
        Assert.Contains("partition_coverage", documented);

        // And a table that must not exist: the materialised ACL payload was deleted at C12, and
        // its absence is a decision rather than an oversight.
        Assert.DoesNotContain("fact_object_acl_materialized", actual);

        // The code's own list and the database agree. This is the weaker comparison, kept only to
        // localise a failure - if this passes and the checks above fail, the document is wrong; if
        // this fails, the code's list is.
        Assert.Equal(
            BundleSchema.TableNames.OrderBy(t => t, StringComparer.Ordinal).ToList(),
            actual.OrderBy(t => t, StringComparer.Ordinal).ToList());
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        if (Directory.Exists(_directory))
            Directory.Delete(_directory, recursive: true);
    }

    /// <summary>
    /// The tables SQLite reports after the schema has been created in a real file.
    /// </summary>
    private List<string> TablesInARealDatabase()
    {
        Directory.CreateDirectory(_directory);
        var path = Path.Combine(_directory, "schema-probe.db");

        using var connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
            }.ToString());

        connection.Open();
        BundleSchema.CreateTables(connection);
        BundleSchema.CreateDeferredIndexes(connection);

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'";

        var tables = new List<string>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
            tables.Add(reader.GetString(0));

        return tables;
    }

    private static HashSet<string> DocumentedTables() =>
        DocumentedRows().Keys.ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The table list in S-16, read only between its markers so that a table named in the prose
    /// does not count as documented, keyed to what the document says its absence means.
    /// </summary>
    private static Dictionary<string, string> DocumentedRows()
    {
        var path = Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Slice);
        if (!File.Exists(path))
            throw new FileNotFoundException("Expected the slice document at " + path + ".", path);

        var lines = File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        if (begin < 0 || end < 0 || end < begin)
        {
            throw new InvalidOperationException(
                "Could not find the " + TableBegin + " / " + TableEnd + " markers in " + Slice
                + ". A missing marker must fail rather than silently empty the scan.");
        }

        var rows = new Dictionary<string, string>(StringComparer.Ordinal);

        for (var i = begin + 1; i < end; i++)
        {
            var trimmed = lines[i].Trim();
            if (!trimmed.StartsWith('|') || !trimmed.EndsWith('|'))
                continue;

            var cells = trimmed.Trim('|').Split('|').Select(c => c.Trim()).ToArray();
            if (cells.Length < 3 || cells[0] == "Table" || cells[0].All(c => c is '-' or ':'))
                continue;

            rows[cells[0].Trim('`')] = cells[2];
        }

        return rows;
    }
}
