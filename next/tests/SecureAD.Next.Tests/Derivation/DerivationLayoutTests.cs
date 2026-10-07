using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using Xunit;

namespace SecureAD.Next.Tests.Derivation;

public sealed class DerivationLayoutTests
{
    // Recorded independently of the production version. Never replace a checkpoint to bless a
    // changed layout: bump the production version and add a new checkpoint instead. Semantic
    // changes without DDL still require their own regression tests and version decision.
    private static readonly IReadOnlyDictionary<int, string> Layouts = new Dictionary<int, string>
    {
        [9] = "1EC635AEEBC498946B41C4F295BF963F5988B914C8D27E88497F3EC84283BFEF",
        [10] = "337F22D4D30400F866A667325815095115079A1A889BF259448EC1282D6FD3C4",
        // Schema 11 adds lossless membership sources; observed from this build, not a historical forest.
        [11] = "15DBD34B6918826C2408E64610E6F1B0E8F4B04675C7F7BD88E1B7D3740BA143",
        // Schema 12 retains naming-context heads in the membership input under 0117. The tables are
        // unchanged - this is a change in which objects are stored, not in the shape that stores
        // them - so the layout hash is deliberately identical to 11 and the version carries the
        // difference. A version 11 store is refused because it does not contain the roots at all.
        [12] = "15DBD34B6918826C2408E64610E6F1B0E8F4B04675C7F7BD88E1B7D3740BA143",
        // Schema 13 changes what a stored evaluation MEANS and touches no DDL at all: under 0118 a
        // principal reachable only through primaryGroupID is NotProtected where 12 wrote Unknown.
        // The hash is identical to 12 for that reason, and this is precisely the case P-149 says a
        // structural fingerprint cannot catch - the guard below would pass unchanged if the version
        // had not been bumped, so ProtectedPrincipalDeriverTests carries the behavioural check.
        [13] = "15DBD34B6918826C2408E64610E6F1B0E8F4B04675C7F7BD88E1B7D3740BA143",
        // Schema 14 adds nesting_unresolved_link under P-164, so unlike 12 and 13 this one really
        // does change the shape and the hash moves with it. A version 13 store has nowhere to have
        // recorded which group carried a membership link naming something no captured object
        // answers to, so it cannot be read as though the absence of those rows meant there were
        // none - which is the whole defect.
        [14] = "FFE987C95F60D7B88BD51060B11F5B34E2666FF5F2B51124BAC2D739264276C4",
        // Schema 15 retains CA source identities and host values; observed with unchanged tables.
        [15] = "FFE987C95F60D7B88BD51060B11F5B34E2666FF5F2B51124BAC2D739264276C4",
        // Version 16 includes captured singleton self-loops; the physical tables are unchanged.
        [16] = "FFE987C95F60D7B88BD51060B11F5B34E2666FF5F2B51124BAC2D739264276C4",
    };

    [Fact]
    public void TheStoredLayoutMatchesItsVersionCheckpoint()
    {
        using var connection = Create();
        AssertLayout(connection);
    }

    [Theory]
    [InlineData("ALTER TABLE protected_principal ADD COLUMN unversioned TEXT")]
    [InlineData("DROP INDEX ix_nesting_edge_member")]
    [InlineData("CREATE TABLE unversioned (id INTEGER PRIMARY KEY)")]
    public void TheCheckpointRejectsAnUnversionedLayoutChange(string mutation)
    {
        using var connection = Create();
        AssertLayout(connection);
        using var command = connection.CreateCommand();
        command.CommandText = mutation;
        command.ExecuteNonQuery();
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => AssertLayout(connection));
        Assert.Contains("layout changed without a new version checkpoint", error.Message);
    }

    private static SqliteConnection Create()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        DerivationSchema.CreateTables(connection);
        DerivationSchema.CreateDeferredIndexes(connection);
        return connection;
    }

    private static void AssertLayout(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT type, name, tbl_name, sql FROM sqlite_schema "
            + "WHERE sql IS NOT NULL ORDER BY type, name";
        using var reader = command.ExecuteReader();
        var layout = new StringBuilder();
        while (reader.Read())
        {
            for (var column = 0; column < reader.FieldCount; column++)
                layout.Append(reader.GetString(column).Replace("\r\n", "\n", StringComparison.Ordinal)).Append('\n');
        }

        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(layout.ToString())));
        Assert.True(Layouts.TryGetValue(DerivationSchema.Version, out var expected),
            $"Schema {DerivationSchema.Version} needs an independently recorded layout checkpoint; actual {actual}.");
        Assert.True(string.Equals(expected, actual, StringComparison.Ordinal),
            $"Schema {DerivationSchema.Version} layout changed without a new version checkpoint. Expected {expected}; actual {actual}.");
    }
}
