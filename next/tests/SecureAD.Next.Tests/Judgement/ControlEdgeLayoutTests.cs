using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ControlEdgeLayoutTests
{
    // Recorded from the actual published ad.lab schema-15 store, not generated from the test's DDL.
    // Add a checkpoint for a new version; never replace this one to bless an unversioned change.
    private static readonly IReadOnlyDictionary<int, string> Layouts = new Dictionary<int, string>
    {
        [15] = "DD3895257D39B029C04ABC2B35DA5B27102485A75A6BF276FE32F5FE5B41ECD4",
        // Schema 16 changes capability semantics, not DDL; the independent schema-15 layout remains the anchor.
        [16] = "DD3895257D39B029C04ABC2B35DA5B27102485A75A6BF276FE32F5FE5B41ECD4",
        [17] = "FAF24769514E72DE2678D259113840E0895FEAB05E97169F507C2EE907C0E523",
        // Schema 18 adds self_membership_discovery. Recorded from this build's published layout
        // rather than an external store, so it detects later unversioned drift but is not an
        // independent anchor the way the schema-15 value is.
        [18] = "D7F06AA5FB0ECA8E137F13E92ECEE979A19BAC3E8E59C6E1CF2F95A0C2CA8CBC",
        // Schema 19 adds reset capability semantics, not DDL; retain the schema-18 layout checkpoint.
        [19] = "D7F06AA5FB0ECA8E137F13E92ECEE979A19BAC3E8E59C6E1CF2F95A0C2CA8CBC",
        // Schema 20 adds key-credential write semantics and the property-scope safeguard, not DDL.
        [20] = "D7F06AA5FB0ECA8E137F13E92ECEE979A19BAC3E8E59C6E1CF2F95A0C2CA8CBC",
        // Schema 21 adds replication semantics; existing control/proof tables are unchanged.
        [21] = "D7F06AA5FB0ECA8E137F13E92ECEE979A19BAC3E8E59C6E1CF2F95A0C2CA8CBC",
        // Schema 22 adds ownership semantics and structured owner-source proof in the existing proof table.
        [22] = "D7F06AA5FB0ECA8E137F13E92ECEE979A19BAC3E8E59C6E1CF2F95A0C2CA8CBC",
        // Schema 23 stores full-control source/proof/support and a separate object assessment manifest.
        // Recorded from this build's observed layout, not an external historical anchor.
        [23] = "049DB54C430BFFEC233CF89D36E888DABDF4858E281FA94C758E7377FBF177D7",
        // Schema 24 adds member attribution; observed from this build, not a historical forest.
        [24] = "1C01DAC6A8A39F345A696C0B7C39119F6ED0F13C95786DF5BD642CBEB606ACFF",
        // Schema 25 shares exact target-bound permission values; observed from this build.
        [25] = "4D3FB7B8C3ECE49F50D06B134E32EAC5CBC754A9A5324C95662D841A7F851373",
        // Schema 26 adds automatic ownership scope and coverage; observed from this build under 0114.
        [26] = "AF47D06ABD44412895EB9BBE5799BC48D065D5638D32959CECF497F88B6881A4",
        // Schema 27 shares explanations and complete routes; observed under 0115, not a historical anchor.
        [27] = "B7CA7DBFC045647A5211E35E833C92626A712383300D0AC2C14D84E49C1E5ADF",
        // Schema 28 re-anchors ownership_relation to a capture-backed witness so a discovered route
        // need not reference a control edge that discovery-first ordering has not derived yet.
        // Observed under 0116 from this build, not a historical anchor.
        [28] = "F7B1CD880966048DD15A3DE28D23C6E6D7B202481A1C6F7F2F5A4C33D3FC4FAA",
    };

    [Fact]
    public void JudgementLayoutMatchesItsIndependentlyRecordedVersion()
    {
        using var connection = Create();
        Check(connection);
    }

    [Theory]
    [InlineData("ALTER TABLE control_edge ADD COLUMN unversioned TEXT")]
    [InlineData("DROP INDEX ix_control_holder")]
    [InlineData("DROP INDEX ux_control_identity")]
    [InlineData("ALTER TABLE self_membership_assessment ADD COLUMN unversioned TEXT")]
    [InlineData("DROP INDEX ux_self_membership_identity")]
    [InlineData("ALTER TABLE self_membership_discovery ADD COLUMN unversioned TEXT")]
    [InlineData("DROP TABLE self_membership_discovery")]
    [InlineData("DROP TABLE full_control_support")]
    [InlineData("DROP INDEX ux_full_control_identity")]
    [InlineData("ALTER TABLE full_control_source ADD COLUMN unversioned TEXT")]
    [InlineData("ALTER TABLE permission_entry ADD COLUMN unversioned TEXT")]
    [InlineData("DROP TABLE full_control_source_entry")]
    [InlineData("ALTER TABLE ownership_audit ADD COLUMN unversioned TEXT")]
    [InlineData("ALTER TABLE ownership_target ADD COLUMN unversioned TEXT")]
    [InlineData("DROP TABLE ownership_seed")]
    [InlineData("DROP TABLE ownership_relation")]
    public void LayoutCheckpointRejectsUnversionedChanges(string mutation)
    {
        using var connection = Create();
        Check(connection);
        using var command = connection.CreateCommand();
        command.CommandText = mutation;
        command.ExecuteNonQuery();
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => Check(connection));
        Assert.Contains("layout changed", error.Message);
    }

    private static SqliteConnection Create()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        JudgementSchema.CreateTables(connection);
        JudgementSchema.CreateDeferredIndexes(connection);
        return connection;
    }
    private static void Check(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name";
        using var reader = command.ExecuteReader();
        var layout = new StringBuilder();
        while (reader.Read())
            for (var column = 0; column < reader.FieldCount; column++)
                layout.Append(reader.GetString(column).Replace("\r\n", "\n", StringComparison.Ordinal)).Append('\n');
        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(layout.ToString())));
        Assert.True(Layouts.TryGetValue(JudgementSchema.Version, out var expected), $"Missing schema {JudgementSchema.Version} checkpoint; actual {actual}.");
        Assert.True(actual == expected, $"Judgement layout changed without a new checkpoint: expected {expected}; actual {actual}.");
    }
}
