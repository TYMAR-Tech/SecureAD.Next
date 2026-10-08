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
        // Schema 29 adds control_product.discovery_scoped, so a reader can tell a scoped count from a
        // forest-wide one instead of inferring it. Observed from this build.
        [29] = "1702E41D511FB64ED4DF4371A3FD6721788FA453096740E78B3EBEDCE8B5DC3C",
        // Schema 30 writes enum names rather than ordinals into every stored proof, per 0119. No DDL
        // changes, so the hash is deliberately identical to 29 and the version carries the whole
        // difference - this guard would pass unchanged if the bump had been forgotten, which is why
        // ProofSerializationGateTests holds the behavioural check.
        [30] = "1702E41D511FB64ED4DF4371A3FD6721788FA453096740E78B3EBEDCE8B5DC3C",
        // Schema 31 adds saved path inputs, fixed anchors and scoped discovery gaps. This is the
        // observed layout of the approved checkpoint, not an independent historical forest anchor.
        [31] = "9BCAD0674D3FA0CC96C2C303A839CD541C0348CD4057FFA5E750EEBE60F8EC38",
        // Schema 32 adds the saved path calculation and predecessor records. Observed from the
        // new build; all historical layouts above remain unchanged.
        [32] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 33 adds requester proof semantics inside the existing path certificate, not DDL.
        [33] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 34 adds own-account operation proof semantics; observed with the existing DDL.
        [34] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 35 adds ordinary member-write proof semantics; the observed DDL is unchanged.
        [35] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 36 adds combined membership-to-DACL proof semantics, not physical tables.
        [36] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 37 adds selection provenance inside the same certificate, not physical tables.
        [37] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 38 adds CA target/source semantics, with the same observed physical tables.
        [38] = "8ABB2495DA29836B56C18EF844E072446086470EEC05FDBB6D1EC3578708D7B5",
        // Schema 39 adds the saved classification payload to ownership_seed. Observed from the
        // approved new build, not an independent historical forest anchor; older hashes stay fixed.
        [39] = "A6B0B4ED6815AE2CCA67649C64698749291D7365AAB15C00A9DFFD23AD017B21",
        // Schema 40 adds the completed LAPS inventory and expected LAPS finding-route lengths.
        // Observed from this approved build; no historical layout value is replaced.
        [40] = "3738DBBD6C6022DC2025F4C9E78D87217304F9322B8E8F4B0FB074CF461ADF52",
        // Format 41 saves per-right classification and indexes shared entry lookup during production.
        // Observed from this approved build, not an independent historical forest anchor.
        [41] = "B5032FCEDCD701BA82CE5F8468154453FDE4A798974446E8C0C3BA4BA8C78C9B",
        // Format 42 stores each distinct reading once in permission_classification_reading and has
        // permission_classification_entry reference it, because the P-251 comparison found 240
        // distinct readings behind 209,032 entries and half the result file was the duplication.
        // Observed from this approved build, not an independent historical forest anchor.
        [42] = "297BED254604EC343AFD4F44FCF47788B3C3CF348692F7D42D776F7344F50B32",
        // Schema 43 stores each distinct access control entry once in permission_entry and links to
        // it, so the row loses target and ordinal, gains the entry_hash identity, and drops
        // ix_permission_entry_target_generation with the column it led on (P-279). Observed from this
        // approved build, not an independent historical forest anchor.
        [43] = "34228CFB43189731C38955C721DCFBD0A59EEC0BBAE6CA8862F0FE503194B1A7",
        // Schema 44 stores the shared form of a trustee, so S-1-5-10 is held as the catalogue's
        // name and resolved against the target on read (P-285). The observed DDL is unchanged -
        // permission_entry.name already existed and only its content differs - so this repeats 43's
        // value, the same way 33 through 38 repeated theirs. The version still had to move, because
        // every occurrence fingerprint is now taken over the shared form and a version 43 store's
        // would not verify: refused on version rather than reported as tampered proofs.
        [44] = "34228CFB43189731C38955C721DCFBD0A59EEC0BBAE6CA8862F0FE503194B1A7",
        // Schema 45 folds the reading's digest into the occurrence fingerprint so reading_id cannot
        // be repointed (P-283). Deliberately no new column - a separate binding would have cost 32
        // bytes on each of the production capture's 330,856,576 occurrences - so the observed DDL is
        // again unchanged and this repeats 43's value.
        [45] = "34228CFB43189731C38955C721DCFBD0A59EEC0BBAE6CA8862F0FE503194B1A7",
        // Schema 46 keys the saved permission classification per descriptor rather than per object
        // (P-280). Unlike 44 and 45 this one really does move the DDL: permission_classification_object
        // loses its descriptor JSON and entry_count and gains descriptor_id, availability and the
        // unreadable reason; permission_classification_descriptor and _value are new; and
        // permission_classification_entry loses target, position, fingerprint, right_count,
        // reading_id and both schema columns to become (descriptor_id, ordinal, entry_id)
        // WITHOUT ROWID. Observed from this approved build, not an independent historical anchor.
        [46] = "06F6363EC8C1E35C0A4255B2C0FE4382A09EB9BAE46588A084663CEB2F02F07C",
        // Observed from the format-47 build adding independent requester-risk records; older checkpoints are unchanged.
        [47] = "5D9F0069E035B69531D4B86C75F7F6E79752F19E0FCB90625EA9B139C4AF3A19",
        // Observed format-48 canonical requester proofs and SEC-071 publication; no earlier value is replaced.
        [48] = "F9E42384A1C323930DD733AD6BB5058129602EE68CB35CAE3EBD0EF1E3A25736",
        // Schema 49 changes nested requester proof semantics only; keep the schema-48 physical-layout anchor.
        [49] = "F9E42384A1C323930DD733AD6BB5058129602EE68CB35CAE3EBD0EF1E3A25736",
        // Observed format-50 layout adds the captured group-nesting admission witness; earlier values stay fixed.
        [50] = "041C226CA55863BADAF2CE5BFC13AFFA3E90A09039DB66355F476A8364172776",
        // Format 51 extends saved JSON proof semantics; the format-50 physical layout is unchanged.
        [51] = "041C226CA55863BADAF2CE5BFC13AFFA3E90A09039DB66355F476A8364172776",
        // Observed format-52 fragmented path proofs; every earlier layout checkpoint remains unchanged.
        [52] = "19981F6B762A37AF6D43D202124A8E87C974569FEAC3474F3661043BA3232235",
        // Format 53 changes source-fingerprint meaning, not the independently recorded format-52 layout.
        [53] = "19981F6B762A37AF6D43D202124A8E87C974569FEAC3474F3661043BA3232235",
        // Format 54 extends continuation proof semantics without changing the format-52 tables.
        [54] = "19981F6B762A37AF6D43D202124A8E87C974569FEAC3474F3661043BA3232235",
        // Observed format-55 distance rows and run-summary table; historical checkpoints are unchanged.
        [55] = "7BB6FE24F859A00998271E83B4F78AF88BFB010448A296CBDEE2545C49E494FB",
        // Observed format-56 best-route references; all earlier layout anchors remain unchanged.
        [56] = "EB0D05D46A889646CBCA9BF066D8389056D3EA8F66FACC09A120540CC6CE8F50",
        // Observed format-57 circular-membership finding evidence; earlier checkpoints remain unchanged.
        [57] = "C5B221893A7519DBA0F0AAA4954214603A9EF434E4864EF9FDA5ABF78AFF97B1",
        // Observed format-58 component-member filter references; retain the initial SEC-052 layout too.
        [58] = "DD53A6F98BABDB9D119F2BC2E929D0DC8F1F572D107B78331B6C5F147B5566E7",
        // Observed format-59 captured group browsing inventory; prior checkpoints remain unchanged.
        [59] = "3E3D77775421AA925A605003D349669A515E00DD0525079169BB9533589BA7CB",
        // Observed format-60 structural totals; all historical layout anchors remain unchanged.
        [60] = "B3BAE0EA13D16E442D28ED3F5928856CAEAF7C1F50FEEE7244D0281C5537E3E4",
        // Observed SEC-026 saved-evidence layout; historical versions remain unchanged.
        [61] = "2565E5A72A0599AC936672496D21F458F4C0A7AE6F47C5956BBDF029B459DD1C",
        // Observed shared path-proof layout; all earlier checkpoints remain unchanged.
        [62] = "71DD9CE407C92C3451A76E337A6B89E6136BDC51920B47534434063871B31F21",
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
