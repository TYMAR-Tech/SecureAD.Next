using System.Security.Cryptography;
using System.Text;
using SecureAD.Derivation;
using SecureAD.Evidence;
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
        // Version 17 checkpoints the published Derivation and Membership roles, root version and
        // persisted definitions. Observed from this build's writer, not a historical forest anchor.
        [17] = "135F8A5900F53B0976273B060BAFDD3C368FE17F0C6C907E4E8D717F8711CA26",
    };

    [Fact]
    public void TheStoredLayoutMatchesItsVersionCheckpoint()
    {
        var layout = PublishedAnalysisLayout.Create(AnalysisStoreKind.Derivation);
        AssertLayout(layout);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Derivation, "ALTER TABLE protected_principal ADD COLUMN unversioned TEXT")]
    [InlineData(StoreSegmentRole.Derivation, "DROP INDEX ix_nesting_edge_member")]
    [InlineData(StoreSegmentRole.Derivation, "CREATE TABLE unversioned (id INTEGER PRIMARY KEY)")]
    [InlineData(StoreSegmentRole.Derivation, "ALTER TABLE derivation ADD COLUMN unversioned TEXT")]
    [InlineData(StoreSegmentRole.Membership, "ALTER TABLE principal ADD COLUMN unversioned TEXT")]
    [InlineData(StoreSegmentRole.Membership, "DROP INDEX ix_nesting_edge_member")]
    [InlineData(StoreSegmentRole.Membership, "CREATE TABLE unversioned (id INTEGER PRIMARY KEY)")]
    [InlineData(StoreSegmentRole.Membership, "ALTER TABLE derivation ADD COLUMN unversioned TEXT")]
    public void TheCheckpointRejectsAnUnversionedLayoutChange(StoreSegmentRole role, string mutation)
    {
        var layout = PublishedAnalysisLayout.Create(AnalysisStoreKind.Derivation);
        AssertLayout(layout);
        layout.Execute(role, mutation);
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => AssertLayout(layout));
        Assert.Contains("layout changed without a new version checkpoint", error.Message);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheCheckpointRejectsMovingAnUnchangedDefinitionToAnotherProduct(bool index)
    {
        var layout = PublishedAnalysisLayout.Create(AnalysisStoreKind.Derivation);
        AssertLayout(layout);
        var before = layout.Roles.SelectMany(layout.Definitions).Order(StringComparer.Ordinal).ToArray();
        if (index) layout.MoveIndex(StoreSegmentRole.Membership, StoreSegmentRole.Derivation, "ix_browse_sid_id");
        else layout.MoveTable(StoreSegmentRole.Derivation, StoreSegmentRole.Membership, "protected_principal");
        Assert.Equal(before, layout.Roles.SelectMany(layout.Definitions).Order(StringComparer.Ordinal));
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => AssertLayout(layout));
        Assert.Contains("layout changed without a new version checkpoint", error.Message);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Derivation, "schema_version=0")]
    [InlineData(StoreSegmentRole.Derivation, "evidence_seal='foreign evidence'")]
    [InlineData(StoreSegmentRole.Derivation, "derivation_generation_id='foreign generation'")]
    [InlineData(StoreSegmentRole.Membership, "schema_version=0")]
    [InlineData(StoreSegmentRole.Membership, "evidence_seal='foreign evidence'")]
    [InlineData(StoreSegmentRole.Membership, "derivation_generation_id='foreign generation'")]
    public void TheCheckpointRejectsAChangedProductBinding(StoreSegmentRole role, string change)
    {
        var layout = PublishedAnalysisLayout.Create(AnalysisStoreKind.Derivation);
        AssertLayout(layout);
        Assert.Equal(1, layout.Execute(role, "UPDATE derivation SET " + change));
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => AssertLayout(layout));
        Assert.Contains("Published layout binding changed", error.Message);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Derivation, "DELETE FROM derivation")]
    [InlineData(StoreSegmentRole.Membership, "DELETE FROM derivation")]
    [InlineData(StoreSegmentRole.Membership, "INSERT INTO derivation SELECT * FROM derivation")]
    public void TheCheckpointRequiresExactlyOneProductHeader(StoreSegmentRole role, string mutation)
    {
        var layout = PublishedAnalysisLayout.Create(AnalysisStoreKind.Derivation);
        AssertLayout(layout);
        Assert.Equal(1, layout.Execute(role, mutation));
        var error = Assert.Throws<Xunit.Sdk.TrueException>(() => AssertLayout(layout));
        Assert.Contains("Published layout binding changed", error.Message);
    }

    [Theory]
    [InlineData("root-version")]
    [InlineData("root-generation")]
    [InlineData("root-evidence")]
    [InlineData("missing-role")]
    [InlineData("duplicate-role")]
    [InlineData("product-version")]
    [InlineData("product-generation")]
    [InlineData("product-file")]
    [InlineData("summary")]
    public void NativeDeclarationsRejectChangedBindings(string change)
    {
        var layout = PublishedAnalysisLayout.Create(AnalysisStoreKind.Derivation);
        AssertLayout(layout);
        layout.ChangeDeclaration(change);
        var error = Assert.Throws<Xunit.Sdk.TrueException>(layout.CheckDeclarations);
        Assert.Contains("Published layout binding changed", error.Message);
    }

    private static void AssertLayout(PublishedAnalysisLayout layout)
    {
        var actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(layout.Read())));
        Assert.True(Layouts.TryGetValue(DerivationSchema.Version, out var expected),
            $"Schema {DerivationSchema.Version} needs a recorded native layout checkpoint; actual {actual}.");
        Assert.True(string.Equals(expected, actual, StringComparison.Ordinal),
            $"Schema {DerivationSchema.Version} layout changed without a new version checkpoint. Expected {expected}; actual {actual}.");
    }
}
