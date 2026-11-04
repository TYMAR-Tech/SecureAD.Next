using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Fact]
    public void DuplicateSpnSelectionReadsOnlyTheRequestedConflictAndExplicitOriginals()
    {
        var directory = DuplicateSpnTests.FindingsRun();
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
            Assert.Equal(2, rows.Count);
            Assert.Equal(0L, counts.Heavy);
            var row = rows[0];
            Assert.Equal(SavedDuplicateSpn.Statement, row.Detail);
            var first = source.ReadDuplicateSpn(directory, row.Reference!.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal(2, first.Value.Owners.Count);
            Assert.Empty(first.Value.Registrations);
            var values = source.ReadDuplicateSpn(directory, row.Reference.Value,
                first.Value.Position with { Kind = DuplicateSpnPageKind.CapturedRegistrations });
            Assert.True(values.IsSuccess, values.Error?.Description);
            Assert.Equal(3, values.Value.Registrations.Count);
            Assert.Contains(values.Value.Registrations, value => value.Value == "http/WEB");
            var next = source.ReadDuplicateSpn(directory, row.Reference.Value, first.Value.NextSpn);
            Assert.True(next.IsSuccess, next.Error?.Description);
            Assert.Equal("LDAP/DC/DOMAIN", next.Value.MatchKey);
            Assert.Null(next.Value.NextSpn);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("subject")]
    public void DuplicateSpnSelectionRefusesMissingOrMisboundSavedFacts(string defect)
    {
        var directory = DuplicateSpnTests.FindingsRun();
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_duplicate_spn",
            "generation" => "UPDATE finding_duplicate_spn SET generation='not the selected generation'",
            _ => "UPDATE finding_duplicate_spn SET proof=json_set(proof,'$.SubjectGuid','11111111-2222-3333-4444-555555555555')",
        });
        using var source = new BundleAssetSource();
        var row = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings[0];
        var read = source.ReadDuplicateSpn(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedDuplicateSpn.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateSpnPositionsCannotCrossAffectedOwners()
    {
        var directory = DuplicateSpnTests.FindingsRun();
        using var source = new BundleAssetSource();
        var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
        var read = source.ReadDuplicateSpn(directory, rows[0].Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.False(source.ReadDuplicateSpn(directory, rows[1].Reference!.Value, read.Value.Position).IsSuccess);
    }
}
