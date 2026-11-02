using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(51)]
    public void AttributeWritePermissionReadsOnlySelectedOriginalEntriesAndPreservesSavedResults(int count)
    {
        var descriptor = "O:SYG:SYD:" + string.Concat(Enumerable.Repeat("(A;;WP;;;S-1-5-21-1-2-3-1200)", count));
        var directory = AttributeWriteRuleTests.Published(descriptor);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
            var row = Assert.Single(rows, item => item.RuleId == "SEC-014");
            Assert.Equal(0L, counts.Heavy);
            Assert.Equal(SavedAttributeWritePermission.ScopeNoteForRule("SEC-014"), row.Detail);
            var first = source.ReadAttributeWritePermission(directory, row.Reference!.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal(Math.Min(50, count), first.Value.Entries.Count);
            Assert.All(first.Value.Entries, entry => Assert.Equal(SavedPropertyWriteScope.AllProperties, entry.Scope));
            if (count > 50)
            {
                var last = source.ReadAttributeWritePermission(directory, row.Reference.Value, first.Value.Next);
                Assert.True(last.IsSuccess, last.Error?.Description);
                Assert.Equal(50, Assert.Single(last.Value.Entries).Ordinal);
                Assert.Null(last.Value.Next);
                Assert.Equal(first.Value.Context, last.Value.Context);
            }
            Assert.True(source.ReadAttributeWritePermission(directory, row.Reference.Value, null).IsSuccess);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("wrong-family")]
    [InlineData("missing-entry")]
    [InlineData("entry-generation")]
    public void AttributeWritePermissionRefusesMissingOrInconsistentSavedFacts(string defect)
    {
        var directory = AttributeWriteRuleTests.FindingsRun();
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_attribute_write_entry; DELETE FROM finding_attribute_write",
            "generation" => "UPDATE finding_attribute_write SET generation='not the selected generation'",
            "wrong-family" => "UPDATE finding_attribute_write SET proof=replace(proof,'ResourceBasedConstrainedDelegation','ServicePrincipalName')",
            "entry-generation" => "UPDATE permission_entry SET generation='not the selected generation'",
            _ => "DELETE FROM finding_attribute_write_entry WHERE finding_id=(SELECT MIN(finding_id) FROM finding_attribute_write)",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings, item => item.RuleId == "SEC-014");
        var read = source.ReadAttributeWritePermission(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedAttributeWritePermission.InvalidDetailsForRule("SEC-014"), read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("target")]
    [InlineData("negative")]
    [InlineData("past-end")]
    public void AttributeWritePermissionContinuationCannotCrossFindingTargetOrGeneration(string defect)
    {
        var directory = AttributeWriteRuleTests.Published("O:SYG:SYD:" + string.Concat(Enumerable.Repeat("(A;;WP;;;S-1-5-21-1-2-3-1200)", 51)));
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings, item => item.RuleId == "SEC-014");
        var first = source.ReadAttributeWritePermission(directory, row.Reference!.Value, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var mark = first.Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "finding" => mark with { FindingId = mark.FindingId + 1 },
            "target" => mark with { TargetGuid = Guid.NewGuid() },
            "negative" => mark with { Ordinal = -1 },
            _ => mark with { Ordinal = 1000 },
        };
        Assert.False(source.ReadAttributeWritePermission(directory, row.Reference.Value, mark).IsSuccess);
    }
}
