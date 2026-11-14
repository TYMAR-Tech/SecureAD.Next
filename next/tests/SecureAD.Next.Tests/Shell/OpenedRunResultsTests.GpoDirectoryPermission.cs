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
    public void GpoDirectoryPagesReadSelectedFactsOnlyWithUnrelatedStoresLocked(int count)
    {
        var directory = GpoDirectoryPermissionRunTests.Published(count);
        var before = CoverageFiles(directory);
        using var checks = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
            Assert.Equal(2, rows.Count);
            Assert.Equal(0L, checks.Heavy);
            foreach (var row in rows)
            {
                var first = source.ReadGpoDirectoryPermission(directory, row.Reference!.Value, null);
                Assert.True(first.IsSuccess, first.Error?.Description);
                Assert.True(first.Value.Context.Matches(row));
                Assert.Equal(count, first.Value.Context.EntryCount);
                Assert.Equal(Math.Min(50, count), first.Value.Entries.Count);
                if (count > 50)
                {
                    var last = source.ReadGpoDirectoryPermission(directory, row.Reference.Value, first.Value.Next);
                    Assert.True(last.IsSuccess, last.Error?.Description);
                    Assert.Equal(50, Assert.Single(last.Value.Entries).Ordinal);
                    Assert.Null(last.Value.Next);
                    Assert.True(first.Value.Context.SameQuestion(last.Value.Context));
                }
            }
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (checks.Count("permission"), checks.Count("path"),
                checks.Count("facts"), checks.Count("evidence"), checks.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("target")]
    [InlineData("holder")]
    [InlineData("missing-entry")]
    [InlineData("coverage")]
    public void GpoDirectoryReadRefusesMissingOrCrossBoundSavedFacts(string defect)
    {
        var directory = GpoDirectoryPermissionRunTests.Published();
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_gpo_directory_entry; DELETE FROM finding_gpo_directory",
            "generation" => "UPDATE finding_gpo_directory SET generation='not the selected generation'",
            "target" => "UPDATE finding_gpo_directory SET context=json_set(context,'$.Target.ObjectGuid','00000000-0000-0000-0000-000000000999')",
            "holder" => "UPDATE finding_gpo_directory SET context=json_set(context,'$.HolderSid','S-1-5-21-1-2-3-1600')",
            "missing-entry" => "DELETE FROM finding_gpo_directory_entry WHERE selected=1",
            _ => "UPDATE finding_gpo_directory SET context=json_set(context,'$.EvidenceIsComplete',json('false'))",
        });
        using var source = new BundleAssetSource();
        var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
        Assert.Equal(2, rows.Count);
        foreach (var row in rows)
        {
            var read = source.ReadGpoDirectoryPermission(directory, row.Reference!.Value, null);
            Assert.False(read.IsSuccess);
        }
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("target")]
    [InlineData("negative")]
    [InlineData("past-end")]
    public void GpoDirectoryContinuationCannotCrossSavedQuestions(string defect)
    {
        var directory = GpoDirectoryPermissionRunTests.Published(51);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings,
            row => row.RuleId == "SEC-080");
        var first = source.ReadGpoDirectoryPermission(directory, row.Reference!.Value, null);
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
        Assert.False(source.ReadGpoDirectoryPermission(directory, row.Reference.Value, mark).IsSuccess);
    }

    [Fact]
    public void GpoDirectoryBrowsingDoesNotReconstructOriginalProofOrReplayPermissions()
    {
        var directory = GpoDirectoryPermissionRunTests.Published();
        ChangeCoverageProof(directory, "UPDATE finding_gpo_directory SET proof='not a full readable permission proof'");
        using var source = new BundleAssetSource();
        var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
        Assert.Equal(2, rows.Count);
        foreach (var row in rows)
        {
            var read = source.ReadGpoDirectoryPermission(directory, row.Reference!.Value, null);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.Single(read.Value.Entries);
        }
    }
}
