using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(0, 1)]
    [InlineData(51, 51)]
    public void GmsaReaderPagesUseSavedWholeFindingCountsAndDoNotOpenUnrelatedStores(int count, int expected)
    {
        var directory = GmsaPasswordReaderReadTests.Published(count);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            var first = source.ReadGmsaPasswordReaders(directory, row.Reference!.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal(expected, first.Value.Context.HolderCount);
            Assert.Equal(count == 0 ? 1 : count, first.Value.Context.OriginalEntryCount);
            Assert.Equal(Math.Min(50, expected), first.Value.Holders.Count);
            Assert.True(first.Value.Context.EvidenceIsComplete);
            if (expected > 50)
            {
                var last = source.ReadGmsaPasswordReaders(directory, row.Reference.Value, first.Value.Next);
                Assert.True(last.IsSuccess, last.Error?.Description);
                Assert.Equal(50, Assert.Single(last.Value.Holders).Ordinal);
                Assert.Equal(expected, last.Value.Context.HolderCount);
                Assert.True(first.Value.Context.SameQuestion(last.Value.Context));
                Assert.Null(last.Value.Next);
            }
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("account")]
    [InlineData("coverage")]
    [InlineData("missing-holder")]
    [InlineData("broad-name")]
    public void GmsaReaderSelectedReadRefusesMissingWrongOrContradictorySavedFacts(string defect)
    {
        var directory = GmsaPasswordReaderReadTests.Published();
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_gmsa_reader_holder; DELETE FROM finding_gmsa_reader",
            "generation" => "UPDATE finding_gmsa_reader SET generation='not the selected generation'",
            "account" => "UPDATE finding_gmsa_reader SET context=json_set(context,'$.ObjectGuid','00000000-0000-0000-0000-000000000999')",
            "coverage" => "UPDATE finding_gmsa_reader SET context=json_set(context,'$.EvidenceIsComplete',json('false'))",
            "missing-holder" => "DELETE FROM finding_gmsa_reader_holder",
            _ => "UPDATE finding_gmsa_reader SET context=json_set(context,'$.BroadName','Another identity')",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadGmsaPasswordReaders(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedGmsaPasswordReaders.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("account")]
    [InlineData("negative")]
    [InlineData("past-end")]
    public void GmsaReaderContinuationCannotCrossSavedQuestions(string defect)
    {
        var directory = GmsaPasswordReaderReadTests.Published();
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var position = new GmsaPasswordReaderMark(row.Reference!.Value.GenerationId, row.Reference.Value.FindingId, row.ObjectGuid, 0);
        position = defect switch
        {
            "generation" => position with { GenerationId = Guid.NewGuid() },
            "finding" => position with { FindingId = position.FindingId + 1 },
            "account" => position with { ObjectGuid = Guid.NewGuid() },
            "negative" => position with { Ordinal = -1 },
            _ => position with { Ordinal = 1000 },
        };
        Assert.False(source.ReadGmsaPasswordReaders(directory, row.Reference.Value, position).IsSuccess);
    }

    [Fact]
    public void GmsaReaderBrowsingDoesNotReparseTheOriginalProof()
    {
        var directory = GmsaPasswordReaderReadTests.Published();
        ChangeCoverageProof(directory, "UPDATE finding_gmsa_reader SET proof='not a readable full proof'");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadGmsaPasswordReaders(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.True(read.Value.Context.Matches(row));
        Assert.Single(read.Value.Holders);
    }
}
