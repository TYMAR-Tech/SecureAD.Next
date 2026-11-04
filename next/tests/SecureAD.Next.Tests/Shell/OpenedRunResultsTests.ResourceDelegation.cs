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
    public void ResourceDelegationUsesSavedProofAndIndexedCapturedNamesWithoutOtherAnalysis(int count)
    {
        var directory = ResourceDelegationReadTests.PublishedRun(count);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            Assert.Equal(SavedDelegationConfiguration.ResourceStatement, row.Detail);
            var first = source.ReadResourceDelegation(directory, row.Reference!.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal("Captured delegation holder", first.Value.Holders[0].Name);
            Assert.Equal("S-1-5-21-1-2-3-1100", first.Value.Holders[0].Sid);
            Assert.Equal(Math.Min(50, count), first.Value.Holders.Count);
            if (count == 51)
            {
                var last = source.ReadResourceDelegation(directory, row.Reference.Value, first.Value.Next);
                Assert.True(last.IsSuccess, last.Error?.Description);
                Assert.Equal("S-1-5-21-1-2-3-1150", Assert.Single(last.Value.Holders).Sid);
                Assert.Null(last.Value.Holders[0].Name);
                Assert.Null(last.Value.Next);
                Assert.Equal(first.Value.Context, last.Value.Context);
            }
            Assert.True(source.ReadResourceDelegation(directory, row.Reference.Value, null).IsSuccess);
            Assert.Equal((1L, 1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("navigation"),
                counts.Count("path"), counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void NullDaclDoesNotResolveOrInventAnEveryoneHolder()
    {
        var directory = ResourceDelegationReadTests.PublishedRun(0, nullDacl: true);
        using var counts = new FindingsVerificationCounts(directory);
        using var locks = new FindingsHeavyLocks(directory, permissionHeaders: true);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadResourceDelegation(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.True(read.Value.Context.HasNullDacl);
        Assert.Empty(read.Value.Holders);
        Assert.Null(read.Value.Next);
        Assert.Equal(0L, counts.Count("navigation"));
        Assert.Equal(1L, counts.Count("permission"));
    }

    [Fact]
    public void ConflictingCapturedNamesRemainAnExactUnresolvedSid()
    {
        var directory = ResourceDelegationReadTests.PublishedRun(1, ambiguousName: true);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadResourceDelegation(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        var holder = Assert.Single(read.Value.Holders);
        Assert.Equal("S-1-5-21-1-2-3-1100", holder.Sid);
        Assert.Null(holder.Name);
        Assert.Equal("Name not resolved from captured evidence.", holder.DisplayName);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("resource")]
    [InlineData("negative")]
    [InlineData("unaligned")]
    [InlineData("past-end")]
    public void ResourceHolderContinuationRemainsBoundToItsFindingResourceAndGeneration(string defect)
    {
        var directory = ResourceDelegationReadTests.PublishedRun(51);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var first = source.ReadResourceDelegation(directory, row.Reference!.Value, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var mark = first.Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "finding" => mark with { FindingId = mark.FindingId + 1 },
            "resource" => mark with { ResourceGuid = Guid.NewGuid() },
            "negative" => mark with { Offset = -50 },
            "unaligned" => mark with { Offset = 1 },
            _ => mark with { Offset = 100 },
        };
        Assert.False(source.ReadResourceDelegation(directory, row.Reference.Value, mark).IsSuccess);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("wrong-family")]
    public void ResourceDelegationRefusesMissingOrInconsistentSavedFacts(string defect)
    {
        var directory = ResourceDelegationReadTests.PublishedRun();
        ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_delegation_configuration",
            "generation" => "UPDATE finding_delegation_configuration SET generation='not the selected generation'",
            _ => "UPDATE finding_delegation_configuration SET proof=replace(proof,'ResourceBased','Constrained')",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadResourceDelegation(directory, row.Reference!.Value, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedDelegationConfiguration.ResourceInvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void ResourceDelegationCannotSubstituteTheConstrainedFamily()
    {
        var directory = ConstrainedDelegationReadTests.PublishedRun(1);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        Assert.False(source.ReadResourceDelegation(directory, row.Reference!.Value, null).IsSuccess);
        Assert.True(source.ReadConstrainedDelegation(directory, row.Reference.Value, null).IsSuccess);
    }
}
