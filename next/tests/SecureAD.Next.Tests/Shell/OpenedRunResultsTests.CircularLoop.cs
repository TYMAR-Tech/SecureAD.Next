using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("self")]
    [InlineData("pair")]
    [InlineData("overlap")]
    [InlineData("member-of")]
    [InlineData("cross-domain")]
    [InlineData("partial-input")]
    public void CircularLoopShowsSourceBackedContainingGroupToMemberAndCloses(string variant)
    {
        var directory = CircularGroupMembershipTests.FindingsRun(variant);
        CircularMembershipEvidence original;
        using (var reader = JudgementReader.Open(directory).Value)
            original = Assert.IsType<CircularMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            var read = source.ReadCircularMembershipLoop(directory, row.Reference!.Value, null);
            Assert.True(read.IsSuccess, read.Error?.Description);
            var loop = read.Value;
            Assert.True(loop.Context.Matches(row)); Assert.True(loop.IsExpectedPage(null));
            Assert.Equal(original.InventoryComplete, loop.Context.InventoryComplete);
            Assert.Equal(variant == "overlap", loop.HasOtherLoops);
            Assert.Null(loop.Next);
            Assert.Equal(loop.Steps[0].Link.ContainingGroup, loop.Steps[^1].Link.Member);
            Assert.All(loop.Steps, step => Assert.Contains(original.Links,
                link => link.GroupGuid == step.Link.ContainingGroup.ObjectGuid && link.MemberGuid == step.Link.Member.ObjectGuid
                    && link.Witnesses.Count == step.Link.WitnessCount));
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void CircularLoopPagesLongLoopsWithoutLosingTheirContinuationOrClosingLink()
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var first = source.ReadCircularMembershipLoop(directory, reference, null).Value;
        var last = source.ReadCircularMembershipLoop(directory, reference, first.Next).Value;
        Assert.Equal(57, first.StepCount); Assert.False(first.HasOtherLoops);
        Assert.Equal(50, first.Steps.Count); Assert.Equal(7, last.Steps.Count); Assert.Null(last.Next);
        Assert.Equal(first.LoopKey, last.LoopKey);
        Assert.Equal(first.Steps[^1].Link.Member, last.Steps[0].Link.ContainingGroup);
        Assert.Equal(first.Steps[0].Link.ContainingGroup, last.Steps[^1].Link.Member);
        Assert.Equal(Enumerable.Range(0, 57).Select(index => (long)index), first.Steps.Concat(last.Steps).Select(step => step.Position));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("component")]
    [InlineData("loop")]
    [InlineData("offset")]
    [InlineData("beyond")]
    public void CircularLoopRejectsCursorsForAnotherLoopOrSavedAnswer(string defect)
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var mark = source.ReadCircularMembershipLoop(directory, reference, null).Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() },
            "finding" => mark with { FindingId = mark.FindingId + 1 },
            "component" => mark with { ComponentKey = "cycle:" + new string('0', 64) },
            "loop" => mark with { LoopKey = new string('0', 64) },
            "offset" => mark with { Offset = 51 },
            _ => mark with { Offset = 100 },
        };
        Assert.False(source.ReadCircularMembershipLoop(directory, reference, mark).IsSuccess);
    }

    [Fact]
    public void CircularLoopDoesNotReadOriginalWitnessPayloadsForTheIllustration()
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        ChangeCoverageProof(directory, "UPDATE finding_circular_membership SET proof=json_set(proof,'$.Links[0].Witnesses[0].Value','unopened original payload')");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var read = source.ReadCircularMembershipLoop(directory, reference, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(50, read.Value.Steps.Count);
    }
}
