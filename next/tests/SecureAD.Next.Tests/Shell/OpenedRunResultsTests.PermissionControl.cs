using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(ObjectTakeoverRight.GenericAll, false, false)]
    [InlineData(ObjectTakeoverRight.GenericAll, true, true)]
    [InlineData(ObjectTakeoverRight.WriteDacl, false, true)]
    [InlineData(ObjectTakeoverRight.WriteDacl, true, false)]
    [InlineData(ObjectTakeoverRight.WriteOwner, false, false)]
    [InlineData(ObjectTakeoverRight.WriteOwner, true, true)]
    public void PermissionControlReadsOnlySelectedSavedHeaderAndRequestedIndexedChain(ObjectTakeoverRight right, bool inherited, bool complete)
    {
        var directory = PermissionControlRun(right, inherited, complete);
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(SavedPermissionControl.Statement, row.Detail);
            Assert.Equal(complete, row.EvidenceIsComplete);
            var answer = source.ReadPermissionControl(directory, row.Reference!.Value);
            Assert.True(answer.IsSuccess, answer.Error?.Description);
            Assert.True(answer.Value.Matches(row));
            Assert.Equal(right, answer.Value.ReportedRight); Assert.Equal(inherited, answer.Value.InheritedContext);
            Assert.Equal(complete, answer.Value.ExpansionWasComplete);
            Assert.Equal(55L, answer.Value.ChainCount);
            var first = source.ReadPermissionControlChain(directory, row.Reference.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description); Assert.True(first.Value.IsExpectedPage(null));
            Assert.Equal(50, first.Value.Steps.Count); Assert.Equal("S-1-5-21-1-2-3-1200", first.Value.Steps[0].Sid);
            Assert.Equal(49L, first.Value.Next!.Value.Ordinal);
            var last = source.ReadPermissionControlChain(directory, row.Reference.Value, first.Value.Next);
            Assert.True(last.IsSuccess, last.Error?.Description); Assert.True(last.Value.IsExpectedPage(first.Value.Next));
            Assert.Equal(5, last.Value.Steps.Count); Assert.Null(last.Value.Next);
            Assert.Equal("S-1-5-21-1-2-3-513", last.Value.Steps[^1].Sid);
            Assert.Equal("Saved step 50", last.Value.Steps[0].Name);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void PermissionControlHeaderDoesNotHydrateAnUnrequestedMiddleChainValue()
    {
        var directory = PermissionControlRun(ObjectTakeoverRight.WriteDacl, false, true);
        ChangeCoverageProof(directory, "UPDATE finding_object_takeover_path SET sid='unreadable saved identifier' WHERE ordinal=1");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        Assert.True(source.ReadPermissionControl(directory, reference).IsSuccess);
        var read = source.ReadPermissionControlChain(directory, reference, null);
        Assert.False(read.IsSuccess); Assert.Contains(SavedPermissionControl.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("holder")]
    [InlineData("broad")]
    [InlineData("name")]
    [InlineData("right")]
    [InlineData("context")]
    [InlineData("complete")]
    [InlineData("missing")]
    [InlineData("chain")]
    public void PermissionControlRefusesMalformedOrMissingSavedFacts(string defect)
    {
        var directory = PermissionControlRun(ObjectTakeoverRight.WriteDacl, false, true);
        ChangeCoverageProof(directory, defect switch
        {
            "holder" => "UPDATE finding_object_takeover SET trustee_sid='invalid SID'",
            "broad" => "UPDATE finding_object_takeover SET broad_principal_sid='S-1-5-21-1-2-3-999'",
            "name" => "UPDATE finding_object_takeover SET trustee_name=''",
            "right" => "UPDATE finding_object_takeover SET takeover_right='GenericWrite'",
            "context" => "UPDATE finding_object_takeover SET inherited_from=''",
            "complete" => "UPDATE finding_object_takeover SET expansion_was_complete=2",
            "chain" => "DELETE FROM finding_object_takeover_path",
            _ => "DELETE FROM finding_object_takeover",
        });
        using var source = new BundleAssetSource();
        var row = source.ReadFindingsList(directory, FindingsQuery.Everything());
        if (defect is "complete" or "missing")
        {
            Assert.False(row.IsSuccess); Assert.Contains("no valid completeness header", row.Error.Description, StringComparison.Ordinal);
        }
        else
        {
            var result = source.ReadPermissionControl(directory, Assert.Single(row.Value.Findings).Reference!.Value);
            Assert.False(result.IsSuccess); Assert.Contains(SavedPermissionControl.InvalidDetails, result.Error.Description, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("object")]
    [InlineData("ordinal")]
    [InlineData("beyond")]
    public void PermissionControlChainRefusesForeignOrMisalignedContinuations(string defect)
    {
        var directory = PermissionControlRun(ObjectTakeoverRight.WriteDacl, false, true);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var mark = source.ReadPermissionControlChain(directory, reference, null).Value.Next!.Value;
        mark = defect switch
        {
            "generation" => mark with { GenerationId = Guid.NewGuid() }, "finding" => mark with { FindingId = mark.FindingId + 1 },
            "object" => mark with { ObjectGuid = Guid.NewGuid() }, "ordinal" => mark with { Ordinal = 50 },
            _ => mark with { Ordinal = long.MaxValue },
        };
        Assert.False(source.ReadPermissionControlChain(directory, reference, mark).IsSuccess);
    }

    [Fact]
    public void PermissionControlDirectAssignmentCanHaveOneUnnamedSavedIdentity()
    {
        var directory = PermissionControlRun(ObjectTakeoverRight.WriteOwner, false, false, direct: true);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var header = source.ReadPermissionControl(directory, reference).Value;
        var page = source.ReadPermissionControlChain(directory, reference, null).Value;
        Assert.Equal(header.HolderSid, header.BroadSid); Assert.Equal(1L, header.ChainCount);
        Assert.Null(Assert.Single(page.Steps).Name);
        Assert.Equal("Name not resolved from saved evidence.", page.Steps[0].DisplayName);
        Assert.Null(page.Next); Assert.False(header.ExpansionWasComplete);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PermissionControlCannotUseAnotherGenerationOrMissingFinding(bool generation)
    {
        var directory = PermissionControlRun(ObjectTakeoverRight.WriteDacl, false, true);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = long.MaxValue };
        var read = source.ReadPermissionControl(directory, reference);
        Assert.False(read.IsSuccess);
        Assert.Equal(generation ? "Evidence.FindingSelectionChanged" : "Evidence.FindingNotFound", read.Error.Code);
    }

    private static string PermissionControlRun(ObjectTakeoverRight right, bool inherited, bool complete, bool direct = false)
    {
        var directory = LapsBundle.BuildMany([(FirstDn, null, null, null, null, 512)], DateTimeOffset.UnixEpoch);
        using var captured = BundleReader.Open(directory).Value;
        const string broad = "S-1-5-21-1-2-3-513";
        var steps = direct ? new[] { new PathStep(broad, null) } : Enumerable.Range(0, 55)
            .Select(index => new PathStep(index == 54 ? broad : "S-1-5-21-1-2-3-" + (1200 + index), "Saved step " + index)).ToArray();
        var evidence = new ObjectTakeoverEvidence(steps[0].Sid, direct ? null : "Recorded holder", broad,
            direct ? null : "Recorded broad identity", steps, right, inherited ? "00000000-0000-0000-0000-000000000001" : null, complete);
        var finding = new Finding("SEC-060", 2, Severity.High,
            new(FindingSubjectKind.Account, BroadPrincipalCanTakeOverObject.SubjectKeyFor(broad)),
            Assert.IsType<Guid>(captured.ReadObjectAttributes(FirstDn)!.ObjectGuid), FirstDn, "ad.lab", "computer",
            "Original takeover prose must not be loaded.", EvidenceCompleteness.Complete, evidence) { PrincipalName = "Recorded broad identity" };
        WriteFindingsFixture(directory, [finding]);
        return directory;
    }
}
