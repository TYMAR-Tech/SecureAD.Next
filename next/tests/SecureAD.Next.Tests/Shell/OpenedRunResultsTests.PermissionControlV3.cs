using System.Text.Json;
using System.Text.Json.Nodes;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("(A;;WD;;;WD)", PermissionControlState.Established, PermissionControlState.NotEstablished, PermissionControlState.NotEstablished)]
    [InlineData("(A;;WO;;;WD)", PermissionControlState.NotEstablished, PermissionControlState.Established, PermissionControlState.NotEstablished)]
    // MS-ADTS 6.1.3's stored specific mapping, not an unmapped generic bit in a synthetic descriptor.
    [InlineData("(A;;0x000f01ff;;;WD)", PermissionControlState.Established, PermissionControlState.Established, PermissionControlState.Established)]
    [InlineData("(OD;;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;;WD)(A;;0x000f01ff;;;WD)",
        PermissionControlState.Established, PermissionControlState.Established, PermissionControlState.NotEstablished)]
    [InlineData(null, PermissionControlState.Established, PermissionControlState.Established, PermissionControlState.Established)]
    public void PermissionControlV3PreparedStatesAreTheActualSavedCalculation(string? entries,
        PermissionControlState modify, PermissionControlState owner, PermissionControlState full)
    {
        var directory = PermissionControlCalculationTests.Saved(entries);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
        var read = source.ReadPermissionControl(directory, row.Reference!.Value);
        Assert.True(read.IsSuccess, read.Error?.Description);
        var header = Assert.IsType<SavedPermissionControlAssessment>(read.Value.Assessment);
        Assert.Equal(modify, header.ModifyPermissions);
        Assert.Equal(owner, header.ChangeOwner);
        Assert.Equal(full, header.FullControl);
        using var reader = JudgementReader.Open(directory).Value;
        var calculation = reader.ReadPermissionControlCalculation(row.Reference.Value).Value.Calculation;
        Assert.Equal(calculation.ModifyPermissions.State, header.ModifyPermissions);
        Assert.Equal(calculation.ChangeOwner.State, header.ChangeOwner);
        Assert.Equal(calculation.FullControl.State, header.FullControl);
        Assert.Equal(calculation.OwnerTransition, header.OwnerTransition);
        Assert.Equal(calculation.IsComplete, header.IsComplete);
        Assert.Equal(entries is null, header.DescriptorState == SecureAD.Kernel.Security.DaclState.Null);
        Assert.True(read.Value.Matches(row));
    }

    [Fact]
    public void PermissionControlV3ReadsPreparedHeaderWhileCalculationAndUnrelatedProductsAreUnreadable()
    {
        var directory = PermissionControlCalculationTests.Saved("(A;;WD;;;WD)");
        ChangeCoverageProof(directory, "UPDATE finding_object_takeover_calculation SET payload='not a readable calculation'");
        var before = CoverageFiles(directory);
        using var source = new BundleAssetSource();
        using var counts = new FindingsVerificationCounts(directory);
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
            var read = source.ReadPermissionControl(directory, row.Reference!.Value);
            Assert.True(read.IsSuccess, read.Error?.Description);
            Assert.True(read.Value.Matches(row));
            Assert.Equal(3, read.Value.RuleVersion);
            Assert.Equal(PermissionControlState.Established, read.Value.Assessment!.ModifyPermissions);
            Assert.Equal(1L, read.Value.ChainCount);
            var page = source.ReadPermissionControlChain(directory, row.Reference.Value, null);
            Assert.True(page.IsSuccess, page.Error?.Description);
            Assert.True(page.Value.IsExpectedPage(null));
            Assert.Single(page.Value.Steps);
            Assert.Null(page.Value.Next);
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void PermissionControlV3HeaderUsesPreparedChainCountWithoutReadingUnrequestedSteps()
    {
        var directory = PermissionControlCalculationTests.Saved("(A;;WD;;;WD)");
        ChangeCoverageProof(directory, "DELETE FROM finding_object_takeover_path");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
        var read = source.ReadPermissionControl(directory, row.Reference!.Value);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(1L, read.Value.ChainCount);
        var page = source.ReadPermissionControlChain(directory, row.Reference.Value, null);
        Assert.False(page.IsSuccess);
        Assert.Contains(SavedPermissionControl.InvalidDetails, page.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    [InlineData("derivation-seal")]
    [InlineData("object")]
    [InlineData("target")]
    [InlineData("domain")]
    [InlineData("holder")]
    [InlineData("broad")]
    [InlineData("right")]
    [InlineData("transition")]
    [InlineData("count")]
    [InlineData("complete")]
    [InlineData("required-state")]
    public void PermissionControlV3RefusesMissingForeignOrContradictoryPreparedHeaders(string defect)
    {
        var directory = PermissionControlCalculationTests.Saved("(A;;WD;;;WD)");
        SavedPermissionControlAssessment header;
        using (var reader = JudgementReader.Open(directory).Value)
        {
            var row = Assert.Single(reader.ReadListPage(FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
            header = reader.ReadPermissionControl(row.Reference!.Value).Value.Assessment!;
        }
        var changed = defect switch
        {
            "generation" => header with { GenerationId = Guid.NewGuid() },
            "evidence" => header with { EvidenceSeal = new string('c', 64) },
            "derivation" => header with { DerivationGenerationId = Guid.NewGuid() },
            "derivation-seal" => header with { DerivationSeal = new string('d', 64) },
            "object" => header with { ObjectGuid = Guid.NewGuid() },
            "target" => header with { Target = "CN=Other,DC=contoso,DC=com" },
            "domain" => header with { ResourceDomain = "other.com" },
            "holder" => header with { HolderSid = "S-1-5-21-1-2-3-1200" },
            "broad" => header with { BroadSid = "S-1-5-11" },
            "right" => header with { ModifyPermissions = PermissionControlState.NotEstablished },
            "transition" => header with { OwnerTransition = PermissionControlState.Established },
            "count" => header with { ChainCount = 0 },
            "complete" => header with { HasLimitations = !header.HasLimitations },
            _ => header,
        };
        var json = JsonSerializer.SerializeToNode(changed, PermissionControlCalculationStorage.DisplayOptions)!;
        if (defect == "required-state") json.AsObject().Remove(nameof(SavedPermissionControlAssessment.ModifyPermissions));
        var payload = defect == "missing" ? "{}" : json.ToJsonString();
        ChangeCoverageProof(directory, "UPDATE finding_object_takeover_calculation SET display_header='"
            + payload.Replace("'", "''", StringComparison.Ordinal) + "'");
        using var source = new BundleAssetSource();
        var selected = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.About(SelfMembershipDiscoveryTests.TargetDn)).Value.Findings);
        var read = source.ReadPermissionControl(directory, selected.Reference!.Value);
        Assert.False(read.IsSuccess);
        Assert.Equal("Shell.SavedResultsInvalidEvidence", read.Error.Code);
    }
}
