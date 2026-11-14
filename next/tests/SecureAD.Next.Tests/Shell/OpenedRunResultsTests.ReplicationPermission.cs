using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(53, false)]
    [InlineData(0, true)]
    public void ReplicationPermissionReadsOriginalBoundPagesWithoutMembershipOrMeaningHydration(int repeated, bool nullDacl)
    {
        var directory = ReplicationPermissionRuleTests.FindingDetailsRun(repeated, nullDacl);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Where(row => row.RuleId == "SEC-002"));
            Assert.Equal(0L, counts.Heavy);
            var first = source.ReadReplicationPermission(directory, row.Reference!.Value, null);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal(nullDacl ? 0 : Math.Min(50, repeated + 2), first.Value.Entries.Count);
            Assert.Equal(nullDacl, first.Value.Context.HasNullDacl);
            Assert.Equal(nullDacl ? 0 : repeated + 2, first.Value.Context.OriginalEntryCount);
            var entries = first.Value.Entries.ToList(); var next = first.Value.Next;
            while (next is { } position)
            {
                var read = source.ReadReplicationPermission(directory, row.Reference.Value, position);
                Assert.True(read.IsSuccess, read.Error?.Description);
                Assert.InRange(read.Value.Entries.Count, 1, 50);
                Assert.Equal(first.Value.Context, read.Value.Context);
                entries.AddRange(read.Value.Entries); next = read.Value.Next;
            }
            Assert.Equal(Enumerable.Range(0, nullDacl ? 0 : repeated + 2), entries.Select(entry => entry.Ordinal));
            Assert.True(entries.All(entry => entry.Scope is "Replicating Directory Changes" or "Replicating Directory Changes All"));
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("root")]
    [InlineData("holder")]
    [InlineData("expectedness")]
    [InlineData("check")]
    [InlineData("entry-generation")]
    public void ReplicationPermissionRefusesBrokenMetadataAndOriginalBindings(string defect)
    {
        var directory = ReplicationPermissionRuleTests.FindingsRun();
        ChangeCoverageProof(directory, defect switch
        {
            "generation" => $"UPDATE finding_replication_permission SET generation='{Guid.NewGuid():D}'",
            "root" => $"UPDATE control_edge SET target_guid='{Guid.NewGuid():D}'",
            "holder" => "UPDATE control_edge SET holder_sid='S-1-5-21-1-2-3-1300'",
            "expectedness" => "UPDATE control_edge SET expectedness='Expected'",
            "check" => "UPDATE control_precondition SET state='NotEstablished' WHERE name='DS-Replication-Get-Changes-All'",
            _ => $"UPDATE permission_entry SET generation='{Guid.NewGuid():D}'",
        });
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Where(row => row.RuleId == "SEC-002"));
        Assert.False(source.ReadReplicationPermission(directory, row.Reference!.Value, null).IsSuccess);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("finding")]
    [InlineData("root")]
    [InlineData("edge")]
    public void ReplicationPermissionRefusesAContinuationFromAnotherAnswer(string defect)
    {
        var directory = ReplicationPermissionRuleTests.FindingDetailsRun(53);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Where(row => row.RuleId == "SEC-002"));
        var first = source.ReadReplicationPermission(directory, row.Reference!.Value, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        var next = first.Value.Next!.Value;
        next = defect switch
        {
            "generation" => next with { GenerationId = Guid.NewGuid() },
            "finding" => next with { FindingId = next.FindingId + 1 },
            "root" => next with { RootGuid = Guid.NewGuid() },
            _ => next with { EdgeId = next.EdgeId + 1 },
        };
        Assert.False(source.ReadReplicationPermission(directory, row.Reference.Value, next).IsSuccess);
    }

    [Fact]
    public void ReplicationPermissionDoesNotSubstituteAnUnrelatedFinding()
    {
        var directory = ProtectionMarkerRun();
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        Assert.False(source.ReadReplicationPermission(directory, row.Reference!.Value, null).IsSuccess);
    }

    [Fact]
    public void ReplicationPermissionDoesNotReconstructUnrequestedPermissionMeanings()
    {
        var directory = ReplicationPermissionRuleTests.FindingsRun();
        ChangeCoverageProof(directory, "UPDATE permission_entry SET meaning_binding=zeroblob(32)");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Where(row => row.RuleId == "SEC-002"));
        var read = source.ReadReplicationPermission(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(2, read.Value.Entries.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReplicationPermissionKeepsBroaderAssignmentsAndOtherTrusteesDenies(bool broad)
    {
        var directory = ReplicationPermissionRuleTests.FindingScopeRun(broad);
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Where(row => row.RuleId == "SEC-002"));
        var read = source.ReadReplicationPermission(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        if (broad)
        {
            var entry = Assert.Single(read.Value.Entries);
            Assert.Equal("All extended rights", entry.Scope);
            Assert.Equal("Allow", entry.EntryType);
        }
        else
        {
            var deny = Assert.Single(read.Value.Entries.Where(entry => entry.EntryType == "Deny"));
            Assert.NotEqual(read.Value.Context.HolderSid, deny.Sid);
            Assert.Equal("Replicating Directory Changes", deny.Scope);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReplicationPermissionCannotUseAnUnrelatedGenerationOrMissingFinding(bool generation)
    {
        var directory = ReplicationPermissionRuleTests.FindingsRun();
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings.Where(row => row.RuleId == "SEC-002"));
        var reference = row.Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = long.MaxValue };
        Assert.False(source.ReadReplicationPermission(directory, reference, null).IsSuccess);
    }
}
