using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class OpenedRunResultsTests
{
    [Theory]
    [InlineData("self", 1, 1)]
    [InlineData("pair", 2, 2)]
    [InlineData("overlap", 3, 4)]
    [InlineData("member-of", 2, 2)]
    [InlineData("cross-domain", 2, 2)]
    [InlineData("distribution", 2, 2)]
    public void CircularMembershipReadsTheExistingRuleWithoutGraphOrOtherAnalysisReplay(string variant, int groups, int links)
    {
        var directory = CircularGroupMembershipTests.FindingsRun(variant);
        var before = CoverageFiles(directory);
        using var counts = new FindingsVerificationCounts(directory);
        using var source = new BundleAssetSource();
        using (var locks = new FindingsHeavyLocks(directory, permissionHeaders: true))
        {
            var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
            Assert.Equal(0L, counts.Heavy);
            var page = source.ReadCircularMembershipGroups(directory, row.Reference!.Value, null);
            Assert.True(page.IsSuccess, page.Error?.Description);
            Assert.True(page.Value.Context.Matches(row)); Assert.True(page.Value.IsExpectedPage(null));
            Assert.Equal((groups, links, true), (page.Value.Context.GroupCount, page.Value.Context.LinkCount, page.Value.Context.InventoryComplete));
            Assert.Equal(groups, page.Value.Groups.Count); Assert.Null(page.Value.Next);
            var recorded = source.ReadCircularMembershipLinks(directory, row.Reference.Value, null);
            Assert.True(recorded.IsSuccess, recorded.Error?.Description);
            Assert.Equal(links, recorded.Value.Links.Count);
            var first = recorded.Value.Links[0];
            var values = source.ReadCircularMembershipWitnesses(directory, row.Reference.Value,
                first.ContainingGroup.ObjectGuid, first.Member.ObjectGuid, null);
            Assert.True(values.IsSuccess, values.Error?.Description);
            Assert.True(values.Value.IsExpectedPage(null));
            Assert.Equal(variant == "self", first.IsSelfMembership);
            Assert.All(values.Value.Witnesses, value => Assert.Equal(variant == "member-of" ? "memberOf" : "member", value.Attribute));
            Assert.Equal((1L, 0L, 0L, 0L, 0L), (counts.Count("permission"), counts.Count("path"),
                counts.Count("facts"), counts.Count("evidence"), counts.Count("derivation")));
        }
        Assert.Equal(before, CoverageFiles(directory));
    }

    [Fact]
    public void CircularMembershipPreservesTheOriginalIncompleteInventoryFlagInsteadOfTheLightweightDefault()
    {
        var directory = CircularGroupMembershipTests.FindingsRun("partial-input");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var read = source.ReadCircularMembershipGroups(directory, row.Reference!.Value, null);
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.False(read.Value.Context.InventoryComplete); Assert.Equal(2, read.Value.Context.GroupCount);
        Assert.True(read.Value.Context.Matches(row));
    }

    [Fact]
    public void CircularMembershipScopesRepeatedBuiltinSidsToTheActualDomain()
    {
        var directory = CircularGroupMembershipTests.FindingsRun("scoped-builtins");
        using var source = new BundleAssetSource();
        var rows = source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings;
        Assert.Equal(2, rows.Count);
        var identities = rows.Select(row =>
        {
            var page = source.ReadCircularMembershipGroups(directory, row.Reference!.Value, null);
            Assert.True(page.IsSuccess, page.Error?.Description);
            return Assert.Single(page.Value.Groups).Group;
        }).ToArray();
        Assert.All(identities, group => Assert.Equal("S-1-5-32-544", group.Sid));
        Assert.Equal(new[] { "child.contoso.com", "contoso.com" }, identities.Select(group => group.SidScope).Order(StringComparer.Ordinal));
        Assert.Equal(2, identities.Select(group => group.ObjectGuid).Distinct().Count());
    }

    [Theory]
    [InlineData("groups")]
    [InlineData("links")]
    [InlineData("witnesses")]
    public void CircularMembershipEveryLevelUsesFiftyRowsAndPreservesOriginalPhysicalOrder(string level)
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        CircularMembershipEvidence original;
        using (var reader = JudgementReader.Open(directory).Value)
            original = Assert.IsType<CircularMembershipEvidence>(Assert.Single(reader.Read().Findings).Evidence);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        if (level == "groups")
        {
            var first = source.ReadCircularMembershipGroups(directory, reference, null).Value;
            var last = source.ReadCircularMembershipGroups(directory, reference, first.Next).Value;
            Assert.Equal(50, first.Groups.Count); Assert.Equal(7, last.Groups.Count); Assert.Null(last.Next);
            Assert.Equal(original.Groups, first.Groups.Concat(last.Groups).Select(value => value.Group));
            Assert.Equal(Enumerable.Range(0, 57).Select(index => (long)index), first.Groups.Concat(last.Groups).Select(value => value.Position));
        }
        else if (level == "links")
        {
            var first = source.ReadCircularMembershipLinks(directory, reference, null).Value;
            var last = source.ReadCircularMembershipLinks(directory, reference, first.Next).Value;
            Assert.Equal(50, first.Links.Count); Assert.Equal(7, last.Links.Count); Assert.Null(last.Next);
            Assert.Equal(original.Links.Select(link => (link.GroupGuid, link.MemberGuid, link.Witnesses.Count)),
                first.Links.Concat(last.Links).Select(link => (link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, link.WitnessCount)));
        }
        else
        {
            var link = original.Links[0];
            var first = source.ReadCircularMembershipWitnesses(directory, reference, link.GroupGuid, link.MemberGuid, null).Value;
            var last = source.ReadCircularMembershipWitnesses(directory, reference, link.GroupGuid, link.MemberGuid, first.Next).Value;
            Assert.Equal(50, first.Witnesses.Count); Assert.Equal(8, last.Witnesses.Count); Assert.Null(last.Next);
            Assert.Equal(link.Witnesses.Select(value => (value.SourceObjectGuid, value.Attribute, value.Ordinal, value.Value)),
                first.Witnesses.Concat(last.Witnesses).Select(value => (value.Source.ObjectGuid, value.Attribute, value.OriginalOrdinal, value.Value)));
            Assert.Equal(Enumerable.Range(0, 58).Select(index => (long)index), first.Witnesses.Concat(last.Witnesses).Select(value => value.Position));
        }
    }

    [Theory]
    [InlineData("groups", "generation")]
    [InlineData("groups", "finding")]
    [InlineData("groups", "component")]
    [InlineData("groups", "offset")]
    [InlineData("links", "generation")]
    [InlineData("links", "finding")]
    [InlineData("links", "component")]
    [InlineData("links", "offset")]
    [InlineData("witnesses", "generation")]
    [InlineData("witnesses", "finding")]
    [InlineData("witnesses", "component")]
    [InlineData("witnesses", "offset")]
    public void CircularMembershipRejectsUnboundOrMispositionedContinuationsAtEveryLevel(string level, string defect)
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var generation = defect == "generation" ? Guid.NewGuid() : reference.GenerationId;
        var id = reference.FindingId + (defect == "finding" ? 1 : 0);
        var component = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Subject.Key;
        if (defect == "component") component = "cycle:" + new string('0', 64);
        var offset = defect == "offset" ? 51 : 50;
        if (level == "groups")
            Assert.False(source.ReadCircularMembershipGroups(directory, reference, new(generation, id, component, offset)).IsSuccess);
        else if (level == "links")
            Assert.False(source.ReadCircularMembershipLinks(directory, reference, new(generation, id, component, offset)).IsSuccess);
        else
        {
            var link = source.ReadCircularMembershipLinks(directory, reference, null).Value.Links[0];
            Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid,
                new(generation, id, component, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, offset)).IsSuccess);
        }
    }

    [Theory]
    [InlineData("groups")]
    [InlineData("links")]
    [InlineData("witnesses")]
    public void CircularMembershipRejectsContinuationsBeyondTheSavedPageTotals(string level)
    {
        var directory = CircularGroupMembershipTests.FindingsRun("pair");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var reference = row.Reference!.Value;
        if (level == "groups") Assert.False(source.ReadCircularMembershipGroups(directory, reference,
            new(reference.GenerationId, reference.FindingId, row.Subject.Key, 50)).IsSuccess);
        else if (level == "links") Assert.False(source.ReadCircularMembershipLinks(directory, reference,
            new(reference.GenerationId, reference.FindingId, row.Subject.Key, 50)).IsSuccess);
        else
        {
            var link = source.ReadCircularMembershipLinks(directory, reference, null).Value.Links[0];
            Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid,
                new(reference.GenerationId, reference.FindingId, row.Subject.Key, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, 50)).IsSuccess);
        }
    }

    [Theory]
    [InlineData("group")]
    [InlineData("member")]
    public void CircularMembershipRejectsAContinuationFromAnotherDirectRelationship(string defect)
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        using var source = new BundleAssetSource();
        var row = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings);
        var reference = row.Reference!.Value;
        var link = source.ReadCircularMembershipLinks(directory, reference, null).Value.Links[0];
        var mark = source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, null).Value.Next!.Value;
        mark = defect == "group" ? mark with { GroupGuid = Guid.NewGuid() } : mark with { MemberGuid = Guid.NewGuid() };
        Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, mark).IsSuccess);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("generation")]
    [InlineData("flag")]
    [InlineData("contradictory-flag")]
    [InlineData("component")]
    [InlineData("index")]
    public void CircularMembershipRefusesMissingOrInconsistentSavedHeaders(string defect)
    {
        var directory = CircularGroupMembershipTests.FindingsRun();
        if (defect == "index") SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM finding_circular_group WHERE object_guid=(SELECT MIN(object_guid) FROM finding_circular_group)";
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        else ChangeCoverageProof(directory, defect switch
        {
            "missing" => "DELETE FROM finding_circular_membership",
            "generation" => "UPDATE finding_circular_membership SET generation='not the selected generation'",
            "flag" => "UPDATE finding_circular_membership SET proof=json_remove(proof,'$.InventoryComplete')",
            "contradictory-flag" => "UPDATE finding_circular_membership SET proof=json_set(proof,'$.IsComplete',json('false'))",
            "component" => "UPDATE finding_circular_membership SET proof=json_set(proof,'$.ComponentKey','cycle:wrong')",
            _ => throw new InvalidOperationException("Unsupported circular header defect."),
        });
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var read = source.ReadCircularMembershipGroups(directory, reference, null);
        Assert.False(read.IsSuccess);
        Assert.Contains(SavedCircularMembershipContext.InvalidDetails, read.Error.Description, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("source")]
    [InlineData("attribute")]
    [InlineData("value")]
    public void CircularMembershipKeepsTheOriginalWitnessSourceAndMembershipDirection(string defect)
    {
        var directory = CircularGroupMembershipTests.FindingsRun("both-sources");
        ChangeCoverageProof(directory, defect switch
        {
            "source" => $"UPDATE finding_circular_membership SET proof=json_set(proof,'$.Links[0].Witnesses[0].SourceObjectGuid','{Guid.NewGuid():D}')",
            "attribute" => "UPDATE finding_circular_membership SET proof=json_set(proof,'$.Links[0].Witnesses[0].Attribute','primaryGroupID')",
            _ => "UPDATE finding_circular_membership SET proof=json_set(proof,'$.Links[0].Witnesses[0].Value','CN=Another group,DC=contoso,DC=com')",
        });
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var link = source.ReadCircularMembershipLinks(directory, reference, null).Value.Links[0];
        Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, null).IsSuccess);
    }

    [Fact]
    public void CircularMembershipDoesNotValidateUnopenedGroupOrWitnessPayloads()
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        ChangeCoverageProof(directory, """
            UPDATE finding_circular_membership SET proof=json_set(proof,
                '$.Groups[56].Sid','unreadable later group',
                '$.Links[0].Witnesses[50].Value','an invalid later value')
            """);
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var first = source.ReadCircularMembershipGroups(directory, reference, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        Assert.False(source.ReadCircularMembershipGroups(directory, reference, first.Value.Next).IsSuccess);
    }

    [Fact]
    public void CircularMembershipReadsOnlyTheRequestedWitnessPageEvenWhenLaterValuesAreInvalid()
    {
        var directory = CircularGroupMembershipTests.FindingsRun("wide");
        ChangeCoverageProof(directory, "UPDATE finding_circular_membership SET proof=json_set(proof,'$.Links[0].Witnesses[50].Value','an invalid later value')");
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        var link = source.ReadCircularMembershipLinks(directory, reference, null).Value.Links[0];
        var first = source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, null);
        Assert.True(first.IsSuccess, first.Error?.Description);
        Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, link.ContainingGroup.ObjectGuid, link.Member.ObjectGuid, first.Value.Next).IsSuccess);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CircularMembershipRejectsAnotherGenerationOrMissingSelectedFinding(bool generation)
    {
        var directory = CircularGroupMembershipTests.FindingsRun();
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        reference = generation ? reference with { GenerationId = Guid.NewGuid() } : reference with { FindingId = long.MaxValue };
        Assert.False(source.ReadCircularMembershipGroups(directory, reference, null).IsSuccess);
        Assert.False(source.ReadCircularMembershipLinks(directory, reference, null).IsSuccess);
        Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, Guid.NewGuid(), Guid.NewGuid(), null).IsSuccess);
    }

    [Fact]
    public void CircularMembershipDoesNotSubstituteAnUnrelatedFinding()
    {
        var directory = ProtectionMarkerRun();
        using var source = new BundleAssetSource();
        var reference = Assert.Single(source.ReadFindingsList(directory, FindingsQuery.Everything()).Value.Findings).Reference!.Value;
        Assert.False(source.ReadCircularMembershipGroups(directory, reference, null).IsSuccess);
        Assert.False(source.ReadCircularMembershipLinks(directory, reference, null).IsSuccess);
        Assert.False(source.ReadCircularMembershipWitnesses(directory, reference, Guid.NewGuid(), Guid.NewGuid(), null).IsSuccess);
    }
}
