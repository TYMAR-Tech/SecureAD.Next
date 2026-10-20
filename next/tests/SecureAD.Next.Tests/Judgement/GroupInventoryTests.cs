using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GroupInventoryTests
{
    private static readonly GroupInventoryQuery All = new(null, ListingScope.Subtree, "",
        GroupInventoryScope.All, GroupInventoryKind.All, false, GroupInventorySort.Name);

    [Theory]
    [InlineData(GroupInventorySort.Name)]
    [InlineData(GroupInventorySort.NameDescending)]
    [InlineData(GroupInventorySort.Direct)]
    [InlineData(GroupInventorySort.DirectDescending)]
    public void GroupsSavedPagingReturnsEveryMatchOnceInTheRequestedOrder(GroupInventorySort sort)
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var query = All with { Search = "Paged-", Sort = sort };
        var result = new List<GroupInventoryRow>();
        GroupInventoryMark? mark = null;
        do
        {
            var page = reader.ReadGroupInventory(query, mark);
            Assert.Equal(123, page.Total);
            Assert.InRange(page.Groups.Count, 1, 50);
            result.AddRange(page.Groups);
            mark = page.Next;
        } while (mark is not null);
        Assert.Equal(123, result.Count);
        Assert.Equal(123, result.Select(row => row.ObjectGuid).Distinct().Count());
        var ordered = sort switch
        {
            GroupInventorySort.Name => result.OrderBy(row => row.Name, StringComparer.OrdinalIgnoreCase),
            GroupInventorySort.NameDescending => result.OrderByDescending(row => row.Name, StringComparer.OrdinalIgnoreCase),
            GroupInventorySort.Direct => result.OrderBy(row => row.DirectMembers),
            _ => result.OrderByDescending(row => row.DirectMembers),
        };
        Assert.Equal(ordered.ThenBy(row => row.DistinguishedName, StringComparer.OrdinalIgnoreCase).Select(row => row.DistinguishedName),
            result.Select(row => row.DistinguishedName));
    }

    [Fact]
    public void GroupsDirectCountIsRecordedDistinctValuesNotAnExpandedTotal()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var group = Assert.Single(reader.ReadGroupInventory(All with { Search = "GRP-003" }, null).Groups);
        Assert.Equal(3, group.DirectMembers);
        Assert.Equal("contoso.com", group.DomainFqdn);
        Assert.Null(group.HasCycle);
        Assert.Contains("has not run", reader.ReadGroupInventory(All, null).CycleQualification);
    }

    [Fact]
    public void GroupsSavedTotalsSurviveReopeningAndStayIndependentOfLoadedPages()
    {
        var directory = Bundle(users: 0, members: [], writeAdditional: (writer, partition) =>
        {
            foreach (var (name, kind, members) in new[]
            {
                ("TotalRoot", "group", new[] { "TotalAlice", "TotalNested", "TotalMissing" }),
                ("TotalNested", "group", new[] { "TotalAlice", "TotalBob" }),
                ("TotalAlice", "user", Array.Empty<string>()),
                ("TotalBob", "contact", Array.Empty<string>()),
            })
                writer.WriteObject(new(partition, $"CN={name},DC=contoso,DC=com", Guid.NewGuid(),
                    [Text("objectClass", kind), Text("member", members.Select(member => $"CN={member},DC=contoso,DC=com").ToArray())], Started));
        });
        Judge(directory);
        Guid generation;
        using (var first = Open(directory))
        {
            var page = first.ReadGroupInventory(All with { Search = "TotalRoot" }, null);
            generation = page.GenerationId;
            var root = Assert.Single(page.Groups);
            Assert.Equal(3, root.DirectMembers);
            Assert.Equal(new(3, 1, 0, GroupMembershipLimitations.UnresolvedReferences), root.MembershipTotal);
        }
        using var reopened = Open(directory);
        var nested = reopened.ReadGroupInventory(All with { Search = "TotalNested" }, null);
        Assert.Equal(generation, nested.GenerationId);
        Assert.Equal(new(2, 0, 0, GroupMembershipLimitations.None), Assert.Single(nested.Groups).MembershipTotal);
    }

    [Theory]
    [InlineData(ListingScope.Base, "CN=Paged-000,OU=Percent_%,DC=contoso,DC=com", 1)]
    [InlineData(ListingScope.OneLevel, "OU=Percent_%,DC=contoso,DC=com", 62)]
    [InlineData(ListingScope.Subtree, "OU=Percent_%,DC=contoso,DC=com", 62)]
    public void GroupsDirectoryScopeTreatsWildcardCharactersLiterally(ListingScope scope, string container, int count)
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var page = reader.ReadGroupInventory(All with { Container = container, Scope = scope }, null);
        Assert.Equal(count, page.Total);
    }

    [Fact]
    public void GroupsScopeAndSecurityFiltersDoNotInventUnknownTypes()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var page = reader.ReadGroupInventory(All with { Search = "Paged-", Kind = GroupInventoryKind.Distribution }, null);
        Assert.True(page.Total > 0);
        Assert.All(page.Groups, row => Assert.Equal(0, row.GroupType!.Value & 2147483648));
        var scoped = reader.ReadGroupInventory(All with { Search = "Paged-", GroupScope = GroupInventoryScope.Universal }, null);
        Assert.All(scoped.Groups, row => Assert.Equal(8, row.GroupType!.Value & 15));
        Assert.Equal(0, reader.ReadGroupInventory(All with { Search = "%" }, null).Total);
    }

    [Fact]
    public void GroupsContinuationCannotCrossQuestionGenerationOrCancellation()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var mark = Assert.IsType<GroupInventoryMark>(reader.ReadGroupInventory(All, null).Next);
        Assert.Throws<ArgumentException>(() => reader.ReadGroupInventory(All with { Search = "changed" }, mark));
        Assert.Throws<ArgumentException>(() => reader.ReadGroupInventory(All, mark with { GenerationId = Guid.NewGuid() }));
        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => reader.ReadGroupInventory(All, null, stopping.Token));
    }

    [Fact]
    public void GroupsCapturedReferenceLookupRetainsUnresolvedValuesAndExactDomainIdentity()
    {
        var directory = Captured();
        using var reader = BundleReader.Open(directory).Value!;
        const string dn = "CN=Paged-003,OU=PercentAB,DC=contoso,DC=com";
        var references = reader.ResolveMembershipReferences([dn.ToUpperInvariant(), "CN=Missing,DC=contoso,DC=com"]);
        Assert.False(references.IsComplete);
        Assert.Equal(dn, references.References[0].DistinguishedName);
        Assert.Equal("contoso.com", references.References[0].DomainFqdn);
        Assert.Null(references.References[1].DistinguishedName);
        Assert.Equal("CN=Missing,DC=contoso,DC=com", references.References[1].RecordedName);
        Assert.Throws<ArgumentException>(() => reader.ResolveMembershipReferences(Enumerable.Repeat(dn, 51).ToArray()));
    }

    [Fact]
    public void GroupsCycleFilterWithoutASavedAssessmentIsExplicitlyRefused()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        Assert.Throws<InvalidOperationException>(() => reader.ReadGroupInventory(All with { CyclesOnly = true }, null));
        Assert.Null(Assert.Single(reader.ReadGroupInventory(All with { Search = "GRP-003" }, null).Groups).HasCycle);
    }

    internal static string Captured() => Bundle(users: 0, members: [], writeAdditional: (writer, partition) =>
    {
        for (var index = 0; index < 123; index++)
        {
            var dn = $"CN=Paged-{index:000},OU={(index % 2 == 0 ? "Percent_%" : "PercentAB")},DC=contoso,DC=com";
            var values = Enumerable.Range(0, index % 7).Select(i => $"CN=Member{i},DC=contoso,DC=com").ToArray();
            writer.WriteObject(new(partition, dn, Guid.NewGuid(),
                [Text("objectClass", "top", "group"), Text("sAMAccountName", $"GRP-{index:000}"),
                    Text("groupType", index % 3 == 0 ? "-2147483646" : index % 3 == 1 ? "-2147483640" : "2"),
                    Text("member", [.. values, .. values.Take(1)])], Started));
        }
    });

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    internal static void Judge(string directory)
    {
        var result = JudgingRun.Judge(directory, [], Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var reader = JudgementReader.Open(directory);
        Assert.True(reader.IsSuccess, reader.Error?.Description);
        return reader.Value;
    }
}
