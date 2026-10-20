using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class BrowsingQueryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FindingFiltersSeekPresentValuesAndCacheOnlyOnTheirReader(bool empty)
    {
        var findings = empty ? [] : Enumerable.Range(0, 257).Select(index =>
            FindingsPagingTests.AFinding($"CN=Finding{index},DC=contoso,DC=com")
                with { Severity = index % 2 == 0 ? Severity.Low : Severity.Critical }).ToArray();
        var directory = FindingsPagingTests.ABundleWith(findings);
        using var file = Protect(directory);
        using var reader = JudgementReader.Open(file).Value;
        using var trace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(reader));
        var values = reader.ReadFilterValues();
        Assert.Equal(empty ? [] : new[] { Severity.Critical, Severity.Low }, values.Severities);
        Assert.Equal(empty ? [] : new[] { "SEC-010" }, values.Rules);
        Assert.False(values.DidNotRun);
        Assert.Same(values, reader.ReadFilterValues());
        var queries = trace.Statements.Where(sql => sql.StartsWith("WITH RECURSIVE", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, queries.Length);
        foreach (var sql in queries)
        {
            var plan = trace.Plan(sql);
            Assert.Contains(plan, line => line.StartsWith("SEARCH finding", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, line => line.StartsWith("SCAN finding", StringComparison.Ordinal));
        }
        using var reopened = JudgementReader.Open(file).Value;
        using var nextTrace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(reopened));
        Assert.Same(values, reopened.ReadFilterValues());
        Assert.Empty(nextTrace.Statements.Where(sql => sql.StartsWith("WITH RECURSIVE", StringComparison.Ordinal)));
        using var independent = JudgementReader.Open(directory).Value;
        using var independentTrace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(independent));
        Assert.Equal(values.Rules, independent.ReadFilterValues().Rules);
        Assert.Equal(2, independentTrace.Statements.Count(sql => sql.StartsWith("WITH RECURSIVE", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData("target")]
    [InlineData("holder")]
    public void ControlQueriesSeekCaseInsensitiveIndexesAndCountOnce(string by)
    {
        var directory = Controls();
        using var file = Protect(directory);
        using var reader = JudgementReader.Open(file).Value;
        using var nextReader = JudgementReader.Open(file).Value;
        using var trace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(reader));
        using var nextTrace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(nextReader));
        var target = by == "target" ? "OU=OBJECT000,DC=CONTOSO,DC=COM" : null;
        var holder = by == "holder" ? ControlEdgeDeriverTests.Holder.ToLowerInvariant() : null;
        var first = reader.ReadControlEdges(target, holder, null, false, 0);
        var last = nextReader.ReadControlEdges(target, holder, null, true, first.LastId);
        Assert.Equal(by == "target" ? 1 : 105, first.UnknownCount);
        Assert.Equal(first.UnknownCount, last.UnknownCount);
        Assert.Equal(by == "target" ? 1 : 106, first.UnansweredObjects);
        Assert.Equal(first.UnansweredObjects, last.UnansweredObjects);
        Assert.Equal(by == "target" ? 1 : 105, first.Edges.Concat(last.Edges).Select(edge => edge.Id).Distinct().Count());
        var statements = trace.Statements.Concat(nextTrace.Statements).ToArray();
        var countSql = Assert.Single(statements, sql => sql.Contains("GROUP BY expectedness", StringComparison.Ordinal));
        var pages = statements.Where(sql => sql.StartsWith("SELECT display_id", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, pages.Length);
        foreach (var sql in pages.Append(countSql))
        {
            var plan = trace.Plan(sql);
            Assert.Contains(plan, line => (line.StartsWith("SEARCH e ", StringComparison.Ordinal)
                || line.StartsWith("SEARCH control_edge ", StringComparison.Ordinal))
                && line.Contains(by == "target" ? "target=?" : "holder_sid=?", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, line => line is "SCAN e" or "SCAN control_edge");
        }
        Assert.DoesNotContain(statements, sql => sql.Contains("COUNT(*) FROM control_object", StringComparison.Ordinal));
        var other = reader.ReadControlEdges("OU=missing,DC=contoso,DC=com", null, null, false, 0);
        Assert.False(other.ProductWasDerived);
        Assert.Equal(1, other.UnansweredObjects);
    }

    [Fact]
    public void CompletedControlsSaveTheExactUnfinishedObjectCount()
    {
        var directory = Controls();
        using var reader = JudgementReader.Open(directory).Value;
        var connection = BrowsingQueryTrace.Connection(reader);
        reader.ReadControlEdges(null, null, null, false, 0);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT unfinished_objects,(SELECT COUNT(*) FROM control_object WHERE is_complete=0) FROM control_product WHERE id=1";
        using var row = command.ExecuteReader();
        Assert.True(row.Read());
        Assert.Equal(106, row.GetInt64(0));
        Assert.Equal(row.GetInt64(1), row.GetInt64(0));
    }

    [Fact]
    public void CompletedControlsRefuseAMissingSavedUnfinishedCount()
    {
        var directory = Controls();
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(directory, root.Segment(StoreSegmentRole.PermissionProof).FileName),
            Pooling = false,
        }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE control_product SET unfinished_objects=NULL";
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidOperationException>(() => reader.ReadControlEdges(null, null, null, false, 0));
    }

    [Theory]
    [InlineData(ListingScope.Subtree)]
    [InlineData(ListingScope.OneLevel)]
    public void LapsPagesUseScopeOrderAndReuseUnfilteredStateCounts(ListingScope scope)
    {
        const string root = "DC=ad,DC=lab";
        var directory = LapsScopePagingTests.FilterRun();
        using var file = Protect(directory);
        using var reader = JudgementReader.Open(file).Value;
        using var nextReader = JudgementReader.Open(file).Value;
        using var trace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(reader));
        using var nextTrace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(nextReader));
        var query = new LapsQuery(root, scope, "", null);
        var coverage = new ListingCoverage(false, "Recorded capture gap");
        var first = reader.ListLapsComputers(query, null, coverage);
        var second = nextReader.ListLapsComputers(query, first.Next, coverage);
        var filtered = nextReader.ListLapsComputers(query with { Search = "Needle", State = LapsManagement.NotManaged }, null, coverage);
        Assert.Equal((205, 205, 205), (first.Total, second.Total, filtered.Total));
        Assert.Equal(LapsManagement.NotManaged, Assert.Single(filtered.Computers).Management);
        Assert.False(second.ComputersAreComplete);
        Assert.Equal(coverage.Shortfall, second.Shortfall);
        Assert.Equal(first.CountsByState, second.CountsByState);
        Assert.Equal(first.CountsByState, filtered.CountsByState);
        var statements = trace.Statements.Concat(nextTrace.Statements).ToArray();
        Assert.Single(statements, sql => sql.Contains("GROUP BY management", StringComparison.Ordinal));
        var pages = statements.Where(sql => sql.StartsWith("SELECT distinguished_name,management,result", StringComparison.Ordinal)).ToArray();
        Assert.Equal(3, pages.Length);
        foreach (var sql in pages)
        {
            var plan = trace.Plan(sql);
            Assert.Contains(plan, line => line.Contains(scope == ListingScope.OneLevel ? "ix_laps_inventory_parent" : "ix_laps_inventory_name", StringComparison.Ordinal));
            if (scope == ListingScope.Subtree)
                Assert.DoesNotContain(plan, line => line.Contains("TEMP B-TREE", StringComparison.Ordinal));
        }
        var narrow = nextReader.ListLapsComputers(query with { Container = "CN=PC000," + root, Scope = ListingScope.Subtree },
            null, new(true, null));
        Assert.Equal(1, narrow.Total);
        Assert.True(narrow.ComputersAreComplete);
        var narrowSql = nextTrace.Statements.Last(sql => sql.StartsWith("SELECT distinguished_name,management,result", StringComparison.Ordinal));
        Assert.Contains(trace.Plan(narrowSql), line => line.Contains("ix_laps_inventory_subtree", StringComparison.Ordinal));
    }

    [Fact]
    public void LapsOneLevelIncludesTheSelectedComputerButNotItsGrandchildren()
    {
        const string selected = "CN=ZZZ-Selected,DC=ad,DC=lab";
        var children = Enumerable.Range(0, 204).Select(index => $"CN=PC{index:000},{selected}").ToArray();
        string[] names = [selected, .. children, "CN=Grandchild," + children[0]];
        var directory = LapsBundle.BuildMany(names.Select(dn =>
            (dn, (string?)"Windows Server 2022", (string?)"10.0 (20348)", (string?)"133700000000000000", (string?)null, 4096u)).ToArray(),
            DateTimeOffset.UnixEpoch);
        SavedLapsTestRun.Judge(directory);
        using var reader = JudgementReader.Open(directory).Value;
        var actual = new List<string>();
        LapsPageMark? mark = null;
        do
        {
            var page = reader.ListLapsComputers(new(selected, ListingScope.OneLevel, "", null), mark, new(true, null));
            Assert.Equal(205, page.Total);
            actual.AddRange(page.Computers.Select(computer => computer.DistinguishedName));
            mark = page.Next;
        } while (mark is not null);
        Assert.Equal(children.Append(selected), actual);
        Assert.Equal(1, reader.ListLapsComputers(new(selected, ListingScope.Base, "", null), null, new(true, null)).Total);
        Assert.Equal(206, reader.ListLapsComputers(new(selected, ListingScope.Subtree, "", null), null, new(true, null)).Total);
    }

    [Fact]
    public void GroupsReuseCountsAcrossPagesAndSortsButNotChangedFilters()
    {
        var directory = GroupInventoryTests.Captured();
        GroupInventoryTests.Judge(directory);
        using var file = Protect(directory);
        using var reader = JudgementReader.Open(file).Value;
        using var nextReader = JudgementReader.Open(file).Value;
        using var trace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(reader));
        using var nextTrace = new BrowsingQueryTrace(BrowsingQueryTrace.Connection(nextReader));
        var query = new GroupInventoryQuery(null, ListingScope.Subtree, "Paged-",
            GroupInventoryScope.All, GroupInventoryKind.All, false, GroupInventorySort.Name);
        var first = reader.ReadGroupInventory(query, null);
        Assert.Equal(123, nextReader.ReadGroupInventory(query, first.Next).Total);
        Assert.Equal(123, nextReader.ReadGroupInventory(query with { Sort = GroupInventorySort.DirectDescending }, null).Total);
        Assert.Single(trace.Statements.Concat(nextTrace.Statements), sql => sql.StartsWith("SELECT COUNT(*) FROM group_inventory", StringComparison.Ordinal));
        var pageSql = trace.Statements.First(sql => sql.StartsWith("SELECT g.object_guid", StringComparison.Ordinal));
        Assert.Contains(trace.Plan(pageSql), line => line.Contains("ix_finding_circular_group_object", StringComparison.Ordinal));
        Assert.Equal(0, nextReader.ReadGroupInventory(query with { Search = "not captured" }, null).Total);
        Assert.Equal(2, trace.Statements.Concat(nextTrace.Statements).Count(sql => sql.StartsWith("SELECT COUNT(*) FROM group_inventory", StringComparison.Ordinal)));
    }

    private static string Controls() => ControlEdgeStorageTests.Store(writer =>
    {
        writer.StartControlEdges(true);
        var original = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(
            ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, 0x40000))) with { FullControlAssessments = [] };
        Assert.False(original.IsComplete);
        for (var index = 0; index < 105; index++)
        {
            var target = $"OU=Object{index:000},DC=contoso,DC=com";
            writer.WriteControlEdges(original with
            {
                Target = target,
                Edges = original.Edges.Select(edge => edge with { Target = target, GenerationId = writer.GenerationId }).ToArray(),
            }, ownershipTarget: null);
        }
        writer.WriteControlEdges(new("CN=Unfinished,DC=contoso,DC=com", null, null, "DescriptorNotRead",
            ControlUncertainty.DescriptorUnreadable, []), ownershipTarget: null);
        writer.CompleteControlEdges();
    });

    private static ProtectedStoreFile Protect(string directory)
    {
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value;
        var file = ProtectedStoreFile.OpenAnalysis(directory, generation);
        Assert.True(file.IsSuccess, file.Error?.Description);
        return file.Value;
    }
}
