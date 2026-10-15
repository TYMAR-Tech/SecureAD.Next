using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsScopePagingTests
{
    private const string Root = "DC=ad,DC=lab";
    private const string Expiry = "133700000000000000";
    private static readonly DateTimeOffset Started = DateTimeOffset.UnixEpoch;

    [Theory]
    [InlineData(0, true, false)]
    [InlineData(1, false, true)]
    public void Arch0405LightweightFindingPageQualifiesAnEmptyResult(int rulesRan, bool didNotRun, bool nothingFound)
    {
        var page = new FindingListPage([], null, rulesRan);
        Assert.Equal(didNotRun, page.DidNotRun);
        Assert.Equal(nothingFound, page.NothingWasFound);
    }

    [Theory]
    [InlineData(LapsManagement.NotManaged)]
    [InlineData(LapsManagement.WindowsLaps)]
    [InlineData(LapsManagement.LegacyLaps)]
    [InlineData(LapsManagement.Migrated)]
    [InlineData(LapsManagement.Unexpected)]
    public void Arch04SearchAndStateApplyToTheWholeScopeBeforePaging(LapsManagement state)
    {
        var directory = FilterRun();
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var coverage = evidence.ReadListingCoverage(Root, ListingScope.Subtree);
        var first = reader.ListLapsComputers(new(Root, ListingScope.Subtree, "", null), null, coverage);
        Assert.Equal(100, first.Computers.Count);
        Assert.DoesNotContain(first.Computers, row => row.Name.Contains("Needle", StringComparison.Ordinal));
        var result = reader.ListLapsComputers(new(Root, ListingScope.Subtree, "nEeDlE", state), null, coverage);
        var found = Assert.Single(result.Computers);
        Assert.Equal(state, found.Management);
        Assert.Equal("ZZ-Needle-" + state, found.Name);
        Assert.Null(result.Next);
        Assert.Equal(205, result.Total);
        Assert.Equal(201, result.CountOf(LapsManagement.WindowsLaps));
        Assert.Equal(first.CountsByState.OrderBy(pair => pair.Key), result.CountsByState.OrderBy(pair => pair.Key));
    }

    [Theory]
    [InlineData("AD.LAB", 205)]
    [InlineData("%_", 1)]
    [InlineData("ö", 1)]
    [InlineData("does-not-exist", 0)]
    public void Arch04SearchPreservesDomainLiteralWildcardAndUnicodeSubstringSemantics(string search, int expected)
    {
        var directory = search is "%_" or "ö" ? NamesRun(["ZZ-100%_literal", "ZZ-Örebro"]) : FilterRun();
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var query = new LapsQuery(Root, ListingScope.Subtree, search, null);
        var coverage = evidence.ReadListingCoverage(Root, ListingScope.Subtree);
        var actual = new List<LapsComputer>();
        LapsPageMark? after = null;
        do
        {
            var page = reader.ListLapsComputers(query, after, coverage);
            actual.AddRange(page.Computers);
            after = page.Next;
        } while (after is not null);
        Assert.Equal(expected, actual.Count);
    }

    [Fact]
    public void Arch04ContinuationKeepsEveryEqualNameAndWholeScopeTotals()
    {
        var names = Enumerable.Range(0, 105).Select(index => $"CN=Same,OU=Branch{index:D3},{Root}").ToArray();
        var directory = Captured(names.Select(dn => (dn, (string?)"Windows Server 2022", (string?)"10.0 (20348)",
            (string?)Expiry, (string?)null, 4096u)).ToArray());
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var query = new LapsQuery(Root, ListingScope.Subtree, "", null);
        var coverage = evidence.ReadListingCoverage(Root, ListingScope.Subtree);
        var first = reader.ListLapsComputers(query, null, coverage);
        var mark = Assert.IsType<LapsPageMark>(first.Next);
        var second = reader.ListLapsComputers(query, mark, coverage);
        Assert.Equal((100, 5, 105, 105), (first.Computers.Count, second.Computers.Count, first.Total, second.Total));
        Assert.Equal(reader.Description.GenerationId, mark.GenerationId);
        Assert.Equal(names, first.Computers.Concat(second.Computers).Select(row => row.DistinguishedName));
        Assert.Null(second.Next);
        Assert.Equal(first.ComputersAreComplete, second.ComputersAreComplete);
        Assert.Equal(first.Shortfall, second.Shortfall);
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("search")]
    [InlineData("state")]
    [InlineData("container")]
    [InlineData("scope")]
    public void Arch04ContinuationRefusesAChangedQuestionOrGeneration(string changed)
    {
        var directory = FilterRun();
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var query = new LapsQuery(Root, ListingScope.Subtree, "", null);
        var coverage = evidence.ReadListingCoverage(Root, ListingScope.Subtree);
        var mark = Assert.IsType<LapsPageMark>(reader.ListLapsComputers(query, null, coverage).Next);
        if (changed == "generation") mark = mark with { GenerationId = Guid.NewGuid() };
        else query = changed switch
        {
            "search" => query with { Search = "Needle" },
            "state" => query with { State = LapsManagement.WindowsLaps },
            "container" => query with { Container = "OU=Other," + Root },
            "scope" => query with { Scope = ListingScope.OneLevel },
            _ => throw new ArgumentOutOfRangeException(nameof(changed)),
        };
        Assert.Throws<InvalidDataException>(() => reader.ListLapsComputers(query, mark, coverage));
    }

    [Fact]
    public void Arch04UnloadedOriginalValuesAreNotDecodedAndSelectedCorruptionIsRefused()
    {
        var directory = FilterRun();
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        var part = root.Segment(StoreSegmentRole.JudgementFacts);
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = Path.Combine(directory, part.FileName), Pooling = false }.ToString()))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE laps_inventory SET result='broken' WHERE name='ZZ-Needle-Unexpected'";
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var coverage = evidence.ReadListingCoverage(Root, ListingScope.Subtree);
        var page = reader.ListLapsComputers(new(Root, ListingScope.Subtree, "", null), null, coverage);
        Assert.Equal(100, page.Computers.Count);
        Assert.Throws<System.Text.Json.JsonException>(() =>
            reader.ListLapsComputers(new(Root, ListingScope.Subtree, "ZZ-Needle-Unexpected", null), null, coverage));
    }

    internal static string FilterRun()
    {
        var ordinary = Enumerable.Range(0, 200).Select(index =>
            ($"CN=PC{index:D3},{Root}", (string?)"Windows Server 2022", (string?)"10.0 (20348)", (string?)Expiry, (string?)null, 4096u));
        var special = Enum.GetValues<LapsManagement>().Select(state =>
            ($"CN=ZZ-Needle-{state},{Root}", (string?)(state == LapsManagement.Unexpected ? "Windows Server 2016" : "Windows Server 2022"),
                (string?)(state == LapsManagement.Unexpected ? "10.0 (14393)" : "10.0 (20348)"),
                (string?)(state is LapsManagement.WindowsLaps or LapsManagement.Migrated or LapsManagement.Unexpected ? Expiry : null),
                (string?)(state is LapsManagement.LegacyLaps or LapsManagement.Migrated ? Expiry : null), 4096u));
        return Captured(ordinary.Concat(special).ToArray());
    }

    private static string NamesRun(string[] names) => Captured(names.Select(name =>
        ($"CN={name},{Root}", (string?)"Windows Server 2022", (string?)"10.0 (20348)", (string?)Expiry, (string?)null, 4096u)).ToArray());

    private static string Captured((string Dn, string? Os, string? Version, string? Modern, string? Legacy, uint Uac)[] rows)
    {
        var directory = LapsBundle.BuildMany(rows, Started);
        SavedLapsTestRun.Judge(directory);
        return directory;
    }
}
