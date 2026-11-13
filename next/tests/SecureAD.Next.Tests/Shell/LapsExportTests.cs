using System.Globalization;
using System.Text;
using Microsoft.VisualBasic.FileIO;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.Services.Export;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class LapsExportTests
{
    private const string Root = "DC=ad,DC=lab";

    [Theory]
    [InlineData("AD.LAB", null, 205)]
    [InlineData("nEeDlE", null, 5)]
    [InlineData("nEeDlE", LapsValuePresence.None, 1)]
    [InlineData("nEeDlE", LapsValuePresence.Both, 1)]
    [InlineData("not-a-computer", null, 0)]
    public void MatchingCountUsesTheSameQuestionAsEverySavedPage(string search, LapsValuePresence? state, int expected)
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var coverage = evidence.ReadListingCoverage(Root, ListingScope.Subtree);
        var query = new LapsQuery(Root, ListingScope.Subtree, search, state);
        var summary = reader.ReadLapsInventorySummary(query, coverage);
        var actual = 0;
        LapsPageMark? after = null;
        do
        {
            var page = reader.ListLapsComputers(query, after, coverage);
            Assert.Equal(summary.Total, page.Total);
            actual += page.Computers.Count;
            after = page.Next;
        } while (after is not null);
        Assert.Equal(expected, actual);
        Assert.Equal(expected, summary.Matching);
        Assert.Equal(205, summary.Total);
        Assert.Equal(query, summary.Query);
        Assert.Equal(reader.Description, summary.Description);
    }

    [Theory]
    [InlineData(ListingScope.Base, "CN=PC000,DC=ad,DC=lab", 1)]
    [InlineData(ListingScope.Base, Root, 0)]
    [InlineData(ListingScope.OneLevel, Root, 205)]
    [InlineData(ListingScope.Subtree, "OU=Absent,DC=ad,DC=lab", 0)]
    public void CountAndPageRetainExactContainerDepth(ListingScope scope, string container, int expected)
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var evidence = BundleReader.Open(directory).Value;
        using var reader = JudgementReader.Open(directory).Value;
        var query = new LapsQuery(container, scope, "", null);
        var coverage = evidence.ReadListingCoverage(container, scope);
        var summary = reader.ReadLapsInventorySummary(query, coverage);
        Assert.Equal(expected, summary.Matching);
        Assert.Equal(expected, summary.Total);
        Assert.Equal(Math.Min(100, expected), reader.ListLapsComputers(query, null, coverage).Computers.Count);
    }

    [Fact]
    public async Task AdapterReadsAll205RowsRatherThanTheSampleOrLoadedPage()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);
        var dataset = new LapsExportDataset(source, directory, new(Root, ListingScope.Subtree, "AD.LAB", null));
        var preview = await dataset.PreviewAsync(ExportSelection.Matching, CancellationToken.None);
        Assert.Equal(205, preview.Context.Rows);
        Assert.Equal(205, preview.Context.ScopeRows);
        Assert.Equal(3, preview.Sample.Count);
        Assert.Equal(20, preview.Columns.Count);
        var rows = new List<IReadOnlyList<ExportCell>>();
        var completed = await dataset.ReadRowsAsync(preview, rows.Add, CancellationToken.None);
        Assert.Equal(205, rows.Count);
        Assert.Equal(205, rows.Select(row => row[2].Value).Distinct().Count());
        Assert.All(rows, row => Assert.Equal(20, row.Count));
        Assert.Contains(rows, row => row[0].Value == "ZZ-Needle-None");
        Assert.Contains(rows, row => row[0].Value == "ZZ-Needle-WindowsOnLegacyOnly");
        Assert.True(preview.IsCurrent());
        Assert.True(completed.IsCurrent());
    }

    [Theory]
    [InlineData("AD.LAB", 205)]
    [InlineData("nEeDlE", 5)]
    [InlineData("not-a-computer", 0)]
    public async Task RealSavedDatasetPublishesEveryMatchingPageWithExactArtifactContext(string search, int expected)
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);
        var dataset = new LapsExportDataset(source, directory, new(Root, ListingScope.Subtree, search, null));
        var preview = await dataset.PreviewAsync(ExportSelection.Matching, CancellationToken.None);
        using var output = new CsvExportTests.Fixture();
        var result = await new CsvExportService().ExportAsync(dataset, preview, new(output.Destination, false),
            new CsvExportTests.SilentProgress(), CancellationToken.None);
        using var parser = new TextFieldParser(result.Path, Encoding.UTF8)
        {
            TextFieldType = FieldType.Delimited,
            HasFieldsEnclosedInQuotes = true,
            TrimWhiteSpace = false,
        };
        parser.SetDelimiters(",");
        var metadata = new List<string[]>();
        var rows = new List<string[]>();
        var foundHeader = false;
        while (!parser.EndOfData)
        {
            var fields = parser.ReadFields() ?? throw new InvalidDataException("The generated CSV ended unexpectedly.");
            if (!foundHeader && fields[0] == "Computer")
            {
                Assert.Equal(LapsExportDataset.Columns, fields);
                foundHeader = true;
            }
            else if (foundHeader) rows.Add(fields);
            else metadata.Add(fields);
        }
        Assert.True(foundHeader);
        Assert.Equal(expected, rows.Count);
        Assert.All(rows, row => Assert.Equal(20, row.Length));
        Assert.Contains(metadata, row => row.SequenceEqual(new[] { "Exported rows", expected.ToString(CultureInfo.InvariantCulture) }));
        Assert.Contains(metadata, row => row.SequenceEqual(new[] { "Rows in directory scope before filters", "205" }));
        Assert.Contains(metadata, row => row.SequenceEqual(new[] { "Judgement generation", preview.Context.Source.JudgementGeneration.ToString("D") }));
        Assert.Contains(metadata, row => row.SequenceEqual(new[] { "Filter: Search (computer or domain substring)", search }));
        Assert.Equal(expected, result.Rows);
        output.AssertNoTemporaryFiles();
    }

    [Fact]
    public async Task ExplicitUnfilteredChoiceRemovesOnlySearchAndValueFilters()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);
        var dataset = new LapsExportDataset(source, directory, new(Root, ListingScope.Subtree, "nEeDlE", LapsValuePresence.None));
        var filtered = await dataset.PreviewAsync(ExportSelection.Matching, CancellationToken.None);
        var all = await dataset.PreviewAsync(ExportSelection.AllInScope, CancellationToken.None);
        Assert.Equal((1L, 205L), (filtered.Context.Rows, filtered.Context.ScopeRows));
        Assert.Equal((205L, 205L), (all.Context.Rows, all.Context.ScopeRows));
        Assert.Equal(filtered.Context.Source, all.Context.Source);
        Assert.Equal((filtered.Context.Scope, filtered.Context.Depth), (all.Context.Scope, all.Context.Depth));
        Assert.Contains(filtered.Context.Filters, entry => entry.Value == "nEeDlE");
        Assert.Contains(filtered.Context.Filters, entry => entry.Value == "No expiry values");
        Assert.Contains(all.Context.Filters, entry => entry.Value == "No search filter applied");
        Assert.Contains(all.Context.Filters, entry => entry.Value == "No value-group filter applied");
        var rows = new List<IReadOnlyList<ExportCell>>();
        await dataset.ReadRowsAsync(filtered, rows.Add, CancellationToken.None);
        Assert.Equal("ZZ-Needle-None", Assert.Single(rows)[0].Value);
    }

    [Fact]
    public async Task ClosedAndReopenedSelectionDoesNotReviveAnOldPreview()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var source = new BundleAssetSource();
        source.SelectRun(directory);
        var dataset = new LapsExportDataset(source, directory, new(Root, ListingScope.Subtree, "", null));
        var preview = await dataset.PreviewAsync(ExportSelection.Matching, CancellationToken.None);
        source.CloseRun();
        source.SelectRun(directory);
        Assert.False(preview.IsCurrent());
        var rows = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            dataset.ReadRowsAsync(preview, _ => rows++, CancellationToken.None));
        Assert.Equal(0, rows);
    }

    [Fact]
    public async Task ChangedGenerationIsRefusedBeforeAnyRowIsWritten()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var real = new BundleAssetSource();
        real.SelectRun(directory);
        var question = new LapsQuery(Root, ListingScope.Subtree, "nEeDlE", LapsValuePresence.None);
        var snapshot = real.ReadLapsExport(directory, question).Value;
        var source = new FakeAssetSource { LapsExport = _ => snapshot };
        source.SelectRun(directory);
        var dataset = new LapsExportDataset(source, directory, question);
        var preview = await dataset.PreviewAsync(ExportSelection.Matching, CancellationToken.None);
        source.LapsExport = _ => snapshot with
        {
            Inventory = snapshot.Inventory with
            {
                Description = snapshot.Inventory.Description with { GenerationId = Guid.NewGuid() },
            },
        };
        var rows = 0;
        await Assert.ThrowsAsync<InvalidDataException>(() => dataset.ReadRowsAsync(preview, _ => rows++, CancellationToken.None));
        Assert.Equal(0, rows);
    }

    [Fact]
    public async Task CapturedShortfallsStayInPreviewAndArtifactContext()
    {
        var directory = LapsScopePagingTests.FilterRun();
        using var real = new BundleAssetSource();
        real.SelectRun(directory);
        var question = new LapsQuery(Root, ListingScope.Subtree, "nEeDlE", LapsValuePresence.None);
        var snapshot = real.ReadLapsExport(directory, question).Value;
        const string shortfall = "Some captured rows have unknown object classes; the computer count may be incomplete.";
        snapshot = snapshot with
        {
            Inventory = snapshot.Inventory with { ComputersAreComplete = false, Shortfall = shortfall },
            FirstPage = snapshot.FirstPage with { ComputersAreComplete = false, Shortfall = shortfall },
        };
        var source = new FakeAssetSource { LapsExport = _ => snapshot };
        source.SelectRun(directory);
        var dataset = new LapsExportDataset(source, directory, question);
        var preview = await dataset.PreviewAsync(ExportSelection.Matching, CancellationToken.None);
        Assert.Contains(shortfall, preview.CoverageSummary);
        Assert.Contains(preview.Context.Coverage, entry => entry.Value == shortfall);
        Assert.Contains(preview.Context.Coverage, entry => entry.Name == "Whole-forest computer count"
            && entry.Value.Contains("Not established", StringComparison.Ordinal));
        Assert.Contains(preview.Context.Notes, note => note.Contains("Missing expiration does not prove GPO failure.", StringComparison.Ordinal));
        using var writer = new StringWriter();
        CsvExportWriter.WriteHeader(writer, preview, DateTimeOffset.UnixEpoch, CancellationToken.None);
        Assert.Contains(shortfall, writer.ToString());
    }

    [Theory]
    [InlineData(LapsTimestampReading.Absent, "No value captured")]
    [InlineData(LapsTimestampReading.Zero, "Zero (no usable date)")]
    [InlineData(LapsTimestampReading.Unreadable, "Unusable value")]
    [InlineData(LapsTimestampReading.Present, "Usable date")]
    public void MappingPreservesSeparateTimestampQualityOriginalsAndFullSavedUtc(LapsTimestampReading quality, string label)
    {
        var expires = DateTimeOffset.Parse("2026-11-13T09:30:00.1234567Z", CultureInfo.InvariantCulture);
        var raw = quality switch
        {
            LapsTimestampReading.Absent => null,
            LapsTimestampReading.Zero => "0",
            LapsTimestampReading.Unreadable => "not a timestamp",
            _ => expires.UtcDateTime.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture),
        };
        var computer = Computer(new(raw, quality, quality == LapsTimestampReading.Present ? expires : null),
            new("legacy-unusable", LapsTimestampReading.Unreadable, null));
        var cells = LapsExportDataset.Map(computer);
        Assert.Equal(20, cells.Count);
        Assert.Equal(label, cells[12].Value);
        Assert.Equal(raw, cells[13].Value);
        Assert.Equal(ExportCellKind.LiteralText, cells[13].Kind);
        Assert.Equal(quality == LapsTimestampReading.Present ? "2026-11-13T09:30:00.1234567Z" : null, cells[11].Value);
        Assert.Equal("Unusable value", cells[16].Value);
        Assert.Equal("legacy-unusable", cells[17].Value);
        Assert.Null(cells[15].Value);
    }

    [Fact]
    public void UnknownPlatformsAccountsAndUnsupportedOriginalsAreNotDroppedOrInvented()
    {
        var computer = Computer(new(null, LapsTimestampReading.Unreadable, null, true),
            new(null, LapsTimestampReading.Absent, null)) with
        {
            AccountState = LapsAttributes.AccountState.Unknown,
            DomainController = new(true, false, false),
            Capability = new(LapsCapabilityKind.Unknown, LapsCapabilityBasis.NothingToReadFrom, null, null),
        };
        var cells = LapsExportDataset.Map(computer);
        Assert.Equal(computer.Name, cells[0].Value);
        Assert.Equal("Unknown", cells[6].Value);
        Assert.Equal("Account flag; Indicators disagree", cells[7].Value);
        Assert.Equal("Unknown", cells[9].Value);
        Assert.Equal("Unusable value", cells[12].Value);
        Assert.Null(cells[13].Value);
        Assert.Equal("Yes", cells[14].Value);
        Assert.Equal("No value captured", cells[16].Value);
        Assert.Equal("No", cells[18].Value);
    }

    private static LapsComputer Computer(StoredLapsTimestamp windows, StoredLapsTimestamp legacy) => new(
        "CN=PC,DC=example", "PC", Guid.NewGuid(), "example", windows, legacy, "Windows Server 2022", "10.0 (20348)",
        "4096", "515", new(LapsCapabilityKind.WindowsLapsCapable, LapsCapabilityBasis.OperatingSystemVersion,
            "Windows Server 2022", "10.0 (20348)"), new(false, false, false),
        LapsAttributes.AccountState.Enabled, LapsValuePresence.Both);
}
