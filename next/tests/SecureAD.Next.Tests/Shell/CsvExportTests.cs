using System.Globalization;
using System.Text;
using SecureAD.Shell.Services.Export;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class CsvExportTests
{
    [Theory]
    [InlineData("plain", "\"plain\"\r\n")]
    [InlineData("comma,value", "\"comma,value\"\r\n")]
    [InlineData("a\"b", "\"a\"\"b\"\r\n")]
    [InlineData("a\r\nb", "\"a\r\nb\"\r\n")]
    [InlineData("\u00d6rebro \ud83d\udd12", "\"\u00d6rebro \ud83d\udd12\"\r\n")]
    [InlineData("=1+1", "\"'=1+1\"\r\n")]
    [InlineData("+1", "\"'+1\"\r\n")]
    [InlineData("-1", "\"'-1\"\r\n")]
    [InlineData("@value", "\"'@value\"\r\n")]
    [InlineData(" =1", "\"' =1\"\r\n")]
    [InlineData("\tvalue", "\"'\tvalue\"\r\n")]
    [InlineData("\rvalue", "\"'\rvalue\"\r\n")]
    [InlineData("\uFEFF=1", "\"'\uFEFF=1\"\r\n")]
    [InlineData("'original", "\"''original\"\r\n")]
    public void TextEncodingKeepsOriginalCharactersAndGuardsSpreadsheetInputs(string value, string expected)
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        CsvExportWriter.WriteRow(writer, [ExportCell.Text(value)], CancellationToken.None);
        Assert.Equal(expected, writer.ToString());
    }

    [Fact]
    public void LiteralTimestampNullEmptyZeroAndLongValuesRemainDifferent()
    {
        using var writer = new StringWriter(CultureInfo.InvariantCulture);
        CsvExportWriter.WriteRow(writer, [ExportCell.Literal(null), ExportCell.Literal(""), ExportCell.Literal("0"),
            ExportCell.Literal("134075142001234567")], CancellationToken.None);
        Assert.Equal("\"\",\"'\",\"'0\",\"'134075142001234567\"\r\n", writer.ToString());
    }

    [Fact]
    public void DatesAndNumbersKeepUtcPrecisionAndInvariantFormatting()
    {
        var previous = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("fr-FR");
            using var writer = new StringWriter();
            CsvExportWriter.WriteRow(writer,
                [ExportCell.Number(-1234567), ExportCell.Utc(DateTimeOffset.Parse("2026-11-13T10:00:00.1234567+02:00", CultureInfo.InvariantCulture))],
                CancellationToken.None);
            Assert.Equal("\"-1234567\",\"2026-11-13T08:00:00.1234567Z\"\r\n", writer.ToString());
        }
        finally { CultureInfo.CurrentCulture = previous; }
    }

    [Fact]
    public void HeaderCarriesSourceFiltersCountsAndCoverageInsideTheArtifact()
    {
        using var fixture = new Fixture();
        var preview = fixture.Preview(2) with
        {
            Context = fixture.Preview(2).Context with
            {
                Filters = [new("Search", "nEeDlE"), new("Captured values", "No expiry values")],
                Coverage = [new("Domain scope: missing.example", "ExcludedByChoice; intentionally excluded")],
                Notes = ["Missing expiration does not prove GPO failure."],
            },
        };
        using var writer = new StringWriter();
        CsvExportWriter.WriteHeader(writer, preview, DateTimeOffset.UnixEpoch, CancellationToken.None);
        var text = writer.ToString();
        Assert.Contains("\"Source run\",\"synthetic-run\"", text);
        Assert.Contains("\"Capture generation\",\"" + preview.Context.Source.CaptureGeneration.ToString("D") + "\"", text);
        Assert.Contains("\"Evidence fingerprint\",\"" + new string('a', 64) + "\"", text);
        Assert.Contains("\"Judgement generation\",\"" + preview.Context.Source.JudgementGeneration.ToString("D") + "\"", text);
        Assert.Contains("\"Filter: Search\",\"nEeDlE\"", text);
        Assert.Contains("\"Filter: Captured values\",\"No expiry values\"", text);
        Assert.Contains("\"Exported rows\",\"2\"", text);
        Assert.Contains("\"Rows in directory scope before filters\",\"5\"", text);
        Assert.Contains("ExcludedByChoice; intentionally excluded", text);
        Assert.Contains("Missing expiration does not prove GPO failure.", text);
        Assert.Contains("remove exactly one", text);
        Assert.EndsWith("\r\n\r\n\"Label\",\"Value\"\r\n", text);
    }

    [Theory]
    [InlineData(-1, 5)]
    [InlineData(6, 5)]
    public void InvalidCompleteCountsAreRefused(long rows, long scope)
    {
        using var fixture = new Fixture();
        var preview = fixture.Preview(rows);
        using var writer = new StringWriter();
        Assert.Throws<InvalidDataException>(() => CsvExportWriter.WriteHeader(writer,
            preview with { Context = preview.Context with { ScopeRows = scope } }, DateTimeOffset.UnixEpoch, CancellationToken.None));
    }

    [Theory]
    [InlineData("empty")]
    [InlineData("duplicate")]
    [InlineData("source")]
    public void InvalidHeadersAreNotWrittenAsAValidExport(string fault)
    {
        using var fixture = new Fixture();
        var preview = fixture.Preview(0);
        preview = fault switch
        {
            "empty" => preview with { Columns = [] },
            "duplicate" => preview with { Columns = ["Name", "name"] },
            _ => preview with { Context = preview.Context with { Source = preview.Context.Source with { CaptureGeneration = Guid.Empty } } },
        };
        using var writer = new StringWriter();
        Assert.Throws<InvalidDataException>(() => CsvExportWriter.WriteHeader(writer, preview, DateTimeOffset.UnixEpoch, CancellationToken.None));
    }

    [Fact]
    public async Task SharedServiceWritesAnUnrelatedSyntheticSchemaWithUtf8AndNoPartialFile()
    {
        using var fixture = new Fixture();
        var dataset = new RowsDataset([[ExportCell.Text("\u00d6rebro"), ExportCell.Literal("134075142001234567")]]);
        var result = await fixture.Export(dataset, fixture.Preview(1));
        var bytes = File.ReadAllBytes(result.Path);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, bytes[..3]);
        var text = File.ReadAllText(result.Path);
        Assert.Contains("\"SecureAD export\",\"Synthetic records\"", text);
        Assert.Contains("\"Filters\",\"No filters applied\"", text);
        Assert.EndsWith("\"\u00d6rebro\",\"'134075142001234567\"\r\n", text);
        Assert.Equal((1L, 5L), (result.Rows, result.ScopeRows));
        Assert.Equal(1, dataset.Reads);
        fixture.AssertNoTemporaryFiles();
    }

    [Fact]
    public async Task ZeroRowsStillHaveMetadataAndTheNormalColumnHeader()
    {
        using var fixture = new Fixture();
        var result = await fixture.Export(new RowsDataset([]), fixture.Preview(0));
        var text = File.ReadAllText(result.Path);
        Assert.Contains("\"Exported rows\",\"0\"", text);
        Assert.Contains("\"Rows in directory scope before filters\",\"5\"", text);
        Assert.EndsWith("\"Label\",\"Value\"\r\n", text);
        Assert.Equal(0, result.Rows);
    }

    [Fact]
    public async Task ExplicitReplacementPublishesOnlyTheCompleteNewFile()
    {
        using var fixture = new Fixture();
        fixture.WriteOriginal();
        await fixture.Export(new RowsDataset([[ExportCell.Text("new"), ExportCell.Number(7)]]), fixture.Preview(1), replace: true);
        Assert.EndsWith("\"new\",\"7\"\r\n", File.ReadAllText(fixture.Destination));
        fixture.AssertNoTemporaryFiles();
    }

    [Fact]
    public async Task AnUnapprovedExistingDestinationIsNeverOverwritten()
    {
        using var fixture = new Fixture();
        var original = fixture.WriteOriginal();
        await Assert.ThrowsAsync<IOException>(() => fixture.Export(new RowsDataset([]), fixture.Preview(0)));
        Assert.Equal(original, File.ReadAllBytes(fixture.Destination));
        fixture.AssertNoTemporaryFiles();
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("read-failure")]
    [InlineData("source-change")]
    [InlineData("too-few")]
    [InlineData("too-many")]
    [InlineData("column-width")]
    [InlineData("invalid-unicode")]
    public async Task FailureOrCancellationPreservesTheExistingDestinationAndRemovesStaging(string fault)
    {
        using var fixture = new Fixture();
        var original = fixture.WriteOriginal();
        using var cancellation = new CancellationTokenSource();
        var rows = new List<IReadOnlyList<ExportCell>> { new[] { ExportCell.Text("one"), ExportCell.Number(1) } };
        if (fault == "too-many") rows.Add([ExportCell.Text("two"), ExportCell.Number(2)]);
        if (fault == "column-width") rows[0] = [ExportCell.Text("only one cell")];
        if (fault == "invalid-unicode") rows[0] = [ExportCell.Text("\uD800"), ExportCell.Number(1)];
        var dataset = new RowsDataset(rows);
        dataset.AfterRow = () =>
        {
            if (fault == "cancel") cancellation.Cancel();
            if (fault == "read-failure") throw new IOException("Synthetic saved-row failure.");
            if (fault == "source-change") dataset.Current = false;
        };
        var expected = fault == "too-few" ? 2 : 1;
        var error = await Record.ExceptionAsync(() => fixture.Export(dataset, fixture.Preview(expected),
            replace: true, cancellation.Token));
        Assert.NotNull(error);
        if (fault == "cancel") Assert.IsAssignableFrom<OperationCanceledException>(error);
        else if (fault is "too-few" or "too-many" or "column-width" or "source-change") Assert.IsType<InvalidDataException>(error);
        else if (fault == "read-failure") Assert.IsType<IOException>(error);
        else Assert.IsType<EncoderFallbackException>(error);
        Assert.True(File.Exists(fixture.Destination), "The existing destination was lost.");
        Assert.Equal(original, File.ReadAllBytes(fixture.Destination));
        fixture.AssertNoTemporaryFiles();
    }

    [Fact]
    public async Task APreviewFromAClosedLifetimeCannotReadOrPublish()
    {
        using var fixture = new Fixture();
        var dataset = new RowsDataset([]);
        var preview = fixture.Preview(0) with { IsCurrent = () => false };
        await Assert.ThrowsAsync<InvalidDataException>(() => fixture.Export(dataset, preview));
        Assert.Equal(0, dataset.Reads);
        Assert.False(File.Exists(fixture.Destination));
        fixture.AssertNoTemporaryFiles();
    }

    [Fact]
    public async Task SourceFoldersAndNonCsvDestinationsAreRefused()
    {
        using var fixture = new Fixture();
        var service = new CsvExportService();
        var dataset = new RowsDataset([]);
        foreach (var target in new[] { Path.Combine(fixture.Source, "export.csv"), Path.Combine(fixture.Root, "evidence.db") })
        {
            await Assert.ThrowsAsync<IOException>(() => service.ExportAsync(dataset, fixture.Preview(0),
                new(target, false), new SilentProgress(), CancellationToken.None));
            Assert.False(File.Exists(target));
        }
        Assert.Equal(0, dataset.Reads);
    }

    [Fact]
    public async Task DestinationOpeningErrorsAreExplicit()
    {
        using var fixture = new Fixture();
        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => new CsvExportService().ExportAsync(
            new RowsDataset([]), fixture.Preview(0), new(Path.Combine(fixture.Root, "absent", "result.csv"), false),
            new SilentProgress(), CancellationToken.None));
        fixture.AssertNoTemporaryFiles();
    }

    internal sealed class RowsDataset(IReadOnlyList<IReadOnlyList<ExportCell>> rows) : IExportDataset
    {
        public string Title => "Synthetic records";
        public ExportPresentation Presentation { get; } = new("rows", "rows", "Saved synthetic rows only.",
            "Keep current filters.", "Remove filters explicitly.", "Synthetic records only.",
            "No live data is read.", "No additional filter.", "Rows to export");
        public int Reads { get; private set; }
        public bool Current { get; set; } = true;
        public Action? AfterRow { get; set; }
        public Func<ExportSelection, CancellationToken, Task<ExportPreview>>? Prepare { get; set; }
        public Task<ExportPreview> PreviewAsync(ExportSelection selection, CancellationToken cancellationToken) =>
            Prepare?.Invoke(selection, cancellationToken) ?? throw new InvalidOperationException("No preview supplied.");
        public Task<ExportReadResult> ReadRowsAsync(ExportPreview preview, Action<IReadOnlyList<ExportCell>> writeRow,
            CancellationToken cancellationToken)
        {
            Reads++;
            foreach (var row in rows) { writeRow(row); AfterRow?.Invoke(); }
            return Task.FromResult(new ExportReadResult(() => Current));
        }
    }

    internal sealed class SilentProgress : IProgress<ExportProgress>
    {
        public void Report(ExportProgress value) { }
    }

    internal sealed class Fixture : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(), "SecureAD-Export-" + Guid.NewGuid().ToString("N"));
        internal string Source => Path.Combine(Root, "run");
        internal string Destination => Path.Combine(Root, "result.csv");
        private readonly Guid _capture = Guid.NewGuid();
        private readonly Guid _judgement = Guid.NewGuid();
        internal Fixture() => Directory.CreateDirectory(Source);
        internal ExportPreview Preview(long rows) => new(
            new("Synthetic records", new(Source, "synthetic-run", _capture, new string('a', 64), null, _judgement,
                    DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddMinutes(1)),
                "OU=Scope,DC=example", "Subtree", ExportSelection.Matching, rows, 5, [], [], []),
            "synthetic-question", ["Label", "Value"], ["Label", "Value", "Third", "Fourth"], [], "Synthetic coverage.", () => true);
        internal byte[] WriteOriginal()
        {
            File.WriteAllText(Destination, "Original destination - do not lose.");
            return File.ReadAllBytes(Destination);
        }
        internal Task<ExportResult> Export(IExportDataset dataset, ExportPreview preview, bool replace = false,
            CancellationToken token = default) =>
            new CsvExportService().ExportAsync(dataset, preview, new(Destination, replace), new SilentProgress(), token);
        internal void AssertNoTemporaryFiles() =>
            Assert.Empty(Directory.EnumerateFiles(Root, ".securead-export-*.tmp", SearchOption.AllDirectories));
        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
