using SecureAD.Shell.Services.Export;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class ExportViewModelTests
{
    [Fact]
    public async Task LoadingDoesNotOfferOldOrEmptyResultsAndZeroRowsCanBeExported()
    {
        using var fixture = new CsvExportTests.Fixture();
        var completion = new TaskCompletionSource<ExportPreview>(TaskCreationOptions.RunContinuationsAsynchronously);
        var dataset = new CsvExportTests.RowsDataset([]) { Prepare = (_, _) => completion.Task };
        using var model = new ExportViewModel(dataset, new Exporter(), new Picker(null));
        var loading = model.OpenCommand.ExecuteAsync(null);
        Assert.True(model.IsLoading);
        Assert.False(model.CanSave);
        Assert.False(model.HasNoRows);
        Assert.Equal("", model.CountText);
        completion.SetResult(fixture.Preview(0));
        await loading;
        Assert.False(model.IsLoading);
        Assert.True(model.HasNoRows);
        Assert.True(model.CanSave);
        Assert.Equal("0 of 5 rows in this scope", model.CountText);
    }

    [Fact]
    public async Task ANewScopeDiscardsALateEarlierPreview()
    {
        using var fixture = new CsvExportTests.Fixture();
        var old = new TaskCompletionSource<ExportPreview>(TaskCreationOptions.RunContinuationsAsynchronously);
        var latest = new TaskCompletionSource<ExportPreview>(TaskCreationOptions.RunContinuationsAsynchronously);
        var asked = new List<ExportSelection>();
        var dataset = new CsvExportTests.RowsDataset([])
        {
            Prepare = (selection, _) =>
            {
                asked.Add(selection);
                return selection == ExportSelection.Matching ? old.Task : latest.Task;
            },
        };
        using var model = new ExportViewModel(dataset, new Exporter(), new Picker(null));
        var earlier = model.OpenCommand.ExecuteAsync(null);
        model.AllInScope = true;
        Assert.Contains(ExportSelection.AllInScope, asked);
        var current = fixture.Preview(5) with
        {
            Context = fixture.Preview(5).Context with { Selection = ExportSelection.AllInScope },
        };
        latest.SetResult(current);
        await model.ReadCompletion;
        old.SetResult(fixture.Preview(1));
        await earlier;
        Assert.Same(current, model.Preview);
        Assert.Equal(new[] { ExportSelection.Matching, ExportSelection.AllInScope }, asked);
        Assert.Equal("5 of 5 rows in this scope", model.CountText);
    }

    [Fact]
    public async Task FailedPreviewIsAnExplicitRefusalNotZeroMatches()
    {
        var dataset = new CsvExportTests.RowsDataset([])
        {
            Prepare = (_, _) => Task.FromException<ExportPreview>(new InvalidDataException("Saved generation mismatch.")),
        };
        using var model = new ExportViewModel(dataset, new Exporter(), new Picker(null));
        await model.OpenCommand.ExecuteAsync(null);
        Assert.True(model.IsError);
        Assert.Null(model.Preview);
        Assert.False(model.CanSave);
        Assert.False(model.HasNoRows);
        Assert.Contains("could not be read", model.Status);
        Assert.Contains("Saved generation mismatch.", model.Status);
    }

    [Fact]
    public async Task CancellingTheDestinationPickerDoesNotStartAnExport()
    {
        using var fixture = new CsvExportTests.Fixture();
        var dataset = Dataset(fixture);
        var exporter = new Exporter();
        using var model = new ExportViewModel(dataset, exporter, new Picker(null));
        await model.OpenCommand.ExecuteAsync(null);
        await model.SaveCommand.ExecuteAsync(null);
        Assert.Equal(0, exporter.Calls);
        Assert.False(model.HasSavedPath);
        Assert.False(model.IsExporting);
    }

    [Fact]
    public async Task SaveUsesTheCommonServiceAndReportsItsActualCompletedCount()
    {
        using var fixture = new CsvExportTests.Fixture();
        var dataset = Dataset(fixture);
        var destination = new ExportDestination(@"C:\synthetic-output\export.csv", true);
        var exporter = new Exporter { Complete = _ => Task.FromResult(new ExportResult(destination.Path, 2, 5)) };
        using var model = new ExportViewModel(dataset, exporter, new Picker(destination));
        await model.OpenCommand.ExecuteAsync(null);
        var prepared = model.Preview;
        await model.SaveCommand.ExecuteAsync(null);
        Assert.Equal(1, exporter.Calls);
        Assert.Same(dataset, exporter.Dataset);
        Assert.Same(prepared, exporter.Preview);
        Assert.Equal(destination, exporter.Destination);
        Assert.Equal(destination.Path, model.SavedPath);
        Assert.Equal("CSV saved - 2 of 5 rows.", model.Status);
        Assert.False(model.IsError);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OutputFailureDoesNotClaimSuccessOrRetainAPreviousOutputPath(bool invalidData)
    {
        using var fixture = new CsvExportTests.Fixture();
        var exporter = new Exporter
        {
            Complete = _ => Task.FromException<ExportResult>(invalidData
                ? new InvalidDataException("Synthetic invalid saved result.") : new IOException("Synthetic disk full.")),
        };
        using var model = new ExportViewModel(Dataset(fixture), exporter, new Picker(new(@"C:\synthetic-output\export.csv", false)));
        await model.OpenCommand.ExecuteAsync(null);
        await model.SaveCommand.ExecuteAsync(null);
        Assert.True(model.IsError);
        Assert.False(model.HasSavedPath);
        Assert.Contains("Export failed. No new CSV was saved.", model.Status);
        Assert.Contains(invalidData ? "Synthetic invalid saved result." : "Synthetic disk full.", model.Status);
        Assert.False(model.IsExporting);
    }

    [Fact]
    public async Task RunningExportKeepsItsPreparedQuestionAndCancellationRemainsExplicit()
    {
        using var fixture = new CsvExportTests.Fixture();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var exporter = new Exporter
        {
            Complete = async token =>
            {
                started.SetResult();
                await Task.Delay(Timeout.Infinite, token);
                throw new InvalidOperationException("Cancellation did not interrupt the test export.");
            },
        };
        using var model = new ExportViewModel(Dataset(fixture), exporter, new Picker(new(@"C:\synthetic-output\export.csv", false)));
        await model.OpenCommand.ExecuteAsync(null);
        var prepared = model.Preview;
        var saving = model.SaveCommand.ExecuteAsync(null);
        await started.Task;
        Assert.True(model.IsExporting);
        Assert.False(model.CanChooseScope);
        Assert.False(model.CanSave);
        Assert.Same(prepared, exporter.Preview);
        model.CancelCommand.Execute(null);
        await Task.WhenAny(saving, Task.Delay(TimeSpan.FromSeconds(3)));
        Assert.True(saving.IsCompleted, "Cancellation did not complete the in-progress export.");
        await saving;
        Assert.False(model.IsExporting);
        Assert.False(model.HasSavedPath);
        Assert.Equal("Export cancelled. No new CSV was saved.", model.Status);
    }

    [Fact]
    public async Task DisposedPreviewDoesNotApplyALateResult()
    {
        using var fixture = new CsvExportTests.Fixture();
        var completion = new TaskCompletionSource<ExportPreview>(TaskCreationOptions.RunContinuationsAsynchronously);
        var dataset = new CsvExportTests.RowsDataset([]) { Prepare = (_, _) => completion.Task };
        var model = new ExportViewModel(dataset, new Exporter(), new Picker(null));
        var loading = model.OpenCommand.ExecuteAsync(null);
        model.Dispose();
        completion.SetResult(fixture.Preview(2));
        await loading;
        Assert.Null(model.Preview);
        Assert.False(model.CanSave);
    }

    internal static CsvExportTests.RowsDataset Dataset(CsvExportTests.Fixture fixture) => new([])
    {
        Prepare = (selection, _) => Task.FromResult(fixture.Preview(2) with
        {
            Context = fixture.Preview(2).Context with { Selection = selection },
        }),
    };

    internal sealed class Picker(ExportDestination? destination) : IExportDestinationPicker
    {
        public ExportDestination? Pick(string suggestedName) => destination;
    }

    internal sealed class Exporter : ICsvExportService
    {
        internal int Calls { get; private set; }
        internal IExportDataset? Dataset { get; private set; }
        internal ExportPreview? Preview { get; private set; }
        internal ExportDestination? Destination { get; private set; }
        internal Func<CancellationToken, Task<ExportResult>> Complete { get; set; } =
            _ => throw new InvalidOperationException("No export result supplied by this test.");
        public Task<ExportResult> ExportAsync(IExportDataset dataset, ExportPreview preview, ExportDestination destination,
            IProgress<ExportProgress> progress, CancellationToken cancellationToken)
        {
            Calls++;
            Dataset = dataset;
            Preview = preview;
            Destination = destination;
            return Complete(cancellationToken);
        }
    }
}
