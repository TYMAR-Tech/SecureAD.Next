using System.Globalization;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Shell.Services.Export;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class ExportViewModel : ObservableObject, IDisposable
{
    private readonly IExportDataset _dataset;
    private readonly ICsvExportService _exporter;
    private readonly IExportDestinationPicker _picker;
    private CancellationTokenSource? _pending;
    private int _revision;
    private bool _disposed;

    [ObservableProperty] private ExportPreview? _preview;
    [ObservableProperty] private bool _allInScope;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _isExporting;
    [ObservableProperty] private bool _isError;
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string _savedPath = "";

    internal ExportViewModel(IExportDataset dataset, ICsvExportService exporter, IExportDestinationPicker picker)
    {
        _dataset = dataset ?? throw new ArgumentNullException(nameof(dataset));
        _exporter = exporter ?? throw new ArgumentNullException(nameof(exporter));
        _picker = picker ?? throw new ArgumentNullException(nameof(picker));
    }

    public event Action? CloseRequested;
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    public string Title => ExportText.Format("Title", _dataset.Title);
    public string Subtitle => _dataset.Presentation.Subtitle;
    public string MatchingLabel => ExportText.Format("Matching", _dataset.Presentation.ItemPlural);
    public string MatchingNote => _dataset.Presentation.MatchingNote;
    public string AllInScopeLabel => ExportText.Format("AllInScope", _dataset.Presentation.ItemPlural);
    public string AllInScopeNote => _dataset.Presentation.AllInScopeNote;
    public string CautionTitle => _dataset.Presentation.CautionTitle;
    public string CautionBody => _dataset.Presentation.CautionBody;
    public string ScopeNote => _dataset.Presentation.ScopeNote;
    public string SelectionHeading => _dataset.Presentation.SelectionHeading;
    public string SampleHeading => ExportText.Get("Preview");
    public string ColumnsHeading => ExportText.Get("Columns");
    public string ContextHeading => ExportText.Get("CsvContext");
    public string CsvNote => ExportText.Get("CsvNote");
    public string TextSafety => ExportText.Get("TextSafety");
    public string EmptyText => ExportText.Format("Empty", _dataset.Presentation.ItemPlural);
    public string SaveLabel => ExportText.Get("Choose");
    public string CancelLabel => ExportText.Get(IsExporting ? "CancelExport" : HasStatus && !IsLoading ? "Close" : "Cancel");
    public bool Matching { get => !AllInScope; set { if (value) AllInScope = false; } }
    public bool CanChooseScope => !IsLoading && !IsExporting;
    public bool HasPreview => Preview is not null && !IsLoading;
    public bool CanSave => HasPreview && !IsExporting && !_disposed;
    public bool HasStatus => !string.IsNullOrEmpty(Status);
    public bool HasSavedPath => !string.IsNullOrEmpty(SavedPath);
    public bool HasNoRows => HasPreview && Preview!.Context.Rows == 0;
    public string SourceRun => Preview?.Context.Source.Run ?? "";
    public string Captured => Preview is { } preview
        ? $"{preview.Context.Source.CaptureStartedUtc.UtcDateTime:yyyy-MM-dd HH:mm:ss} - {preview.Context.Source.CaptureCompletedUtc.UtcDateTime:yyyy-MM-dd HH:mm:ss} UTC" : "";
    public string Scope => Preview is { } preview ? preview.Context.Scope + " - " + preview.Context.Depth : "";
    public string CountText => Preview is { } preview
        ? ExportText.Format("Count", preview.Context.Rows, preview.Context.ScopeRows, _dataset.Presentation.CountedItems) : "";
    public string FiltersText => Preview is { } preview
        ? string.Join(Environment.NewLine, preview.Context.Filters.Select(entry => entry.Name + ": " + entry.Value)) : "";
    public string Coverage => Preview?.CoverageSummary ?? "";
    public string ColumnsText => Preview is { } preview ? string.Join(Environment.NewLine, preview.Columns) : "";
    public IReadOnlyList<string> SampleHeaders => Preview?.SampleHeaders ?? [];
    public IReadOnlyList<ExportSampleRow> Sample => Preview?.Sample ?? [];
    public string SourceDetails => Preview is { Context: var context }
        ? string.Join(Environment.NewLine, new[]
        {
            "Capture generation: " + context.Source.CaptureGeneration.ToString("D"),
            "Evidence fingerprint: " + context.Source.EvidenceFingerprint,
            "Derivation generation: " + (context.Source.DerivationGeneration?.ToString("D") ?? "Not used by this saved judgement"),
            "Judgement generation: " + context.Source.JudgementGeneration.ToString("D"),
        }.Concat(context.Coverage.Select(entry => entry.Name + ": " + entry.Value)).Concat(context.Notes)) : "";

    [RelayCommand]
    private async Task OpenAsync()
    {
        ReadCompletion = LoadAsync();
        await ReadCompletion;
    }

    private async Task LoadAsync()
    {
        _pending?.Cancel();
        var revision = ++_revision;
        using var pending = new CancellationTokenSource();
        _pending = pending;
        Preview = null;
        IsLoading = true;
        IsError = false;
        SavedPath = "";
        Status = ExportText.Get("Loading");
        try
        {
            var preview = await _dataset.PreviewAsync(AllInScope ? ExportSelection.AllInScope : ExportSelection.Matching, pending.Token);
            if (_disposed || revision != _revision || pending.IsCancellationRequested) return;
            Preview = preview;
            Status = "";
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested)
        {
            if (!_disposed && revision == _revision) Status = ExportText.Get("Cancelled");
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException
            or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (_disposed || revision != _revision) return;
            IsError = true;
            Status = ExportText.Format("PreviewFailed", error.Message);
        }
        finally
        {
            if (ReferenceEquals(_pending, pending)) _pending = null;
            if (!_disposed && revision == _revision) IsLoading = false;
        }
    }

    [RelayCommand(CanExecute = nameof(CanSave))]
    private async Task SaveAsync()
    {
        var preview = Preview ?? throw new InvalidOperationException("No export has been prepared.");
        using var pending = new CancellationTokenSource();
        try
        {
            var destination = _picker.Pick("securead-export-" + DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmss'Z'", CultureInfo.InvariantCulture) + ".csv");
            if (destination is null) return;
            _pending = pending;
            IsExporting = true;
            IsError = false;
            SavedPath = "";
            Status = ExportText.Format("Writing", 0, preview.Context.Rows, _dataset.Presentation.ItemPlural);
            var progress = new Progress<ExportProgress>(value =>
            {
                if (!_disposed && ReferenceEquals(_pending, pending))
                    Status = ExportText.Format("Writing", value.Written, value.Total, _dataset.Presentation.ItemPlural);
            });
            var result = await _exporter.ExportAsync(_dataset, preview, destination, progress, pending.Token);
            if (_disposed) return;
            SavedPath = result.Path;
            Status = ExportText.Format("Saved", result.Rows, result.ScopeRows, _dataset.Presentation.ItemPlural);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested)
        {
            if (!_disposed) Status = ExportText.Get("Cancelled");
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException
            or ArgumentException or Microsoft.Data.Sqlite.SqliteException or AggregateException)
        {
            if (_disposed) return;
            IsError = true;
            Status = ExportText.Format("Failed", error.Message);
        }
        finally
        {
            if (ReferenceEquals(_pending, pending)) _pending = null;
            if (!_disposed) IsExporting = false;
        }
    }

    [RelayCommand]
    private void Cancel()
    {
        _pending?.Cancel();
        if (!IsExporting) CloseRequested?.Invoke();
    }

    partial void OnAllInScopeChanged(bool value)
    {
        OnPropertyChanged(nameof(Matching));
        if (!_disposed && !IsExporting) ReadCompletion = LoadAsync();
    }
    partial void OnPreviewChanged(ExportPreview? value) => Announce();
    partial void OnIsLoadingChanged(bool value) => Announce();
    partial void OnIsExportingChanged(bool value) => Announce();
    partial void OnStatusChanged(string value)
    {
        OnPropertyChanged(nameof(HasStatus));
        OnPropertyChanged(nameof(CancelLabel));
    }
    partial void OnSavedPathChanged(string value) => OnPropertyChanged(nameof(HasSavedPath));

    private void Announce()
    {
        foreach (var name in new[] { nameof(CanChooseScope), nameof(HasPreview), nameof(CanSave), nameof(HasNoRows),
            nameof(SourceRun), nameof(Captured), nameof(Scope), nameof(CountText), nameof(FiltersText), nameof(Coverage),
            nameof(ColumnsText), nameof(SampleHeaders), nameof(Sample), nameof(SourceDetails), nameof(CancelLabel) })
            OnPropertyChanged(name);
        SaveCommand.NotifyCanExecuteChanged();
    }

    public void Dispose()
    {
        _disposed = true;
        _revision++;
        _pending?.Cancel();
    }
}
