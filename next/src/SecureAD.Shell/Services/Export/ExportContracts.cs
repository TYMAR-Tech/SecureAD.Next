using System.Globalization;

namespace SecureAD.Shell.Services.Export;

internal enum ExportSelection { Matching, AllInScope }
internal enum ExportCellKind { Text, LiteralText, Number, UtcDate }

internal readonly record struct ExportCell(string? Value, ExportCellKind Kind)
{
    internal static ExportCell Text(string? value) => new(value, ExportCellKind.Text);
    internal static ExportCell Literal(string? value) => new(value, ExportCellKind.LiteralText);
    internal static ExportCell Number(long value) => new(value.ToString(CultureInfo.InvariantCulture), ExportCellKind.Number);
    internal static ExportCell Utc(DateTimeOffset? value) => new(value?.ToUniversalTime()
        .ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'", CultureInfo.InvariantCulture), ExportCellKind.UtcDate);
}

internal sealed record ExportField(string Name, string Value);

internal sealed record ExportSource(
    string Directory, string Run, Guid CaptureGeneration, string EvidenceFingerprint,
    Guid? DerivationGeneration, Guid JudgementGeneration, DateTimeOffset CaptureStartedUtc,
    DateTimeOffset CaptureCompletedUtc);

internal sealed record ExportContext(
    string Dataset, ExportSource Source, string Scope, string Depth, ExportSelection Selection,
    long Rows, long ScopeRows, IReadOnlyList<ExportField> Filters, IReadOnlyList<ExportField> Coverage,
    IReadOnlyList<string> Notes);

internal sealed record ExportSampleRow(string First, string Second, string Third, string Fourth);

internal sealed record ExportPreview(
    ExportContext Context, string Question, IReadOnlyList<string> Columns,
    IReadOnlyList<string> SampleHeaders, IReadOnlyList<ExportSampleRow> Sample, string CoverageSummary,
    Func<bool> IsCurrent);

internal sealed record ExportReadResult(Func<bool> IsCurrent);
internal sealed record ExportDestination(string Path, bool ReplaceExisting);
internal sealed record ExportProgress(long Written, long Total);
internal sealed record ExportResult(string Path, long Rows, long ScopeRows);

internal sealed record ExportPresentation(
    string ItemPlural, string CountedItems, string Subtitle, string MatchingNote, string AllInScopeNote,
    string CautionTitle, string CautionBody, string ScopeNote, string SelectionHeading);

internal interface IExportDataset
{
    string Title { get; }
    ExportPresentation Presentation { get; }
    Task<ExportPreview> PreviewAsync(ExportSelection selection, CancellationToken cancellationToken);
    Task<ExportReadResult> ReadRowsAsync(ExportPreview preview, Action<IReadOnlyList<ExportCell>> writeRow,
        CancellationToken cancellationToken);
}

internal interface ICsvExportService
{
    Task<ExportResult> ExportAsync(IExportDataset dataset, ExportPreview preview, ExportDestination destination,
        IProgress<ExportProgress> progress, CancellationToken cancellationToken);
}

internal interface IExportDestinationPicker
{
    ExportDestination? Pick(string suggestedName);
}
