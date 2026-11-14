using System.IO;
using System.Text;

namespace SecureAD.Shell.Services.Export;

/// <summary>Publishes a complete CSV or leaves the destination unchanged; it knows no dataset mapping.</summary>
internal sealed class CsvExportService : ICsvExportService
{
    public Task<ExportResult> ExportAsync(IExportDataset dataset, ExportPreview preview, ExportDestination destination,
        IProgress<ExportProgress> progress, CancellationToken cancellationToken) =>
        Task.Run(() => ExportCoreAsync(dataset, preview, destination, progress, cancellationToken), cancellationToken);

    private static async Task<ExportResult> ExportCoreAsync(IExportDataset dataset, ExportPreview preview,
        ExportDestination destination, IProgress<ExportProgress> progress, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(dataset);
        ArgumentNullException.ThrowIfNull(preview);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(progress);
        token.ThrowIfCancellationRequested();
        if (!preview.IsCurrent()) throw new InvalidDataException(ExportText.Get("SourceChanged"));
        var path = Path.GetFullPath(destination.Path);
        if (!string.Equals(Path.GetExtension(path), ".csv", StringComparison.OrdinalIgnoreCase))
            throw new IOException("Choose a destination with the .csv extension.");
        var source = Path.TrimEndingDirectorySeparator(Path.GetFullPath(preview.Context.Source.Directory));
        if (path.Equals(source, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(source + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Choose a CSV location outside this run's saved-data folder.");
        var parent = Path.GetDirectoryName(path) ?? throw new IOException("The export destination has no parent folder.");
        var temporary = Path.Combine(parent, ".securead-export-" + Guid.NewGuid().ToString("N") + ".tmp");
        var created = false;
        Exception? failure = null;
        try
        {
            long written = 0;
            ExportReadResult reading;
            await using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                65536, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                created = true;
                using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: true,
                    throwOnInvalidBytes: true), 16384, leaveOpen: true))
                {
                    CsvExportWriter.WriteHeader(writer, preview, DateTimeOffset.UtcNow, token);
                    reading = await dataset.ReadRowsAsync(preview, row =>
                    {
                        token.ThrowIfCancellationRequested();
                        if (row.Count != preview.Columns.Count || written >= preview.Context.Rows)
                            throw new InvalidDataException("The saved export rows do not match the approved columns or complete count.");
                        CsvExportWriter.WriteRow(writer, row, token);
                        written = checked(written + 1);
                        if (written % 100 == 0 || written == preview.Context.Rows)
                            progress.Report(new(written, preview.Context.Rows));
                    }, token).ConfigureAwait(false);
                    if (written != preview.Context.Rows)
                        throw new InvalidDataException("The saved export ended before its complete matching-row count was written.");
                    await writer.FlushAsync(token).ConfigureAwait(false);
                }
                stream.Flush(flushToDisk: true);
            }
            token.ThrowIfCancellationRequested();
            if (!preview.IsCurrent() || !reading.IsCurrent()) throw new InvalidDataException(ExportText.Get("SourceChanged"));
            token.ThrowIfCancellationRequested();
            // No cancellation or callback after this boundary may relabel an already published file.
            if (destination.ReplaceExisting) File.Replace(temporary, path, destinationBackupFileName: null);
            else File.Move(temporary, path, overwrite: false);
            created = false;
            return new(path, written, preview.Context.ScopeRows);
        }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or InvalidOperationException
            or ArgumentException or OperationCanceledException or Microsoft.Data.Sqlite.SqliteException)
        {
            failure = error;
            throw;
        }
        finally
        {
            if (created)
            {
                try { File.Delete(temporary); }
                catch (Exception cleanup) when (cleanup is IOException or UnauthorizedAccessException)
                {
                    throw new AggregateException("The temporary export could not be removed: " + temporary,
                        failure is null ? [cleanup] : [failure, cleanup]);
                }
            }
        }
    }
}
