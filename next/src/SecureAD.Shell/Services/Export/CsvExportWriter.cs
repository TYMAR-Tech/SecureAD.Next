using System.IO;

namespace SecureAD.Shell.Services.Export;

/// <summary>CSV encoding and artifact context, independent of any dataset or presentation control.</summary>
internal static class CsvExportWriter
{
    internal static void WriteHeader(TextWriter writer, ExportPreview preview, DateTimeOffset started,
        CancellationToken token)
    {
        var context = preview.Context;
        if (string.IsNullOrWhiteSpace(context.Dataset) || string.IsNullOrWhiteSpace(context.Source.Run)
            || string.IsNullOrWhiteSpace(context.Source.EvidenceFingerprint) || string.IsNullOrWhiteSpace(context.Scope)
            || context.Source.CaptureGeneration == Guid.Empty || context.Source.JudgementGeneration == Guid.Empty
            || !Enum.IsDefined(context.Selection))
            throw new InvalidDataException("The export source or scope is invalid.");
        if (context.Rows < 0 || context.ScopeRows < context.Rows || preview.Columns.Count == 0
            || preview.Columns.Any(string.IsNullOrWhiteSpace)
            || preview.Columns.Distinct(StringComparer.OrdinalIgnoreCase).Count() != preview.Columns.Count)
            throw new InvalidDataException("The export columns or complete row counts are invalid.");
        void Field(string name, ExportCell value) => WriteRow(writer, [ExportCell.Text(name), value], token);
        void Text(string name, string value) => Field(name, ExportCell.Text(value));
        Text("SecureAD export", context.Dataset);
        Text("Source run", context.Source.Run);
        Field("Capture start UTC", ExportCell.Utc(context.Source.CaptureStartedUtc));
        Field("Capture completion UTC", ExportCell.Utc(context.Source.CaptureCompletedUtc));
        Text("Capture generation", context.Source.CaptureGeneration.ToString("D"));
        Text("Evidence fingerprint", context.Source.EvidenceFingerprint);
        Text("Derivation generation", context.Source.DerivationGeneration?.ToString("D") ?? "Not used by this saved judgement");
        Text("Judgement generation", context.Source.JudgementGeneration.ToString("D"));
        Field("Export started UTC", ExportCell.Utc(started));
        Text("Directory scope", context.Scope);
        Text("Depth", context.Depth);
        Text("Selection", context.Selection == ExportSelection.Matching ? "All matching rows" : "All rows in this scope");
        if (context.Filters.Count == 0) Text("Filters", "No filters applied");
        foreach (var filter in context.Filters) Text("Filter: " + filter.Name, filter.Value);
        Field("Exported rows", ExportCell.Number(context.Rows));
        Field("Rows in directory scope before filters", ExportCell.Number(context.ScopeRows));
        foreach (var coverage in context.Coverage) Text(coverage.Name, coverage.Value);
        foreach (var note in context.Notes) Text("Note", note);
        Text("Text safety", "A leading export apostrophe is a literal-text marker; remove exactly one to recover text. "
            + "Literal columns are always guarded. Formula/control-leading and original apostrophe-leading text is guarded; other text is unchanged.");
        Text("Missing cells", "Blank optional values mean no saved value. Dataset quality columns and coverage notes retain their separate meaning.");
        writer.Write("\r\n");
        WriteRow(writer, preview.Columns.Select(ExportCell.Text).ToArray(), token);
    }

    internal static void WriteRow(TextWriter writer, IReadOnlyList<ExportCell> cells, CancellationToken token)
    {
        for (var index = 0; index < cells.Count; index++)
        {
            token.ThrowIfCancellationRequested();
            if (index != 0) writer.Write(',');
            var cell = cells[index];
            if (!Enum.IsDefined(cell.Kind)) throw new InvalidDataException("The export cell kind is not recognized.");
            writer.Write('"');
            if (cell.Value is { } value)
            {
                if (cell.Kind == ExportCellKind.LiteralText
                    || cell.Kind == ExportCellKind.Text && NeedsTextGuard(value)) writer.Write('\'');
                for (var position = 0; position < value.Length; position++)
                {
                    if ((position & 4095) == 0) token.ThrowIfCancellationRequested();
                    var character = value[position];
                    if (character == '"') writer.Write('"');
                    writer.Write(character);
                }
            }
            writer.Write('"');
        }
        writer.Write("\r\n");
    }

    private static bool NeedsTextGuard(string value)
    {
        if (value.Length == 0) return false;
        if (value[0] == '\'') return true;
        var first = 0;
        while (first < value.Length && (char.IsWhiteSpace(value[first]) || value[first] == '\uFEFF'))
        {
            if (char.IsControl(value[first])) return true;
            first++;
        }
        return first < value.Length && (char.IsControl(value[first]) || "=+-@".Contains(value[first]));
    }
}
