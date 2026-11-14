using System.IO;
using System.Text.Json;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Shell.ViewModels;

namespace SecureAD.Shell.Services.Export;

/// <summary>Maps saved inventory to export cells; it neither encodes CSV nor owns output files.</summary>
internal sealed class LapsExportDataset : IExportDataset
{
    public string Title => LapsInventoryText.Get("Title");
    public ExportPresentation Presentation { get; } = new("computers", "captured computers",
        ExportText.Get("Subtitle"), ExportText.Get("MatchingNote"), ExportText.Get("AllInScopeNote"),
        ExportText.Get("MissingCaution"), ExportText.Get("Meaning"), ExportText.Get("NoTypeFilter"), "Computers to export");
    private readonly IAssetSource _source;
    private readonly string _bundle;
    private readonly LapsQuery _question;

    internal static IReadOnlyList<string> Columns { get; } = Array.AsReadOnly(new[]
    {
        "Computer", "Domain", "Distinguished name", "Object GUID", "Operating system", "OS version",
        "Account state", "Controller indicators", "Captured values", "LAPS platform capability", "Capability basis",
        "Windows expiry (UTC)", "Windows value quality", "Windows captured value", "Windows unsupported representation",
        "Legacy expiry (UTC)", "Legacy value quality", "Legacy captured value", "Legacy unsupported representation", "Scope notes",
    });

    internal LapsExportDataset(IAssetSource source, string bundle, LapsQuery question)
    {
        _source = source ?? throw new ArgumentNullException(nameof(source));
        _bundle = Path.GetFullPath(bundle);
        _question = question with { Search = question.Search.Trim() };
    }

    public Task<ExportPreview> PreviewAsync(ExportSelection selection, CancellationToken cancellationToken)
    {
        var question = Question(selection);
        return _source.ReadAsync(_bundle, (reader, token) =>
        {
            var snapshot = Snapshot(reader, question);
            token.ThrowIfCancellationRequested();
            return new ExportPreview(Context(snapshot, selection), JsonSerializer.Serialize(question), Columns,
                ["Computer", "Windows expiry (UTC)", "Legacy expiry (UTC)", "Account state"],
                snapshot.FirstPage.Computers.Take(3).Select(computer =>
                {
                    var values = Map(computer);
                    return new ExportSampleRow(computer.Name, values[11].Value ?? Quality(computer.WindowsLaps),
                        values[15].Value ?? Quality(computer.LegacyLaps), values[6].Value!);
                }).ToArray(),
                (snapshot.Inventory.ComputersAreComplete ? "No object-listing shortfall is recorded for this selected scope."
                    : snapshot.Inventory.Shortfall ?? "Captured computer coverage is incomplete; the missing count is not established.")
                + $" The source run records {snapshot.CaptureScope.ReadCount} of {snapshot.CaptureScope.DeclaredCount} domains read."
                + (snapshot.Capture.ExcludedObjectClasses.Count == 0 ? "" : " Some object classes were explicitly excluded.")
                + " Optional LDAP attributes may be unset or unreturned. These are selected-scope counts, not a whole-forest total.",
                reader.CaptureReadValidity());
        }, cancellationToken);
    }

    public Task<ExportReadResult> ReadRowsAsync(ExportPreview preview, Action<IReadOnlyList<ExportCell>> writeRow,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(writeRow);
        if (!preview.IsCurrent()) throw new InvalidDataException(ExportText.Get("SourceChanged"));
        var question = Question(preview.Context.Selection);
        if (preview.Question != JsonSerializer.Serialize(question) || !preview.Columns.SequenceEqual(Columns))
            throw new InvalidDataException("The selected export columns or question changed.");
        return _source.ReadAsync(_bundle, (reader, token) =>
        {
            var snapshot = Snapshot(reader, question);
            var context = Context(snapshot, preview.Context.Selection);
            if (context.Source != preview.Context.Source || context.Rows != preview.Context.Rows
                || context.ScopeRows != preview.Context.ScopeRows
                || !context.Coverage.SequenceEqual(preview.Context.Coverage)
                || !context.Filters.SequenceEqual(preview.Context.Filters))
                throw new InvalidDataException(ExportText.Get("SourceChanged"));
            var current = reader.CaptureReadValidity();
            var page = snapshot.FirstPage;
            LapsPageMark? previous = null;
            while (true)
            {
                token.ThrowIfCancellationRequested();
                if (page.Total != context.ScopeRows || page.ComputersAreComplete != snapshot.Inventory.ComputersAreComplete
                    || page.Shortfall != snapshot.Inventory.Shortfall)
                    throw new InvalidDataException("The saved export page changed its scope or coverage.");
                foreach (var computer in page.Computers)
                {
                    token.ThrowIfCancellationRequested();
                    writeRow(Map(computer));
                }
                if (page.Next is not { } next) break;
                if (page.Computers.Count == 0 || next == previous
                    || next.GenerationId != context.Source.JudgementGeneration)
                    throw new InvalidDataException("The saved export continuation is invalid.");
                var read = reader.ListLapsComputers(_bundle, question, next);
                if (!read.IsSuccess) throw new InvalidDataException(read.Error.Description);
                page = read.Value;
                previous = next;
            }
            token.ThrowIfCancellationRequested();
            return new ExportReadResult(current);
        }, cancellationToken);
    }

    private LapsQuery Question(ExportSelection selection) => selection switch
    {
        ExportSelection.Matching => _question,
        ExportSelection.AllInScope => _question with { Search = "", State = null },
        _ => throw new ArgumentOutOfRangeException(nameof(selection)),
    };

    private LapsExportSnapshot Snapshot(IAssetReader reader, LapsQuery question)
    {
        var read = reader.ReadLapsExport(_bundle, question);
        if (!read.IsSuccess) throw new InvalidDataException(read.Error.Description);
        if (read.Value.Inventory.Query != question || !reader.CaptureReadValidity()())
            throw new InvalidDataException(ExportText.Get("SourceChanged"));
        return read.Value;
    }

    private ExportContext Context(LapsExportSnapshot snapshot, ExportSelection selection)
    {
        var capture = snapshot.Capture;
        var saved = snapshot.Inventory;
        var source = new ExportSource(_bundle, Path.GetFileName(Path.TrimEndingDirectorySeparator(_bundle)),
            capture.CaptureGenerationId, saved.Description.EvidenceSeal, saved.Description.DerivationGenerationId,
            saved.Description.GenerationId, capture.CaptureStartedUtc, capture.CaptureCompletedUtc);
        var coverage = new List<ExportField>
        {
            new("Selected-scope listing shortfall", saved.ComputersAreComplete ? "No object-listing shortfall recorded"
                : saved.Shortfall ?? "Captured computer coverage is incomplete; the missing count is not established."),
            new("Capture class exclusions", capture.ExcludedObjectClasses.Count == 0
                ? "No classes explicitly excluded" : string.Join("; ", capture.ExcludedObjectClasses)),
            new("Declared capture units", capture.EveryDeclaredUnitRecordedAsRead
                ? "Every declared unit recorded as read" : "Not every declared unit recorded as read"),
            new("Continuation reconciliation", capture.ContinuationReconciliationOutcome.ToString()),
            new("Saved judgement state", saved.Description.State.ToString()),
            new("Attribute visibility", "Optional LDAP values may be unset or unreturned; this export does not establish complete attribute visibility."),
            new("Whole-forest computer count", "Not established by this selected-scope export"),
        };
        foreach (var domain in snapshot.CaptureScope.Domains)
            coverage.Add(new("Domain scope: " + domain.DomainFqdn,
                domain.Outcome + (domain.Reason is null ? "" : "; " + domain.Reason)));
        return new(LapsInventoryText.Get("Title"), source, saved.Query.Container, saved.Query.Scope.ToString(), selection,
            saved.Matching, saved.Total,
            [
                new("Search (computer or domain substring)", saved.Query.Search.Length == 0 ? "No search filter applied" : saved.Query.Search),
                new("Captured values", saved.Query.State is { } state ? LapsInventoryText.Label(state) : "No value-group filter applied"),
                new("Computer type/account/controller", "No filter applied"),
            ], coverage.AsReadOnly(),
            [
                "Expiration values are not last GPO-processing times. Missing expiration does not prove GPO failure.",
                "A retained legacy value does not prove current operation or completed migration.",
                "No value captured, zero and unusable input are distinct. Unusable does not establish LDAP access denial.",
                "Windows captured value and Legacy captured value are literal-text columns; their saved original text follows one export apostrophe.",
                "Unsupported original representations absent from saved inventory are not reconstructed or fetched.",
                "Controller indicators are saved signals, not independent proof of the actual role. Capability and account state are saved answers, not a new assessment.",
            ]);
    }

    internal static IReadOnlyList<ExportCell> Map(LapsComputer computer)
    {
        static ExportCell YesNo(bool value) => ExportCell.Text(value ? "Yes" : "No");
        return
        [
            ExportCell.Text(computer.Name), ExportCell.Text(computer.DomainFqdn),
            ExportCell.Text(computer.DistinguishedName), ExportCell.Text(computer.ObjectGuid?.ToString("D")),
            ExportCell.Text(computer.OperatingSystem), ExportCell.Text(computer.OperatingSystemVersion),
            ExportCell.Text(computer.AccountState switch
            {
                LapsAttributes.AccountState.Enabled => "Enabled",
                LapsAttributes.AccountState.Disabled => "Disabled",
                LapsAttributes.AccountState.Unknown => "Unknown",
                _ => throw new InvalidDataException("The saved account state is not recognized."),
            }),
            ExportCell.Text(ControllerIndicators(computer.DomainController)),
            ExportCell.Text(LapsInventoryText.Label(computer.ValuePresence)),
            ExportCell.Text(computer.Capability.Kind switch
            {
                LapsCapabilityKind.WindowsLapsCapable => "Windows LAPS capable",
                LapsCapabilityKind.LegacyLapsOnly => "Legacy LAPS only",
                LapsCapabilityKind.Unknown => "Unknown",
                _ => throw new InvalidDataException("The saved LAPS capability is not recognized."),
            }),
            ExportCell.Text(computer.Capability.Basis switch
            {
                LapsCapabilityBasis.OperatingSystemVersion => "operating system version",
                LapsCapabilityBasis.OperatingSystemName => "operating system name",
                LapsCapabilityBasis.NothingToReadFrom => "nothing to read",
                _ => throw new InvalidDataException("The saved LAPS capability basis is not recognized."),
            }),
            ExportCell.Utc(computer.WindowsLaps.ExpiresUtc), ExportCell.Text(Quality(computer.WindowsLaps)),
            ExportCell.Literal(computer.WindowsLaps.Raw), YesNo(computer.WindowsLaps.HasUnsupportedRepresentation),
            ExportCell.Utc(computer.LegacyLaps.ExpiresUtc), ExportCell.Text(Quality(computer.LegacyLaps)),
            ExportCell.Literal(computer.LegacyLaps.Raw), YesNo(computer.LegacyLaps.HasUnsupportedRepresentation),
            ExportCell.Text(LapsInventoryText.ScopeNotes(computer)),
        ];
    }

    private static string Quality(StoredLapsTimestamp timestamp) => timestamp.Reading switch
    {
        LapsTimestampReading.Present => "Usable date",
        LapsTimestampReading.Absent => LapsInventoryText.Get("ExpiryNone"),
        LapsTimestampReading.Zero => LapsInventoryText.Get("ExpiryZero"),
        LapsTimestampReading.Unreadable => LapsInventoryText.Get("ExpiryUnusable"),
        _ => throw new InvalidDataException("The saved timestamp quality is not recognized."),
    };

    private static string ControllerIndicators(DomainControllerSignals signals)
    {
        var values = new List<string>();
        if (signals.ServerTrustAccountBit) values.Add("Account flag");
        if (signals.PrimaryGroupIsDomainController) values.Add("Primary group");
        if (signals.UnderDomainControllersOu) values.Add("Domain Controllers OU");
        if (signals.SignalsDisagree) values.Add("Indicators disagree");
        return values.Count == 0 ? "No indicators recorded; role not verified" : string.Join("; ", values);
    }
}
