using System.Globalization;
using System.Resources;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureAD.Shell.ViewModels;

internal sealed record AuditWorkReport(string Time, string Detail);

/// <summary>Visible activity and observed timings, never a fabricated percentage or worker heartbeat.</summary>
internal sealed partial class AuditProgressViewModel(TimeProvider time) : ObservableObject
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.AuditProgress", typeof(AuditProgressViewModel).Assembly);
    private long _started;
    private long _lastUpdate;
    private string _activity = string.Empty;
    private bool _stopping;
    private bool _hasWorkReport;
    [ObservableProperty] private bool _hasStarted;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private string _status = string.Empty;
    [ObservableProperty] private string _counter = string.Empty;
    [ObservableProperty] private string _elapsed = string.Empty;
    [ObservableProperty] private string _lastUpdateAge = string.Empty;
    [ObservableProperty] private string _elapsedClock = "00:00";
    [ObservableProperty] private string _lastWorkReportAge = Text("NoWorkReport");
    [ObservableProperty] private string _workCountText = Text("UnreportedCount");
    [ObservableProperty] private string _workUnit = Text("NoCountForPhase");
    public ObservableCollection<AuditWorkReport> RecentReports { get; } = [];
    public string Heading => Text("Heading");
    public string Caveat => Text("Caveat");
    public string CaptureHeading => Text("CaptureHeading");
    public string DerivationHeading => Text("DerivationHeading");
    public string JudgingHeading => Text("JudgingHeading");

    internal void Begin(string activity)
    {
        _started = _lastUpdate = time.GetTimestamp();
        _stopping = false;
        _hasWorkReport = false;
        RecentReports.Clear();
        HasStarted = IsActive = true;
        SetActivity(activity);
        Refresh();
    }

    internal void Report(string activity, string counter)
        => RecordReport(activity, counter, counter.Length == 0 ? Text("UnreportedCount") : counter,
            counter.Length == 0 ? Text("NoCountForPhase") : string.Empty);

    internal void ReportCount(string activity, long? count, string unit)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        var number = count?.ToString("N0", CultureInfo.CurrentCulture) ?? Text("UnreportedCount");
        RecordReport(activity, count.HasValue ? $"{unit}: {number}" : string.Empty, number, unit);
    }

    internal void SetActivity(string activity)
    {
        _activity = activity;
        Status = _stopping ? Text("Stopping", activity) : activity;
        Counter = string.Empty;
        WorkCountText = Text("UnreportedCount");
        WorkUnit = Text("NoCountForPhase");
    }

    private void RecordReport(string activity, string counter, string number, string unit)
    {
        if (!IsActive) return;
        _activity = activity;
        _lastUpdate = time.GetTimestamp();
        _hasWorkReport = true;
        Status = _stopping ? Text("Stopping", activity) : activity;
        Counter = counter;
        WorkCountText = number;
        WorkUnit = unit;
        Refresh();
        // This is a three-row display, not a limit on captured data or the run log.
        RecentReports.Add(new(ElapsedClock, counter.Length == 0 ? activity : $"{activity} — {counter}"));
        if (RecentReports.Count > 3) RecentReports.RemoveAt(0);
    }

    internal void RequestStop()
    {
        if (!IsActive) return;
        _stopping = true;
        Status = Text("Stopping", _activity);
    }

    internal void End(string status)
    {
        Refresh();
        Status = status;
        IsActive = false;
    }

    internal void Refresh()
    {
        if (!IsActive) return;
        var now = time.GetTimestamp();
        var elapsed = time.GetElapsedTime(_started, now);
        var age = time.GetElapsedTime(_lastUpdate, now);
        Elapsed = Text("Elapsed", Duration(elapsed));
        ElapsedClock = elapsed.TotalHours >= 1
            ? $"{(long)elapsed.TotalHours}:{elapsed.Minutes:00}:{elapsed.Seconds:00}"
            : $"{(long)elapsed.TotalMinutes:00}:{elapsed.Seconds:00}";
        LastUpdateAge = Text("LastUpdate", Duration(age));
        LastWorkReportAge = !_hasWorkReport ? Text("NoWorkReport")
            : age.TotalHours >= 1 ? Text("LastWorkHours", (long)age.TotalHours)
            : age.TotalMinutes >= 1 ? Text("LastWorkMinutes", (long)age.TotalMinutes)
            : Text("LastWorkSeconds", (long)Math.Max(0, age.TotalSeconds));
    }

    internal static string PhaseText(string phase) => Resources.GetString(phase, CultureInfo.CurrentUICulture) ?? Text("Deriving");
    internal static string Text(string key, params object?[] values)
    {
        var format = Resources.GetString(key, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(key);
        return values.Length == 0 ? format : string.Format(CultureInfo.CurrentCulture, format, values);
    }

    private static string Duration(TimeSpan value) => TimeSpan.FromSeconds(Math.Max(0, Math.Floor(value.TotalSeconds))).ToString("c", CultureInfo.InvariantCulture);

    /// <summary>
    /// A duration in words, for a line an operator reads rather than compares.
    /// </summary>
    /// <remarks>
    /// <b>Distinct from <see cref="Duration"/>, which stays a clock value.</b> This renders the Tier-0
    /// discovery line, where "3 min 41 sec" is read at a glance and "00:03:41" is not. Seconds are
    /// truncated rather than rounded so the figure never runs ahead of the work it describes.
    /// </remarks>
    internal static string Spoken(TimeSpan value)
    {
        var total = (long)Math.Max(0, Math.Floor(value.TotalSeconds));
        var (hours, minutes, seconds) = (total / 3600, total % 3600 / 60, total % 60);
        return hours > 0 ? Text("DurationHours", hours, minutes, seconds)
            : minutes > 0 ? Text("DurationMinutes", minutes, seconds)
            : Text("DurationSeconds", seconds);
    }
}
