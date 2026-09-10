using System.Globalization;
using System.Resources;
using CommunityToolkit.Mvvm.ComponentModel;

namespace SecureAD.Shell.ViewModels;

/// <summary>Visible activity and observed timings, never a fabricated percentage or worker heartbeat.</summary>
internal sealed partial class AuditProgressViewModel(TimeProvider time) : ObservableObject
{
    private static readonly ResourceManager Resources = new("SecureAD.Shell.Resources.AuditProgress", typeof(AuditProgressViewModel).Assembly);
    private long _started;
    private long _lastUpdate;
    private string _activity = string.Empty;
    private bool _stopping;
    [ObservableProperty] private bool _hasStarted;
    [ObservableProperty] private bool _isActive;
    [ObservableProperty] private string _status = string.Empty;
    [ObservableProperty] private string _counter = string.Empty;
    [ObservableProperty] private string _elapsed = string.Empty;
    [ObservableProperty] private string _lastUpdateAge = string.Empty;
    public string Heading => Text("Heading");
    public string Caveat => Text("Caveat");
    public string CaptureHeading => Text("CaptureHeading");
    public string DerivationHeading => Text("DerivationHeading");
    public string JudgingHeading => Text("JudgingHeading");

    internal void Begin(string activity)
    {
        _started = _lastUpdate = time.GetTimestamp();
        _stopping = false;
        HasStarted = IsActive = true;
        Report(activity, string.Empty);
    }

    internal void Report(string activity, string counter)
    {
        if (!IsActive) return;
        _activity = activity;
        _lastUpdate = time.GetTimestamp();
        Status = _stopping ? Text("Stopping", activity) : activity;
        Counter = counter;
        Refresh();
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
        Elapsed = Text("Elapsed", Duration(time.GetElapsedTime(_started, now)));
        LastUpdateAge = Text("LastUpdate", Duration(time.GetElapsedTime(_lastUpdate, now)));
    }

    internal static string PhaseText(string phase) => Resources.GetString(phase, CultureInfo.CurrentUICulture) ?? Text("Deriving");
    internal static string Text(string key, params object?[] values)
    {
        var format = Resources.GetString(key, CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(key);
        return values.Length == 0 ? format : string.Format(CultureInfo.CurrentCulture, format, values);
    }

    private static string Duration(TimeSpan value) => TimeSpan.FromSeconds(Math.Max(0, Math.Floor(value.TotalSeconds))).ToString("c", CultureInfo.InvariantCulture);
}
