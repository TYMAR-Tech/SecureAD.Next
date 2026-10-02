using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

internal sealed class NavigationDiagnostics : IDisposable
{
    private static readonly AsyncLocal<NavigationDiagnostics?> Active = new();
    private readonly NavigationDiagnostics? _previous;
    private readonly RunLogFile? _file;
    private readonly IRunLog _log;
    private readonly long _started = Stopwatch.GetTimestamp();
    private bool _completed;

    private NavigationDiagnostics(string bundleDirectory, string action)
    {
        Action = action;
        _previous = Active.Value;
        var opened = Directory.Exists(bundleDirectory)
            ? RunLogFile.Open(bundleDirectory, "saved-result navigation", TimeProvider.System)
            : Result<RunLogFile>.Failure(AuditError.Create(ErrorCategory.Shell, "NavigationLogUnavailable",
                ErrorSeverity.Degraded, "The selected run directory does not exist.", bundleDirectory));
        _file = opened.IsSuccess ? opened.Value : null;
        _log = _file ?? RunLog.Discarded;
        Active.Value = this;
        var assembly = typeof(NavigationDiagnostics).Assembly;
        _log.Note("Browse", "navigation started",
        [
            new("action", action),
            new("run", Path.GetFullPath(bundleDirectory)),
            new("process", Environment.ProcessPath ?? "unavailable"),
            new("processSha256", Hash(Environment.ProcessPath)),
            new("shellMvid", assembly.ManifestModule.ModuleVersionId.ToString("D")),
            new("shellVersion", assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unavailable"),
        ]);
    }

    internal string Action { get; }

    internal static NavigationDiagnostics Begin(string bundleDirectory, string action) =>
        new(bundleDirectory, action);

    internal static void Mark(string work, TimeSpan elapsed) =>
        Active.Value?._log.Note("Browse", "navigation work",
        [
            new("action", Active.Value.Action),
            new("work", work),
            new("elapsedMs", elapsed.TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture)),
        ]);

    internal static void Identity(string name, string value) =>
        Active.Value?._log.Note("Browse", "navigation identity",
        [
            new("action", Active.Value.Action), new(name, value),
        ]);

    internal void Complete(string outcome, string? detail)
    {
        if (_completed) return;
        _completed = true;
        var values = new List<RunLogDetail>
        {
            new("action", Action),
            new("outcome", outcome),
            new("appliedMs", Stopwatch.GetElapsedTime(_started).TotalMilliseconds.ToString("F3", CultureInfo.InvariantCulture)),
        };
        if (!string.IsNullOrWhiteSpace(detail)) values.Add(new("detail", detail));
        _log.Note("Browse", "navigation finished", values);
    }

    public void Dispose()
    {
        if (!_completed) Complete("abandoned", null);
        if (ReferenceEquals(Active.Value, this)) Active.Value = _previous;
        _file?.Dispose();
    }

    private static string Hash(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return "unavailable";
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
