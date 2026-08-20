using System.IO;
using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Shell.Settings;

/// <summary>
/// Settings kept in a small JSON file in the operator's roaming profile.
/// </summary>
/// <remarks>
/// <para>
/// <b>An absent file and an unreadable one are answered differently.</b> No file is a new
/// installation and reads as <see cref="ShellSettings.Unconfigured"/>. A file that exists and
/// cannot be parsed is a failure, because silently resetting it would throw away a path the
/// operator chose and then present the result as though they had never chosen one.
/// </para>
/// <para>
/// <b>The path stored here is not validated as a run library.</b> Whether the directory exists,
/// is reachable, or holds anything is <see cref="Evidence.Run.RunLibrary"/>'s question, asked when
/// it is opened. A settings file records what the operator said, not what is true of the disk
/// today - a removable drive that is currently unplugged has not stopped being their choice.
/// </para>
/// <para>
/// Reads and writes are synchronous. The file holds a handful of bytes and is touched at startup
/// and when the operator changes a setting; an asynchronous API here would add ceremony to
/// something that never blocks meaningfully.
/// </para>
/// </remarks>
internal sealed class JsonShellSettingsStore : IShellSettingsStore
{
    private static readonly JsonSerializerOptions Format = new() { WriteIndented = true };

    private readonly string _path;

    /// <summary>Creates a store over <paramref name="settingsFilePath"/>.</summary>
    /// <param name="settingsFilePath">The file the settings live in.</param>
    public JsonShellSettingsStore(string settingsFilePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(settingsFilePath);

        _path = settingsFilePath;
    }

    /// <summary>The file this installation keeps its settings in by default.</summary>
    /// <remarks>
    /// <b>Local rather than roaming, and the distinction is the whole decision.</b>
    /// <c>%LOCALAPPDATA%</c> stays on the machine; <c>%APPDATA%</c> follows the user between them.
    /// The one setting kept here is a path to a run library, and a run library is expected to be a
    /// local disk. A roamed <c>D:\audits</c> is a confident answer that is wrong on the next
    /// machine, which is worse than having no answer and asking. Recorded in
    /// <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c>.
    /// </remarks>
    public static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SecureAD",
        "shell-settings.json");

    /// <inheritdoc/>
    public Result<ShellSettings> Read()
    {
        if (!File.Exists(_path))
            return Result<ShellSettings>.Success(ShellSettings.Unconfigured);

        try
        {
            var stored = JsonSerializer.Deserialize<ShellSettings>(File.ReadAllText(_path));

            return stored is null
                ? Failure<ShellSettings>("The settings file holds nothing.")
                : Result<ShellSettings>.Success(stored);
        }
        catch (JsonException ex)
        {
            return Failure<ShellSettings>($"The settings file could not be read. {ex.Message}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure<ShellSettings>($"The settings file could not be opened. {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public Result<bool> Write(ShellSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);

        try
        {
            var directory = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(directory))
                Directory.CreateDirectory(directory);

            File.WriteAllText(_path, JsonSerializer.Serialize(settings, Format));

            return Result<bool>.Success(true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Failure<bool>($"The settings file could not be written. {ex.Message}");
        }
    }

    private Result<T> Failure<T>(string description) =>
        Result<T>.Failure(AuditError.Create(
            ErrorCategory.Shell,
            "ShellSettingsUnusable",
            ErrorSeverity.Failed,
            description,
            _path));
}
