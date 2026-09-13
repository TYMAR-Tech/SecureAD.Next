using System.IO;
using System.Text.Json;
using SecureAD.Kernel;

namespace SecureAD.Shell.Settings;

/// <summary>
/// Settings kept in a small JSON file in the operator's local profile, per machine.
/// </summary>
/// <remarks>
/// <para>
/// <b>The local profile, deliberately, and not the roaming one.</b> A run library is a path on a
/// particular machine, so a setting that followed an operator to another machine would point at a
/// directory that is not there - or, worse, at a different directory that is. This said
/// <i>roaming profile</i> until 2026-08-24, which was never what the code did:
/// <see cref="Environment.SpecialFolder.LocalApplicationData"/> is what it has always asked for, and
/// <c>JsonShellSettingsStoreTests.SettingsAreKeptInTheLocalProfileRatherThanTheRoamingOne</c> holds
/// it there.
/// </para>
/// <para>
/// <b>An absent file, an unreadable one and an unusable value are answered differently.</b> No file
/// is a new installation and reads as <see cref="ShellSettings.Unconfigured"/>. A file that exists
/// and cannot be parsed is a failure, because silently resetting it would throw away a path the
/// operator chose and then present the result as though they had never chosen one. A file that
/// parses but carries a concurrency ceiling below one is also a failure, for the reason recorded
/// at <see cref="Read"/>.
/// </para>
/// <para>
/// <b>An absent property is none of those three.</b> Every settings file written before 2026-09-13
/// is missing the ceiling, and that is not damage - it is an operator who has not been asked yet.
/// It reads as not chosen and the capture uses its default. Treating it as a stored zero is the
/// defect this store exists to not have; see <see cref="ShellSettings.DomainsAtOnce"/>.
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
    /// Both settings kept here describe a particular machine - a path to a run library, which is
    /// expected to be a local disk, and how many domains that machine reads at once, which is a fact
    /// about its own storage. A roamed <c>D:\audits</c> is a confident answer that is wrong on the
    /// next machine, which is worse than having no answer and asking; a roamed ceiling chosen for a
    /// laptop's NVMe disk is the same mistake more quietly. Recorded in
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

            if (stored is null)
                return Failure<ShellSettings>("The settings file holds nothing.");

            // A ceiling below one is refused rather than repaired, and zero is the case that
            // matters: a capture bounded at zero waits forever while looking exactly like one that
            // is working - 0041. Nothing in the product writes such a value, so a file carrying one
            // was edited by hand, and quietly substituting nine would run a capture the operator did
            // not ask for while showing him the number he did. An ABSENT property is a different
            // thing entirely and is not an error: it is every settings file written before this
            // setting existed, and it reads as "not chosen".
            return stored.DomainsAtOnce is { } ceiling && ceiling < 1
                ? Failure<ShellSettings>(
                    $"The settings file asks for {ceiling} domains at a time. It must be 1 or more: "
                    + "a capture allowed to read no domains at once would wait for ever without "
                    + "appearing to have stopped.")
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
