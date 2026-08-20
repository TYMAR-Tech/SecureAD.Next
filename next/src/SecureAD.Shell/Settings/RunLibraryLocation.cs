using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Kernel;

namespace SecureAD.Shell.Settings;

/// <summary>
/// Where this installation keeps its runs, as one answer shared by everything that asks.
/// </summary>
/// <remarks>
/// <para>
/// <b>One owner, because two copies would disagree.</b> The home screen changes the path and the
/// run library reads it; if each held its own, changing it in one place would leave the other
/// listing the old library while appearing to list the new one. That is the shape of bug that shows
/// an operator evidence from somewhere they are not looking at.
/// </para>
/// <para>
/// <b>A path that could not be stored is not adopted.</b> If writing the settings file fails, the
/// current path is left alone and the failure is returned, because a product that acts on a setting
/// it could not save will behave differently after a restart with nothing explaining why.
/// </para>
/// </remarks>
internal sealed partial class RunLibraryLocation : ObservableObject
{
    private readonly IShellSettingsStore _store;

    [ObservableProperty]
    private string? _path;

    [ObservableProperty]
    private string? _problem;

    /// <summary>Creates the location over <paramref name="store"/>.</summary>
    /// <param name="store">Where the operator's choice is kept.</param>
    public RunLibraryLocation(IShellSettingsStore store)
    {
        ArgumentNullException.ThrowIfNull(store);

        _store = store;
    }

    /// <summary>Whether the operator has chosen a library yet.</summary>
    public bool IsChosen => !string.IsNullOrWhiteSpace(Path);

    /// <summary>
    /// Loads the stored choice. A failure to read is surfaced rather than treated as "not chosen".
    /// </summary>
    public void Load()
    {
        var read = _store.Read();

        if (!read.IsSuccess)
        {
            Problem = read.Error.Description;
            return;
        }

        Problem = null;
        Path = read.Value.RunLibraryPath;
    }

    /// <summary>Adopts and stores <paramref name="path"/>.</summary>
    /// <param name="path">The directory the operator chose.</param>
    public Result<bool> Choose(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var written = _store.Write(new ShellSettings(path));

        if (!written.IsSuccess)
        {
            Problem = written.Error.Description;
            return written;
        }

        Problem = null;
        Path = path;

        return written;
    }

    partial void OnPathChanged(string? value) => OnPropertyChanged(nameof(IsChosen));
}
