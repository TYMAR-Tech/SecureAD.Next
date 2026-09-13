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
/// <b><see cref="DomainConcurrency"/> is a second object over the same file, and it does not breach
/// the rule above.</b> One owner per <i>setting</i> is what that rule requires; the two own disjoint
/// fields and neither holds a copy of the other's. What would breach it is either of them keeping
/// the whole record in memory and writing it back, which is why both read the file at the moment
/// they write.
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
    /// <remarks>
    /// <b>It replaces its own field and leaves the rest of the file alone.</b> This wrote
    /// <c>new ShellSettings(path)</c> until 2026-09-13, when the run library path was the only
    /// setting and a whole-record write could lose nothing. It is not any more: choosing a library
    /// would have silently reset the concurrency ceiling to "not chosen", and the operator would
    /// have discovered it on his next capture or never. The current settings are read back rather
    /// than remembered, because this object holds no copy of anything but the path and inventing one
    /// is how the two would come to disagree.
    ///
    /// <para>
    /// <b>A settings file that cannot be read refuses the choice rather than replacing the file.</b>
    /// If it cannot be read it cannot be preserved, and overwriting it would discard whatever is in
    /// there unseen - which is the thing <see cref="JsonShellSettingsStore"/> already refuses to do
    /// on the operator's behalf. The cost is that a corrupt file must be dealt with on disk: the
    /// operator is told the same thing here that he was told at startup, rather than being handed a
    /// product that appears to have accepted his answer.
    /// </para>
    /// </remarks>
    /// <param name="path">The directory the operator chose.</param>
    public Result<bool> Choose(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var current = _store.Read();

        if (!current.IsSuccess)
        {
            Problem = current.Error.Description;
            return Result<bool>.Failure(current.Error);
        }

        var written = _store.Write(current.Value with { RunLibraryPath = path });

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
