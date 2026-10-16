namespace SecureAD.Shell.Services;

/// <summary>
/// How a run in the library gets opened for reading.
/// </summary>
/// <remarks>
/// <para>
/// A seam for the same reason <see cref="IConfirmation"/> is one: the run library screen can be
/// tested for what it asks to be opened without a window existing. It also keeps the library from
/// reaching into the shell to change sections, which would make the list responsible for the
/// application's navigation as well as for its own contents.
/// </para>
/// <para>
/// <b>Only a run whose evidence sealed can be opened</b>, and the caller checks that rather than
/// this. A run that ended badly wrote no <c>evidence.db</c>, so there is nothing to open and the
/// honest thing is to say so before a reader is asked for one.
/// </para>
/// </remarks>
internal interface IRunOpener
{
    /// <summary>Opens the run in <paramref name="bundleDirectory"/> and shows it.</summary>
    /// <param name="bundleDirectory">The run's bundle directory, as listed.</param>
    Task OpenAsync(string bundleDirectory);

    /// <summary>Clears displayed results and waits for their protected readers to close.</summary>
    Task CloseAsync();
}

/// <summary>
/// Opens a run by handing it to whatever the application wired up.
/// </summary>
/// <remarks>
/// A delegate rather than a reference to the shell, because the shell and this are constructed in
/// the same breath and one has to exist first. The same knot is already tied this way for the New
/// Audit window in <c>App.xaml.cs</c>.
/// </remarks>
/// <param name="open">What to do with the run's directory.</param>
internal sealed class RunOpener(Func<string, Task> open, Func<Task> close) : IRunOpener
{
    private readonly Func<string, Task> _open =
        open ?? throw new ArgumentNullException(nameof(open));
    private readonly Func<Task> _close =
        close ?? throw new ArgumentNullException(nameof(close));

    /// <inheritdoc/>
    public Task CloseAsync() => _close();

    /// <inheritdoc/>
    public Task OpenAsync(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);
        return _open(bundleDirectory);
    }
}
