using System.IO;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;

namespace SecureAD.Shell.Services;

/// <summary>
/// The run catalogue, over a real run library on a real disk.
/// </summary>
/// <remarks>
/// A run library opens its root, creating it if absent, so a root the operator has typed wrongly
/// or a drive that is not mounted surfaces here rather than at some later point. That failure is
/// returned rather than thrown, because it is an ordinary thing for an operator to have done and
/// the shell has to say so on a screen.
/// </remarks>
internal sealed class RunCatalog : IRunCatalog
{
    /// <inheritdoc/>
    public Result<IReadOnlyList<RunListing>> List(string libraryRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryRoot);

        try
        {
            return new RunLibrary(libraryRoot, TimeProvider.System).List();
        }
        catch (Exception ex) when (ex is IOException
                                      or UnauthorizedAccessException
                                      or ArgumentException
                                      or NotSupportedException)
        {
            return Result<IReadOnlyList<RunListing>>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "RunLibraryCannotBeOpened",
                ErrorSeverity.Failed,
                $"'{libraryRoot}' could not be opened as a run library. {ex.Message}",
                libraryRoot));
        }
    }

    /// <inheritdoc/>
    public Result<RunAnnotation> Annotate(string bundleDirectory, RunAnnotation annotation) =>
        RunAnnotations.Save(bundleDirectory, annotation);

    /// <inheritdoc/>
    public Result<string> Delete(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        // The library owns the containment rule, so the directory is split back into a root and a
        // name and handed to it rather than deleted here. A shell that called Directory.Delete on
        // the path it happens to be holding would be a second door onto the one act 0025 keeps to
        // one, and the first path arriving from somewhere unexpected would go straight through it.
        var root = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(bundleDirectory));
        var identifier = Path.GetFileName(Path.TrimEndingDirectorySeparator(bundleDirectory));

        if (string.IsNullOrWhiteSpace(root) || string.IsNullOrWhiteSpace(identifier))
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "RunPathIsNotInALibrary",
                ErrorSeverity.Failed,
                $"'{bundleDirectory}' is not a run inside a library, so there is no library to ask "
                + "to delete it.",
                bundleDirectory));
        }

        try
        {
            return new RunLibrary(root, TimeProvider.System).DeleteRun(identifier);
        }
        catch (Exception ex) when (ex is IOException
                                      or UnauthorizedAccessException
                                      or ArgumentException
                                      or NotSupportedException)
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "RunLibraryCannotBeOpened",
                ErrorSeverity.Failed,
                $"'{root}' could not be opened as a run library. {ex.Message}",
                root));
        }
    }
}
