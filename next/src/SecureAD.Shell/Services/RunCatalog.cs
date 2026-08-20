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
}
