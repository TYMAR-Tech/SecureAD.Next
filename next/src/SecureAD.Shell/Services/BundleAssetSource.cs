using System.IO;
using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;

namespace SecureAD.Shell.Services;

/// <summary>
/// The asset source, over real bundles on a real disk.
/// </summary>
/// <remarks>
/// <para>
/// <b>It keeps the bundle it was last asked about open.</b> The seal is verified once, when the
/// operator arrives at a run, rather than on every page turned - see <see cref="IAssetSource"/>
/// for why that matters. Moving to another run closes the previous bundle before opening the next,
/// so at most one is held and an operator can always move, copy or delete every run but the one on
/// screen.
/// </para>
/// <para>
/// <b>Verification is not skipped, only not repeated.</b> The bundle is opened with SQLite told the
/// file is immutable, which it is: the seal has just proved so, and nothing in this product writes
/// to sealed evidence.
/// </para>
/// </remarks>
internal sealed class BundleAssetSource : IAssetSource, IDisposable
{
    private BundleReader? _open;
    private string? _openPath;

    /// <summary>
    /// The open bundle's schema catalogue, built on first use and dropped with the bundle.
    /// </summary>
    /// <remarks>
    /// Cached because reading it walks every schema definition in the forest, and unlike the seal
    /// there is nothing dangerous about not repeating it: the bundle is immutable, so the answer
    /// cannot change while it is open.
    /// </remarks>
    private SchemaGuidCatalog? _schema;

    /// <inheritdoc/>
    public Result<DirectoryTree> ReadTree(string bundleDirectory)
    {
        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(() => opened.Value.ReadTree(), bundleDirectory)
            : Result<DirectoryTree>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<ObjectPage> ListObjects(
        string bundleDirectory, string containerDn, ListingScope scope, int pageNumber)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(containerDn);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(
                () => opened.Value.ListObjects(containerDn, scope, pageNumber), bundleDirectory)
            : Result<ObjectPage>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<ObjectPermissions?> ReadPermissions(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(() => opened.Value.ReadPermissions(distinguishedName), bundleDirectory)
            : Result<ObjectPermissions?>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<ObjectAttributes?> ReadObjectAttributes(
        string bundleDirectory, string distinguishedName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(distinguishedName);

        var opened = Open(bundleDirectory);

        return opened.IsSuccess
            ? Guarded(() => opened.Value.ReadObjectAttributes(distinguishedName), bundleDirectory)
            : Result<ObjectAttributes?>.Failure(opened.Error);
    }

    /// <inheritdoc/>
    public Result<SchemaGuidCatalog> ReadSchemaGuids(string bundleDirectory)
    {
        var opened = Open(bundleDirectory);

        if (!opened.IsSuccess)
            return Result<SchemaGuidCatalog>.Failure(opened.Error);

        if (_schema is not null)
            return Result<SchemaGuidCatalog>.Success(_schema);

        var read = Guarded(() => opened.Value.ReadSchemaGuids(), bundleDirectory);

        if (read.IsSuccess)
            _schema = read.Value;

        return read;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _open?.Dispose();
        _open = null;
        _openPath = null;
        _schema = null;
    }

    private Result<BundleReader> Open(string bundleDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundleDirectory);

        if (_open is not null
            && string.Equals(_openPath, bundleDirectory, StringComparison.OrdinalIgnoreCase))
        {
            return _open;
        }

        Dispose();

        var opening = BundleReader.Open(bundleDirectory);
        if (!opening.IsSuccess)
            return opening;

        _open = opening.Value;
        _openPath = bundleDirectory;
        return opening;
    }

    /// <summary>
    /// Turns a failure to read an opened bundle into a refusal the shell can state.
    /// </summary>
    /// <remarks>
    /// The seal was intact, so the bytes are the bytes that were sealed. A failure here is a defect
    /// in this build rather than damage to the bundle, and it is worded as one.
    /// </remarks>
    private static Result<T> Guarded<T>(Func<T> read, string bundleDirectory)
    {
        try
        {
            return Result<T>.Success(read());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<T>.Failure(AuditError.Create(
                ErrorCategory.Shell,
                "BundleCannotBeRead",
                ErrorSeverity.Failed,
                $"'{bundleDirectory}' was opened and could not be read. {ex.Message}",
                bundleDirectory));
        }
    }
}
