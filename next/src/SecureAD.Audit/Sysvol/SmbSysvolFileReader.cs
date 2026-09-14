using System.Runtime.Versioning;
using System.Security.AccessControl;
using SecureAD.Kernel;

namespace SecureAD.Audit.Sysvol;

/// <summary>
/// Reads SYSVOL over SMB, using the Windows file redirector and the token the run already holds.
/// </summary>
/// <remarks>
/// <para>
/// The only network surface in SYSVOL capture. Everything above it works against
/// <see cref="ISysvolFileReader"/>.
/// </para>
/// <para>
/// <b>Nothing here is silent.</b> A read that could not be performed comes back as a failure
/// carrying the path it was about and what the file system said, because per
/// <c>docs/decisions/0044</c> the run continues past it and the reason is all the operator will
/// ever get. The predecessor logged these at debug level and returned <c>null</c>, which made a
/// locked-down policy folder indistinguishable from an empty one in the evidence.
/// </para>
/// <para>
/// <b>Presence is tested by asking the file system for the path's attributes rather than by
/// <c>File.Exists</c>.</b> <c>Exists</c> answers false both for a path that is not there and for
/// one the run may not look at, which is the exact confusion this type exists to remove.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class SmbSysvolFileReader(Action<SysvolIoEvent> progress) : ISysvolFileReader
{
    private long _items;
    private long _bytes;

    private void Report(string operation, string path, string state) =>
        progress(new SysvolIoEvent(operation, path, state, _items, _bytes));

    /// <summary>
    /// Owner, group and DACL - never the SACL. Reading the audit part of a descriptor needs a
    /// privilege that is not granted over a share even to a domain administrator, and asking for
    /// it turns every read into an exception. The rules judge the DACL.
    /// </summary>
    private const AccessControlSections DescriptorSections =
        AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;

    /// <inheritdoc />
    public async Task<Result<byte[]?>> ReadFileAsync(
        GpoTarget target,
        string relativePath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var gpoFileSysPath = target.FileSysPath;
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);
        ArgumentNullException.ThrowIfNull(relativePath);

        cancellationToken.ThrowIfCancellationRequested();

        var fullPath = Combine(gpoFileSysPath, relativePath);

        try
        {
            Report("OpenFile", fullPath, "Started");
            await using var file = new FileStream(fullPath, FileMode.Open, FileAccess.Read,
                FileShare.Read, 65536, FileOptions.Asynchronous | FileOptions.SequentialScan);
            Report("OpenFile", fullPath, "Completed");
            using var content = new MemoryStream();
            var buffer = new byte[65536];
            while (true)
            {
                Report("ReadFile", fullPath, "Started");
                var read = await file.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                _bytes += read;
                Report("ReadFile", fullPath, "Completed");
                if (read == 0)
                    break;
                content.Write(buffer, 0, read);
            }
            return content.ToArray();
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (FileNotFoundException)
        {
            return Absent();
        }
        catch (DirectoryNotFoundException)
        {
            return Absent();
        }
        catch (UnauthorizedAccessException ex)
        {
            return Denied(fullPath, ex);
        }
        catch (IOException ex)
        {
            return Unreadable(fullPath, ex);
        }
    }

    /// <inheritdoc />
    public Task<Result<byte[]?>> ReadSecurityDescriptorAsync(
        GpoTarget target,
        string relativePath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var gpoFileSysPath = target.FileSysPath;
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);
        ArgumentNullException.ThrowIfNull(relativePath);

        cancellationToken.ThrowIfCancellationRequested();

        var fullPath = Combine(gpoFileSysPath, relativePath);

        try
        {
            Report("GetAttributes", fullPath, "Started");
            var attributes = File.GetAttributes(fullPath);
            Report("GetAttributes", fullPath, "Completed");

            Report("GetAccessControl", fullPath, "Started");
            var descriptor = attributes.HasFlag(FileAttributes.Directory)
                ? new DirectoryInfo(fullPath).GetAccessControl(DescriptorSections)
                    .GetSecurityDescriptorBinaryForm()
                : new FileInfo(fullPath).GetAccessControl(DescriptorSections)
                    .GetSecurityDescriptorBinaryForm();

            _bytes += descriptor.Length;
            Report("GetAccessControl", fullPath, "Completed");
            return Task.FromResult<Result<byte[]?>>(descriptor);
        }
        catch (FileNotFoundException)
        {
            return Task.FromResult(Absent());
        }
        catch (DirectoryNotFoundException)
        {
            return Task.FromResult(Absent());
        }
        catch (UnauthorizedAccessException ex)
        {
            return Task.FromResult(Denied(fullPath, ex));
        }
        catch (IOException ex)
        {
            return Task.FromResult(Unreadable(fullPath, ex));
        }
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(
        GpoTarget target,
        string searchPattern,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var gpoFileSysPath = target.FileSysPath;
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(searchPattern);

        return Task.FromResult(Enumerate(gpoFileSysPath, searchPattern, files: true, cancellationToken));
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(
        GpoTarget target,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var gpoFileSysPath = target.FileSysPath;
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);

        return Task.FromResult(Enumerate(gpoFileSysPath, "*", files: false, cancellationToken));
    }

    /// <summary>
    /// Walks the tree beneath a GPO folder, returning paths relative to it.
    /// </summary>
    /// <remarks>
    /// The walk is done by hand rather than with <c>SearchOption.AllDirectories</c>, so that a
    /// subfolder the run may not open fails the enumeration it belongs to instead of being dropped
    /// from the middle of an otherwise complete-looking list. That silent truncation is the shape
    /// of the defect this whole seam is built to avoid.
    /// </remarks>
    private Result<IReadOnlyList<string>> Enumerate(
        string gpoFileSysPath,
        string searchPattern,
        bool files,
        CancellationToken cancellationToken)
    {
        var basePath = TrimTrailingSeparators(gpoFileSysPath);
        var prefixLength = basePath.Length + 1;
        var results = new List<string>();
        var pending = new Queue<string>();
        pending.Enqueue(basePath);

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var directory = pending.Dequeue();

            try
            {
                if (files)
                {
                    Report("EnumerateFiles", directory, "Started");
                    foreach (var file in Directory.EnumerateFiles(directory, searchPattern))
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        results.Add(file[prefixLength..]);
                        _items++;
                        Report("EnumerateFiles", directory, "Progress");
                    }
                    Report("EnumerateFiles", directory, "Completed");
                }

                Report("EnumerateDirectories", directory, "Started");
                foreach (var child in Directory.EnumerateDirectories(directory))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    pending.Enqueue(child);
                    _items++;
                    Report("EnumerateDirectories", directory, "Progress");

                    if (!files)
                    {
                        results.Add(child[prefixLength..]);
                    }
                }
                Report("EnumerateDirectories", directory, "Completed");
            }
            catch (UnauthorizedAccessException ex)
            {
                return DeniedListing(directory, ex);
            }
            catch (IOException ex)
            {
                // A vanished root is a failed listing too. Its ACL may already have been read;
                // returning an empty list here would turn lost scope into complete coverage.
                return UnreadableListing(directory, ex);
            }
        }

        return Result<IReadOnlyList<string>>.Success(results);
    }

    /// <summary>Joins a GPO folder and a path beneath it, accepting either separator.</summary>
    internal static string Combine(string gpoFileSysPath, string relativePath)
    {
        var basePath = TrimTrailingSeparators(gpoFileSysPath);
        if (relativePath.Length == 0)
        {
            return basePath;
        }

        var normalized = relativePath.Replace('/', '\\').TrimStart('\\');
        return normalized.Length == 0 ? basePath : basePath + "\\" + normalized;
    }

    private static string TrimTrailingSeparators(string path) => path.TrimEnd('\\', '/');

    /// <summary>
    /// The path is not on the share, and the run was able to establish that. A success, because
    /// a GPO that has no <c>GptTmpl.inf</c> has genuinely granted no user rights.
    /// </summary>
    private static Result<byte[]?> Absent() => Result<byte[]?>.Success(null);

    private static Result<byte[]?> Denied(string path, Exception cause) =>
        Result<byte[]?>.Failure(AccessDeniedError(path, cause));

    private static Result<IReadOnlyList<string>> DeniedListing(string path, Exception cause) =>
        Result<IReadOnlyList<string>>.Failure(AccessDeniedError(path, cause));

    private static Result<byte[]?> Unreadable(string path, Exception cause) =>
        Result<byte[]?>.Failure(UnreadableError(path, cause));

    private static Result<IReadOnlyList<string>> UnreadableListing(string path, IOException cause) =>
        Result<IReadOnlyList<string>>.Failure(UnreadableError(path, cause));

    private static AuditError AccessDeniedError(string path, Exception cause) => AuditError.Create(
        ErrorCategory.Capture,
        "SysvolAccessDenied",
        ErrorSeverity.Failed,
        "The account running the audit was not allowed to read this SYSVOL path, so what it holds "
        + "is unknown rather than absent: " + cause.Message,
        path);

    private static AuditError UnreadableError(string path, Exception cause) => AuditError.Create(
        ErrorCategory.Capture,
        "SysvolUnreadable",
        ErrorSeverity.Failed,
        "This SYSVOL path could not be read, so what it holds is unknown rather than absent: "
        + cause.Message,
        path);
}
