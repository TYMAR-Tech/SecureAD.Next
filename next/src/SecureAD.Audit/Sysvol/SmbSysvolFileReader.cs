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
public sealed class SmbSysvolFileReader : ISysvolFileReader
{
    /// <summary>
    /// Owner, group and DACL - never the SACL. Reading the audit part of a descriptor needs a
    /// privilege that is not granted over a share even to a domain administrator, and asking for
    /// it turns every read into an exception. The rules judge the DACL.
    /// </summary>
    private const AccessControlSections DescriptorSections =
        AccessControlSections.Owner | AccessControlSections.Group | AccessControlSections.Access;

    /// <inheritdoc />
    public async Task<Result<byte[]?>> ReadFileAsync(
        string gpoFileSysPath,
        string relativePath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);
        ArgumentNullException.ThrowIfNull(relativePath);

        cancellationToken.ThrowIfCancellationRequested();

        var fullPath = Combine(gpoFileSysPath, relativePath);

        try
        {
            return await File.ReadAllBytesAsync(fullPath, cancellationToken).ConfigureAwait(false);
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
        string gpoFileSysPath,
        string relativePath,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);
        ArgumentNullException.ThrowIfNull(relativePath);

        cancellationToken.ThrowIfCancellationRequested();

        var fullPath = Combine(gpoFileSysPath, relativePath);

        try
        {
            var attributes = File.GetAttributes(fullPath);

            var descriptor = attributes.HasFlag(FileAttributes.Directory)
                ? new DirectoryInfo(fullPath).GetAccessControl(DescriptorSections)
                    .GetSecurityDescriptorBinaryForm()
                : new FileInfo(fullPath).GetAccessControl(DescriptorSections)
                    .GetSecurityDescriptorBinaryForm();

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
        string gpoFileSysPath,
        string searchPattern,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(gpoFileSysPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(searchPattern);

        return Task.FromResult(Enumerate(gpoFileSysPath, searchPattern, files: true, cancellationToken));
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(
        string gpoFileSysPath,
        CancellationToken cancellationToken)
    {
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
    private static Result<IReadOnlyList<string>> Enumerate(
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
                    foreach (var file in Directory.EnumerateFiles(directory, searchPattern))
                    {
                        results.Add(file[prefixLength..]);
                    }
                }

                foreach (var child in Directory.EnumerateDirectories(directory))
                {
                    pending.Enqueue(child);

                    if (!files)
                    {
                        results.Add(child[prefixLength..]);
                    }
                }
            }
            catch (DirectoryNotFoundException)
            {
                // Only reachable for the GPO folder itself; a child was listed a moment ago by its
                // own parent. A GPO whose folder is not on the share is a real state of the
                // directory - the object exists and its files do not - and it is reported as an
                // empty listing rather than a failure, because nothing was denied.
                if (!string.Equals(directory, basePath, StringComparison.OrdinalIgnoreCase))
                {
                    return UnreadableListing(directory, new IOException("The folder disappeared while it was being read."));
                }

                return Result<IReadOnlyList<string>>.Success([]);
            }
            catch (UnauthorizedAccessException ex)
            {
                return DeniedListing(directory, ex);
            }
            catch (IOException ex)
            {
                return UnreadableListing(directory, ex);
            }
        }

        return Result<IReadOnlyList<string>>.Success(results);
    }

    /// <summary>Joins a GPO folder and a path beneath it, accepting either separator.</summary>
    private static string Combine(string gpoFileSysPath, string relativePath)
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
