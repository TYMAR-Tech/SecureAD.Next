using SecureAD.Audit.Sysvol;
using SecureAD.Kernel;

namespace SecureAD.Next.Tests.Sysvol;

/// <summary>
/// A SYSVOL share held in memory, so the capture module can be exercised without a network.
/// </summary>
/// <remarks>
/// <para>
/// This is what the file-access seam is for. The predecessor had the same seam and the same reason
/// for it, and it is the one part of that design carried over unchanged.
/// </para>
/// <para>
/// It can refuse as well as answer, and that is the point rather than a convenience. The failure
/// this session exists to prevent - a policy nobody could read looking like a policy that
/// configures nothing - is only testable against a share that can say no.
/// </para>
/// </remarks>
public sealed class InMemorySysvolFileReader : ISysvolFileReader
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, byte[]> _descriptors = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _denied = [];
    private readonly HashSet<string> _vanished = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Puts a file on the share, beneath a policy's folder.</summary>
    public InMemorySysvolFileReader WithFile(string gpoFileSysPath, string relativePath, byte[] content)
    {
        _files[Key(gpoFileSysPath, relativePath)] = content;
        return this;
    }

    /// <summary>Gives a path a security descriptor.</summary>
    public InMemorySysvolFileReader WithDescriptor(
        string gpoFileSysPath, string relativePath, byte[] descriptor)
    {
        _descriptors[Key(gpoFileSysPath, relativePath)] = descriptor;
        return this;
    }

    /// <summary>
    /// Refuses every read at or beneath a path, as a share refuses a folder the run may not open.
    /// </summary>
    public InMemorySysvolFileReader Denying(string gpoFileSysPath, string relativePath)
    {
        _denied.Add(Key(gpoFileSysPath, relativePath));
        return this;
    }

    /// <summary>
    /// Puts a file on the share that enumeration will list and that will then refuse to open,
    /// answering success with no content.
    /// </summary>
    /// <remarks>
    /// <b>Success carrying null, not a failure</b>, because that is the case that used to pass
    /// silently. A refusal was always recorded; a share that listed a file and then produced
    /// nothing for it read as "the file is not there" and left the policy's coverage complete -
    /// <c>CAP-003</c>. It is what a policy being rewritten underneath an audit looks like.
    /// </remarks>
    /// <param name="gpoFileSysPath">The policy's folder.</param>
    /// <param name="relativePath">The file that will be listed and will not open.</param>
    public InMemorySysvolFileReader WithListedButUnopenableFile(
        string gpoFileSysPath, string relativePath)
    {
        var key = Key(gpoFileSysPath, relativePath);

        // Held in _files so enumeration finds it, and named in _vanished so the read declines.
        _files[key] = [];
        _vanished.Add(key);

        return this;
    }

    /// <inheritdoc />
    public Task<Result<byte[]?>> ReadFileAsync(
        GpoTarget target, string relativePath, CancellationToken cancellationToken)
    {
        var gpoFileSysPath = target.FileSysPath;
        var key = Key(gpoFileSysPath, relativePath);

        if (IsDenied(key))
        {
            return Task.FromResult(Denied(key));
        }

        if (_vanished.Contains(key))
        {
            return Task.FromResult(Result<byte[]?>.Success(null));
        }

        return Task.FromResult(
            _files.TryGetValue(key, out var content)
                ? Result<byte[]?>.Success(content)
                : Result<byte[]?>.Success(null));
    }

    /// <inheritdoc />
    public Task<Result<byte[]?>> ReadSecurityDescriptorAsync(
        GpoTarget target, string relativePath, CancellationToken cancellationToken)
    {
        var gpoFileSysPath = target.FileSysPath;
        var key = Key(gpoFileSysPath, relativePath);

        if (IsDenied(key))
        {
            return Task.FromResult(Denied(key));
        }

        return Task.FromResult(
            _descriptors.TryGetValue(key, out var descriptor)
                ? Result<byte[]?>.Success(descriptor)
                : Result<byte[]?>.Success(null));
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(
        GpoTarget target, string searchPattern, CancellationToken cancellationToken)
    {
        var gpoFileSysPath = target.FileSysPath;
        var root = Key(gpoFileSysPath, string.Empty);

        if (IsDenied(root))
        {
            return Task.FromResult(
                Result<IReadOnlyList<string>>.Failure(AccessDenied(root)));
        }

        var suffix = searchPattern.TrimStart('*');

        IReadOnlyList<string> matches = _files.Keys
            .Where(k => k.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
            .Select(k => k[(root.Length + 1)..])
            .Where(p => suffix.Length == 0 || p.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return Task.FromResult(Result<IReadOnlyList<string>>.Success(matches));
    }

    /// <inheritdoc />
    public Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(
        GpoTarget target, CancellationToken cancellationToken)
    {
        var gpoFileSysPath = target.FileSysPath;
        var root = Key(gpoFileSysPath, string.Empty);

        if (IsDenied(root))
        {
            return Task.FromResult(
                Result<IReadOnlyList<string>>.Failure(AccessDenied(root)));
        }

        IReadOnlyList<string> folders = _descriptors.Keys
            .Concat(_files.Keys)
            .Where(k => k.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
            .Select(k => k[(root.Length + 1)..])
            .SelectMany(AncestorFolders)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return Task.FromResult(Result<IReadOnlyList<string>>.Success(folders));
    }

    private static IEnumerable<string> AncestorFolders(string relativePath)
    {
        var segments = relativePath.Split('\\');

        for (var depth = 1; depth < segments.Length; depth++)
        {
            yield return string.Join('\\', segments.Take(depth));
        }
    }

    private bool IsDenied(string key) =>
        _denied.Any(d => key.Equals(d, StringComparison.OrdinalIgnoreCase)
            || key.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase));

    private static Result<byte[]?> Denied(string key) => Result<byte[]?>.Failure(AccessDenied(key));

    private static AuditError AccessDenied(string key) => AuditError.Create(
        ErrorCategory.Capture,
        "SysvolAccessDenied",
        ErrorSeverity.Failed,
        "The account running the audit was not allowed to read this SYSVOL path, so what it holds "
        + "is unknown rather than absent.",
        key);

    private static string Key(string gpoFileSysPath, string relativePath) =>
        relativePath.Length == 0
            ? gpoFileSysPath.TrimEnd('\\')
            : gpoFileSysPath.TrimEnd('\\') + "\\" + relativePath.Replace('/', '\\').TrimStart('\\');
}
