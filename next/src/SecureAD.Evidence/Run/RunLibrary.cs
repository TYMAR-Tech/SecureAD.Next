using SecureAD.Kernel;

namespace SecureAD.Evidence.Run;

/// <summary>
/// The directory the tool owns, and the runs created inside it.
/// </summary>
/// <remarks>
/// <para>
/// This is inventory row F11 and the mechanism
/// <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c> decided. The operator chooses
/// where the root is; the tool chooses the layout within it. Capture to an arbitrary path is not
/// offered, because without a catalogue there is nothing to list, nowhere for a baseline to live,
/// and comparison cannot offer <i>runs comparable with this one</i>.
/// </para>
/// <para>
/// <b>The root is not chosen here and there is no default.</b> A tool that decides for itself where
/// several gigabytes of evidence go is a tool that fills the wrong disk, and the predecessor
/// hardcoded <c>%LOCALAPPDATA%</c> into two constructors. It is supplied by the caller, which gets
/// it from configuration.
/// </para>
/// <para>
/// <b>The guards are a traversal defence, not a gesture.</b> Containment normalises both sides and
/// requires a separator, so <c>C:\runs-elsewhere</c> is not inside <c>C:\runs</c>. A run identifier
/// is rejected if it is rooted, contains either separator, is <c>.</c> or <c>..</c>, or carries a
/// character a filename may not. Deletion of a failed run will depend on these, which is why they
/// are here before anything deletes anything.
/// </para>
/// </remarks>
public sealed class RunLibrary
{
    private readonly TimeProvider _time;

    /// <summary>
    /// Opens the library rooted at <paramref name="root"/>, creating the root if it is absent.
    /// </summary>
    /// <param name="root">The directory the operator configured.</param>
    /// <param name="time">The clock a run's directory name is taken from.</param>
    public RunLibrary(string root, TimeProvider time)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(time);

        Root = Path.GetFullPath(root);
        _time = time;

        Directory.CreateDirectory(Root);
    }

    /// <summary>The root, normalised. Every run lives directly inside it.</summary>
    public string Root { get; }

    /// <summary>
    /// Creates the directory for a new run and returns its path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The name carries the forest and the moment, because those are the two things an operator
    /// looking at a folder listing needs in order to tell one run from another. It is a convenience
    /// and nothing reads meaning back out of it: what a bundle is evidence of is recorded inside
    /// the bundle, and a name is not evidence.
    /// </para>
    /// <para>
    /// A second run of the same forest in the same second is refused rather than being given a
    /// suffix. Two runs that close together are almost certainly one run started twice, and a
    /// silent suffix would produce two bundles that are hard to tell apart at exactly the moment
    /// somebody is confused about what they started.
    /// </para>
    /// </remarks>
    /// <param name="forestFqdn">The forest this run will read.</param>
    public Result<string> CreateRun(string forestFqdn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(forestFqdn);

        var identifier = $"{Sanitise(forestFqdn)}-{_time.GetUtcNow():yyyyMMdd-HHmmss}";

        var resolved = Resolve(identifier);
        if (!resolved.IsSuccess)
            return Result<string>.Failure(resolved.Error!);

        if (Directory.Exists(resolved.Value))
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunDirectoryAlreadyExists",
                ErrorSeverity.Failed,
                $"'{resolved.Value}' already exists. A bundle is sealed evidence of one forest at "
                + "one moment and is never written over, and two runs of one forest in the same "
                + "second is a run started twice rather than two audits.",
                resolved.Value));
        }

        Directory.CreateDirectory(resolved.Value);

        return Result<string>.Success(resolved.Value);
    }

    /// <summary>
    /// The full path of a run inside this library, refusing anything that would leave it.
    /// </summary>
    /// <remarks>
    /// Every entry point taking a caller-supplied identifier goes through here first. That is the
    /// rule <c>0025</c> carried across whole, and it only works if there is one door.
    /// </remarks>
    /// <param name="runIdentifier">The run's directory name, not a path.</param>
    public Result<string> Resolve(string runIdentifier)
    {
        if (string.IsNullOrWhiteSpace(runIdentifier))
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunIdentifierIsEmpty",
                ErrorSeverity.Failed,
                "A run identifier is required.",
                context: null));
        }

        if (runIdentifier is "." or ".."
            || runIdentifier.Contains('/', StringComparison.Ordinal)
            || runIdentifier.Contains('\\', StringComparison.Ordinal)
            || Path.IsPathRooted(runIdentifier)
            || runIdentifier.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunIdentifierIsNotAName",
                ErrorSeverity.Failed,
                $"'{runIdentifier}' is not a run identifier. It must be a single directory name "
                + "inside the library, so that a path supplied from outside cannot reach a "
                + "directory this tool does not own.",
                runIdentifier));
        }

        var candidate = Path.GetFullPath(Path.Combine(Root, runIdentifier));

        if (!IsInsideRoot(candidate))
        {
            return Result<string>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunIsOutsideTheLibrary",
                ErrorSeverity.Failed,
                $"'{candidate}' is not inside '{Root}'. Everything this tool creates or deletes "
                + "lives directly in the library, which is what makes 'is this one of ours' a "
                + "question with an answer.",
                candidate));
        }

        return Result<string>.Success(candidate);
    }

    /// <summary>
    /// Every run in the library, as observed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A directory that is not a run is left out rather than listed as a broken one.</b>
    /// <see cref="RunStateReader.Observe"/> refuses a directory holding neither finished evidence
    /// nor a run in progress, and that refusal is honoured here. The library root is a folder on an
    /// operator's disk; something else being in it is not a damaged audit, and saying so would be a
    /// claim about a run that does not exist.
    /// </para>
    /// <para>
    /// <b>A run that is genuinely unreadable is listed, with its state.</b> The two cases are
    /// different and are kept different: <see cref="RunState.Damaged"/> says we found a run and
    /// could not trust it, which an operator must see. Skipping it would hide a real failure among
    /// files that were never ours.
    /// </para>
    /// <para>
    /// <b>The order is the identifier's, and it is not a chronological claim.</b> Run names embed
    /// the moment they were created, so this usually reads as oldest first - but nothing reads
    /// meaning back out of a name, and a caller wanting runs in time order must get that from the
    /// evidence rather than from this sort.
    /// </para>
    /// </remarks>
    public Result<IReadOnlyList<RunListing>> List()
    {
        List<string> directories;

        try
        {
            directories = Directory.EnumerateDirectories(Root).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<IReadOnlyList<RunListing>>.Failure(AuditError.Create(
                ErrorCategory.Evidence,
                "RunLibraryCannotBeRead",
                ErrorSeverity.Failed,
                $"'{Root}' could not be read, so the runs it holds are unknown. {ex.Message}",
                Root));
        }

        var listings = new List<RunListing>();

        foreach (var directory in directories.OrderBy(d => d, StringComparer.Ordinal))
        {
            var observation = RunStateReader.Observe(directory);
            if (!observation.IsSuccess)
                continue;

            listings.Add(new RunListing(
                Path.GetFileName(directory),
                directory,
                observation.Value.State,
                observation.Value.Detail));
        }

        return Result<IReadOnlyList<RunListing>>.Success(listings);
    }

    /// <summary>
    /// Whether <paramref name="candidate"/> is genuinely below the root.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both sides are normalised and the root is given a trailing separator before the comparison,
    /// so a sibling whose name merely starts with the root's - <c>C:\runs-elsewhere</c> against
    /// <c>C:\runs</c> - is not mistaken for a child. The root itself is not inside itself.
    /// </para>
    /// <para>
    /// <b>It is a second wall, and the first makes it unreachable today.</b> Mutating this to
    /// always pass was not observed by any test on 2026-08-14, and that is structural rather than a
    /// gap in coverage: <see cref="Resolve"/> rejects a rooted path, either separator, <c>.</c> and
    /// <c>..</c> before containment is asked, so what reaches here cannot escape. It is kept for
    /// the reason B9 keeps two walls against an unfinished attribute - the first can be weakened by
    /// someone who does not know the second is load-bearing - but nothing here should be read as
    /// evidence that it fires.
    /// </para>
    /// </remarks>
    private bool IsInsideRoot(string candidate)
    {
        var root = Root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

        return candidate.StartsWith(root, StringComparison.OrdinalIgnoreCase)
            && candidate.Length > root.Length;
    }

    /// <summary>
    /// A forest name reduced to characters a directory name may hold.
    /// </summary>
    /// <remarks>
    /// A forest FQDN is already close to safe, but it is a value read off a directory this product
    /// does not control, and a name that arrives with a separator in it must not become a path.
    /// </remarks>
    private static string Sanitise(string forestFqdn)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(forestFqdn
            .Select(c => invalid.Contains(c) || c is '/' or '\\' ? '_' : c)
            .ToArray());

        return cleaned.Trim('.', ' ') is { Length: > 0 } trimmed ? trimmed : "forest";
    }
}
