namespace SecureAD.Shell.Settings;

/// <summary>
/// What the operator has told this installation of the product.
/// </summary>
/// <remarks>
/// <para>
/// <b>There is no default run library path, and that is a decision rather than an omission.</b>
/// <c>docs/decisions/0025-the-run-library-is-a-managed-root.md</c> is explicit: a tool that decides
/// for itself where several gigabytes of evidence go is a tool that fills the wrong disk, and the
/// predecessor hardcoded <c>%LOCALAPPDATA%</c> into two constructors. The operator chooses, the
/// product remembers, and until they have chosen this is null.
/// </para>
/// <para>
/// <b>Null means unanswered, not empty.</b> A shell holding a null path must ask for one rather
/// than show an empty run library, because "you have no runs" and "I do not know where to look"
/// are different sentences and only one of them is true.
/// </para>
/// </remarks>
/// <param name="RunLibraryPath">
/// The directory the operator chose to keep runs in, or null if they have not chosen yet.
/// </param>
internal sealed record ShellSettings(string? RunLibraryPath)
{
    /// <summary>The settings of an installation nobody has configured yet.</summary>
    public static ShellSettings Unconfigured { get; } = new(RunLibraryPath: null);
}
