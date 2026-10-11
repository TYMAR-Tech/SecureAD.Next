using System.Text.Json.Serialization;

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
/// <para>
/// <b>There is a second setting as of 2026-09-13, and adding it took overturning a sentence.</b>
/// <c>docs/decisions/0047-settings-are-per-user-and-per-machine.md</c> said the run library path was
/// the only thing an operator sets, and required that a second be added by overturning that sentence
/// rather than by adding a field. The owner overturned it. The test it was applying is unchanged and
/// still governs anything proposed here: <b>nothing a customer can switch makes a run read more or
/// less.</b>
/// </para>
/// <para>
/// Appearance is the third setting, approved 2026-10-10. It changes application colors only and
/// is kept per machine with the other installation choices.
/// </para>
/// </remarks>
/// <param name="RunLibraryPath">
/// The directory the operator chose to keep runs in, or null if they have not chosen yet.
/// </param>
/// <param name="DomainsAtOnce">
/// How many domains a capture reads at the same time, or null if the operator has not chosen.
///
/// <para>
/// <b>Nullable because every settings file already on a disk is missing this property, and a plain
/// <c>int</c> would read it as zero.</b> That is not a tidiness point. A ceiling of zero waits
/// forever while looking precisely like a capture that is working, which is the failure
/// <c>docs/decisions/0041-capture-reads-domains-in-parallel.md</c> names when it refuses zero at
/// construction. Every operator who had already chosen a run library would have got one, on the
/// first run after upgrading, with nothing on screen saying why.
/// </para>
/// <para>
/// Null therefore means <i>not stated</i> and resolves to
/// <see cref="Audit.Connect.DirectoryConnectionSettings.DefaultDomainsAtOnce"/>. A value that is
/// present and below one was written by hand and is refused rather than silently replaced - see
/// <see cref="JsonShellSettingsStore.Read"/>.
/// </para>
/// </param>
/// <param name="Appearance">The chosen application theme, or null for the default Dark theme.</param>
internal sealed record ShellSettings(
    string? RunLibraryPath,
    int? DomainsAtOnce,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Appearance = null)
{
    /// <summary>The settings of an installation nobody has configured yet.</summary>
    public static ShellSettings Unconfigured { get; } =
        new(RunLibraryPath: null, DomainsAtOnce: null, Appearance: null);
}
