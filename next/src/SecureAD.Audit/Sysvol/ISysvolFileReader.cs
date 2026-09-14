using SecureAD.Kernel;

namespace SecureAD.Audit.Sysvol;

/// <summary>
/// Reads Group Policy files and folder security descriptors from a domain's SYSVOL share.
/// </summary>
/// <remarks>
/// <para>
/// This is the seam that isolates network access from the SYSVOL capture logic, so the capture
/// module can be tested without a share to talk to and the only real network surface lives in
/// <see cref="SmbSysvolFileReader"/>. The predecessor had the same seam and it earned its place;
/// this is the same idea with two things changed.
/// </para>
/// <para>
/// <b>Absent and unreadable are different answers, and every method here keeps them apart.</b>
/// The predecessor returned <c>null</c> for both, logged the reason at debug level and threw it
/// away. That is survivable while a read failure aborts the run, because the run is gone anyway.
/// It is not survivable here: per
/// <c>docs/decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md</c> a SYSVOL
/// failure does not fail the run, so the reason is the only thing that will ever reach the
/// operator, and a policy folder nobody could open must not read as a policy folder holding
/// nothing. That is <c>docs/decisions/0002</c> at the level of a single file.
/// </para>
/// <para>
/// <b>There are no alternate credentials.</b> The predecessor established an authenticated share
/// session with <c>WNetAddConnection2</c> and held a password in memory for the lifetime of the
/// reader. A run uses the token it already has, per
/// <c>docs/decisions/0039-one-way-to-start-a-capture.md</c>.
/// </para>
/// <para>Implementations are safe to call concurrently for reads.</para>
/// </remarks>
public interface ISysvolFileReader
{
    /// <summary>
    /// Reads the full bytes of a file beneath a GPO's SYSVOL folder.
    /// </summary>
    /// <param name="target">
    /// The GPO's <c>gPCFileSysPath</c>, for example
    /// <c>\\contoso.com\SysVol\contoso.com\Policies\{GUID}</c>.
    /// </param>
    /// <param name="relativePath">
    /// Path beneath <see cref="GpoTarget.FileSysPath"/>, using either separator, for example
    /// <c>Machine\Registry.pol</c>.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// The file's bytes; or a success carrying <c>null</c> when the folder was readable and the
    /// file is genuinely not there; or a failure when it could not be determined which of those
    /// two is true.
    /// </returns>
    Task<Result<byte[]?>> ReadFileAsync(
        GpoTarget target,
        string relativePath,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads the raw security descriptor - owner, group and DACL - of a file or folder beneath a
    /// GPO's SYSVOL folder.
    /// </summary>
    /// <param name="target">The GPO identity and its captured share path.</param>
    /// <param name="relativePath">
    /// Path beneath <see cref="GpoTarget.FileSysPath"/>, or empty for the GPO folder itself.
    /// </param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>
    /// The self-relative security descriptor bytes; or a success carrying <c>null</c> when the
    /// path is genuinely not there; or a failure when the permissions could not be read.
    /// </returns>
    /// <remarks>
    /// The audit part of the descriptor - the SACL - is never requested. Reading one needs a
    /// privilege that is not available over a file share even to a domain administrator, and
    /// asking for it turns every read into an exception. The DACL is what the rules judge.
    /// </remarks>
    Task<Result<byte[]?>> ReadSecurityDescriptorAsync(
        GpoTarget target,
        string relativePath,
        CancellationToken cancellationToken);

    /// <summary>
    /// Lists the files beneath a GPO's SYSVOL folder matching a wildcard pattern, at any depth.
    /// </summary>
    /// <param name="target">The GPO identity and the folder to enumerate.</param>
    /// <param name="searchPattern">A wildcard file pattern, for example <c>*.xml</c>.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>
    /// Paths relative to the GPO folder, so each can be passed straight back to
    /// <see cref="ReadFileAsync"/>; empty when the folder holds no match; or a failure when the
    /// folder could not be listed.
    /// </returns>
    /// <remarks>
    /// Group Policy Preferences files are found this way rather than from the GPO's declared
    /// extension list, because the files on the share are what a workstation actually applies.
    /// </remarks>
    Task<Result<IReadOnlyList<string>>> EnumerateRelativeFilesAsync(
        GpoTarget target,
        string searchPattern,
        CancellationToken cancellationToken);

    /// <summary>
    /// Lists the folders beneath a GPO's SYSVOL folder, at any depth.
    /// </summary>
    /// <param name="target">The GPO identity and the folder to enumerate.</param>
    /// <param name="cancellationToken">Cancels the enumeration.</param>
    /// <returns>
    /// Paths relative to the GPO folder, ordered so a parent precedes what it contains; empty when
    /// the GPO folder has no subfolders; or a failure when it could not be listed.
    /// </returns>
    /// <remarks>
    /// New here: the predecessor's seam could match files and could not list folders at all, so
    /// its permission read stopped at the GPO folder. Per
    /// <c>docs/decisions/0043-a-gpos-file-permissions-are-read-below-the-root-folder.md</c> the
    /// folders beneath it are in scope, because a policy folder whose root is locked down and whose
    /// <c>Machine\Scripts</c> folder is writable by everyone is a logon script anybody can rewrite.
    /// </remarks>
    Task<Result<IReadOnlyList<string>>> EnumerateRelativeDirectoriesAsync(
        GpoTarget target,
        CancellationToken cancellationToken);
}
