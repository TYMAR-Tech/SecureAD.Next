namespace SecureAD.Audit.Sysvol;

/// <summary>
/// One Group Policy object whose files are to be read, as the directory described it.
/// </summary>
/// <remarks>
/// <para>
/// This is the denominator, and it comes from LDAP before a single file is opened. That ordering is
/// what earns SYSVOL the right to record coverage at all: per
/// <c>docs/decisions/0044-sysvol-coverage-is-recorded-beside-the-capture-units.md</c> a thing that
/// is not a capture unit may record coverage only where its incompleteness has knowable edges, and
/// the edges are knowable here precisely because the list of what should be there does not depend
/// on the share answering.
/// </para>
/// <para>
/// A target is not a promise that the folder exists. A policy whose <c>gPCFileSysPath</c> points at
/// nothing is a real and reportable state of a directory - it means the policy object outlived its
/// files - and it is recorded as such rather than skipped.
/// </para>
/// <para>
/// <b>The identifier here is not the name of the folder.</b> A policy has two GUIDs. Its
/// <c>objectGUID</c> is assigned by the directory, and is what this record carries and what joins a
/// SYSVOL finding back to the directory object it came from. Its folder on the share is named for
/// the <b>CN GUID</b> of the <c>groupPolicyContainer</c> - the braced value in its distinguished
/// name - which is a different value. Anything that built a path from <see cref="GpoGuid"/> would
/// look in the wrong place, or worse, in a place that exists and belongs to another policy.
/// Nothing does: <see cref="FileSysPath"/> comes from <c>gPCFileSysPath</c>, which the directory
/// supplies. This paragraph previously said the folder was named for <c>objectGUID</c>, which was
/// false. Corrected 2026-08-19; see <c>docs/next/S-58</c> finding 18.
/// </para>
/// </remarks>
/// <param name="GpoGuid">
/// The policy's <c>objectGUID</c>, which identifies the directory object. Not the name of its
/// folder on the share - see the remarks.
/// </param>
/// <param name="DisplayName">The policy's display name, as an administrator would recognise it.</param>
/// <param name="FileSysPath">The policy's folder, from its <c>gPCFileSysPath</c>.</param>
public sealed record GpoTarget(Guid GpoGuid, string DisplayName, string FileSysPath)
{
    /// <summary>Creates a target, refusing one that could not be reported to an operator.</summary>
    /// <exception cref="ArgumentException">
    /// The identifier is empty, or the name or path is blank.
    /// </exception>
    public static GpoTarget Of(Guid gpoGuid, string displayName, string fileSysPath)
    {
        if (gpoGuid == Guid.Empty)
        {
            throw new ArgumentException(
                "A policy with no identifier cannot be named in the coverage record, and a policy "
                + "that cannot be named is a hole with no edges.",
                nameof(gpoGuid));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileSysPath);

        return new GpoTarget(gpoGuid, displayName.Trim(), fileSysPath.Trim());
    }
}
