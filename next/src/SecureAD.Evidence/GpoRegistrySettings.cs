namespace SecureAD.Evidence;

/// <summary>
/// What became of the attempt to read one Group Policy Object's files out of SYSVOL.
/// </summary>
/// <remarks>
/// Mirrors the <c>outcome</c> column of <c>sysvol_gpo_coverage</c>, which capture writes for every
/// policy it recognised.
/// </remarks>
/// <remarks>
/// <b>Ordered worst first, so that the default value is the one that claims least.</b> A default
/// enum is zero, and a zero meaning <c>Read</c> would let a value nobody filled in assert that a
/// policy's settings are known in full - the same shape of fault as a completeness flag that is
/// always true.
/// </remarks>
public enum GpoSettingsOutcome
{
    /// <summary>
    /// This bundle carries no SYSVOL capture at all, so nothing is known about any policy's
    /// settings.
    /// </summary>
    /// <remarks>
    /// <b>Distinct from a policy that was read and set nothing.</b> A capture without SYSVOL is a
    /// fact about the run; a policy with no settings is a fact about the policy. Collapsing the two
    /// is exactly what <c>docs/decisions/0002</c> forbids.
    /// </remarks>
    NotCaptured,

    /// <summary>
    /// The policy's files could not be read, so nothing is known about what it configures.
    /// </summary>
    Unreadable,

    /// <summary>
    /// Some of the policy's files were read and some were not, so a setting that is absent here may
    /// still be present in the part that could not be read.
    /// </summary>
    PartiallyRead,

    /// <summary>The policy's files were read, so its settings are known in full.</summary>
    Read,
}

/// <summary>
/// The machine-side registry settings one Group Policy Object carries, beside a statement of
/// whether they could be read at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>The two travel together because an empty list means three different things.</b> A policy that
/// configures nothing, a policy whose SYSVOL files could not be read, and a bundle captured without
/// SYSVOL are indistinguishable from the list alone - and a rule reading the first as the others
/// would tell an operator that a policy is harmless when nobody looked. Gate 4 in
/// <c>docs/next/README.md</c> exists for this, and it is what caught the first version of SEC-093
/// treating an unreadable policy as one setting no decryptor.
/// </para>
/// <para>
/// <b><see cref="Reason"/> is present exactly when the outcome is not <c>Read</c></b>, which the
/// <c>sysvol_gpo_coverage</c> table enforces with a check constraint of its own.
/// </para>
/// </remarks>
/// <param name="Settings">
/// Every machine-scope entry the bundle holds for this policy, in the order the file stated them.
/// </param>
/// <param name="Outcome">What became of the attempt to read the policy's files.</param>
/// <param name="Reason">
/// Why the read did not finish, where it did not. Null when <paramref name="Outcome"/> is
/// <see cref="GpoSettingsOutcome.Read"/>.
/// </param>
public sealed record GpoRegistrySettings(
    IReadOnlyList<Kernel.GroupPolicy.RegistryPolicyEntry> Settings,
    GpoSettingsOutcome Outcome,
    string? Reason)
{
    /// <summary>
    /// Whether everything this policy configures is present, so an absent setting is a fact about
    /// the policy rather than about the capture.
    /// </summary>
    public bool IsComplete => Outcome is GpoSettingsOutcome.Read;
}
