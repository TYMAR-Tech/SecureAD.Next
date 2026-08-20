namespace SecureAD.Evidence;

/// <summary>
/// Which half of a Group Policy object a setting came from.
/// </summary>
/// <remarks>
/// A policy holds two independent sets of settings - one applied to the machine, one to the user
/// signing in - and they are stored in separate files under the policy's folder. Recording which
/// is which is not bookkeeping: a registry value applied machine-wide and the same value applied to
/// one user's profile are different security facts, and a rule that could not tell them apart would
/// report a user preference as a machine-wide weakening.
/// </remarks>
public enum GpoSettingScope
{
    /// <summary>Applied to every machine the policy reaches.</summary>
    Machine,

    /// <summary>Applied to every user the policy reaches.</summary>
    User,
}

/// <summary>
/// Which way round a Restricted Groups entry places a principal.
/// </summary>
/// <remarks>
/// Both directions exist in the file format and they are opposites. <see cref="Member"/> means the
/// principal is put into the named group - the dangerous direction, because it is how a policy
/// grants administrative rights on every machine it reaches. <see cref="MemberOf"/> means the named
/// group is put into the principal. Collapsing the two would invert half the memberships in the
/// evidence.
/// </remarks>
public enum RestrictedGroupRelationship
{
    /// <summary>The principal is placed into the named group.</summary>
    Member,

    /// <summary>The named group is placed into the principal.</summary>
    MemberOf,
}
