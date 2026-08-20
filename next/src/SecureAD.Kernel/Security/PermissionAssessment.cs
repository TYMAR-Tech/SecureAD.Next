namespace SecureAD.Kernel.Security;

/// <summary>
/// What the product is prepared to say about a single access control entry.
/// </summary>
/// <remarks>
/// <para>
/// This is an enumeration rather than a <c>bool</c> on purpose, and the reason is the defect the
/// map records against the previous classifier: an ACE whose object-type GUID the product did not
/// recognise was <i>not assessed and found safe</i>, it was never examined, and both came back as
/// <c>false</c>. A reader cannot tell those apart, and one of them is a permission nobody has
/// looked at.
/// </para>
/// <para>
/// The same separation is what <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> and
/// <c>docs/decisions/0004-unknown-counts-name-the-failed-phase.md</c> require of every other part
/// of this product: "found nothing" and "could not compute" are never rendered alike.
/// </para>
/// </remarks>
public enum PermissionVerdict
{
    /// <summary>
    /// The permission this entry grants is a takeover of the object it is written on, or of the
    /// account, policy or credential the named right controls.
    /// </summary>
    Dangerous,

    /// <summary>
    /// The right is not a takeover on its own, and it becomes one in the presence of evidence a
    /// single entry does not carry. A single entry cannot say which other rights the same
    /// principal holds, and it cannot say which container it is written on, so the answer belongs
    /// to a per-principal or per-container assessment that this component does not perform.
    /// Recorded rather than answered, per
    /// <c>docs/decisions/0016-the-filtered-set-replication-route-is-a-product-judgement.md</c>.
    /// </summary>
    /// <remarks>
    /// The second half - the container - was added for <c>S-57</c> finding <c>#8</c>. A right to
    /// create children of one class is what a delegation wizard produces and is
    /// <c>docs/rules/SEC-121.md</c>'s Critical rogue domain controller injection, depending only
    /// on which object the entry sits on. The member previously named the per-principal case
    /// alone; the shape is the same in both, which is why it is one member and not two.
    /// </remarks>
    DangerousInCombination,

    /// <summary>
    /// Examined, understood, and not a takeover. This is a positive statement, and it is only ever
    /// returned when the entry was actually understood.
    /// </summary>
    NotDangerous,

    /// <summary>
    /// Not assessed. The GUID is not in the catalogue, the access mask names no kind of right the
    /// classifier understands, or the entry type is not one Windows defines. Never rendered as
    /// safe.
    /// </summary>
    CannotClassify,
}

/// <summary>
/// A verdict about one access control entry, with the reason it was reached.
/// </summary>
/// <remarks>
/// The reason is carried rather than logged because the reader of an audit is an administrator
/// deciding whether to remove a delegation. "Dangerous" on its own is not something a person can
/// act on or argue with; "grants Reset Password on this account" is.
/// </remarks>
/// <param name="Verdict">What the product is prepared to say.</param>
/// <param name="Reason">Why, in terms a reader of the audit would understand.</param>
/// <param name="RightName">
/// The LDAP name of the right the entry is scoped to, when it is scoped to one and the catalogue
/// knows it. <c>null</c> for an entry scoped to the whole object, and for a GUID the catalogue
/// does not know - in which case the verdict is <see cref="PermissionVerdict.CannotClassify"/>
/// and the reason says so.
/// </param>
public sealed record PermissionAssessment(
    PermissionVerdict Verdict,
    string Reason,
    string? RightName)
{
    /// <summary>A takeover-class permission.</summary>
    /// <param name="reason">Why it is a takeover.</param>
    /// <param name="rightName">The right it is scoped to, or null if it is scoped to the object.</param>
    public static PermissionAssessment Dangerous(string reason, string? rightName) =>
        Create(PermissionVerdict.Dangerous, reason, rightName);

    /// <summary>A right that is a component of a dangerous combination and not one on its own.</summary>
    /// <param name="reason">Which combination, and who owns the question.</param>
    /// <param name="rightName">The right it is scoped to.</param>
    public static PermissionAssessment DangerousInCombination(string reason, string? rightName) =>
        Create(PermissionVerdict.DangerousInCombination, reason, rightName);

    /// <summary>Examined and found not to be a takeover.</summary>
    /// <param name="reason">What was examined.</param>
    /// <param name="rightName">The right it is scoped to, or null if it is scoped to the object.</param>
    public static PermissionAssessment NotDangerous(string reason, string? rightName) =>
        Create(PermissionVerdict.NotDangerous, reason, rightName);

    /// <summary>Not assessed, and not to be rendered as safe.</summary>
    /// <param name="reason">What stopped the assessment.</param>
    public static PermissionAssessment CannotClassify(string reason) =>
        Create(PermissionVerdict.CannotClassify, reason, null);

    private static PermissionAssessment Create(PermissionVerdict verdict, string reason, string? rightName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        return new PermissionAssessment(verdict, reason, rightName);
    }
}
