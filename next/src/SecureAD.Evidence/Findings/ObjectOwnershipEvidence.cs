namespace SecureAD.Evidence.Findings;

/// <summary>
/// Whether the account that owns an object still exists.
/// </summary>
/// <remarks>
/// <b>The two states carry opposite remedies, which is why this is not a boolean.</b> An owner that
/// exists can be asked to hand ownership over. An owner that has been deleted cannot, and the object
/// is orphaned — nobody can act as its owner and nobody can be asked to stop.
/// </remarks>
public enum ObjectOwnerStanding
{
    /// <summary>The bundle holds a principal carrying this identifier.</summary>
    Exists,

    /// <summary>
    /// The identifier belongs to a domain this run read in full, and no object in it carries the
    /// identifier — so the owner has been deleted and the object is orphaned.
    /// </summary>
    /// <remarks>
    /// <b>This is the opposite of how SEC-060 treats the same outcome, and deliberately so.</b>
    /// There, a grant to a principal that does not exist reaches nobody and is not worth reporting.
    /// Here, an object owned by a deleted account is a real and durable problem.
    /// </remarks>
    DoesNotExist,
}

/// <summary>
/// What SEC-031 and SEC-032 rest on: an object whose owner is not an administrative principal.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is worth reporting at all.</b> Ownership is not in the permission list. An
/// administrator can review every entry on an object, find nothing wrong, and miss that the owner
/// can replace the whole list whenever they like. Microsoft is blunt about it: <i>"No matter what
/// permissions are set on an object, the owner of the object can always change the permissions on an
/// object."</i>
/// </para>
/// <para>
/// <b>This reports latent authority. It is not evidence of abuse and must never be worded as if it
/// were.</b> The ordinary sequence is that somebody was allowed to create an object, they created
/// it, they became its owner, and it stayed that way for years. Nobody did anything wrong at any
/// point. An operator who reads this as evidence of malicious delegation will waste a day and then
/// stop trusting the rule.
/// </para>
/// <para>
/// <b>One record, two rules.</b> <c>SEC-031</c> reports ordinary objects at <c>Low</c> and
/// <c>SEC-032</c> reports objects <c>AdminSDHolder</c> protects at <c>High</c>. The facts recorded
/// are identical — what differs is the claim being made about them — so they share this record and
/// its table, and the finding's own rule identifier says which claim was made. The two rules cover
/// disjoint sets of objects, so no object is ever reported by both.
/// </para>
/// </remarks>
/// <param name="OwnerSid">The security identifier in the descriptor's owner field.</param>
/// <param name="OwnerName">
/// What the owner is called, or null where nothing in this bundle holds the object carrying the SID.
/// </param>
/// <param name="Standing">Whether that owner still exists.</param>
/// <param name="ObjectClass">
/// The object's most derived class, carried because it decides whether the forest's owner-rights
/// hardening could have applied and because it is the first thing an operator wants to know.
/// </param>
/// <param name="MembershipWasComplete">
/// Whether the walk that decided the owner is not administrative reached everything it needed to.
/// </param>
public sealed record ObjectOwnershipEvidence(
    string OwnerSid,
    string? OwnerName,
    ObjectOwnerStanding Standing,
    string ObjectClass,
    bool MembershipWasComplete) : FindingEvidence
{
    /// <summary>
    /// Whether the membership walk behind this answer finished, so that "not administrative" is a
    /// fact rather than a walk that stopped early.
    /// </summary>
    public bool IsComplete => MembershipWasComplete;

    /// <summary>The owner as an operator would read it, naming what can be named.</summary>
    public string Display => OwnerName ?? OwnerSid;

    /// <summary>
    /// Whether nobody can be asked to hand ownership over, because the owning account is gone.
    /// </summary>
    public bool IsOrphaned => Standing is ObjectOwnerStanding.DoesNotExist;
}
