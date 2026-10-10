namespace SecureAD.Judgement;

/// <summary>
/// Why a derived fact left a rule unable to decide.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are not missing attributes, and the difference reaches the operator.</b> An uncaptured
/// attribute is a fact about the capture, and the answer is to capture again. Everything here is a
/// fact about what is known: the derivation did not cover this principal, or Microsoft's own pages
/// disagree about it. Telling an operator to re-run a capture over a documentation conflict wastes
/// hours and fixes nothing. <c>docs/decisions/0091</c> requires the two to stay apart.
/// </para>
/// <para>
/// <b>Named for what the operator can do about it</b>, which is why <see cref="ClaimDisputed"/> and
/// <see cref="ClaimUnverified"/> are separate. A dispute is Microsoft contradicting itself and will
/// not resolve by looking harder at this forest; an unverified claim is a question this product has
/// not yet answered and may answer later.
/// </para>
/// </remarks>
public enum UnresolvedReason
{
    /// <summary>
    /// The derivation holds no fact about this principal at all, so nothing is known either way.
    /// </summary>
    NotDerived,

    /// <summary>
    /// The membership evidence behind the answer was incomplete, so an unseen route may reach a
    /// protected root.
    /// </summary>
    MembershipIncomplete,

    /// <summary>
    /// The only route runs through a group whose own protection Microsoft's documentation
    /// contradicts itself about.
    /// </summary>
    ClaimDisputed,

    /// <summary>
    /// The only route runs through a group whose member propagation nothing has established.
    /// </summary>
    ClaimUnverified,

    /// <summary>
    /// The only route is a <c>primaryGroupID</c> reference, and whether protection travels that way
    /// is not settled.
    /// </summary>
    PrimaryGroupRoute,

    /// <summary>
    /// The forest's <c>dSHeuristics</c> was not read or was malformed, and the answer depends on a
    /// root the forest may have excluded.
    /// </summary>
    ForestMaskUnknown,

    /// <summary>
    /// The object's security descriptor was absent or could not be parsed, so its current
    /// inheritance state is unknown.
    /// </summary>
    SecurityDescriptorUnreadable,

    /// <summary>
    /// The descriptor was read, but not every entry it declared arrived, so an entry that was never
    /// seen may grant exactly what the rule was looking for.
    /// </summary>
    /// <remarks>
    /// Kept apart from <see cref="SecurityDescriptorUnreadable"/> deliberately, and for the reason
    /// <c>docs/decisions/0091</c> gives about keeping an uncaptured attribute apart from a disputed
    /// claim: telling an operator the descriptor could not be read, when it was read and came back
    /// short, sends him to look for a capture failure that did not happen.
    /// </remarks>
    SecurityDescriptorIncomplete,

    /// <summary>The object carried no usable SID, so it could not be matched against anything.</summary>
    IdentityUnreadable,

    /// <summary>The captured forest identity is missing, so schema-scoped ownership cannot be judged.</summary>
    ForestIdentityUnreadable,
    /// <summary>Owner-right authorization depends on serving DC behavior not recorded in the evidence.</summary>
    OwnerServerBehaviorNotRecorded,
    /// <summary>The forest's implicit-owner-right heuristic was not captured.</summary>
    OwnerHeuristicNotRead,
    /// <summary>The named ownership modification has unresolved class, scope or requester applicability.</summary>
    OwnerRightsNotEvaluated,

    /// <summary>
    /// This account's own domain was not read in full, so nothing was established about it.
    /// </summary>
    /// <remarks>
    /// <b>Kept apart from <see cref="MembershipIncomplete"/> deliberately</b>, for the reason
    /// <c>docs/decisions/0091</c> gives about keeping an uncaptured attribute apart from a disputed
    /// claim. Telling an operator the membership evidence was short sends him to look at group
    /// nesting, when the answer is that he excluded the account's domain from the run or the run
    /// could not read it. The remedy is a wider capture, and naming the wrong cause wastes his
    /// afternoon. P-163.
    /// </remarks>
    PrincipalDomainNotRead,

    /// <summary>A captured membership hop has unsupported or contradictory authorization scope.</summary>
    MembershipScopeUnsupported,
}

/// <summary>
/// One reason a rule could not decide, and which derived fact it was about.
/// </summary>
/// <param name="Kind">The derived fact that fell short.</param>
/// <param name="Reason">Why it fell short.</param>
public sealed record UnresolvedInput(DerivedFactKind Kind, UnresolvedReason Reason)
{
    /// <summary>
    /// A short stable token for storage and counting, in the shape the judgement store already uses
    /// for a missing attribute name.
    /// </summary>
    /// <remarks>
    /// Composed rather than free text so a store can group by it, and so the wording an operator
    /// reads can change without rewriting rows already written.
    /// </remarks>
    public string Token => $"{Kind}.{Reason}";
}
