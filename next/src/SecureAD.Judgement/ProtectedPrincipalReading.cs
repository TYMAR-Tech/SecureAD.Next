using SecureAD.Derivation;
using SecureAD.Evidence.Findings;

namespace SecureAD.Judgement;

/// <summary>
/// Reading the protected-principal derivation, shared by every rule that consumes it.
/// </summary>
/// <remarks>
/// <b>One mapping, because two would drift.</b> <c>SEC-030</c> and <c>SEC-021</c> both ask the same
/// derivation the same question and must report the same doubt in the same words. A second copy of
/// the translation below would be a second opinion about what the derivation said, and the operator
/// would have no way of knowing which rule's vocabulary he was reading.
/// </remarks>
internal static class ProtectedPrincipalReading
{
    /// <summary>
    /// Turns the derivation's reason into the vocabulary a rule reports, so the doubt an operator
    /// reads is the doubt the derivation actually recorded.
    /// </summary>
    /// <remarks>
    /// <b>Order matters where several apply.</b> The most specific and least recoverable is
    /// reported: a dispute is Microsoft contradicting itself and no amount of re-capturing will
    /// settle it, while incomplete membership is a fact about this run that another run may fix.
    /// Telling an operator to capture again over a documentation conflict wastes his afternoon.
    /// </remarks>
    /// <param name="reasons">What the derivation said it could not settle.</param>
    internal static UnresolvedReason ReasonFor(ProtectionUnknownReason reasons)
    {
        if (reasons.HasFlag(ProtectionUnknownReason.PrincipalClaimDisputed))
            return UnresolvedReason.ClaimDisputed;

        if (reasons.HasFlag(ProtectionUnknownReason.PrincipalClaimUnverified))
            return UnresolvedReason.ClaimUnverified;

        if (reasons.HasFlag(ProtectionUnknownReason.PrimaryGroupTraversalResearchBlocked))
            return UnresolvedReason.PrimaryGroupRoute;

        if (reasons.HasFlag(ProtectionUnknownReason.ForestMaskNotRead)
            || reasons.HasFlag(ProtectionUnknownReason.ForestMaskMalformed))
            return UnresolvedReason.ForestMaskUnknown;

        // Below the forest-wide reasons above, and that ordering is the point. Where a run both
        // failed to read the forest mask and did not read this account's domain, the mask is the
        // thing to say: it is one fact about the whole run that an operator fixes once, while this
        // would send him to widen a capture that the mask would still spoil. Above the catch-all
        // below, because "membership incomplete" would send him to look at group nesting when
        // nothing is wrong with the nesting - the account's domain was simply never read. P-163.
        if (reasons.HasFlag(ProtectionUnknownReason.PrincipalDomainNotReadInFull))
            return UnresolvedReason.PrincipalDomainNotRead;

        // Everything left - incomplete membership evidence, a possible root reached, an unknown
        // forest root - is the graph being short of what the answer needed.
        return UnresolvedReason.MembershipIncomplete;
    }

    /// <summary>A verdict that could not be reached, naming the derived fact and the reason.</summary>
    /// <param name="reason">Why the rule could not decide.</param>
    internal static RuleVerdict Unresolved(UnresolvedReason reason) =>
        RuleVerdict.CouldNotResolve(
            [new UnresolvedInput(DerivedFactKind.ProtectedPrincipals, reason)]);
}
