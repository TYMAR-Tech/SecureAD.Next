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
