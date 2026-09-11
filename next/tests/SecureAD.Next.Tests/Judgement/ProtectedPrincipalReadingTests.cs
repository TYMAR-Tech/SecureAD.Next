using SecureAD.Derivation;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Turning what the protection derivation could not settle into the words a rule reports.
/// </summary>
/// <remarks>
/// <b>One mapping shared by every rule that consumes the derivation</b>, so a defect here is a
/// defect in each of them at once and shows up as an operator being sent to fix the wrong thing.
/// The ordering is the part worth guarding: several reasons can apply to one principal, and which
/// is reported decides where he looks first.
/// </remarks>
public sealed class ProtectedPrincipalReadingTests
{
    /// <summary>
    /// A principal whose own domain was not read is said to be that, not a membership problem.
    /// </summary>
    /// <remarks>
    /// <b>The fire for the reporting half of P-163.</b> Falling through to
    /// <see cref="UnresolvedReason.MembershipIncomplete"/> would send an operator to inspect group
    /// nesting. Nothing is wrong with the nesting; he excluded the domain or the run could not read
    /// it, and the remedy is a wider capture.
    /// </remarks>
    [Fact]
    public void AnUnreadDomainIsNamedRatherThanBlamedOnTheMembership()
    {
        Assert.Equal(
            UnresolvedReason.PrincipalDomainNotRead,
            ProtectedPrincipalReading.ReasonFor(
                ProtectionUnknownReason.PrincipalDomainNotReadInFull));
    }

    /// <summary>
    /// Where the forest mask was also unreadable, the mask is reported instead.
    /// </summary>
    /// <remarks>
    /// The mask is one fact about the whole run that an operator fixes once, and fixing it may
    /// change every answer. Sending him to widen a capture the mask would still spoil wastes the
    /// second run as well as the first.
    /// </remarks>
    [Fact]
    public void TheForestMaskOutranksAnUnreadDomain()
    {
        Assert.Equal(
            UnresolvedReason.ForestMaskUnknown,
            ProtectedPrincipalReading.ReasonFor(
                ProtectionUnknownReason.PrincipalDomainNotReadInFull
                | ProtectionUnknownReason.ForestMaskNotRead));
    }

    /// <summary>
    /// Incomplete membership on its own still reads as incomplete membership.
    /// </summary>
    /// <remarks>
    /// <b>The negative control.</b> Without it a mapping that answered
    /// <see cref="UnresolvedReason.PrincipalDomainNotRead"/> to everything would satisfy the first
    /// test, and every rule in the product would tell an operator to widen a capture that was
    /// already whole.
    /// </remarks>
    [Fact]
    public void IncompleteMembershipAloneStillReadsAsIncompleteMembership()
    {
        Assert.Equal(
            UnresolvedReason.MembershipIncomplete,
            ProtectedPrincipalReading.ReasonFor(
                ProtectionUnknownReason.MembershipEvidenceIncomplete));
    }

    /// <summary>
    /// A disputed claim still outranks everything, as it did before this reason existed.
    /// </summary>
    /// <remarks>
    /// Microsoft contradicting itself is not settled by capturing again, so it is reported ahead of
    /// anything a further run could fix. Asserted here because a new value inserted in the wrong
    /// place in that chain would silently demote it.
    /// </remarks>
    [Fact]
    public void ADisputedClaimStillOutranksEverything()
    {
        Assert.Equal(
            UnresolvedReason.ClaimDisputed,
            ProtectedPrincipalReading.ReasonFor(
                ProtectionUnknownReason.PrincipalClaimDisputed
                | ProtectionUnknownReason.PrincipalDomainNotReadInFull
                | ProtectionUnknownReason.ForestMaskNotRead));
    }
}
