using System.Globalization;
using System.Resources;
using SecureAD.Judgement;

namespace SecureAD.Shell.Services;

/// <summary>
/// Turns what stopped a rule deciding into something an administrator can act on.
/// </summary>
/// <remarks>
/// <para>
/// <b>The store keeps a token; an operator needs a sentence.</b> A judging records
/// <c>ProtectedPrincipals.ClaimDisputed</c> against a count, which is exactly right for a database
/// and useless on a screen. The wording lives here rather than in the store so it can be improved
/// without rewriting rows already written, which is why the token is composed rather than free text.
/// </para>
/// <para>
/// <b>Each sentence says what to do, or says plainly that there is nothing to do.</b> That is the
/// distinction the vocabulary exists for: a missing attribute means capture again, and a disputed
/// claim means Microsoft's own pages disagree and another capture will change nothing. Telling an
/// administrator to re-read his forest over a documentation conflict wastes an afternoon and finds
/// nothing, which is the failure <c>docs/decisions/0091</c> named.
/// </para>
/// <para>
/// <b>An unrecognised token is shown rather than swallowed.</b> A reason this build has no words for
/// is still a reason a rule could not decide, and hiding it would report a judging as more complete
/// than it was.
/// </para>
/// </remarks>
internal static class UnresolvedWording
{
    private static readonly ResourceManager Ownership = new("SecureAD.Shell.Resources.ControlEdgePresentation", typeof(UnresolvedWording).Assembly);
    private const string AdministrativeEvidenceUnavailable =
        "The membership or identity evidence needed to complete this administrative-group assessment is unavailable or could not be verified. "
        + "Recorded positive links do not establish that all other membership has been assessed.";
    private const string MembershipScopeUnsupported =
        "The captured membership relationship has unsupported or contradictory group scope; this run cannot establish authorization through that relationship.";

    /// <summary>
    /// What to tell an operator about <paramref name="token"/>, as a judging recorded it.
    /// </summary>
    /// <param name="token">
    /// The stored reason: either an LDAP attribute name, or a derived fact and why it fell short.
    /// </param>
    public static string For(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        // An attribute name has no dot and names something the capture did not bring back, which is
        // a different instruction from everything below it.
        var split = token.Split('.', 2);

        if (split.Length != 2)
            return $"{token} was not captured, so the rules that read it could not decide.";

        if (!Enum.TryParse<UnresolvedReason>(split[1], out var reason))
            return $"{token} was undecided, and this version has no plainer way to say why.";

        if (split[0] == nameof(DerivedFactKind.NestingCycles))
            return reason switch
            {
                UnresolvedReason.NotDerived => "Circular membership was not derived for this run.",
                UnresolvedReason.MembershipIncomplete => "Circular membership could not be assessed completely from this run's captured and derived group data. Recorded loops do not establish that no others exist.",
                UnresolvedReason.IdentityUnreadable => "A group identity needed for circular membership could not be established from the captured evidence.",
                _ => $"{token} was undecided, and this version has no plainer way to say why.",
            };

        if (split[0] == nameof(DerivedFactKind.AdministrativeMembership))
            return reason switch
            {
                UnresolvedReason.NotDerived or UnresolvedReason.MembershipIncomplete or UnresolvedReason.IdentityUnreadable => AdministrativeEvidenceUnavailable,
                UnresolvedReason.MembershipScopeUnsupported => MembershipScopeUnsupported,
                UnresolvedReason.MembershipProcessingLimit =>
                    "The saved administrative-membership route calculation reached its recorded processing limit. "
                    + "Established membership remains evidence; absence of other routes is not a complete answer.",
                UnresolvedReason.ForestIdentityUnreadable =>
                    "The captured forest-root identity is unavailable, so Enterprise Admins and Schema Admins membership could not be fully qualified.",
                UnresolvedReason.MembershipIdentityUnsupported =>
                    "A captured foreign reference matches SID history, which the saved security-membership routes do not resolve. "
                    + "Established current membership remains evidence; membership through the historical identity is not assessed.",
                UnresolvedReason.AttributeWriteSchemaUnavailable =>
                    "The captured schema does not establish the requested attribute's identity; this attribute-write rule cannot report a complete answer.",
                UnresolvedReason.AttributeWriteIncomplete =>
                    "The attribute-write permission or the holder's administrative expectedness could not be assessed completely. Established findings remain evidence of the permissions shown.",
                _ => $"{token} was undecided, and this version has no plainer way to say why.",
            };

        return reason switch
        {
            UnresolvedReason.NotDerived =>
                "Some principals were not covered by the derivation, so nothing is known about "
                + "whether they are protected. Deriving the run again would settle it.",

            UnresolvedReason.MembershipIncomplete =>
                "Group membership could not be followed all the way, so a route to a protected "
                + "group may have been missed. Capturing every domain in the forest would settle it.",

            UnresolvedReason.ClaimDisputed =>
                "Microsoft's own documentation contradicts itself about whether a group here is "
                + "protected, so this product will not decide. Capturing again will not change it.",

            UnresolvedReason.ClaimUnverified =>
                "Whether protection passes down through a group here is not established by any "
                + "Microsoft source this product trusts, so it is left open rather than guessed.",

            UnresolvedReason.PrimaryGroupRoute =>
                "These reach their group only through the primary-group setting, and whether "
                + "protection travels that way is not settled. Domain controllers usually appear "
                + "here, and that is expected.",

            UnresolvedReason.ForestMaskUnknown =>
                "The forest setting that says which operator groups it still protects could not be "
                + "read, so nothing was called unprotected. Capturing the configuration partition "
                + "would settle it.",

            UnresolvedReason.PrincipalDomainNotRead =>
                "The domain these accounts belong to was not read in full, so nothing was "
                + "established about whether they are protected. Including that domain in the run "
                + "would settle it.",

            UnresolvedReason.SecurityDescriptorUnreadable =>
                "Permissions could not be read for these objects, so their current state is "
                + "unknown. Capturing with an account that can read them would settle it.",

            // "May settle it" rather than "would", approved by the owner on 2026-09-10 and worth
            // keeping honest: a short list comes from the stored descriptor failing to parse all
            // the way through, and a second capture may return intact bytes or exactly the same
            // ones. The neighbouring wordings promise a remedy only where there is one, and one of
            // them says plainly that capturing again will not help.
            UnresolvedReason.SecurityDescriptorIncomplete =>
                "Permissions were read for these objects but the list came back short, so an entry "
                + "nobody saw may grant what this check looks for. These are not reported as clean; "
                + "capturing them again may settle it.",

            UnresolvedReason.IdentityUnreadable =>
                "These objects carried no readable security identifier, so they could not be "
                + "matched against anything.",

            UnresolvedReason.MembershipScopeUnsupported => MembershipScopeUnsupported,

            UnresolvedReason.ForestIdentityUnreadable =>
                "The captured forest could not be identified, so schema-scoped owner acceptance "
                + "could not be checked. Check the run's recorded forest identity before judging again.",

            UnresolvedReason.MembershipProcessingLimit =>
                "The saved membership-route calculation reached its recorded processing limit; absence of other routes is not a complete answer.",
            UnresolvedReason.MembershipIdentityUnsupported =>
                "A captured historical identity cannot be followed through the saved security-membership routes; absence of a route is not a complete answer.",
            UnresolvedReason.AttributeWriteSchemaUnavailable =>
                "The captured schema does not establish the requested attribute-write identity.",
            UnresolvedReason.AttributeWriteIncomplete =>
                "The requested attribute-write permission or its expectedness has unresolved captured or derived inputs.",

            UnresolvedReason.OwnerServerBehaviorNotRecorded or UnresolvedReason.OwnerHeuristicNotRead or UnresolvedReason.OwnerRightsNotEvaluated =>
                Ownership.GetString(reason.ToString(), CultureInfo.CurrentUICulture) ?? throw new MissingManifestResourceException(reason.ToString()),

            _ => $"{token} was undecided, and this version has no plainer way to say why.",
        };
    }
}
