using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// What became of the question <i>is this object's owner one this product accepts</i>.
/// </summary>
/// <remarks>
/// <b>Acceptance rather than administrativeness, and the difference is P-148.</b> These outcomes
/// were once named for whether the owner was an administrator, and three of the principals the
/// accepting arm covers are not administrators at all: CREATOR OWNER is a placeholder the directory
/// substitutes when a child object is created and names nobody, SYSTEM is the platform, and
/// Enterprise Domain Controllers is a machine identity. They go unreported because they are
/// directory artefacts rather than people - a different question, as <c>0099</c> and <c>0100</c>
/// both say, and precisely the conflation <c>0101</c> exists to prevent. The consequence was always
/// identical, which is why the wrong name survived; the name is read by anyone extending this rule,
/// which is why it did not survive longer. The vocabulary here now matches the registry these
/// answers actually come from - <c>PrincipalClassificationRegistry.AcceptedOwnerSids</c> and
/// <see cref="OwnerAcceptance"/>.
/// </remarks>
internal enum ObjectOwnershipOutcome
{
    /// <summary>The owner is not an accepted one, and the evidence settles it.</summary>
    OwnerIsNotAccepted,

    /// <summary>
    /// The owner is accepted, so there is nothing to report - whether because the principal holds
    /// directory authority or because it is an artefact naming no person at all.
    /// </summary>
    OwnerIsAccepted,

    /// <summary>
    /// The owner keeps no implicit right to rewrite the permission list, so the claim this rule
    /// makes would be false on this object.
    /// </summary>
    OwnerHoldsNoImplicitRights,

    /// <summary>The question could not be answered, and <c>Reason</c> says why.</summary>
    CouldNotResolve,
}

/// <summary>
/// The one place that decides whether an object's owner is a non-administrator who can still
/// rewrite the object's permissions.
/// </summary>
/// <remarks>
/// <para>
/// <b>Two rules ask this and neither owns the answer.</b> <c>SEC-031</c> reports ordinary objects
/// and <c>SEC-032</c> reports objects <c>AdminSDHolder</c> protects. They differ in which objects
/// they cover and what they say, and in nothing else - so the decision lives here rather than in
/// both, which is how the DN helpers came to have three ways to ask one question.
/// </para>
/// <para>
/// <b>Ownership matters because of what it silently confers.</b> Microsoft: an object's owner
/// <i>implicitly has WRITE_DAC access to the object… and thus can control access to the object</i>.
/// So the owner is a permission holder who does not appear in the permission list, and no permission
/// review will show them.
/// </para>
/// </remarks>
internal static class ObjectOwnershipReading
{
    /// <summary>
    /// Identifiers that are accepted owners wherever they appear, whoever is inside them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>SYSTEM</c>, <c>Enterprise Domain Controllers</c> and <c>CREATOR OWNER</c> are platform
    /// identities rather than people. Reporting them would be reporting the directory for being a
    /// directory. <c>CREATOR OWNER</c> in particular names nobody at all - it is a placeholder the
    /// directory substitutes when a child object is created - so a finding about it would send an
    /// operator to look for an account that does not exist.
    /// </para>
    /// <para>
    /// <b>Matched on the identifier because that is the shape of the question.</b> Nobody is a
    /// member of <c>CREATOR OWNER</c>, so there is nothing to walk; these are accepted for what
    /// they are and not for what they contain. <c>BUILTIN\Administrators</c> is here as well
    /// because it is the default owner of most objects in the directory, and an answer that
    /// depended on the derivation having a fact about it would report every one of them the moment
    /// the closure did not. Its <i>members</i> are covered separately by
    /// <see cref="OwnerAcceptance"/>, which is the part this list cannot do.
    /// </para>
    /// <para>
    /// <b>Five operator groups were removed from this list on 2026-09-05, per <c>P-140</c>.</b>
    /// Account Operators, Server Operators, Print Operators, Backup Operators and Replicator were
    /// treated as administrative here while <c>0099</c> excludes every one of them from the control
    /// plane, so the same principal produced silence on the ownership screen and a visible
    /// unexpected edge on the control-edge screen. Removing them from this list alone changed
    /// nothing, because the protection closure below reached the same answer by a second route;
    /// that is why <see cref="OwnerAcceptance"/> exists.
    /// </para>
    /// </remarks>
    private static readonly IReadOnlySet<string> AcceptedOwnerSids = PrincipalClassificationRegistry.AcceptedOwnerSids;

    /// <summary>
    /// Relative identifiers accepted as owners under any domain.
    /// </summary>
    /// <remarks>
    /// <c>AdminSDHolder</c> is owned by <c>Domain Admins</c> rather than <c>Administrators</c> by
    /// design, which is why 512 is here and why that documented exception costs nothing.
    /// </remarks>
    private static readonly IReadOnlySet<int> AcceptedOwnerRids = PrincipalClassificationRegistry.AcceptedOwnerIdentifierRids;

    /// <summary>
    /// Decides the ownership question for one object.
    /// </summary>
    /// <param name="subject">The object being judged.</param>
    /// <param name="context">The derived facts offered to the rule.</param>
    public static ObjectOwnershipDecision Decide(
        ObjectAttributes subject, JudgingContext context)
    {
        var eligibility = Eligibility(subject, context);
        if (eligibility.Outcome != ObjectOwnershipOutcome.OwnerIsNotAccepted || eligibility.Evidence?.IsOrphaned == true)
            return eligibility;
        var permissions = context.Permissions?.Invoke(subject.DistinguishedName);
        if (permissions?.Owner is not { } owner)
            return Unresolved(UnresolvedReason.IdentityUnreadable);
        var rights = OwnerRightsReading.Check(permissions, owner, OwnerRightsReading.TargetSid(subject),
            OwnerRightsReading.ComputerClass(subject), context.OwnerImplicitRights, ControlEvaluationState.NotEstablished);
        return rights.State switch
        {
            ControlEvaluationState.Established => eligibility,
            ControlEvaluationState.NotEstablished => new(ObjectOwnershipOutcome.OwnerHoldsNoImplicitRights, null, null),
            _ => Unresolved(OwnerRightsReading.Reason(rights.Uncertainty)),
        };
    }

    /// <summary>Reuses the accepted owner policy without treating rights qualification as owner acceptance.</summary>
    internal static ObjectOwnershipDecision Eligibility(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (context.Permissions?.Invoke(subject.DistinguishedName) is not { } permissions
            || permissions.Availability is not DescriptorAvailability.Read)
        {
            // Nobody knows who owns it. Reporting an object as fine because its descriptor was
            // never read is the one thing an audit tool must not do.
            return Unresolved(UnresolvedReason.SecurityDescriptorUnreadable);
        }

        // A CORRECTION TO THE PREDECESSOR, whose SEC-031 silently skipped these (N6). A missing
        // owner on a descriptor that WAS read is not "the owner is fine" - it is a fact nobody has,
        // and 0002 forbids treating that silence as an answer.
        if (permissions.Owner?.Sid is not { Length: > 0 } ownerSid)
            return Unresolved(UnresolvedReason.IdentityUnreadable);

        if (IsAcceptedOwnerByIdentifier(ownerSid))
            return Accepted();

        if (context.ProtectedPrincipals is not { } protection)
            return Unresolved(UnresolvedReason.NotDerived);

        if (context.MembersOfPrincipal is not { } expand)
            return Unresolved(UnresolvedReason.NotDerived);

        // AN ACCEPTED OWNER THROUGH MEMBERSHIP IS ALSO UNREPORTED, AND THIS IS A CORRECTION TO THE
        // PREDECESSOR. Its SEC-031 decided administrativeness from the identifier alone and
        // recorded its own false positive: "An owner who is privileged only by transitive group
        // membership will still fire a finding."
        //
        // WHAT THIS ASKS CHANGED ON 2026-09-05, PER P-140. It used to ask whether AdminSDHolder
        // protects the owner, which is a different question and gave a different answer: the
        // protected set includes the five operator groups, so an account inside Backup Operators
        // was silently accepted as an owner while 0099 puts Backup Operators outside the control
        // plane. It now asks the derivation's own accepted-owner answer, walked over the accepted
        // roots alone and carrying its own evidence, per 0101.
        var scope = Sid.IsBuiltinDomain(ownerSid) ? subject.DomainFqdn : null;

        if (protection.Lookup(ownerSid, scope) is { } fact)
        {
            switch (fact.OwnerAcceptance)
            {
                case OwnerAcceptance.Accepted:
                    return Accepted();

                case OwnerAcceptance.SchemaOnly:
                case OwnerAcceptance.SchemaOnlyOtherwiseUnknown:
                    if (string.IsNullOrWhiteSpace(context.ForestFqdn))
                        return Unresolved(UnresolvedReason.ForestIdentityUnreadable);

                    if (IsInSchema(subject.DistinguishedName, context.ForestFqdn))
                        return Accepted();

                    if (fact.OwnerAcceptance == OwnerAcceptance.SchemaOnlyOtherwiseUnknown)
                        return Unresolved(UnresolvedReason.MembershipIncomplete);
                    break;

                case OwnerAcceptance.NotAccepted:
                    break;

                default:
                    // The derivation declined to call it either way. Reporting an owner as
                    // non-administrative on that basis could name a domain administrator.
                    return Unresolved(UnresolvedReason.MembershipIncomplete);
            }
        }

        // Whether the owning account still exists, which decides what an operator can do about it.
        var expansion = PrincipalExpansionReading.MembersOfTrustee(
            expand,
            permissions.Owner,
            subject.DomainFqdn);

        if (expansion.Outcome == PrincipalExpansionOutcome.PrincipalNotFound)
            return Unresolved(UnresolvedReason.IdentityUnreadable);
        if (protection.Lookup(ownerSid, scope) is null && expansion.Outcome != PrincipalExpansionOutcome.PrincipalDoesNotExist)
            return Unresolved(UnresolvedReason.NotDerived);

        var standing = expansion.Outcome switch
        {
            PrincipalExpansionOutcome.PrincipalDoesNotExist => ObjectOwnerStanding.DoesNotExist,
            _ => ObjectOwnerStanding.Exists,
        };

        // A walk that stopped early could have missed the group that makes this owner
        // administrative, and so could one that passed through a group whose type was never
        // captured, or one whose group claimed a member nothing in the bundle answers to. The
        // answer is carried rather than asserted. All three are tested by name: an outcome added
        // later and not listed here would be read as a complete walk, which is the failure where a
        // check goes on passing while it measures less than it did.
        var complete = expansion.Outcome is not (PrincipalExpansionOutcome.StoppedAtBudget
            or PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType
            or PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember);

        var evidence = new ObjectOwnershipEvidence(
            ownerSid,
            permissions.Owner.Name ?? context.PrincipalNames?.Invoke(ownerSid),
            standing,
            AttributeReading.LastText(subject, "objectClass") ?? string.Empty,
            complete);

        return new ObjectOwnershipDecision(
            ObjectOwnershipOutcome.OwnerIsNotAccepted, evidence, null);
    }

    private static bool IsAcceptedOwnerByIdentifier(string sid)
    {
        foreach (var known in AcceptedOwnerSids)
        {
            if (string.Equals(sid, known, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return RelativeIdentifierOf(sid) is { } rid && AcceptedOwnerRids.Contains(rid);
    }

    /// <summary>
    /// The relative identifier of a domain principal, or null where the SID is not one.
    /// </summary>
    /// <remarks>
    /// Read from a SID of the right shape rather than off the end of any string, for the reason
    /// <c>BroadPrincipalCatalogue</c> gives: reading the tail alone would match 512 under a machine
    /// SID and call the result Domain Admins.
    /// </remarks>
    private static int? RelativeIdentifierOf(string sid)
    {
        if (!sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase))
            return null;

        var lastDash = sid.LastIndexOf('-');

        return lastDash > 0 && int.TryParse(sid[(lastDash + 1)..], out var rid) ? rid : null;
    }

    private static bool IsInSchema(string distinguishedName, string forestFqdn)
    {
        // Microsoft documents this fixed forest-relative naming context. Walk parsed ancestors:
        // a comma escaped inside a leaf name must never manufacture a schema ancestor.
        var schema = "CN=Schema,CN=Configuration,"
            + string.Join(',', forestFqdn.Split('.').Select(label => "DC=" + label));

        for (string? ancestor = distinguishedName; ancestor is not null; ancestor = DnHelper.GetParentDn(ancestor))
        {
            if (string.Equals(ancestor, schema, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static ObjectOwnershipDecision Accepted() =>
        new(ObjectOwnershipOutcome.OwnerIsAccepted, null, null);

    private static ObjectOwnershipDecision Unresolved(UnresolvedReason reason) =>
        new(ObjectOwnershipOutcome.CouldNotResolve, null, reason);
}

/// <summary>
/// What the ownership question came to, and the evidence behind it where there is any.
/// </summary>
/// <param name="Outcome">What became of the question.</param>
/// <param name="Evidence">
/// The facts to report, present only where <paramref name="Outcome"/> is
/// <see cref="ObjectOwnershipOutcome.OwnerIsNotAccepted"/>.
/// </param>
/// <param name="Reason">
/// Why the question could not be answered, present only where it could not be.
/// </param>
internal sealed record ObjectOwnershipDecision(
    ObjectOwnershipOutcome Outcome,
    ObjectOwnershipEvidence? Evidence,
    UnresolvedReason? Reason);
