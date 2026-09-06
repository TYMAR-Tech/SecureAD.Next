using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// What became of the question <i>is this object owned by somebody who is not an administrator</i>.
/// </summary>
internal enum ObjectOwnershipOutcome
{
    /// <summary>The owner is not an administrative principal, and the evidence settles it.</summary>
    OwnerIsNotAdministrative,

    /// <summary>The owner is administrative, so there is nothing to report.</summary>
    OwnerIsAdministrative,

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
    /// <summary><c>OWNER RIGHTS</c>, which switches off an owner's implicit rights.</summary>
    private const string OwnerRightsSid = "S-1-3-4";

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
    private static readonly IReadOnlySet<string> AdministrativeSids = PrincipalClassificationRegistry.AcceptedOwnerSids;

    /// <summary>
    /// Relative identifiers that are administrative under any domain.
    /// </summary>
    /// <remarks>
    /// <c>AdminSDHolder</c> is owned by <c>Domain Admins</c> rather than <c>Administrators</c> by
    /// design, which is why 512 is here and why that documented exception costs nothing.
    /// </remarks>
    private static readonly IReadOnlySet<int> AdministrativeRids = PrincipalClassificationRegistry.AcceptedOwnerIdentifierRids;

    /// <summary>
    /// Decides the ownership question for one object.
    /// </summary>
    /// <param name="subject">The object being judged.</param>
    /// <param name="context">The derived facts offered to the rule.</param>
    public static ObjectOwnershipDecision Decide(
        ObjectAttributes subject, JudgingContext context)
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

        if (context.ProtectedPrincipals is not { } protection)
            return Unresolved(UnresolvedReason.NotDerived);

        if (context.MembersOfPrincipal is not { } expand)
            return Unresolved(UnresolvedReason.NotDerived);

        // An owner that cannot rewrite the list is not what either rule reports, and saying it
        // could would be false. Checked before administrativeness because it ends the question
        // whoever the owner turns out to be.
        if (!RetainsImplicitRights(subject, permissions, context, out var unknownForest))
        {
            return unknownForest
                ? Unresolved(UnresolvedReason.ForestMaskUnknown)
                : new ObjectOwnershipDecision(
                    ObjectOwnershipOutcome.OwnerHoldsNoImplicitRights, null, null);
        }

        if (IsAdministrativeByIdentifier(ownerSid))
            return Administrative();

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
                    return Administrative();

                case OwnerAcceptance.SchemaOnly:
                case OwnerAcceptance.SchemaOnlyOtherwiseUnknown:
                    if (string.IsNullOrWhiteSpace(context.ForestFqdn))
                        return Unresolved(UnresolvedReason.ForestIdentityUnreadable);

                    if (IsInSchema(subject.DistinguishedName, context.ForestFqdn))
                        return Administrative();

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

        var standing = expansion.Outcome switch
        {
            PrincipalExpansionOutcome.PrincipalDoesNotExist => ObjectOwnerStanding.DoesNotExist,
            _ => ObjectOwnerStanding.Exists,
        };

        // A walk that stopped early could have missed the group that makes this owner
        // administrative, so the answer is carried rather than asserted.
        var complete = expansion.Outcome is not PrincipalExpansionOutcome.StoppedAtBudget;

        var evidence = new ObjectOwnershipEvidence(
            ownerSid,
            permissions.Owner.Name ?? context.PrincipalNames?.Invoke(ownerSid),
            standing,
            AttributeReading.LastText(subject, "objectClass") ?? string.Empty,
            complete);

        return new ObjectOwnershipDecision(
            ObjectOwnershipOutcome.OwnerIsNotAdministrative, evidence, null);
    }

    /// <summary>
    /// Whether this object's owner keeps the implicit right to rewrite its permission list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Two things switch it off.</b> An <c>OWNER RIGHTS</c> (<c>S-1-3-4</c>) entry on the object,
    /// and the forest setting <c>BlockOwnerImplicitRights</c> under the three conditions MS-ADTS
    /// 6.1.3.4 gives together. An earlier draft of the specification named only the first and called
    /// it <i>the one thing that would make this rule lie</i>; that was wrong, and <c>P-138</c>
    /// records the correction.
    /// </para>
    /// <para>
    /// <b>The forest setting only ever applies to computer objects</b>, so a forest nobody read is
    /// not a doubt about an organizational unit, a group or a user. That is what keeps these rules
    /// answerable across the directory in a hardened forest, and reading the setting as a general
    /// switch would have silenced them across most of it.
    /// </para>
    /// </remarks>
    private static bool RetainsImplicitRights(
        ObjectAttributes subject,
        ObjectPermissions permissions,
        JudgingContext context,
        out bool forestUnknown)
    {
        forestUnknown = false;

        if (permissions.Entries.Any(entry => string.Equals(
                entry.Trustee.Sid, OwnerRightsSid, StringComparison.OrdinalIgnoreCase)))
        {
            return false;
        }

        var isComputer = string.Equals(
            AttributeReading.LastText(subject, "objectClass"),
            "computer",
            StringComparison.OrdinalIgnoreCase);

        if (!isComputer)
            return true;

        if (context.OwnerImplicitRights is not { } setting || !setting.IsComplete)
        {
            forestUnknown = true;
            return false;
        }

        // The owner of a computer object created by a non-administrator is that person, who is by
        // definition not in Domain Admins or Enterprise Admins - which is the condition being
        // tested here rather than assumed. Where the owner IS in one of those groups the check
        // above has already returned administrative.
        return !DirectoryHeuristics.BlocksImplicitOwnerRights(
            setting, objectIsComputerClass: true, ownerIsDomainOrEnterpriseAdmin: false);
    }

    private static bool IsAdministrativeByIdentifier(string sid)
    {
        foreach (var known in AdministrativeSids)
        {
            if (string.Equals(sid, known, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return RelativeIdentifierOf(sid) is { } rid && AdministrativeRids.Contains(rid);
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

    private static ObjectOwnershipDecision Administrative() =>
        new(ObjectOwnershipOutcome.OwnerIsAdministrative, null, null);

    private static ObjectOwnershipDecision Unresolved(UnresolvedReason reason) =>
        new(ObjectOwnershipOutcome.CouldNotResolve, null, reason);
}

/// <summary>
/// What the ownership question came to, and the evidence behind it where there is any.
/// </summary>
/// <param name="Outcome">What became of the question.</param>
/// <param name="Evidence">
/// The facts to report, present only where <paramref name="Outcome"/> is
/// <see cref="ObjectOwnershipOutcome.OwnerIsNotAdministrative"/>.
/// </param>
/// <param name="Reason">
/// Why the question could not be answered, present only where it could not be.
/// </param>
internal sealed record ObjectOwnershipDecision(
    ObjectOwnershipOutcome Outcome,
    ObjectOwnershipEvidence? Evidence,
    UnresolvedReason? Reason);
