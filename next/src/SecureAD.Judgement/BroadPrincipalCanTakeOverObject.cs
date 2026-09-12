using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-060 - a principal broad in every organisation can take control of an object.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it finds, in one sentence.</b> <i>Everyone can take over this object</i> - where "take
/// over" means rewrite its permission list, or become its owner and then rewrite its permission
/// list.
/// </para>
/// <para>
/// <b>Why it is worth having.</b> An administrator can look at an object's permission list and see
/// the word <i>Everyone</i> next to <i>Write DACL</i> without registering what it means: that any
/// person who can log on can grant themselves, or anybody else, full control of that object, and
/// nothing about the object will look unusual afterwards. The list shows what was granted. It does
/// not show what the grant is <i>worth</i>.
/// </para>
/// <para>
/// <b>What it refuses to claim.</b> That the permission is wrong. This product cannot know which
/// principals an organisation intended to hold access - the owner's decision recorded as
/// <c>P-123</c> - so the rule reports only that the holder is broad in every organisation, which
/// needs no local knowledge.
/// </para>
/// <para>
/// <b>The <c>WriteOwner</c> chain is conditional, and that is the whole of what makes this rule
/// truthful.</b> Becoming the owner yields the power to rewrite the list only where an owner's
/// implicit rights survive. Two things remove them, and a finding that ignored either would tell a
/// customer a principal can change permissions the platform stops them changing. See
/// <see cref="RetainsOwnerRights"/>.
/// </para>
/// <para>
/// <b>Specified in</b>
/// docs/layers/judgement/rules/SEC-060-broad-principal-can-take-over-an-object.md.
/// </para>
/// </remarks>
public sealed class BroadPrincipalCanTakeOverObject : IRule
{
    private const string RuleId = "SEC-060";

    private const int RuleVersion = 2;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        RuleId,
        "A broad principal can take over an object",
        Severity.High,
        Version: RuleVersion,

        // EVERY OBJECT, NOT A CHOSEN SET. The owner's decision of 2026-09-04. Scoping to
        // "sensitive" objects today would mean inventing a definition of sensitive that stage 7
        // will define properly later, and two definitions that must agree is the shape that has
        // already cost this repository three defects.
        SubjectClasses: [],
        RequiredAttributes: ["objectClass"],
        RequiredDerivedFacts: [nameof(DerivedFactKind.PrincipalExpansion)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-060 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (context.MembersOfPrincipal is not { } expand)
        {
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        }

        if (context.Permissions?.Invoke(subject.DistinguishedName) is not { } permissions)
        {
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion,
                UnresolvedReason.SecurityDescriptorUnreadable)]);
        }

        var access = EffectiveAccessCalculator.Over(permissions, objectTypeGuid: null);

        // A production domain returned 19,927 of 100,000 objects with no readable descriptor.
        // Reporting those as granting nothing would say an object is safe when nobody knows. The
        // calculator keeps the three silences apart from a real answer so this rule does not have
        // to reproduce that reasoning.
        if (access.Outcome is not EffectiveAccessOutcome.Computed)
        {
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion,
                UnresolvedReason.SecurityDescriptorUnreadable)]);
        }

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);

        var pending = new Dictionary<string, PendingTakeover>(StringComparer.OrdinalIgnoreCase);
        var unresolved = new List<UnresolvedInput>();

        foreach (var holder in access.Holders)
        {
            if ((holder.Mask & (GenericRightsExpander.WriteDacl | GenericRightsExpander.WriteOwner)) == 0)
                continue;
            // Independent WRITE_DAC must not inherit uncertainty from a hypothetical owner change.
            var ownerUncertainty = ControlUncertainty.None;
            var ownerRights = (holder.Mask & GenericRightsExpander.WriteDacl) != 0
                ? true : RetainsOwnerRights(subject, permissions, context, holder.Trustee, out ownerUncertainty);
            if (ownerRights is null)
            {
                unresolved.Add(new(DerivedFactKind.PrincipalExpansion, OwnerRightsReading.Reason(ownerUncertainty)));
                continue;
            }
            if (TakeoverRightOf(holder.Mask, ownerRights.Value) is not { } right)
                continue;

            Collect(subject, expand, holder, right, pending, unresolved);
        }

        // Whether another broad principal could be hiding is a property of the whole object rather
        // than of the one expansion that produced a finding, and it travels on the finding rather
        // than as an unresolved input - a verdict cannot carry both, and returning both turned two
        // real findings into zero against ad.lab on 2026-09-03.
        var objectIsComplete = unresolved.Count == 0 && access.IsComplete;

        var findings = pending.Values
            .Select(p => Build(
                subject, objectGuid, p, p.Complete && objectIsComplete, context.PrincipalNames))
            .ToList();

        // Finding nothing is a statement about the object only when the object was read in full. A
        // DACL that declared more entries than arrived may have declared the very entry this rule
        // looks for, so silence over a short list is a refusal rather than a clean verdict - P-159.
        // Where there are findings the incompleteness rides on them instead, for the reason above:
        // a verdict cannot carry both, and returning both cost two real findings once already.
        return findings.Count == 0 && (unresolved.Count > 0 || !access.IsComplete)
            ? RuleVerdict.CouldNotResolve(unresolved.Count > 0
                ? unresolved
                : [new UnresolvedInput(
                    DerivedFactKind.PrincipalExpansion,
                    UnresolvedReason.SecurityDescriptorIncomplete)])
            : RuleVerdict.Judged(findings);
    }

    /// <summary>
    /// Uses the same bounded owner-rights check as ownership findings and stored capabilities.
    /// </summary>
    private static bool? RetainsOwnerRights(
        ObjectAttributes subject, ObjectPermissions permissions, JudgingContext context, PermissionTrustee holder, out ControlUncertainty uncertainty)
    {
        var answer = OwnerRightsReading.Check(permissions, holder, OwnerRightsReading.TargetSid(subject),
            OwnerRightsReading.ComputerClass(subject), context.OwnerImplicitRights, ControlEvaluationState.Unknown);
        uncertainty = answer.Uncertainty;
        return answer.State switch
        {
            ControlEvaluationState.Established => true,
            ControlEvaluationState.NotEstablished => false,
            _ => null,
        };
    }

    /// <summary>
    /// Which takeover-class right a mask carries, or null where it carries none.
    /// </summary>
    /// <remarks>
    /// <b><c>GenericWrite</c> is absent and that is provable.</b> <c>GENERIC_WRITE_MAPPING</c> is
    /// <c>READ_CONTROL</c>, <c>WRITE_PROPERTY</c> and <c>WRITE_PROPERTY_EXTENDED</c> and nothing
    /// else, so it cannot yield control of the access control list. The mapping is
    /// <see cref="GenericRightsExpander"/>'s, verified against MS-ADTS, rather than restated here.
    /// </remarks>
    private static ObjectTakeoverRight? TakeoverRightOf(int mask, bool ownerKeepsRights)
    {
        if (GenericRightsExpander.IsFullControl(mask))
            return ObjectTakeoverRight.GenericAll;

        if ((mask & GenericRightsExpander.WriteDacl) != 0)
            return ObjectTakeoverRight.WriteDacl;

        // The conditional one. Where the platform has taken an owner's implicit rights away,
        // becoming the owner reaches nothing, and reporting it would be false.
        if ((mask & GenericRightsExpander.WriteOwner) != 0 && ownerKeepsRights)
            return ObjectTakeoverRight.WriteOwner;

        return null;
    }

    /// <summary>
    /// Expands one holder and notes a pending finding for every broad principal it reaches.
    /// </summary>
    private static void Collect(
        ObjectAttributes subject,
        Func<string, string, PrincipalExpansion> expand,
        EffectiveAccess holder,
        ObjectTakeoverRight right,
        Dictionary<string, PendingTakeover> pending,
        List<UnresolvedInput> unresolved)
    {
        var expansion = PrincipalExpansionReading.MembersOfTrustee(
            expand, holder.Trustee, subject.DomainFqdn);

        if (expansion.Outcome is PrincipalExpansionOutcome.PrincipalNotFound)
        {
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived));
        }
        else if (expansion.Outcome is PrincipalExpansionOutcome.StoppedAtBudget
            or PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType
            or PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember)
        {
            // Three different silences, one consequence. A budget leaves members unreached; a group
            // whose type was never captured leaves it unsettled whether the members reached are
            // members for authorization at all; a group that claimed a member nobody captured holds
            // more than this bundle can show. Any of them means the membership is not established,
            // so finding nothing here is not a statement that there is nothing. P-164.
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.MembershipIncomplete));
        }

        // PrincipalDoesNotExist adds nothing to unresolved and is not an error. The identifier
        // belongs to a domain read in full and no object carries it, so the entry grants the right
        // to nobody. Note this is the opposite of SEC-031's handling of the same outcome, and
        // deliberately so: there, an owner that does not exist means the object is orphaned.

        // The named principal may itself be broad, which the expansion does not cover because it
        // returns what is inside. A direct grant to Everyone is the plainest form of this finding
        // and would otherwise be the one case missed.
        if (BroadPrincipalCatalogue.IsBroad(holder.Trustee.Sid))
        {
            Note(holder, right, holder.Trustee.Sid, [holder.Trustee.Sid],
                expansion.IsComplete, pending);
        }

        foreach (var member in expansion.BroadMembers)
        {
            Note(holder, right, member.Sid, member.PathFromRoot,
                expansion.IsComplete && member.IsComplete, pending);
        }
    }

    /// <summary>
    /// Notes one broad principal reached, keeping the most serious right and the shortest route.
    /// </summary>
    /// <remarks>
    /// <b>Keyed on the broad principal alone, as the judgement store requires.</b> A finding is
    /// identified by its rule, its subject and its object, so an acceptance made against it stays
    /// attached months later. Two routes to the same principal on the same object are one finding.
    /// </remarks>
    private static void Note(
        EffectiveAccess holder,
        ObjectTakeoverRight right,
        string broadSid,
        IReadOnlyList<string> path,
        bool complete,
        Dictionary<string, PendingTakeover> pending)
    {
        if (pending.TryGetValue(broadSid, out var existing))
        {
            // The strongest right wins, and shorter is better only among equals. An operator shown
            // WriteOwner where the same principal also holds WriteDacl would be told the weaker of
            // two true things and might conclude the hardening protects them.
            if (right >= existing.Right && !(right == existing.Right && path.Count < existing.Path.Count))
                return;
        }

        pending[broadSid] = new PendingTakeover(holder, right, broadSid, path, complete);
    }

    private static Finding Build(
        ObjectAttributes subject,
        Guid objectGuid,
        PendingTakeover pending,
        bool complete,
        Func<string, string?>? names)
    {
        var evidence = new ObjectTakeoverEvidence(
            pending.Holder.Trustee.Sid,
            pending.Holder.Trustee.Name ?? NameFor(pending.Holder.Trustee.Sid, names),
            pending.BroadSid,
            NameFor(pending.BroadSid, names),
            [.. pending.Path.Select(sid => new PathStep(sid, NameFor(sid, names)))],
            pending.Right,
            pending.Holder.FirstGrantingEntry.IsInherited
                ? pending.Holder.FirstGrantingEntry.InheritedObjectTypeGuid ?? "an inherited scope"
                : null,
            complete);

        return new Finding(
            RuleId,
            RuleVersion,
            Severity.High,

            // THE SUBJECT IS THE BROAD PRINCIPAL AND THE OBJECT IS THE THING IT CAN TAKE OVER, the
            // same shape SEC-090 uses and for the same reason: the grid then reads "Domain Users can
            // take over OU=Applications", and each principal is accepted on its own, so accepting
            // one does not silently accept a different broad principal that appears later.
            //
            // THE SID IS IN THE KEY AND NOT ONLY THE NAME. "Domain Users" is not unique in a forest
            // - this lab has three domains, each with its own - and two of them on one object would
            // collide into one finding and lose the second.
            new FindingSubject(FindingSubjectKind.Account, SubjectKeyFor(pending.BroadSid)),
            objectGuid,
            subject.DistinguishedName,
            subject.DomainFqdn ?? string.Empty,
            AttributeReading.LastText(subject, "objectClass") ?? string.Empty,
            Detail(evidence),
            subject.Completeness,
            evidence);
    }

    /// <summary>
    /// What a principal is called: the catalogue's word for a principal broad everywhere, then what
    /// this bundle captured, and the identifier where neither answers.
    /// </summary>
    private static string? NameFor(string sid, Func<string, string?>? names) =>
        BroadPrincipalCatalogue.NameOf(sid) ?? names?.Invoke(sid);

    /// <summary>
    /// How a broad principal is named as the subject of a finding: the name it is known by, with
    /// its security identifier, which is what makes the key unique and stable.
    /// </summary>
    private static string SubjectKeyFor(string sid) =>
        BroadPrincipalCatalogue.NameOf(sid) is { } known ? $"{known} ({sid})" : sid;

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <b>It states the route and stops short of a verdict on the delegation.</b> The rule cannot
    /// know whether the principal should hold this access, so the wording says what is true - a
    /// principal broad in every organisation can rewrite this object's permissions - and leaves
    /// whether that was intended to the person reading it.
    /// </remarks>
    private static string Detail(ObjectTakeoverEvidence evidence)
    {
        var who = evidence.BroadPrincipalName ?? evidence.BroadPrincipalSid;

        var how = evidence.Right switch
        {
            ObjectTakeoverRight.GenericAll =>
                "holds Full Control, which includes the right to rewrite the permission list",
            ObjectTakeoverRight.WriteDacl =>
                "can rewrite the permission list directly",
            _ =>
                "can take ownership of it, and an owner may then rewrite the permission list",
        };

        var route = evidence.NestingDepth == 0
            ? "granted directly"
            : $"reached through {evidence.Route}";

        var caveat = evidence.IsComplete
            ? string.Empty
            : " The membership walk behind this did not finish, so other broad principals may also"
              + " hold it.";

        return $"{who} {how} ({route}).{caveat}";
    }

    /// <summary>One broad principal reached, before the object's own completeness is known.</summary>
    private sealed record PendingTakeover(
        EffectiveAccess Holder,
        ObjectTakeoverRight Right,
        string BroadSid,
        IReadOnlyList<string> Path,
        bool Complete);
}
