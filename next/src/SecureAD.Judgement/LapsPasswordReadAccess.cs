using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-090 - a principal broad in every organisation can read a machine's LAPS password attributes.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it finds.</b> A computer object whose LAPS password attributes can be read by
/// <i>Everyone</i>, <i>Authenticated Users</i>, <i>Domain Users</i>, <i>Domain Computers</i>,
/// <i>Guests</i> or <i>Anonymous Logon</i> - not necessarily named in the access control entry, but
/// falling out of the full expansion of whichever principal is. The finding carries the membership
/// path that reached it.
/// </para>
/// <para>
/// <b>What it refuses to claim, and this is the whole design.</b> It does not decide which
/// principals <i>should</i> hold LAPS read access. Nothing in the directory says whether a
/// delegation is correct, and the predecessor's rule - which fired on an "unexpected" principal
/// against a hard-coded list of administrators - presumed otherwise. The owner settled this on
/// 2026-09-03 as <c>P-123</c>, from a live customer whose decryptor group is deeply nested and is
/// also used to delegate attribute read at the domain root, a configuration that looks alarming and
/// may be deliberate. Only broadness needs no local knowledge, so only broadness is asserted.
/// </para>
/// <para>
/// <b>Two rights, not one.</b> Every LAPS password attribute is confidential, and Microsoft requires
/// <c>READ_PROPERTY</c> <i>and</i> <c>CONTROL_ACCESS</c> to read a confidential attribute. The
/// predecessor tested the second alone and so named principals who cannot retrieve the password. A
/// <c>CONTROL_ACCESS</c>-only grant is carried into the evidence as a stated fact and never raises a
/// finding - the owner's decision, same date.
/// </para>
/// <para>
/// <b>Specified in</b>
/// <c>docs/specs/rules/SEC-090-who-can-read-laps-passwords.md</c>.
/// </para>
/// </remarks>
public sealed class LapsPasswordReadAccess : IRule
{
    /// <summary><c>ADS_RIGHT_DS_READ_PROP</c>.</summary>
    private const int ReadProperty = 0x00000010;

    /// <summary><c>ADS_RIGHT_DS_CONTROL_ACCESS</c>, which a confidential attribute also needs.</summary>
    private const int ControlAccess = 0x00000100;

    private const int BothRights = ReadProperty | ControlAccess;

    /// <summary>
    /// The identifier and version, held once so the definition and the findings it produces cannot
    /// drift apart - the finding is built in a static helper that has no definition to read.
    /// </summary>
    private const string RuleId = "SEC-090";

    private const int RuleVersion = 1;

    /// <inheritdoc />
    public RuleDefinition Definition { get; } = new(
        RuleId,
        LapsPasswordReadMessages.Get("Title"),
        Severity.High,
        Version: RuleVersion,
        SubjectClasses: ["computer"],
        RequiredAttributes:
        [
            "objectClass",
            "userAccountControl",
        ],
        RequiredDerivedFacts: [nameof(DerivedFactKind.PrincipalExpansion)]);

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject) =>
        throw new InvalidOperationException(
            "SEC-090 reads derived facts and must be offered them. Judging refuses a bundle that "
            + "cannot supply them, so reaching this is a defect rather than a missing derivation.");

    /// <inheritdoc />
    public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context)
    {
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(context);

        if (!LapsAttributes.IsComputer(subject))
            return RuleVerdict.Judged([]);

        // No live machine, so no local administrator password for anything to read. Consistent with
        // SEC-091, and for the same reason: the exposure lives on the machine's local security
        // database, and a stale account in the directory has no machine attached to it. An account
        // whose state could not be read is refused rather than silenced - see P-158.
        if (LapsAttributes.RefusalFor(subject) is { } accountState)
            return accountState;

        if (context.SchemaGuids is not { } schema || context.MembersOfPrincipal is not { } expand)
        {
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived)]);
        }

        // Resolved by ldapDisplayName against this forest's own schema. A forest that never ran
        // Update-LapsADSchema has no such attribute, and no object in it can carry a password for
        // anything to be delegated read of - so an empty list here is a fact about the forest and
        // the rule stays silent rather than reporting the estate for the state of its schema.
        var attributes = LapsPasswordAttributeCatalogue.All
            .Select(name => (Name: name, Guid: schema.GuidFor(name)))
            .Where(a => a.Guid is not null)
            .ToArray();

        if (attributes.Length == 0)
            return RuleVerdict.Judged([]);

        if (context.Permissions?.Invoke(subject.DistinguishedName) is not { } permissions
            || permissions.Availability is not DescriptorAvailability.Read
            || permissions.DaclState is not DaclState.Present)
        {
            // A production domain returned 19,927 of 100,000 objects with no readable descriptor.
            // Reporting those as granting nothing would say an object is safe when nobody knows.
            return RuleVerdict.CouldNotResolve([new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion,
                UnresolvedReason.SecurityDescriptorUnreadable)]);
        }

        if (subject.ObjectGuid is not { } objectGuid)
            return RuleVerdict.CouldNotJudge(["objectGUID"]);

        var pending = new Dictionary<string, PendingFinding>(StringComparer.OrdinalIgnoreCase);
        var unresolved = new List<UnresolvedInput>();

        // The calculator's answer is kept, not just its holders. Until 2026-09-10 this took
        // .Holders and dropped EveryDeclaredEntryArrived on the floor, so an object whose DACL came
        // back short read exactly like one that granted nothing - P-159.
        var everyEntryArrived = true;

        foreach (var attribute in attributes)
        {
            var access = EffectiveAccessCalculator.Over(permissions, attribute.Guid!);

            everyEntryArrived &= access.IsComplete;

            foreach (var grant in GrantsFrom(access))
            {
                Collect(
                    subject, expand, attribute.Name, grant, pending, unresolved);
            }
        }

        // WHETHER ANOTHER BROAD PRINCIPAL COULD BE HIDING IS A PROPERTY OF THE WHOLE OBJECT, not of
        // the one expansion that produced a finding. A list naming a group that expands cleanly and,
        // beside it, a principal this bundle never captured yields a true finding and an incomplete
        // answer at the same time, and an operator who fixed only what was named would believe he
        // was done.
        //
        // IT TRAVELS ON THE FINDING RATHER THAN AS AN UNRESOLVED INPUT because a verdict cannot
        // carry both: the judging counts an object with unresolved inputs as not judged and
        // discards its findings. Measured against ad.lab on 2026-09-03 - returning both turned two
        // real findings into none. LapsPasswordReaderEvidence.IsComplete exists for exactly this.
        var objectIsComplete = unresolved.Count == 0;

        var findings = pending.Values
            .Select(p => Build(
                subject, objectGuid, p, p.Complete && objectIsComplete, context.PrincipalNames))
            .ToList();

        // Unresolved only where there is nothing to report. Where there is, the incompleteness has
        // already been said on every finding, and saying it twice would cost the findings. A short
        // entry list joins that condition: finding nothing in a list that is missing entries is not
        // a statement that nobody can read the password.
        return findings.Count == 0 && (unresolved.Count > 0 || !everyEntryArrived)
            ? RuleVerdict.CouldNotResolve(unresolved.Count > 0
                ? unresolved
                : [new UnresolvedInput(
                    DerivedFactKind.PrincipalExpansion,
                    UnresolvedReason.SecurityDescriptorIncomplete)])
            : RuleVerdict.Judged(findings);
    }

    /// <summary>
    /// What each trustee effectively holds over one attribute, after deny entries are applied the
    /// way Active Directory applies them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Accumulated across the whole DACL rather than stopping at the first match.</b> Active
    /// Directory gathers granted and denied masks over every entry and adds a deny only for rights
    /// it has not already granted - so an allow appearing before a deny keeps that deny from taking
    /// effect. Evaluating in stored order is therefore the faithful model, and it is also why
    /// <c>DaclWasCanonical</c> exists: a non-canonical DACL is more open than its entries read.
    /// </para>
    /// <para>
    /// <b>An entry with no object type reaches this attribute.</b> That is read from
    /// <c>HasObjectType</c> and never from whether the GUID is null, because those are different
    /// questions - an object entry carrying no GUID narrows nothing. Microsoft names this case as
    /// the one to hunt for: holders of the extended rights permission on an organizational unit can
    /// read confidential attributes, and every LAPS password attribute is confidential.
    /// </para>
    /// <para>
    /// <b>A trustee that does not hold the permission is skipped</b> - <c>CREATOR OWNER</c> and
    /// <c>OWNER RIGHTS</c> are placeholders rather than principals, and one lab bundle credited
    /// 1,708 entries to two of them.
    /// </para>
    /// <para>
    /// <b>An inherit-only entry grants nothing here, and this rule used to count one.</b> Until
    /// 2026-09-05 this walked the entries itself and never consulted the propagation flags, so an
    /// entry marked <c>INHERIT_ONLY_ACE</c> - which MS-ADTS 6.1.3 calls <i>"an ineffective ACE,
    /// which does not control access to the object to which it is attached"</i> - counted as a
    /// grant on the computer carrying it. A delegation inherited from an organizational unit but
    /// scoped by <c>inheritedObjectType</c> to some other class lands on a computer object exactly
    /// that way, so this was reachable rather than theoretical: the rule could name a broad
    /// principal as able to read a machine's LAPS password from an entry that grants nothing on
    /// that machine. Recorded as <c>F-S45-1</c>.
    /// </para>
    /// </remarks>
    private static IEnumerable<EffectiveGrant> GrantsFrom(EffectiveAccessResult result)
    {
        foreach (var access in result.Holders)
        {
            var rights = RightsOf(access.Mask);

            if (rights is LapsReadRights.Neither)
                continue;

            var entry = access.FirstGrantingEntry;

            yield return new EffectiveGrant(
                entry.Trustee,
                rights,
                Reach(entry),
                entry.IsInherited ? entry.InheritedObjectTypeGuid ?? "an inherited scope" : null);
        }
    }

    private static LapsGrantReach Reach(PermissionEntry entry) =>
        entry.HasObjectType ? LapsGrantReach.ThisAttributeOnly : LapsGrantReach.EveryAttribute;

    private static LapsReadRights RightsOf(int mask) => (mask & BothRights) switch
    {
        BothRights => LapsReadRights.Both,
        ReadProperty => LapsReadRights.ReadPropertyOnly,
        ControlAccess => LapsReadRights.ControlAccessOnly,
        _ => LapsReadRights.Neither,
    };

    /// <summary>
    /// Expands one grant and notes a pending finding for every broad principal it reaches.
    /// </summary>
    /// <remarks>
    /// Nothing is built here, because whether the object's answer is complete is not known until
    /// every grant on it has been walked.
    /// </remarks>
    private static void Collect(
        ObjectAttributes subject,
        Func<string, string, PrincipalExpansion> expand,
        string attribute,
        EffectiveGrant grant,
        Dictionary<string, PendingFinding> pending,
        List<UnresolvedInput> unresolved)
    {
        // A CONTROL_ACCESS-only grant is a fact and not a finding, per the owner's decision: it is
        // sensitive, and on its own it does not yield the password.
        if (grant.Rights is not LapsReadRights.Both)
            return;

        var expansion = PrincipalExpansionReading.MembersOfTrustee(
            expand, grant.Trustee, subject.DomainFqdn);

        // NOBODY HOLDS THIS RIGHT, AND THAT IS AN ANSWER RATHER THAN A GAP. PrincipalDoesNotExist
        // says the identifier belongs to a domain the run read in full and that no object in it
        // carries the identifier, so no such principal exists and the entry grants the right to
        // nobody. Most often an account deleted while the entries naming it were left behind, which
        // is what the owner confirmed these were in ad.lab on 2026-09-04.
        //
        // IT ADDS NOTHING TO unresolved, WHICH IS THE WHOLE OF THE CHANGE HERE. It deliberately does
        // not return: whether the trustee is itself broad is decided below from the shape of the
        // identifier, and that question is not the expansion's to answer. An orphan that is not
        // broad reaches neither branch below and the object is judged silently, which is the case
        // P-134 was raised for.
        if (expansion.Outcome is PrincipalExpansionOutcome.PrincipalNotFound)

        {
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived));
        }
        else if (expansion.Outcome is PrincipalExpansionOutcome.StoppedAtBudget
            or PrincipalExpansionOutcome.ExpandedThroughUnknownGroupType
            or PrincipalExpansionOutcome.ExpandedWithUnidentifiedMember)
        {
            // Everything found is genuinely inside; the absence of anything else is not a fact.
            // The same holds where the walk passed through a group whose type was never captured,
            // because whether that route carries authorization was never established - and where a
            // group claimed a member no captured object answers to, because then the directory says
            // it holds more than this bundle can show. Reporting the machine clean on that would be
            // could-not-work-it-out presented as nothing-to-report. P-164.
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.MembershipIncomplete));
        }

        // The delegated principal may itself be broad, which the expansion does not cover because it
        // returns what is *inside*. A direct grant to Authenticated Users is the plainest form of
        // this finding and would otherwise be the one case missed.
        if (BroadPrincipalCatalogue.IsBroad(grant.Trustee.Sid))
        {
            Note(attribute, grant, grant.Trustee.Sid, [grant.Trustee.Sid],
                expansion.IsComplete, pending);
        }

        foreach (var member in expansion.BroadMembers)
        {
            Note(attribute, grant, member.Sid, member.PathFromRoot,
                expansion.IsComplete && member.IsComplete, pending);
        }
    }



    /// <summary>
    /// Notes one broad principal reached, keeping the shortest route to it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Keyed on the broad principal alone, and that is what the judgement store requires.</b> A
    /// finding is identified by its rule, its subject and its object, so that an acceptance made
    /// against it stays attached months later - and the subject here is the broad principal. Two
    /// routes to the same principal on the same computer are therefore one finding, not two, and
    /// emitting both aborts the whole judging on a uniqueness violation. That is not hypothetical:
    /// it killed a full run of <c>ba.ad.lab</c> on 2026-09-03.
    /// </para>
    /// <para>
    /// <b>The shortest route wins</b>, for the reason the expansion walks breadth first in the
    /// first place: a shortest route is the link an operator would cut. Where two delegated groups
    /// both reach <i>Domain Users</i>, showing the longer chain would send him to the wrong one.
    /// </para>
    /// </remarks>
    private static void Note(
        string attribute,
        EffectiveGrant grant,
        string broadSid,
        IReadOnlyList<string> path,
        bool complete,
        Dictionary<string, PendingFinding> pending)
    {
        var candidate = new PendingFinding(attribute, grant, broadSid, path, complete);

        if (!pending.TryGetValue(broadSid, out var held))
        {
            pending[broadSid] = candidate;
            return;
        }

        if (path.Count < held.Path.Count)
            pending[broadSid] = candidate;
    }

    /// <summary>
    /// Builds the finding, once the object's overall completeness is known.
    /// </summary>
    private static Finding Build(
        ObjectAttributes subject,
        Guid objectGuid,
        PendingFinding p,
        bool complete,
        Func<string, string?>? names)
    {
        var name =
            AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;

        // RESOLVED HERE, ONCE, RATHER THAN WHEN THE FINDING IS SHOWN. A path of raw identifiers is
        // true and unactionable, and P-123 requires the path precisely so an operator can see which
        // link to cut. Resolving at display time would be one lookup per path entry per row per
        // page - measured at about three seconds a page on a million objects, on every redraw - so
        // the name is stored beside the identifier instead. The lookup is memoised for the run.
        var path = p.Path
            .Select(sid => new PathStep(sid, NameFor(sid, names)))
            .ToArray();

        var evidence = new LapsPasswordReaderEvidence(
            p.Grant.Trustee.Sid,
            p.Grant.Trustee.Name,
            p.BroadSid,
            NameFor(p.BroadSid, names),
            path,
            p.Attribute,
            p.Grant.Rights,
            p.Grant.Reach,
            p.Grant.InheritedFrom,
            complete);

        return new Finding(
            RuleId,
            RuleVersion,
            Severity.High,

            // THE SUBJECT IS THE BROAD PRINCIPAL AND THE OBJECT IS THE MACHINE, settled by the
            // owner on 2026-09-03. The grid then reads "Domain Users can read BAWK1", and - because
            // a finding's identity is its rule, its subject and its object - each route is accepted
            // on its own, so accepting one does not silently accept a different broad principal
            // that appears later. It is also what makes several broad principals on one machine
            // storable at all.
            //
            // THE SID IS IN THE KEY AND NOT ONLY THE NAME. "Domain Users" is not unique in a
            // forest - this lab has three domains, each with its own - and two of them delegated on
            // one machine would collide into one finding and lose the second. The name is first
            // because that is what an administrator recognises.
            new FindingSubject(FindingSubjectKind.Account, SubjectKeyFor(p.BroadSid)),
            objectGuid,
            subject.DistinguishedName,
            DnHelper.DnToFqdn(subject.DistinguishedName),
            LapsAttributes.ClassOf(subject),
            Detail(name, evidence),
            subject.Completeness,
            evidence);
    }

    /// <summary>
    /// What a principal is called: the catalogue's word for a principal broad everywhere, then what
    /// this bundle captured, and the identifier where neither answers.
    /// </summary>
    /// <remarks>
    /// The catalogue is asked first because it names the identifiers that mean the same thing in
    /// every forest - <c>Everyone</c> has no captured object worth preferring to that.
    /// </remarks>
    private static string? NameFor(string sid, Func<string, string?>? names) =>
        BroadPrincipalCatalogue.NameOf(sid) ?? names?.Invoke(sid);

    /// <summary>
    /// How a broad principal is named as the subject of a finding: the name it is known by, with
    /// its security identifier, which is what makes the key unique and stable.
    /// </summary>
    private static string SubjectKeyFor(string sid) =>
        BroadPrincipalCatalogue.NameOf(sid) is { } known
            ? $"{known} ({sid})"
            : sid;

    /// <summary>
    /// One broad principal reached, held until the object's overall completeness is known.
    /// </summary>
    private sealed record PendingFinding(
        string Attribute,
        EffectiveGrant Grant,
        string BroadSid,
        IReadOnlyList<string> Path,
        bool Complete);

    /// <summary>What the operator is told.</summary>
    /// <remarks>
    /// <b>It states the route and stops short of a verdict on the delegation.</b> The rule cannot
    /// know whether the delegated group should hold this access, so the wording says what is true -
    /// a principal broad in every organisation is inside it - and leaves the delegation itself to
    /// the reader. Where the grant is inherited, the scope is named as a fact, because a domain-root
    /// delegation may be deliberate.
    /// </remarks>
    private static string Detail(string name, LapsPasswordReaderEvidence evidence)
    {
        var route = evidence.NestingDepth == 0
            ? "directly"
            : $"through {evidence.NestingDepth} nested group(s): {evidence.Route}";
        var reach = evidence.Reach is LapsGrantReach.EveryAttribute
            ? LapsPasswordReadMessages.Get("EveryAttributeReach")
            : $"The entry is scoped to {evidence.Attribute}.";

        // Attribute read permission does not establish the separate right to decrypt its value.
        var readEffect = LapsPasswordReadMessages.Get(
            string.Equals(evidence.Attribute, LapsAttributes.WindowsLapsEncryptedPassword,
                StringComparison.OrdinalIgnoreCase) ? "EncryptedRead" : "ClearTextRead");

        var scope = evidence.InheritedFrom is null
            ? "The entry is set on this object itself."
            : "The entry is inherited rather than set on this object; where it is inherited from a "
                + "container high in the tree that may be deliberate, and is reported here as a "
                + "fact rather than as an error.";

        // Worded for both causes, because the evidence carries one flag and the finding must not
        // name the wrong one. It is set either when this principal's own walk stopped at a budget,
        // or when some other trustee holding the same access could not be expanded at all - and on
        // ad.lab it was the second, so a sentence blaming the delegated principal's walk would have
        // been false on the only two findings the forest produced.
        var thinned = evidence.IsComplete
            ? string.Empty
            : " Not every principal holding this access could be expanded, so further broad "
                + "principals may also hold it and are not listed here.";

        return $"{name}'s LAPS password attribute {evidence.Attribute} can be read by "
            + $"{evidence.BroadPrincipalName ?? evidence.BroadPrincipalSid} "
            + $"({evidence.BroadPrincipalSid}), a principal that is broad in every organisation, "
            + $"reached {route}. {readEffect} {reach} {scope} Cut the link in the "
            + "membership path above, or narrow the entry, rather than removing the delegation "
            + "outright: this product cannot know which principals your organisation intended to "
            + "hold this access, and reports only the one that is wrong everywhere."
            + thinned;
    }

    /// <summary>
    /// One trustee's effective position on one attribute, with the entry that produced it.
    /// </summary>
    private sealed record EffectiveGrant(
        PermissionTrustee Trustee,
        LapsReadRights Rights,
        LapsGrantReach Reach,
        string? InheritedFrom);
}
