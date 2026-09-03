using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Naming;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

/// <summary>
/// SEC-090 - a principal broad in every organisation can read a machine's LAPS password.
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
/// <c>docs/layers/judgement/rules/SEC-090-who-can-read-laps-passwords.md</c>.
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
        "A broad principal can read LAPS passwords",
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
        // database, and a stale account in the directory has no machine attached to it.
        if (LapsAttributes.IsDisabled(subject))
            return RuleVerdict.Judged([]);

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

        var pending = new List<PendingFinding>();
        var unresolved = new List<UnresolvedInput>();
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var attribute in attributes)
        {
            foreach (var grant in EffectiveGrants(permissions, attribute.Guid!))
            {
                Collect(
                    subject, expand, attribute.Name, grant, pending, unresolved, reported);
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

        var findings = pending
            .Select(p => Build(subject, objectGuid, p, p.Complete && objectIsComplete))
            .ToList();

        // Unresolved only where there is nothing to report. Where there is, the incompleteness has
        // already been said on every finding, and saying it twice would cost the findings.
        return findings.Count == 0 && unresolved.Count > 0
            ? RuleVerdict.CouldNotResolve(unresolved)
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
    /// </remarks>
    private static IEnumerable<EffectiveGrant> EffectiveGrants(
        ObjectPermissions permissions, string attributeGuid)
    {
        var granted = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var denied = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var context = new Dictionary<string, PermissionEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in permissions.Entries)
        {
            if (!entry.Trustee.HoldsThePermission)
                continue;

            if (!Reaches(entry, attributeGuid))
                continue;

            var sid = entry.Trustee.Sid;
            var isDeny = entry.AceType.Contains("Denied", StringComparison.OrdinalIgnoreCase);
            var alreadyGranted = granted.GetValueOrDefault(sid);

            if (isDeny)
            {
                denied[sid] = denied.GetValueOrDefault(sid) | (entry.AccessMask & ~alreadyGranted);
                continue;
            }

            granted[sid] = alreadyGranted | entry.AccessMask;

            // The entry that first granted a right is the one worth showing an operator, because it
            // is the one to change. A later, wider entry would name a scope that is not the cause.
            context.TryAdd(sid, entry);
        }

        foreach (var (sid, mask) in granted)
        {
            var effective = mask & ~denied.GetValueOrDefault(sid);
            var rights = RightsOf(effective);

            if (rights is LapsReadRights.Neither)
                continue;

            var entry = context[sid];

            yield return new EffectiveGrant(
                entry.Trustee,
                rights,
                Reach(entry),
                entry.IsInherited ? entry.InheritedObjectTypeGuid ?? "an inherited scope" : null);
        }
    }

    /// <summary>Whether the entry reaches this attribute at all.</summary>
    private static bool Reaches(PermissionEntry entry, string attributeGuid) =>
        !entry.HasObjectType
        || string.Equals(entry.ObjectTypeGuid, attributeGuid, StringComparison.OrdinalIgnoreCase);

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
        List<PendingFinding> pending,
        List<UnresolvedInput> unresolved,
        HashSet<string> reported)
    {
        // A CONTROL_ACCESS-only grant is a fact and not a finding, per the owner's decision: it is
        // sensitive, and on its own it does not yield the password.
        if (grant.Rights is not LapsReadRights.Both)
            return;

        var expansion = MembersOfTrustee(expand, grant.Trustee, subject.DomainFqdn);

        // A principal from a trusted external forest, or one left behind by a deleted object, is not
        // in this bundle, so nothing can be said about what is inside it. Not found is not
        // "not broad".
        if (expansion.Outcome is PrincipalExpansionOutcome.PrincipalNotFound)
        {
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived));
        }
        else if (expansion.Outcome is PrincipalExpansionOutcome.StoppedAtBudget)
        {
            // Everything found is genuinely inside; the absence of anything else is not a fact.
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.MembershipIncomplete));
        }

        // The delegated principal may itself be broad, which the expansion does not cover because it
        // returns what is *inside*. A direct grant to Authenticated Users is the plainest form of
        // this finding and would otherwise be the one case missed.
        if (BroadPrincipalCatalogue.IsBroad(grant.Trustee.Sid))
        {
            Note(attribute, grant, grant.Trustee.Sid, [grant.Trustee.Sid],
                expansion.IsComplete, pending, reported);
        }

        foreach (var member in expansion.BroadMembers)
        {
            Note(attribute, grant, member.Sid, member.PathFromRoot,
                expansion.IsComplete && member.IsComplete, pending, reported);
        }
    }

    /// <summary>
    /// Expands a trustee, asking at each scope a principal can be keyed under before concluding it
    /// is absent.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A SID is unique within its scope, not within the forest</b>, so the expansion is keyed by
    /// the pair — and which scope a given trustee lives under cannot be read off the trustee.
    /// Measured against <c>ad.lab</c> on 2026-09-03: a domain-relative SID (<c>S-1-5-21-…</c>) is
    /// keyed under the <i>empty</i> scope, because it is already unique across the forest; a
    /// <c>BUILTIN</c> SID such as <c>S-1-5-32-544</c> is keyed under a <i>domain</i>, because that
    /// same SID exists in every domain and means a different group in each.
    /// </para>
    /// <para>
    /// <b>And a BUILTIN trustee carries no domain of its own</b>, because the SID names no single
    /// captured object. What settles it is the object being judged: <c>BUILTIN\Administrators</c>
    /// in a computer's access control list is that computer's domain's group, which is why the
    /// subject's domain is one of the scopes tried.
    /// </para>
    /// <para>
    /// <b>The forest found this and 2,973 green tests did not.</b> The first run against
    /// <c>ad.lab</c> asked only at the trustee's captured domain, so every computer whose list named
    /// <c>SYSTEM</c> or a domain group answered <c>PrincipalNotFound</c>: SEC-090 reported
    /// <i>Indeterminate</i> over half the estate and buried two real findings behind a rule that
    /// looked broken. This is what step 18 of <c>building-a-rule.md</c> exists for.
    /// </para>
    /// <para>
    /// <b>Asking more than once can only turn "not found" into an answer</b>, never the reverse, so
    /// it cannot manufacture a finding. What survives every scope is a principal this bundle does
    /// not hold — a trustee from a trusted external forest, or one left behind by a deleted object —
    /// and that stays unresolved, as it must.
    /// </para>
    /// </remarks>
    private static PrincipalExpansion MembersOfTrustee(
        Func<string, string, PrincipalExpansion> expand,
        PermissionTrustee trustee,
        string? subjectDomain)
    {
        // Most specific first. Nothing here can produce a wrong match: a domain-relative SID is
        // unique across the forest, so asking under a domain it does not belong to simply answers
        // not found. The only thing an extra scope can do is turn a false absence into an answer.
        var scopes = new List<string>();

        if (!string.IsNullOrEmpty(trustee.DomainFqdn))
            scopes.Add(trustee.DomainFqdn);

        if (!string.IsNullOrEmpty(subjectDomain) && !scopes.Contains(subjectDomain))
            scopes.Add(subjectDomain);

        scopes.Add(string.Empty);

        PrincipalExpansion last = null!;

        foreach (var scope in scopes)
        {
            last = expand(trustee.Sid, scope);

            if (last.Outcome is not PrincipalExpansionOutcome.PrincipalNotFound)
                return last;
        }

        return last;
    }

    /// <summary>
    /// Notes one broad principal reached by one grant, deduplicated.
    /// </summary>
    private static void Note(
        string attribute,
        EffectiveGrant grant,
        string broadSid,
        IReadOnlyList<string> path,
        bool complete,
        List<PendingFinding> pending,
        HashSet<string> reported)
    {
        // One finding per broad principal reached, not per attribute. Where an administrator used
        // Set-LapsADReadPasswordPermission the same principal holds an entry on each attribute, and
        // reporting the same exposure three times would treat one delegation as three problems.
        if (!reported.Add($"{grant.Trustee.Sid}|{broadSid}"))
            return;

        pending.Add(new PendingFinding(attribute, grant, broadSid, path, complete));
    }

    /// <summary>
    /// Builds the finding, once the object's overall completeness is known.
    /// </summary>
    private static Finding Build(
        ObjectAttributes subject, Guid objectGuid, PendingFinding p, bool complete)
    {
        var name =
            AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;

        var evidence = new LapsPasswordReaderEvidence(
            p.Grant.Trustee.Sid,
            p.Grant.Trustee.Name,
            p.BroadSid,
            p.Path,
            p.Attribute,
            p.Grant.Rights,
            p.Grant.Reach,
            p.Grant.InheritedFrom,
            complete);

        return new Finding(
            RuleId,
            RuleVersion,
            Severity.High,
            new FindingSubject(FindingSubjectKind.Account, name),
            objectGuid,
            subject.DistinguishedName,
            DnHelper.DnToFqdn(subject.DistinguishedName),
            LapsAttributes.ClassOf(subject),
            Detail(name, evidence),
            subject.Completeness,
            evidence);
    }

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
            : $"through {evidence.NestingDepth} nested group(s): "
                + string.Join(" -> ", evidence.MembershipPath);

        var reach = evidence.Reach is LapsGrantReach.EveryAttribute
            ? "The entry carries no object type, so it reaches every attribute on this object "
                + "rather than only the password - which is the blanket extended-rights grant "
                + "Microsoft warns about, because all LAPS password attributes are confidential."
            : $"The entry is scoped to {evidence.Attribute}.";

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
            + $"{evidence.BroadPrincipalSid}, a principal that is broad in every organisation, "
            + $"reached {route}. Reading it yields the machine's local administrator password, "
            + "which grants administrative control of the machine locally - with no domain "
            + $"authentication and nothing logged centrally. {reach} {scope} Cut the link in the "
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
