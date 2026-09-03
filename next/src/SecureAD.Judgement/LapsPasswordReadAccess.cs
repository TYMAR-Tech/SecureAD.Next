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

        var findings = new List<Finding>();
        var unresolved = new List<UnresolvedInput>();
        var reported = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var attribute in attributes)
        {
            foreach (var grant in EffectiveGrants(permissions, attribute.Guid!))
            {
                Report(
                    subject, objectGuid, expand, attribute.Name, grant, findings, unresolved,
                    reported);
            }
        }

        // Findings and an unresolved input are not exclusive: one trustee may expand cleanly while
        // another is a principal from a trusted forest this bundle never captured. Reporting what
        // was found while saying what could not be reached is the honest pair.
        return unresolved.Count > 0 && findings.Count == 0
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
    /// Expands one grant and records a finding for every broad principal it reaches.
    /// </summary>
    private static void Report(
        ObjectAttributes subject,
        Guid objectGuid,
        Func<string, string, PrincipalExpansion> expand,
        string attribute,
        EffectiveGrant grant,
        List<Finding> findings,
        List<UnresolvedInput> unresolved,
        HashSet<string> reported)
    {
        // A CONTROL_ACCESS-only grant is a fact and not a finding, per the owner's decision: it is
        // sensitive, and on its own it does not yield the password.
        if (grant.Rights is not LapsReadRights.Both)
            return;

        var scope = grant.Trustee.DomainFqdn ?? string.Empty;
        var expansion = expand(grant.Trustee.Sid, scope);

        // A principal from a trusted external forest is not in this bundle, so nothing can be said
        // about what is inside it. Not found is not "not broad".
        if (expansion.Outcome is PrincipalExpansionOutcome.PrincipalNotFound)
        {
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.NotDerived));
        }
        else if (expansion.Outcome is PrincipalExpansionOutcome.StoppedAtBudget)
        {
            // Everything found is genuinely inside; the absence of anything else is not a fact. The
            // findings below are still reported, and each records that the walk thinned out.
            unresolved.Add(new UnresolvedInput(
                DerivedFactKind.PrincipalExpansion, UnresolvedReason.MembershipIncomplete));
        }

        // The delegated principal may itself be broad, which the expansion does not cover because it
        // returns what is *inside*. A direct grant to Authenticated Users is the plainest form of
        // this finding and would otherwise be the one case missed.
        if (BroadPrincipalCatalogue.IsBroad(grant.Trustee.Sid))
        {
            Add(subject, objectGuid, attribute, grant, grant.Trustee.Sid, [grant.Trustee.Sid],
                expansion.IsComplete, findings, reported);
        }

        foreach (var member in expansion.BroadMembers)
        {
            Add(subject, objectGuid, attribute, grant, member.Sid, member.PathFromRoot,
                expansion.IsComplete && member.IsComplete, findings, reported);
        }
    }

    private static void Add(
        ObjectAttributes subject,
        Guid objectGuid,
        string attribute,
        EffectiveGrant grant,
        string broadSid,
        IReadOnlyList<string> path,
        bool complete,
        List<Finding> findings,
        HashSet<string> reported)
    {
        // One finding per broad principal reached, not per attribute. Where an administrator used
        // Set-LapsADReadPasswordPermission the same principal holds an entry on each attribute, and
        // reporting the same exposure three times would treat one delegation as three problems.
        if (!reported.Add($"{grant.Trustee.Sid}|{broadSid}"))
            return;

            var name =
                AttributeReading.Text(subject, "sAMAccountName") ?? subject.DistinguishedName;

        var evidence = new LapsPasswordReaderEvidence(
            grant.Trustee.Sid,
            grant.Trustee.Name,
            broadSid,
            path,
            attribute,
            grant.Rights,
            grant.Reach,
            grant.InheritedFrom,
            complete);

        findings.Add(new Finding(
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
            evidence));
    }

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

        var thinned = evidence.IsComplete
            ? string.Empty
            : " The membership walk did not reach everything nested inside the delegated "
                + "principal, so further broad principals may also be inside and are not listed.";

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
