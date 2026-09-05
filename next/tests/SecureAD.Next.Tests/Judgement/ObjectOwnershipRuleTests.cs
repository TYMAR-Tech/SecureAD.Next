using System.Security.Principal;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-031 and SEC-032 - an object owned by somebody who is not an administrator.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both rules are tested together because the thing most worth proving is about the pair.</b>
/// They cover disjoint sets: every object is reported by exactly one of them, or by neither. If that
/// ever stopped being true an operator would see one problem twice at two severities and have to
/// work out they were the same thing, and no test of either rule alone would notice.
/// </para>
/// <para>
/// <b>The claim these rules make is that an owner can rewrite an object's permissions.</b> Three
/// things make that false - an <c>OWNER RIGHTS</c> entry, the forest's owner-rights hardening, and
/// an owner who is administrative after all - and each has a control here.
/// </para>
/// </remarks>
public sealed class ObjectOwnershipRuleTests
{
    private const string Forest = "contoso.com";
    private const string Ou = "OU=Finance,DC=contoso,DC=com";

    private const string Administrators = "S-1-5-32-544";
    private const string DomainAdmins = "S-1-5-21-1004336348-1177238915-682003330-512";
    private const string Person = "S-1-5-21-1004336348-1177238915-682003330-1310";
    private const string ProtectedGroup = "S-1-5-21-1004336348-1177238915-682003330-1400";
    private const string OwnerRights = "S-1-3-4";

    private const int ReadProperty = 0x00000010;

    private static readonly DateTimeOffset Started =
        new(2026, 9, 5, 9, 0, 0, TimeSpan.Zero);

    // ---- the pair ----

    /// <summary>
    /// An ordinary object owned by a non-administrator is reported by SEC-031 alone.
    /// </summary>
    [Fact]
    public void AnOrdinaryObjectIsReportedByTheLowRuleOnly()
    {
        var subject = Container();

        var low = JudgeLow(subject, Person);
        var high = JudgeHigh(subject, Person);

        var finding = Assert.Single(low.Findings);
        Assert.Equal("SEC-031", finding.RuleId);
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Empty(high.Findings);
        Assert.True(high.IsComplete);
    }

    /// <summary>
    /// A protected object owned by a non-administrator is reported by SEC-032 alone.
    /// </summary>
    /// <remarks>
    /// <b>This is the case the split exists for.</b> Owning an object the directory protects is a
    /// route to privilege, not latent authority over one object, and it is worth a different
    /// sentence at a different severity.
    /// </remarks>
    [Fact]
    public void AProtectedObjectIsReportedByTheHighRuleOnly()
    {
        var subject = Group();

        var low = JudgeLow(subject, Person, subjectIsProtected: true);
        var high = JudgeHigh(subject, Person, subjectIsProtected: true);

        var finding = Assert.Single(high.Findings);
        Assert.Equal("SEC-032", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Empty(low.Findings);
        Assert.True(low.IsComplete);
    }

    /// <summary>
    /// Where the protection closure cannot say, neither rule reports.
    /// </summary>
    /// <remarks>
    /// A partial closure can make a protected object look unprotected, which would move it to the
    /// Low rule and understate it. Reporting it there would be worse than saying nothing.
    /// </remarks>
    [Fact]
    public void NeitherRuleReportsWhereProtectionCouldNotBeDetermined()
    {
        var subject = Group();
        var protection = IncompleteProtection();

        var low = new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, Person, protection));
        var high = new ProtectedObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, Person, protection));

        Assert.Empty(low.Findings);
        Assert.Empty(high.Findings);
        Assert.False(low.IsComplete);
        Assert.False(high.IsComplete);
    }

    // ---- what counts as administrative ----

    /// <summary>An object owned by the Administrators group is not reported.</summary>
    [Fact]
    public void AnObjectOwnedByAdministratorsIsNotReported()
    {
        var verdict = JudgeLow(Container(), Administrators);

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// AdminSDHolder owned by Domain Admins is not reported, which is the documented exception.
    /// </summary>
    [Fact]
    public void AdminSdHolderOwnedByDomainAdminsIsNotReported()
    {
        var verdict = JudgeLow(Container(), DomainAdmins);

        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// An owner who is administrative only through group membership is not reported.
    /// </summary>
    /// <remarks>
    /// <b>A correction to the predecessor, which recorded this as its own false positive:</b> <i>"An
    /// owner who is privileged only by transitive group membership will still fire a finding."</i>
    /// Reporting a domain administrator as a problem would train an operator to ignore the rule.
    /// </remarks>
    [Fact]
    public void AnOwnerAdministrativeOnlyThroughMembershipIsNotReported()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, ProtectedGroup, Protection((ProtectedGroup, true))));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    // ---- when the owner cannot actually rewrite the list ----

    /// <summary>
    /// An object carrying an <c>OWNER RIGHTS</c> entry is not reported.
    /// </summary>
    /// <remarks>
    /// Microsoft: where such an entry is applied, the system ignores the implicit
    /// <c>READ_CONTROL</c> and <c>WRITE_DAC</c> for the object owner. The rule looks entirely
    /// correct without this control, and reports a capability that does not exist.
    /// </remarks>
    [Fact]
    public void AnObjectCarryingOwnerRightsIsNotReported()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(
                subject,
                Person,
                ProtectionFor(subject, isProtected: false),
                entries: [Entry(OwnerRights, ReadProperty)]));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// A computer object in a forest that has blocked implicit owner rights is not reported.
    /// </summary>
    [Fact]
    public void AComputerInAHardenedForestIsNotReported()
    {
        var subject = Computer();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, Person, ProtectionFor(subject, isProtected: false), ownerRights: Hardened()));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// The same forest, the same owner, on an object that is not a computer - and here it <b>is</b>
    /// reported.
    /// </summary>
    /// <remarks>
    /// <b>The control that keeps the hardening from silencing the rule across the directory.</b>
    /// MS-ADTS 6.1.3.4 scopes the block to computer objects. Read as a general switch, a forest
    /// that set it would have hidden non-administrative ownership of every organizational unit,
    /// group, user and certificate template - which is most of what this rule is worth having on.
    /// </remarks>
    [Fact]
    public void ANonComputerInAHardenedForestIsStillReported()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, Person, ProtectionFor(subject, isProtected: false), ownerRights: Hardened()));

        Assert.Single(verdict.Findings);
    }

    /// <summary>
    /// A computer whose forest setting was never read is refused rather than answered.
    /// </summary>
    [Fact]
    public void AComputerIsRefusedWhereTheForestSettingWasNeverRead()
    {
        var subject = Computer();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, Person, ProtectionFor(subject, isProtected: false)) with { OwnerImplicitRights = null });

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains(
            verdict.Unresolved, u => u.Reason == UnresolvedReason.ForestMaskUnknown);
    }

    // ---- the state of the owning account ----

    /// <summary>
    /// An object owned by an account that no longer exists is reported, and said to be orphaned.
    /// </summary>
    /// <remarks>
    /// <b>The opposite of SEC-060's handling of the same outcome, and deliberately so.</b> A grant
    /// to a deleted account reaches nobody and is not worth reporting. An object owned by one is
    /// orphaned: nobody can be asked to hand ownership over.
    /// </remarks>
    [Fact]
    public void AnObjectOwnedByADeletedAccountIsReportedAsOrphaned()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, Person, ProtectionFor(subject, isProtected: false), expansionOutcome:
                PrincipalExpansionOutcome.PrincipalDoesNotExist));

        var evidence = Assert.IsType<ObjectOwnershipEvidence>(
            Assert.Single(verdict.Findings).Evidence);

        Assert.Equal(ObjectOwnerStanding.DoesNotExist, evidence.Standing);
        Assert.True(evidence.IsOrphaned);
    }

    /// <summary>
    /// A membership walk that stopped early is reported but does not vouch for itself.
    /// </summary>
    [Fact]
    public void ATruncatedMembershipWalkIsCarriedOnTheFinding()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, Person, ProtectionFor(subject, isProtected: false), expansionOutcome:
                PrincipalExpansionOutcome.StoppedAtBudget));

        var evidence = Assert.IsType<ObjectOwnershipEvidence>(
            Assert.Single(verdict.Findings).Evidence);

        Assert.False(evidence.IsComplete);
    }

    // ---- silences that are not answers ----

    /// <summary>A descriptor nobody read is refused.</summary>
    [Fact]
    public void AnUnreadableDescriptorIsRefused()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, Person, ProtectionFor(subject, isProtected: false)) with
            {
                Permissions = _ => Permissions(
                    DescriptorAvailability.Unreadable, owner: null, []),
            });

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    /// <summary>
    /// A descriptor that was read but carries no owner is refused, not passed.
    /// </summary>
    /// <remarks>
    /// <b>A correction to the predecessor, whose SEC-031 silently skipped these.</b> A missing owner
    /// on a descriptor that was read is not "the owner is fine" - it is a fact nobody has.
    /// </remarks>
    [Fact]
    public void ADescriptorWithNoOwnerIsRefused()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, Person, ProtectionFor(subject, isProtected: false)) with
            {
                Permissions = _ => Permissions(DescriptorAvailability.Read, owner: null, []),
            });

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
    }

    /// <summary>
    /// An organizational unit carries no security identifier, and that is an answer rather than a
    /// gap.
    /// </summary>
    /// <remarks>
    /// <b>Without this, both rules would refuse most of the directory.</b> AdminSDHolder protects
    /// principals by stamping their descriptors; an object that is not a principal cannot be in the
    /// protected set, so the absence of a SID settles the question rather than leaving it open.
    /// </remarks>
    [Fact]
    public void AnObjectWithNoSecurityIdentifierIsTreatedAsUnprotected()
    {
        var verdict = JudgeLow(Container(), Person);

        Assert.Single(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    // ---- fixtures ----

    private static RuleVerdict JudgeLow(
        ObjectAttributes subject, string ownerSid, bool subjectIsProtected = false) =>
        new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, ownerSid, ProtectionFor(subject, subjectIsProtected)));

    private static RuleVerdict JudgeHigh(
        ObjectAttributes subject, string ownerSid, bool subjectIsProtected = false) =>
        new ProtectedObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, ownerSid, ProtectionFor(subject, subjectIsProtected)));

    private static JudgingContext Context(
        ObjectAttributes subject,
        string ownerSid,
        StoredProtectedPrincipalDerivation protection,
        IReadOnlyList<PermissionEntry>? entries = null,
        OwnerImplicitRightsSetting? ownerRights = null,
        PrincipalExpansionOutcome expansionOutcome = PrincipalExpansionOutcome.Expanded) =>
        JudgingContext.At(Started) with
        {
            Permissions = _ => Permissions(
                DescriptorAvailability.Read,
                new PermissionTrustee(ownerSid, null, null, Forest, null, null, null),
                entries ?? []),
            ProtectedPrincipals = protection,
            MembersOfPrincipal = (sid, _) => new PrincipalExpansion(sid, expansionOutcome, []),
            OwnerImplicitRights = ownerRights ?? Unhardened(),
        };

    private static OwnerImplicitRightsSetting Unhardened() =>
        DirectoryHeuristics.OwnerImplicitRights(string.Empty);

    private static OwnerImplicitRightsSetting Hardened() =>
        DirectoryHeuristics.OwnerImplicitRights(
            new string('0', 9) + "1" + new string('0', 9) + "2" + new string('0', 8) + "1");

    /// <summary>
    /// A closure holding a <c>NotProtected</c> fact for every principal named.
    /// </summary>
    /// <remarks>
    /// <b>Built the way the derivation builds it, which matters.</b>
    /// <c>ProtectedPrincipalClosure.Derive</c> starts every principal it knows about at
    /// <c>NotProtected</c> and then marks the protected ones, so a real closure holds a fact for
    /// every SID in the forest. A fixture that held facts only for protected principals would make
    /// the rules refuse every ordinary computer and user, and the tests would then be measuring a
    /// closure no forest produces.
    /// </remarks>
    private static StoredProtectedPrincipalDerivation Protection(
        params (string Sid, bool IsProtected)[] facts) =>
        new(
            1,
            Mask(),
            [],
            [
                .. facts.Select((f, i) => new StoredProtectedPrincipalFact(
                    i + 1,
                    f.Sid,
                    null,
                    f.IsProtected
                        ? ProtectedPrincipalEvaluation.Protected
                        : ProtectedPrincipalEvaluation.NotProtected,
                    null,
                    ProtectionUnknownReason.None,
                    [])),
            ],
            ProtectionUnknownReason.None);

    /// <summary>
    /// A closure that answers about the subject itself, which is what decides the rule split.
    /// </summary>
    private static StoredProtectedPrincipalDerivation ProtectionFor(
        ObjectAttributes subject, bool isProtected) =>
        SidOf(subject) is { } sid
            ? Protection((sid, isProtected))
            : Protection();

    private static StoredProtectedPrincipalDerivation IncompleteProtection() =>
        new(1, Mask(), [], [], ProtectionUnknownReason.MembershipEvidenceIncomplete);

    private static AdminSdExclusionMask Mask() =>
        new([], HeuristicReadOutcome.DefaultedByAbsence, '0');

    /// <summary>A security identifier in the binary form the directory stores.</summary>
    private static byte[] BytesOf(string sid)
    {
        var identifier = new SecurityIdentifier(sid);
        var bytes = new byte[identifier.BinaryLength];
        identifier.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static string? SidOf(ObjectAttributes subject) =>
        subject.Attributes
            .Where(a => string.Equals(
                a.LdapDisplayName, "objectSid", StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => a.Values)
            .Select(v => v.Bytes is null ? null : Sid.ToText(v.Bytes))
            .FirstOrDefault(s => s is not null);

    private static ObjectPermissions Permissions(
        DescriptorAvailability availability,
        PermissionTrustee? owner,
        IReadOnlyList<PermissionEntry> entries) => new(
        Ou,
        availability,
        availability is DescriptorAvailability.Unreadable ? "access denied" : null,
        owner,
        availability is DescriptorAvailability.Read ? DaclState.Present : DaclState.Unreadable,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        entries,
        Errors: []);

    private static int _ordinal;

    private static PermissionEntry Entry(string sid, int mask) => new(
        _ordinal++,
        "AccessAllowed",
        new PermissionTrustee(sid, null, null, Forest, null, null, null),
        mask,
        ObjectTypeGuid: null,
        InheritedObjectTypeGuid: null,
        IsInherited: false,
        InheritanceFlags: 0,
        PropagationFlags: 0,
        HasObjectType: false,
        HasInheritedObjectType: false,
        ApplicationData: []);

    /// <summary>An organizational unit, which carries no security identifier.</summary>
    private static ObjectAttributes Container() => Subject("organizationalUnit", sid: null);

    /// <summary>A group, which does carry one and so can be in the protected set.</summary>
    private static ObjectAttributes Group() => Subject("group", ProtectedGroup);

    private static ObjectAttributes Computer() =>
        Subject("computer", "S-1-5-21-1004336348-1177238915-682003330-1500");

    private static ObjectAttributes Subject(string mostDerivedClass, string? sid)
    {
        var attributes = new List<ObjectAttribute>
        {
            new(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, mostDerivedClass, null),
                ]),
        };

        if (sid is not null)
        {
            // STORED AS BYTES, WHICH IS HOW THE DIRECTORY STORES IT. A fixture holding the text
            // form would pass against a rule that read the text form, and that rule would find
            // nothing in a real forest - which is exactly what happened, as F-S45-6 records.
            attributes.Add(new ObjectAttribute(
                "objectSid",
                AttributeCardinality.SingleValued,
                [new AttributeValue(0, null, BytesOf(sid))]));
        }

        return new ObjectAttributes(
            Ou,
            Guid.NewGuid(),
            Started,
            EvidenceCompleteness.Complete,
            attributes,
            Forest);
    }
}
