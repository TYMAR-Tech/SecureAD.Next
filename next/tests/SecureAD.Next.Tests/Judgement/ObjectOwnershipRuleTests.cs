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
    /// <b>This is the case the split exists for.</b> A protected object is one the directory
    /// repairs on a schedule, so non-administrative ownership of it means something different
    /// from the same condition on an ordinary object - and it is worth a different sentence at a
    /// different severity.
    /// </remarks>
    [Fact]
    public void AProtectedObjectIsReportedByTheHigherRuleOnly()
    {
        var subject = Group();

        var low = JudgeLow(subject, Person, subjectIsProtected: true);
        var high = JudgeHigh(subject, Person, subjectIsProtected: true);

        var finding = Assert.Single(high.Findings);
        Assert.Equal("SEC-032", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Empty(low.Findings);
        Assert.True(low.IsComplete);
    }

    /// <summary>
    /// SEC-032 tells the operator the finding may already have repaired itself; SEC-031 does not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This pins the correction made in <c>F-S45-7</c>.</b> The rule shipped saying the
    /// exposure was durable because <c>AdminSDHolder</c> leaves ownership alone. The lab showed
    /// SDProp restores the owner within the hour, so an operator who investigates may find it
    /// already back to <c>Domain Admins</c>.
    /// </para>
    /// <para>
    /// <b>Without this sentence the rule looks broken to the person acting on it</b> - they check,
    /// find nothing wrong, and trust the next finding less. The assertion is deliberately on the
    /// presence of the explanation rather than on exact wording, which is prose and will change.
    /// </para>
    /// </remarks>
    [Fact]
    public void OnlyTheProtectedRuleWarnsThatTheOwnerMayAlreadyHaveBeenRestored()
    {
        var protectedSubject = Group();
        var ordinarySubject = Group();

        var high = JudgeHigh(protectedSubject, Person, subjectIsProtected: true);
        var low = JudgeLow(ordinarySubject, Person, subjectIsProtected: false);

        var protectedDetail = Assert.Single(high.Findings).Detail;
        Assert.Contains("AdminSDHolder is not running", protectedDetail, StringComparison.Ordinal);
        Assert.Contains("restored by the time you look", protectedDetail, StringComparison.Ordinal);

        // SEC-031 covers objects nothing repairs on a schedule, so the same caveat there would be
        // false rather than merely redundant.
        Assert.DoesNotContain(
            "AdminSDHolder", Assert.Single(low.Findings).Detail, StringComparison.Ordinal);
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
    /// <para>
    /// <b>A correction to the predecessor, which recorded this as its own false positive:</b> <i>"An
    /// owner who is privileged only by transitive group membership will still fire a finding."</i>
    /// Reporting a domain administrator as a problem would train an operator to ignore the rule.
    /// </para>
    /// <para>
    /// <b>The fixture says accepted rather than merely protected, and on 2026-09-05 that stopped
    /// being the same statement.</b> Membership of an operator group also makes a principal
    /// protected, and under <c>0099</c> that is not an owner the product accepts. The case this
    /// test is about is membership of the control plane, so the fixture says so directly.
    /// </para>
    /// </remarks>
    [Fact]
    public void AnOwnerAdministrativeOnlyThroughMembershipIsNotReported()
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject,
            Context(subject, ProtectedGroup, OwnerProtection(ProtectedGroup, OwnerAcceptance.Accepted)));

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
    /// A heuristic alone cannot establish the applicable server's behavior.
    /// </summary>
    [Fact]
    public void AComputerInAHardenedForestWithoutAServerBaselineIsUnanswered()
    {
        var subject = Computer();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, Person, ProtectionFor(subject, isProtected: false), ownerRights: Hardened()));

        Assert.Empty(verdict.Findings);
        Assert.Contains(verdict.Unresolved, input => input.Reason == UnresolvedReason.OwnerServerBehaviorNotRecorded);
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
            verdict.Unresolved, u => u.Reason == UnresolvedReason.OwnerHeuristicNotRead);
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

    // ---- P-140: the rules consume the corrected predicate ----

    /// <summary>
    /// An operator group outside the control plane, owning an ordinary object, raises SEC-031.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The closure marks it protected, which is true and is not the question.</b> AdminSDHolder
    /// really does repair Backup Operators, so a real forest hands this rule a
    /// <c>Protected</c> fact about the owner. <c>0099</c> excludes it from the control plane all
    /// the same, so its ownership of an object is a control edge worth reporting rather than
    /// routine administration to be hidden.
    /// </para>
    /// <para>
    /// <b>Downstream of <c>ObjectOwnershipReadingTests</c> and not a duplicate of it.</b> That file
    /// proves the predicate returns the right outcome; this proves the rule turns that outcome into
    /// a finding an operator actually sees, at the right severity, under the right identifier.
    /// A predicate that was fixed while the rule swallowed its answer would pass there and fail
    /// here.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("S-1-5-32-548")]
    [InlineData("S-1-5-32-549")]
    [InlineData("S-1-5-32-550")]
    [InlineData("S-1-5-32-551")]
    [InlineData("S-1-5-32-552")]
    public void AnOperatorGroupOwningAnOrdinaryObjectIsReported(string ownerSid)
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, ownerSid, OwnerProtection(ownerSid, OwnerAcceptance.NotAccepted)));

        var finding = Assert.Single(verdict.Findings);
        Assert.Equal("SEC-031", finding.RuleId);
        Assert.Equal(Severity.Low, finding.Severity);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// A principal that is still in the control plane, owning the same object, is not reported.
    /// </summary>
    /// <remarks>
    /// <b>The negative control for the row, and it is what stops the fix going too far.</b>
    /// <c>P-140</c> narrows what counts as an acceptable owner; narrowing it to nothing would put a
    /// finding on every object in the directory, since most of them are owned by
    /// <c>BUILTIN\Administrators</c> or <c>Domain Admins</c> by default. That failure would be far
    /// louder than the one being fixed, and no test of the operator groups alone would catch it.
    /// </remarks>
    [Theory]
    [InlineData(Administrators)]
    [InlineData(DomainAdmins)]
    public void AControlPlanePrincipalOwningAnOrdinaryObjectIsNotReported(string ownerSid)
    {
        var subject = Container();

        var verdict = new ObjectOwnedByNonAdministrator().Judge(
            subject, Context(subject, ownerSid, OwnerProtection(ownerSid, OwnerAcceptance.Accepted)));

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }

    /// <summary>
    /// Ownership and the control plane give compatible answers about the same security identifier.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The condition <c>P-140</c> exists to remove.</b> Two screens answering
    /// <i>is this principal administrative</i> two ways about one SID sends an operator looking for
    /// a defect in the product rather than in the directory. An owner the ownership rule stays
    /// silent about must be a principal <c>0099</c> puts in the control plane, and an owner it
    /// reports must be one <c>0099</c> leaves out.
    /// </para>
    /// <para>
    /// <b>What this does not cover, stated because the check would otherwise read as more than it
    /// is.</b> Control-edge expectedness is not built - <c>ControlEdge</c> does not exist and stage
    /// 6 has not started - so the control-plane side of this comparison is the set written here
    /// from <c>0099</c> rather than the catalogue the product will actually consult. That makes
    /// this an internal agreement anchored to a set this repository wrote, which is the
    /// <c>F-S44-2</c> shape and is not evidence that either side matches Microsoft. It is retargeted
    /// at the real catalogue when stage 6 lands; the row carrying that is on the punch list.
    /// </para>
    /// <para>
    /// <b>Deliberately restricted to the entries whose authority scope is unrestricted.</b> Schema
    /// Admins is in the control plane for the schema partition only, so whether it is an acceptable
    /// owner depends on which object it owns - a question <c>P-140</c> does not settle and this
    /// test must not pretend to.
    /// </para>
    /// </remarks>
    [Fact]
    public void OwnershipAndTheControlPlaneClassifyTheSameIdentifierCompatibly()
    {
        // 0099, the entries with an unrestricted authority scope within their own domain, plus
        // Enterprise Admins which is unrestricted forest-wide.
        string[] inTheControlPlane =
        [
            Administrators,
            DomainAdmins,
            "S-1-5-21-1004336348-1177238915-682003330-500",
            "S-1-5-21-1004336348-1177238915-682003330-519",
        ];

        // 0099, "everything else is out, and out does not mean safe".
        string[] outsideTheControlPlane =
        [
            "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552",
        ];

        foreach (var sid in inTheControlPlane.Concat(outsideTheControlPlane))
        {
            var classification = PrincipalClassificationRegistry.For(sid);
            var controlPlane = classification.ControlPlaneScope is PrincipalAuthorityScope.Domain or PrincipalAuthorityScope.Forest;
            Assert.Equal(inTheControlPlane.Contains(sid), controlPlane);
            var subject = Container();
            var verdict = new ObjectOwnedByNonAdministrator().Judge(
                subject, Context(subject, sid, OwnerProtection(sid, AcceptanceFromCatalogue(sid))));
            Assert.Equal(controlPlane ? 0 : 1, verdict.Findings.Count);
        }
    }

    /// <summary>
    /// The acceptance answer the shipped catalogue gives for one identifier.
    /// </summary>
    /// <remarks>
    /// <b>Taken from <c>ProtectedGroupCatalogue</c> rather than written into the test, which is
    /// what stops this checking its own homework.</b> If the accepted set were widened to include
    /// an operator group, the input to this test would flip to <c>Accepted</c>, the rule would fall
    /// silent, and the assertion against the <c>0099</c> list above would fail - which is the
    /// change to the product this test exists to notice. Handing the acceptance in directly would
    /// only prove that a fixture value reaches the rule.
    /// </remarks>
    private static OwnerAcceptance AcceptanceFromCatalogue(string sid)
    {
        var separator = sid.LastIndexOf('-');
        return separator > 0
            && int.TryParse(sid[(separator + 1)..], out var rid)
            && ProtectedGroupCatalogue.AcceptedOwnerRids.Contains(rid)
                ? OwnerAcceptance.Accepted
                : OwnerAcceptance.NotAccepted;
    }

    [Theory]
    [InlineData(true, false, 0, 0)]
    [InlineData(false, false, 1, 0)]
    [InlineData(false, true, 0, 1)]
    public void SchemaAcceptanceReachesBothOwnershipRulesWithoutWideningTheirScope(
        bool inSchema, bool protectedTarget, int lowFindings, int highFindings)
    {
        const string ownerSid = "S-1-5-21-1004336348-1177238915-682003330-518";
        var subject = protectedTarget ? Group() : Container();
        if (inSchema)
            subject = subject with { DistinguishedName = "CN=Example,CN=Schema,CN=Configuration,"
                + string.Join(',', Forest.Split('.').Select(label => "DC=" + label)) };
        var protection = OwnerProtection(ownerSid, OwnerAcceptance.SchemaOnly);
        protection = protection with
        {
            Principals = [.. protection.Principals, .. ProtectionFor(subject, protectedTarget).Principals],
        };
        var context = Context(subject, ownerSid, protection) with { ForestFqdn = Forest };
        var low = new ObjectOwnedByNonAdministrator().Judge(subject, context);
        var high = new ProtectedObjectOwnedByNonAdministrator().Judge(subject, context);
        Assert.True(low.IsComplete);
        Assert.True(high.IsComplete);
        Assert.Equal(lowFindings, low.Findings.Count);
        Assert.Equal(highFindings, high.Findings.Count);
    }

    [Theory]
    [InlineData(0x10, 0, 0)]
    [InlineData(0x40000, 0, 1)]
    [InlineData(0x10, 8, 1)]
    public void OwnerRightsQualificationReachesThePublicRule(int mask, byte propagation, int expectedFindings)
    {
        var subject = Container();
        var verdict = new ObjectOwnedByNonAdministrator().Judge(subject,
            Context(subject, Person, ProtectionFor(subject, false), entries: [Entry(OwnerRights, mask) with { PropagationFlags = propagation }]));
        Assert.Equal(expectedFindings, verdict.Findings.Count);
    }

    [Fact]
    public void MissingOwnerAcceptanceFactIsNotNegativeMembershipEvidence()
    {
        var subject = Container();
        var context = Context(subject, Person, Protection()) with { ProtectedPrincipals = Protection() };
        var verdict = new ObjectOwnedByNonAdministrator().Judge(subject, context);
        Assert.Contains(verdict.Unresolved, item => item.Reason == UnresolvedReason.NotDerived);
    }

    [Fact]
    public void AComputerDerivedClassCannotBypassTheMissingServerBaseline()
    {
        var subject = Computer();
        subject = subject with { Attributes = subject.Attributes.Select(attribute => attribute.LdapDisplayName == "objectClass"
            ? attribute with { Values = [.. attribute.Values, new(3, "customComputerClass", null)] } : attribute).ToArray() };
        var verdict = new ObjectOwnedByNonAdministrator().Judge(subject, Context(subject, Person, ProtectionFor(subject, false)));
        Assert.Contains(verdict.Unresolved, item => item.Reason == UnresolvedReason.OwnerServerBehaviorNotRecorded);
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
            ProtectedPrincipals = protection.Lookup(ownerSid, Sid.IsBuiltinDomain(ownerSid) ? Forest : null) is not null ? protection
                : protection with { Principals = [.. protection.Principals, .. OwnerProtection(ownerSid, OwnerAcceptance.NotAccepted).Principals] },
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
                    [],
                    // Says nothing about ownership. This fixture answers the subject-side question
                    // - is the judged object itself protected - and acceptance is about owners.
                    OwnerAcceptance.NotAccepted)),
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

    /// <summary>
    /// A closure that answers about an <i>owner</i>, saying protection and acceptance separately.
    /// </summary>
    /// <remarks>
    /// <b>Two answers because they are two questions, which is <c>0101</c> in a test fixture.</b>
    /// Every principal here is <c>Protected</c> - AdminSDHolder really does repair all of them,
    /// operator groups included - and only some are accepted owners. A fixture that derived one
    /// from the other could not express the case <c>P-140</c> is about, and these tests would pass
    /// against the defect they exist to catch.
    /// Built-in owners carry the object's domain: without that scope the rule's lookup misses
    /// this fact, so changing its acceptance would change nothing the test observes.
    /// </remarks>
    private static StoredProtectedPrincipalDerivation OwnerProtection(
        string ownerSid, OwnerAcceptance acceptance) =>
        new(
            1,
            Mask(),
            [],
            [
                new StoredProtectedPrincipalFact(
                    1,
                    ownerSid,
                    Sid.IsBuiltinDomain(ownerSid) ? Forest : null,
                    ProtectedPrincipalEvaluation.Protected,
                    null,
                    ProtectionUnknownReason.None,
                    [],
                    acceptance),
            ],
            ProtectionUnknownReason.None);

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
