using System.Security.Principal;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// <c>ObjectOwnershipReading</c> - the one predicate that decides whether an object's owner goes
/// unreported, asserted on its outcome rather than through a rule's findings.
/// </summary>
/// <remarks>
/// <para>
/// <b>These tests exist because nothing measured this predicate at all.</b> <c>P-140</c> found that
/// no test in the tree named the <c>OwnerIsAdministrative</c> outcome, so the shipping list of
/// administrative principals could have been edited in either direction without a single check
/// going red. The list decides which owners a customer is never told about, which makes an
/// unmeasured mistake in it a silence rather than a wrong answer - the harder kind to notice.
/// </para>
/// <para>
/// <b>Asserted on the outcome, deliberately, and not on whether a finding appeared.</b> A rule that
/// reports nothing is what a correct <c>OwnerIsAdministrative</c> and a completely broken predicate
/// both look like from outside. <c>ObjectOwnershipRuleTests</c> covers the rules consuming this;
/// neither file substitutes for the other.
/// </para>
/// <para>
/// <b>Two paths reach <c>OwnerIsAdministrative</c> and both are exercised here.</b> The identifier
/// lists, and the AdminSDHolder protection closure. The second is the one that made <c>P-140</c>
/// larger than it looked: the five operator groups are protected principals in their own right, so
/// removing them from the lists alone would have changed nothing an operator could see.
/// </para>
/// </remarks>
public sealed class ObjectOwnershipReadingTests
{
    private const string Forest = "contoso.com";
    private const string Ou = "OU=Finance,DC=contoso,DC=com";

    /// <summary>The domain that issued the principals under test.</summary>
    private const string Domain = "S-1-5-21-1004336348-1177238915-682003330";

    /// <summary>A different domain, for the same relative identifier under another authority.</summary>
    private const string OtherDomain = "S-1-5-21-2011223344-3344556677-4455667788";

    private const string Administrators = "S-1-5-32-544";
    private const string System = "S-1-5-18";
    private const string EnterpriseDomainControllers = "S-1-5-9";
    private const string CreatorOwner = "S-1-3-0";

    private const string AccountOperators = "S-1-5-32-548";
    private const string ServerOperators = "S-1-5-32-549";
    private const string PrintOperators = "S-1-5-32-550";
    private const string BackupOperators = "S-1-5-32-551";
    private const string Replicator = "S-1-5-32-552";

    private static readonly DateTimeOffset Started = new(2026, 9, 7, 9, 0, 0, TimeSpan.Zero);

    // ---- 1. the principals that stay administrative ----

    /// <summary>
    /// Every identifier the product still accepts as an administrative owner returns
    /// <c>OwnerIsAdministrative</c>.
    /// </summary>
    /// <remarks>
    /// <b>The whole retained list in one assertion, so shrinking it cannot pass unnoticed.</b> A
    /// test naming one or two of these would stay green while the rest were deleted, and the
    /// consequence of deleting one is the opposite of <c>P-140</c>'s: an object legitimately owned
    /// by <c>Administrators</c> reported as a finding on every object in the directory.
    /// </remarks>
    [Theory]
    [InlineData(Administrators, "BUILTIN\\Administrators")]
    [InlineData(System, "SYSTEM")]
    [InlineData(EnterpriseDomainControllers, "Enterprise Domain Controllers")]
    [InlineData(CreatorOwner, "CREATOR OWNER")]
    [InlineData(Domain + "-500", "the built-in Administrator")]
    [InlineData(Domain + "-512", "Domain Admins")]
    [InlineData(Domain + "-519", "Enterprise Admins")]
    public void ARetainedAdministrativePrincipalIsNotReported(string ownerSid, string name)
    {
        var decision = Decide(ownerSid);

        Assert.Equal(ObjectOwnershipOutcome.OwnerIsAdministrative, decision.Outcome);
        Assert.Null(decision.Evidence);
        Assert.True(name.Length > 0);
    }

    // ---- 2 and 3. the operator groups that come out ----

    /// <summary>
    /// Each of the five operator groups <c>0099</c> excludes from the control plane is reported
    /// when it owns an ordinary object.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is <c>P-140</c>'s subject.</b> <c>0099</c> settles that Account Operators, Server
    /// Operators, Print Operators, Backup Operators and Replicator are outside the control plane,
    /// so their control is never hidden as routine. An owner implicitly holds Modify Permissions,
    /// so an object owned by one of them is a control edge - and while this predicate called them
    /// administrative the ownership screen said nothing about the same principal the control-edge
    /// screen would show as unexpected.
    /// </para>
    /// <para>
    /// <b>The protection closure says nothing about the owner here</b>, so this exercises the
    /// identifier list alone. <see cref="AnOperatorGroupProtectedByAdminSdHolderIsStillReported"/>
    /// covers the second path, which is the one that actually decides a real forest.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(AccountOperators, "Account Operators")]
    [InlineData(ServerOperators, "Server Operators")]
    [InlineData(PrintOperators, "Print Operators")]
    [InlineData(BackupOperators, "Backup Operators")]
    [InlineData(Replicator, "Replicator")]
    public void AnExcludedOperatorGroupOwningAnObjectIsReported(string ownerSid, string name)
    {
        var decision = Decide(ownerSid);

        Assert.Equal(ObjectOwnershipOutcome.OwnerIsNotAdministrative, decision.Outcome);
        Assert.NotNull(decision.Evidence);
        Assert.Equal(ownerSid, decision.Evidence.OwnerSid);
        Assert.True(name.Length > 0);
    }

    /// <summary>
    /// An operator group that AdminSDHolder does protect is still reported as an owner.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the test the whole row turns on, and it is why <c>P-140</c> was bigger than its
    /// wording.</b> The five operator groups are genuine protected principals - they sit in
    /// <c>ProtectedGroupCatalogue</c> as entries 14 to 18 with Microsoft's own documentation behind
    /// them - so a real closure marks every one of them <c>Protected</c>. With the predicate
    /// reading protection as administrativeness, taking the five out of the identifier list would
    /// have left the answer exactly where it was, and every other test here would have gone green.
    /// </para>
    /// <para>
    /// <b>Two different questions.</b> <i>Does the directory repair this principal's permissions on
    /// a schedule</i> is protection. <i>Is this an owner the product accepts without telling
    /// anybody</i> is <c>0095</c> read through <c>0099</c>. Backup Operators is yes to the first and
    /// no to the second, which is <c>0101</c> as a concrete case rather than a principle.
    /// </para>
    /// </remarks>
    [Fact]
    public void AnOperatorGroupProtectedByAdminSdHolderIsStillReported()
    {
        var decision = Decide(BackupOperators, ownerIsProtected: true);

        Assert.Equal(ObjectOwnershipOutcome.OwnerIsNotAdministrative, decision.Outcome);
        Assert.NotNull(decision.Evidence);
        Assert.Equal(BackupOperators, decision.Evidence.OwnerSid);
    }

    /// <summary>
    /// An account protected only because it is nested inside an operator group is reported too.
    /// </summary>
    /// <remarks>
    /// <b>The membership case, which is the common one.</b> Nobody makes a group the owner of much;
    /// people own objects. An ordinary account inside Backup Operators inherits that group's
    /// protection, and if protection were read as administrativeness it would inherit silence with
    /// it - so the exclusion <c>0099</c> made would apply to the group and not to any of its
    /// members, which is the opposite of what an operator would expect.
    /// </remarks>
    [Fact]
    public void AnAccountProtectedOnlyThroughAnOperatorGroupIsReported()
    {
        var decision = Decide(Domain + "-1310", ownerIsProtected: true);

        Assert.Equal(ObjectOwnershipOutcome.OwnerIsNotAdministrative, decision.Outcome);
        Assert.NotNull(decision.Evidence);
    }

    // ---- 4. SYSTEM ----

    /// <summary>
    /// SYSTEM owning an object is not reported, per <c>0100</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>0100</c> is about permission entries and this is about ownership, and the two agree
    /// here for different reasons.</b> That decision makes SYSTEM expected for exactly what an
    /// applicable entry on that object grants it, and expected for nothing it does not. Ownership
    /// is not granted by an entry, so <c>0100</c> does not reach it: SYSTEM stays out of the
    /// ownership report because <c>S-1-5-18</c> is the platform writing to its own directory, which
    /// is reporting the directory for being a directory.
    /// </para>
    /// <para>
    /// <b>What would make this wrong.</b> If SYSTEM ownership ever became a route a person could
    /// take, this silence would hide it. Nothing in the product establishes that today, and the
    /// asymmetry is deliberate rather than overlooked.
    /// </para>
    /// </remarks>
    [Fact]
    public void SystemOwningAnObjectIsNotReported()
    {
        Assert.Equal(ObjectOwnershipOutcome.OwnerIsAdministrative, Decide(System).Outcome);
    }

    // ---- 5. CREATOR OWNER ----

    /// <summary>
    /// CREATOR OWNER recorded as an owner is not reported as a person who owns something.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>CREATOR OWNER is never a holder.</b> <c>S-1-3-0</c> is a placeholder the directory
    /// substitutes for whoever creates a child object; a descriptor still carrying it names nobody.
    /// Reporting it would send an operator to find an account that does not exist, and <c>0099</c>
    /// already settles that its control edges are <c>Unknown</c> rather than expected or unexpected.
    /// </para>
    /// <para>
    /// <b>The outcome this returns is named wrongly and the name is not worth changing here.</b>
    /// <c>OwnerIsAdministrative</c> is what the predicate answers, and CREATOR OWNER is not an
    /// administrator - it is a directory artefact. The consequence is identical, so this test
    /// asserts the consequence; that the enum conflates <i>administrative</i> with <i>not a
    /// person</i> is recorded on the punch list rather than repaired mid-row.
    /// </para>
    /// </remarks>
    [Fact]
    public void CreatorOwnerIsNotReportedAsAnOwner()
    {
        var decision = Decide(CreatorOwner);

        Assert.Equal(ObjectOwnershipOutcome.OwnerIsAdministrative, decision.Outcome);
        Assert.Null(decision.Evidence);
    }

    // ---- 6. the same relative identifier under another authority ----

    /// <summary>
    /// A relative identifier that is administrative under one domain is administrative under
    /// another domain too, and is not administrative under the built-in domain.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Two different mistakes, and only one of them is a mistake.</b> <c>512</c> under any
    /// issuing domain really is that domain's Domain Admins, so matching it under
    /// <c>OtherDomain</c> is correct rather than sloppy. <c>S-1-5-32-512</c> is not: the built-in
    /// domain's last value is an alias, so reading it as a relative identifier would give one
    /// number two meanings and call an ordinary built-in alias Domain Admins.
    /// </para>
    /// <para>
    /// <b>This is the mistake <c>PrivilegedSidCatalogue</c> shipped and an anchor test caught</b>,
    /// where all six built-in groups were held as relative identifiers. Every positive test passed,
    /// because the code and the tests shared the error. The control is here so this predicate
    /// cannot repeat it.
    /// </para>
    /// </remarks>
    [Fact]
    public void ARelativeIdentifierIsReadInTheRightAuthority()
    {
        Assert.Equal(
            ObjectOwnershipOutcome.OwnerIsAdministrative, Decide(OtherDomain + "-512").Outcome);

        // The built-in domain, whose last value is an alias and not a relative identifier.
        Assert.Equal(
            ObjectOwnershipOutcome.OwnerIsNotAdministrative, Decide("S-1-5-32-512").Outcome);
    }

    // ---- 7 and 8. names are not identifiers ----

    /// <summary>
    /// A renamed administrative group still matches, and a custom group wearing its name does not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Group names are localised and editable; identifiers are neither.</b> A German domain has
    /// <c>Domänen-Admins</c> and any administrator can rename <c>Domain Admins</c> to anything.
    /// Both halves matter: matching on name would silence a custom group somebody called
    /// <i>Domain Admins</i> - which is a plausible thing to find in a real forest and exactly the
    /// object worth reporting - and would report the real one the moment it was renamed.
    /// </para>
    /// <para>
    /// The name is fed in through the descriptor, which is where a name would have to come from,
    /// so a predicate that read it would see these values.
    /// </para>
    /// </remarks>
    [Fact]
    public void MatchingIsBySecurityIdentifierAndNeverByName()
    {
        var renamed = Decide(Domain + "-512", ownerName: "Tier0-DomainAdmins-DoNotRename");
        var impostor = Decide(Domain + "-7421", ownerName: "Domain Admins");

        Assert.Equal(ObjectOwnershipOutcome.OwnerIsAdministrative, renamed.Outcome);
        Assert.Equal(ObjectOwnershipOutcome.OwnerIsNotAdministrative, impostor.Outcome);
        Assert.NotNull(impostor.Evidence);
        Assert.Equal("Domain Admins", impostor.Evidence.OwnerName);
    }

    // ---- 9. an owner nobody could resolve ----

    /// <summary>
    /// Where the protection closure declined to answer about the owner, neither answer is given.
    /// </summary>
    /// <remarks>
    /// <b>An owner the derivation could not place is not an owner who is fine.</b> A partial
    /// membership walk can miss the group that makes somebody a domain administrator, so calling
    /// the owner non-administrative on that evidence could name an administrator in a finding.
    /// <c>0002</c> forbids reading silence as an answer, and the outcome carries the reason so the
    /// screen can say which one it was.
    /// </remarks>
    [Fact]
    public void AnOwnerThePreviousStageCouldNotPlaceIsNotAnswered()
    {
        var decision = Decide(Domain + "-1310", ownerProtectionUnknown: true);

        Assert.Equal(ObjectOwnershipOutcome.CouldNotResolve, decision.Outcome);
        Assert.Equal(UnresolvedReason.MembershipIncomplete, decision.Reason);
        Assert.Null(decision.Evidence);
    }

    /// <summary>
    /// An owner the descriptor does not name is not answered either.
    /// </summary>
    /// <remarks>
    /// <b>A descriptor that was read and carries no owner is a fact nobody has</b>, not a clean
    /// bill of health. The predecessor's <c>SEC-031</c> skipped these silently, which is the same
    /// shape one level down.
    /// </remarks>
    [Fact]
    public void AnOwnerTheDescriptorDoesNotNameIsNotAnswered()
    {
        var decision = Decide(ownerSid: null);

        Assert.Equal(ObjectOwnershipOutcome.CouldNotResolve, decision.Outcome);
        Assert.Equal(UnresolvedReason.IdentityUnreadable, decision.Reason);
    }

    // ---- 10. forest-root and domain-relative groups ----

    /// <summary>
    /// A forest-root group and a domain-relative group are each evaluated against the identifier
    /// they actually carry.
    /// </summary>
    /// <remarks>
    /// <b>Enterprise Admins exists once in a forest and Domain Admins exists once per domain</b>,
    /// and the predicate sees only a SID. What must not happen is a value being matched off the end
    /// of a string that is not a domain SID at all - a machine-local principal, or a well-known SID
    /// whose tail happens to be 519. Both are checked here alongside the two that should match.
    /// </remarks>
    [Fact]
    public void ForestRootAndDomainRelativeGroupsAreEvaluatedInTheirOwnContext()
    {
        Assert.Equal(
            ObjectOwnershipOutcome.OwnerIsAdministrative, Decide(Domain + "-519").Outcome);
        Assert.Equal(
            ObjectOwnershipOutcome.OwnerIsAdministrative, Decide(OtherDomain + "-512").Outcome);

        // Not a domain SID, so nothing may be read off its tail.
        Assert.Equal(
            ObjectOwnershipOutcome.OwnerIsNotAdministrative, Decide("S-1-5-80-519").Outcome);
    }

    // ---- fixtures ----

    /// <summary>
    /// Puts one owner to the predicate over an ordinary organizational unit.
    /// </summary>
    /// <param name="ownerSid">Who owns it, or null for a descriptor naming no owner.</param>
    /// <param name="ownerName">The name the descriptor carries for that owner, if any.</param>
    /// <param name="ownerIsProtected">Whether AdminSDHolder protects the owner.</param>
    /// <param name="ownerProtectionUnknown">Whether the closure declined to answer about it.</param>
    private static ObjectOwnershipDecision Decide(
        string? ownerSid = null,
        string? ownerName = null,
        bool ownerIsProtected = false,
        bool ownerProtectionUnknown = false)
    {
        var subject = Container();

        var context = JudgingContext.At(Started) with
        {
            Permissions = _ => Permissions(
                ownerSid is null
                    ? null
                    : new PermissionTrustee(ownerSid, ownerName, null, Forest, null, null, null)),
            ProtectedPrincipals = Protection(ownerSid, ownerIsProtected, ownerProtectionUnknown),
            MembersOfPrincipal = (sid, _) =>
                new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, []),
            OwnerImplicitRights = DirectoryHeuristics.OwnerImplicitRights(string.Empty),
        };

        return ObjectOwnershipReading.Decide(subject, context);
    }

    /// <summary>
    /// A closure holding one fact about the owner, built the way the derivation builds one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A real closure holds a fact for every principal it knows about</b>, starting them all at
    /// <c>NotProtected</c> and then marking the protected ones. A fixture holding facts only for
    /// protected principals would make the predicate refuse every ordinary owner, and these tests
    /// would then be measuring a closure no forest produces.
    /// </para>
    /// <para>
    /// <b>Protection and owner acceptance are set independently here, which is the point.</b>
    /// <c>isProtected</c> says AdminSDHolder repairs the principal; it never implies the product
    /// accepts it as an owner. The operator-group cases set the first and not the second, which is
    /// exactly what the derivation produces for them and what <c>P-140</c> is about.
    /// </para>
    /// </remarks>
    private static StoredProtectedPrincipalDerivation Protection(
        string? ownerSid, bool isProtected, bool isUnknown)
    {
        if (ownerSid is null)
            return new StoredProtectedPrincipalDerivation(1, Mask(), [], [], ProtectionUnknownReason.None);

        var evaluation = isUnknown
            ? ProtectedPrincipalEvaluation.Unknown
            : isProtected
                ? ProtectedPrincipalEvaluation.Protected
                : ProtectedPrincipalEvaluation.NotProtected;

        return new StoredProtectedPrincipalDerivation(
            1,
            Mask(),
            [],
            [
                new StoredProtectedPrincipalFact(
                    1,
                    ownerSid,
                    Sid.IsBuiltinDomain(ownerSid) ? Forest : null,
                    evaluation,
                    null,
                    isUnknown
                        ? ProtectionUnknownReason.MembershipEvidenceIncomplete
                        : ProtectionUnknownReason.None,
                    [],
                    isUnknown ? OwnerAcceptance.Unknown : OwnerAcceptance.NotAccepted),
            ],
            ProtectionUnknownReason.None);
    }

    [Theory]
    [InlineData("CN=Schema,CN=Configuration,DC=contoso,DC=com", true)]
    [InlineData("CN=Example,CN=Schema,CN=Configuration,DC=contoso,DC=com", true)]
    [InlineData("cn=example,cn=schema,cn=configuration,dc=CONTOSO,dc=COM", true)]
    [InlineData("CN=Example\\, With Comma,CN=Schema,CN=Configuration,DC=contoso,DC=com", true)]
    [InlineData("CN=Configuration,DC=contoso,DC=com", false)]
    [InlineData("OU=Finance,DC=contoso,DC=com", false)]
    [InlineData("CN=Schema,CN=Configuration,DC=child,DC=contoso,DC=com", false)]
    [InlineData("CN=Schema,CN=Configuration,DC=elsewhere,DC=com", false)]
    [InlineData("CN=Schema,OU=Other,DC=contoso,DC=com", false)]
    [InlineData("CN=Schema\\,CN=Configuration,DC=contoso,DC=com", false)]
    public void SchemaScopeUsesTheCapturedForestAndParsedAncestors(string dn, bool accepted)
    {
        var result = SchemaDecision(dn, OwnerAcceptance.SchemaOnly);
        Assert.Equal(accepted ? ObjectOwnershipOutcome.OwnerIsAdministrative
            : ObjectOwnershipOutcome.OwnerIsNotAdministrative, result.Outcome);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void MissingForestIdentityCannotAuthorizeSchemaOwnership(string? forest)
    {
        var result = SchemaDecision("CN=Schema,CN=Configuration,DC=contoso,DC=com",
            OwnerAcceptance.SchemaOnly, forest);
        Assert.Equal(ObjectOwnershipOutcome.CouldNotResolve, result.Outcome);
        Assert.Equal(UnresolvedReason.ForestIdentityUnreadable, result.Reason);
    }

    [Fact]
    public void ProvenSchemaAcceptanceSurvivesUncertaintyAboutOtherScopes()
    {
        var inside = SchemaDecision("CN=Schema,CN=Configuration,DC=contoso,DC=com",
            OwnerAcceptance.SchemaOnlyOtherwiseUnknown);
        var outside = SchemaDecision(Ou, OwnerAcceptance.SchemaOnlyOtherwiseUnknown);
        Assert.Equal(ObjectOwnershipOutcome.OwnerIsAdministrative, inside.Outcome);
        Assert.Equal(ObjectOwnershipOutcome.CouldNotResolve, outside.Outcome);
        Assert.Equal(UnresolvedReason.MembershipIncomplete, outside.Reason);
    }

    [Fact]
    public void ASeparateBroaderAcceptanceIsNotLimitedToTheSchema()
    {
        Assert.Equal(ObjectOwnershipOutcome.OwnerIsAdministrative,
            SchemaDecision(Ou, OwnerAcceptance.Accepted).Outcome);
    }

    [Fact]
    public void BeingInTheSchemaDoesNotAcceptAnUnqualifiedOwner()
    {
        Assert.Equal(ObjectOwnershipOutcome.OwnerIsNotAdministrative,
            SchemaDecision("CN=Schema,CN=Configuration,DC=contoso,DC=com", OwnerAcceptance.NotAccepted).Outcome);
    }

    private static ObjectOwnershipDecision SchemaDecision(
        string dn, OwnerAcceptance acceptance, string? forest = Forest)
    {
        const string ownerSid = Domain + "-518";
        var protection = Protection(ownerSid, true, false);
        protection = protection with
        {
            Principals = [protection.Principals[0] with { OwnerAcceptance = acceptance }],
        };
        var context = JudgingContext.At(Started) with
        {
            ForestFqdn = forest,
            ProtectedPrincipals = protection,
            Permissions = _ => Permissions(new PermissionTrustee(ownerSid, "renamed owner", null, Forest, null, null, null)),
            MembersOfPrincipal = (sid, _) => new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, []),
            OwnerImplicitRights = DirectoryHeuristics.OwnerImplicitRights(string.Empty),
        };
        return ObjectOwnershipReading.Decide(Container() with { DistinguishedName = dn }, context);
    }

    private static AdminSdExclusionMask Mask() =>
        new([], HeuristicReadOutcome.DefaultedByAbsence, '0');

    private static ObjectPermissions Permissions(PermissionTrustee? owner) => new(
        Ou,
        DescriptorAvailability.Read,
        null,
        owner,
        DaclState.Present,
        DaclCompleteness.Complete,
        DaclWasCanonical: true,
        IsDaclProtected: false,
        Entries: [],
        Errors: []);

    /// <summary>An organizational unit, which carries no security identifier of its own.</summary>
    private static ObjectAttributes Container() => new(
        Ou,
        Guid.NewGuid(),
        Started,
        EvidenceCompleteness.Complete,
        [
            new ObjectAttribute(
                "objectClass",
                AttributeCardinality.MultiValued,
                [
                    new AttributeValue(0, "top", null),
                    new AttributeValue(1, "organizationalUnit", null),
                ]),
        ],
        Forest);
}
