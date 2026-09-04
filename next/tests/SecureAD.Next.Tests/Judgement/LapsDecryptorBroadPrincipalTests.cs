using System.Text;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.GroupPolicy;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-093 against the cases its specification names, and the two the code demands that the
/// specification does not.
/// </summary>
/// <remarks>
/// <para>
/// <b>The refusals are the point of half of these.</b> The rule reads two things that can each be
/// empty for opposite reasons - a policy's registry settings and a membership walk - and in both
/// cases <i>nobody looked</i> is indistinguishable from <i>nothing there</i> unless the outcome is
/// read beside the list. Gate 4 caught the first of those in the first version of this rule, which
/// reported an unreadable policy as one configuring no decryptor. Four tests here exist to fail if
/// that collapse ever returns.
/// </para>
/// <para>
/// <b>These drive the rule directly rather than through a bundle</b>, because what is under test is
/// the reading of a Group Policy value against a principal expansion, and both arrive through
/// <see cref="JudgingContext"/>. The one case that cannot be reached this way is the user-scope
/// setting, which <see cref="BundleReader"/> filters out before the rule ever sees it; that is
/// tested where the filter lives, in <c>BundleReaderTests</c>.
/// </para>
/// </remarks>
public sealed class LapsDecryptorBroadPrincipalTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 4, 9, 0, 0, TimeSpan.Zero);

    private const string PolicyDn =
        "CN={A1B2C3D4-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=ad,DC=lab";

    private const string PolicyName = "Workstation LAPS";
    private const string Forest = "ad.lab";

    /// <summary>
    /// Microsoft's documented LAPS Group Policy root, as <c>Registry.pol</c> stores it.
    /// </summary>
    /// <remarks>
    /// Verified against a real file rather than taken from the rule: see
    /// <c>TheKeyPathAWindowsLapsPolicyActuallyWritesIsMatched</c>, which reads the bytes a policy
    /// editor produced. An earlier version of these tests used a key path that existed nowhere but
    /// in the rule they were testing.
    /// </remarks>
    private const string LapsKey = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
    private const string DecryptorValue = "ADPasswordEncryptionPrincipal";

    private const string DomainUsers = "S-1-5-21-1-2-3-513";
    private const string AuthenticatedUsers = "S-1-5-11";
    private const string Everyone = "S-1-1-0";

    private const string WrapperGroup = "S-1-5-21-1-2-3-1105";
    private const string ScopedGroup = "S-1-5-21-1-2-3-1106";

    // -------------------------------------------------------------------------------------------
    // P1 - the value is a broad principal outright
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A policy naming a broad principal directly fires, and the route is the one step.
    /// </summary>
    /// <remarks>
    /// The plainest form of this finding. There is no membership to walk - the policy hands the
    /// password to Domain Users by naming it - so <c>NestingDepth</c> is zero and the wording says
    /// the principal is named by the policy directly rather than reached through anything.
    /// </remarks>
    [Fact]
    public void ADecryptorThatIsItselfABroadPrincipalIsReported()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, DomainUsers)],
            Expands(DomainUsers, [])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(DomainUsers, evidence.BroadPrincipalSid);
        Assert.Equal(DomainUsers, evidence.DecryptorSid);
        Assert.Equal(DomainUsers, evidence.ConfiguredValue);
        Assert.Equal(LapsDecryptorForm.SecurityIdentifier, evidence.Form);
        Assert.True(evidence.BroadPrincipalFound);
        Assert.Equal(0, evidence.NestingDepth);
        Assert.Equal(Severity.Critical, finding.Severity);
    }

    /// <summary>
    /// The subject of the finding is the policy, and never a machine.
    /// </summary>
    /// <remarks>
    /// <b>This is the rule's central refusal, and a test rather than a comment because it is the
    /// thing most likely to be "improved" later.</b> Microsoft states the authorized decryptor
    /// "can't be changed after a password is encrypted", so a stored password was encrypted against
    /// whatever the policy named at the time - a value the directory does not record. Naming
    /// machines would state a fact about the past that no evidence establishes.
    /// </remarks>
    [Fact]
    public void TheSubjectIsThePolicyAndCarriesNoSecurityIdentifier()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, DomainUsers)],
            Expands(DomainUsers, [])));

        Assert.Equal(FindingSubjectKind.Policy, finding.Subject.Kind);
        Assert.Contains(PolicyName, finding.Subject.Key, StringComparison.Ordinal);

        // The key is the policy's name and identifier - not the broad principal, the way SEC-090
        // keys its own, and not a computer.
        Assert.DoesNotContain(DomainUsers, finding.Subject.Key, StringComparison.Ordinal);
        Assert.Equal("groupPolicyContainer", finding.ObjectClass);
    }

    /// <summary>
    /// Every finding says that correcting the policy is not the whole fix.
    /// </summary>
    /// <remarks>
    /// The same Microsoft sentence that makes the subject a policy makes rotation part of the
    /// remediation: passwords already stored stay decryptable by the old principal until each is
    /// rotated, so an operator who edits the setting and stops has not finished.
    /// </remarks>
    [Fact]
    public void TheDetailSaysStoredPasswordsMustAlsoBeRotated()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, DomainUsers)],
            Expands(DomainUsers, [])));

        Assert.Contains("rotated", finding.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(DecryptorValue, finding.Detail, StringComparison.Ordinal);
    }

    // -------------------------------------------------------------------------------------------
    // P2 - a scoped group that reaches a broad principal by nesting
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A wrapper group with a broad principal nested inside it fires, and the finding shows the
    /// route that reached it.
    /// </summary>
    /// <remarks>
    /// <b>The wrapper group is Microsoft's own documented pattern and is not itself a finding.</b>
    /// Windows LAPS encrypts against exactly one principal, and the supported answer to needing
    /// more than one is "a wrapper group that has all the relevant security principals as members".
    /// What makes it a finding is what ended up inside, which is why the path is carried and not
    /// just the endpoints.
    /// </remarks>
    [Fact]
    public void ABroadPrincipalNestedInsideTheDecryptorIsReportedWithItsRoute()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, WrapperGroup)],
            Expands(WrapperGroup,
                [Member(AuthenticatedUsers, [WrapperGroup, ScopedGroup, AuthenticatedUsers])])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(AuthenticatedUsers, evidence.BroadPrincipalSid);
        Assert.Equal(WrapperGroup, evidence.DecryptorSid);
        Assert.Equal(2, evidence.NestingDepth);
        Assert.Equal(
            [WrapperGroup, ScopedGroup, AuthenticatedUsers],
            evidence.MembershipPath.Select(s => s.Sid));
    }

    /// <summary>
    /// Two routes to the same broad principal are one finding, by the shortest.
    /// </summary>
    /// <remarks>
    /// The shortest route is the link an operator would cut, and showing the longer chain would
    /// send him to the wrong one. SEC-090 keeps the shortest for the same reason.
    /// </remarks>
    [Fact]
    public void TwoRoutesToTheSameBroadPrincipalAreOneFindingByTheShortest()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, WrapperGroup)],
            Expands(WrapperGroup,
            [
                Member(AuthenticatedUsers, [WrapperGroup, ScopedGroup, AuthenticatedUsers]),
                Member(AuthenticatedUsers, [WrapperGroup, AuthenticatedUsers]),
            ])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(2, evidence.MembershipPath.Count);
        Assert.Equal(1, evidence.NestingDepth);
    }

    /// <summary>
    /// Two <i>different</i> broad principals inside one decryptor are two findings that share a
    /// subject, because both are routes into the same misconfigured policy.
    /// </summary>
    /// <remarks>
    /// <b>Deliberately unlike SEC-090.</b> That rule keys its subject on the broad principal so
    /// that accepting one route does not silence another. Here the thing an operator fixes is the
    /// policy, so the policy is the subject and both findings name it.
    /// </remarks>
    [Fact]
    public void TwoBroadPrincipalsInsideOneDecryptorBothNameThePolicy()
    {
        var findings = Judge(
            [Setting(LapsKey, DecryptorValue, WrapperGroup)],
            Expands(WrapperGroup,
            [
                Member(AuthenticatedUsers, [WrapperGroup, AuthenticatedUsers]),
                Member(Everyone, [WrapperGroup, ScopedGroup, Everyone]),
            ]));

        Assert.Equal(2, findings.Count);
        Assert.Single(findings.Select(f => f.Subject.Key).Distinct());

        // Ordered shortest route first, which is the one to cut.
        var first = Assert.IsType<LapsDecryptorEvidence>(findings[0].Evidence);
        Assert.Equal(AuthenticatedUsers, first.BroadPrincipalSid);
    }

    // -------------------------------------------------------------------------------------------
    // P3 - the value cannot be resolved
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A decryptor named as <c>DOMAIN\name</c> is reported as unresolvable rather than guessed at.
    /// </summary>
    /// <remarks>
    /// This product resolves principals by identifier: the capture reads objects, not the
    /// name-mapping a domain controller does. So a qualified name is reported as what it is.
    /// </remarks>
    [Fact]
    public void AQualifiedNameIsReportedAsUnresolvedWithoutBeingExpanded()
    {
        var expanded = false;

        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, @"AD\LAPSAdmins")],
            (sid, scope) =>
            {
                expanded = true;
                return new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, []);
            }));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.False(expanded);
        Assert.Equal(LapsDecryptorForm.QualifiedName, evidence.Form);
        Assert.Null(evidence.DecryptorSid);
        Assert.Null(evidence.BroadPrincipalSid);
        Assert.False(evidence.BroadPrincipalFound);
        Assert.False(evidence.IsComplete);
        Assert.Equal(@"AD\LAPSAdmins", evidence.ConfiguredValue);
    }

    /// <summary>
    /// A user principal name is likewise unresolvable, and is recorded as that form rather than
    /// collapsed into the qualified one.
    /// </summary>
    [Fact]
    public void AUserPrincipalNameIsReportedAsItsOwnForm()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, "lapsadmins@ad.lab")],
            Expands("lapsadmins@ad.lab", [])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(LapsDecryptorForm.UserPrincipalName, evidence.Form);
        Assert.Null(evidence.DecryptorSid);
    }

    /// <summary>
    /// A value shaped like an identifier that is not one is treated as a name, not as an identifier
    /// that failed to resolve.
    /// </summary>
    /// <remarks>
    /// <c>S-1-5-21-oops</c> starts like an identifier and is not one. The rule parses the value
    /// rather than checking its prefix, which is the stronger test.
    /// </remarks>
    [Fact]
    public void AValueShapedLikeAnIdentifierButUnparseableIsNotTreatedAsOne()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, "S-1-5-21-oops")],
            Expands("S-1-5-21-oops", [])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(LapsDecryptorForm.QualifiedName, evidence.Form);
    }

    /// <summary>
    /// An identifier no captured object carries is reported, naming the value.
    /// </summary>
    /// <remarks>
    /// <b>Reported rather than dropped, and it is not the same finding as a broad decryptor.</b>
    /// Microsoft records that when an invalid principal is named "a policy processing failure
    /// occurs and the managed account's password isn't backed up", which the lab confirmed on
    /// 2026-09-03 - events 10035 then 10017, and no stored password. Staying silent would leave an
    /// operator believing LAPS is working.
    /// </remarks>
    [Fact]
    public void ADecryptorNoObjectCarriesIsReportedAsUnresolved()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, ScopedGroup)],
            (sid, scope) => new PrincipalExpansion(
                sid, PrincipalExpansionOutcome.PrincipalNotFound, null)));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(LapsDecryptorForm.SecurityIdentifier, evidence.Form);
        Assert.Equal(ScopedGroup, evidence.ConfiguredValue);
        Assert.Null(evidence.BroadPrincipalSid);
        Assert.Contains("not backed up", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    // -------------------------------------------------------------------------------------------
    // N1, N2 - silence, where silence is a fact about the policy
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A scoped group with nothing broad inside it is silent.
    /// </summary>
    /// <remarks>
    /// <b>This negative control is the rule.</b> A version that reported every configured decryptor
    /// would satisfy every positive test above and would report a correctly configured estate,
    /// which is what <c>P-123</c> exists to stop: the product cannot know which principals an
    /// organisation intended, and the only judgement it may make is that a member is broad
    /// everywhere.
    /// </remarks>
    [Fact]
    public void AScopedDecryptorWithNothingBroadInsideIsSilent()
    {
        AssertSilent(
            [Setting(LapsKey, DecryptorValue, WrapperGroup)],
            Expands(WrapperGroup,
            [
                Member(ScopedGroup, [WrapperGroup, ScopedGroup]),
                Member("S-1-5-21-1-2-3-1200", [WrapperGroup, "S-1-5-21-1-2-3-1200"]),
            ]));
    }

    /// <summary>
    /// A policy that configures no decryptor at all is silent, where its files were read.
    /// </summary>
    /// <remarks>
    /// Microsoft: "If this setting isn't specified, only members of the Domain Admins group in the
    /// device's domain can decrypt the password." An unconfigured setting is the safe state.
    /// </remarks>
    [Fact]
    public void APolicyConfiguringNoDecryptorIsSilent()
    {
        AssertSilent([], Never());
    }

    /// <summary>
    /// A policy that configures other LAPS settings but no decryptor is silent.
    /// </summary>
    [Fact]
    public void APolicyConfiguringOtherLapsSettingsButNoDecryptorIsSilent()
    {
        AssertSilent(
            [
                Setting(LapsKey, "PasswordAgeDays", "30"),
                Setting(LapsKey, "PasswordComplexity", "4"),
            ],
            Never());
    }

    /// <summary>
    /// A decryptor value that is present but blank counts as unset.
    /// </summary>
    /// <remarks>
    /// Microsoft's default applies when the setting "isn't specified", and an empty string
    /// specifies nothing.
    /// </remarks>
    [Fact]
    public void ABlankDecryptorValueCountsAsUnset()
    {
        AssertSilent([Setting(LapsKey, DecryptorValue, "   ")], Never());
    }

    /// <summary>
    /// A setting of the same name under an unrelated key is not read as the LAPS decryptor.
    /// </summary>
    [Fact]
    public void TheSameValueNameUnderAnotherProductsKeyIsIgnored()
    {
        AssertSilent(
            [Setting(@"Software\Policies\Contoso\Backup", DecryptorValue, DomainUsers)],
            Never());
    }

    /// <summary>
    /// Where a policy sets the decryptor twice, the last one is the one a machine applies.
    /// </summary>
    [Fact]
    public void TheLastDecryptorValueStatedIsTheOneJudged()
    {
        AssertSilent(
            [
                Setting(LapsKey, DecryptorValue, DomainUsers),
                Setting(LapsKey, DecryptorValue, WrapperGroup),
            ],
            Expands(WrapperGroup, []));
    }

    /// <summary>
    /// An object that is not a Group Policy Object is not judged by this rule at all.
    /// </summary>
    [Fact]
    public void AnObjectThatIsNotAPolicyIsNotJudged()
    {
        var verdict = new LapsDecryptorBroadPrincipal().Judge(
            Object("CN=WS01,OU=Workstations,DC=ad,DC=lab", "computer"),
            Context([Setting(LapsKey, DecryptorValue, DomainUsers)], Expands(DomainUsers, [])));

        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.Unresolved);
    }

    // -------------------------------------------------------------------------------------------
    // The two refusals the specification does not list, which the code demands
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// A policy whose SYSVOL files could not be read refuses, rather than reporting that it
    /// configures no decryptor.
    /// </summary>
    /// <remarks>
    /// <b>Gate 4 caught this in the first version of the rule.</b> An empty settings list covers
    /// three different situations - a policy that configures nothing, a policy whose files were
    /// refused, and a bundle captured without SYSVOL - and reading the first for the others tells
    /// an operator a policy is harmless because nobody looked at it, which
    /// <c>docs/decisions/0002</c> forbids.
    /// </remarks>
    [Theory]
    [InlineData(GpoSettingsOutcome.Unreadable)]
    [InlineData(GpoSettingsOutcome.NotCaptured)]
    [InlineData(GpoSettingsOutcome.PartiallyRead)]
    public void APolicyWhoseSettingsWereNotFullyReadRefusesRatherThanStayingSilent(
        GpoSettingsOutcome outcome)
    {
        var verdict = Verdict([], Never(), outcome);

        Assert.Empty(verdict.Findings);
        var unresolved = Assert.Single(verdict.Unresolved);
        Assert.Equal(DerivedFactKind.PrincipalExpansion, unresolved.Kind);
    }

    /// <summary>
    /// A membership walk that stopped early and found nothing broad refuses, rather than reporting
    /// silence.
    /// </summary>
    /// <remarks>
    /// A walk that hit its budget can find no broad principal while one is still inside. Empty is
    /// not the same as safe unless the walk finished.
    /// </remarks>
    [Fact]
    public void ATruncatedExpansionFindingNothingRefusesRatherThanStayingSilent()
    {
        var verdict = Verdict(
            [Setting(LapsKey, DecryptorValue, WrapperGroup)],
            (sid, scope) => new PrincipalExpansion(
                sid, PrincipalExpansionOutcome.StoppedAtBudget,
                [Member(ScopedGroup, [WrapperGroup, ScopedGroup])]));

        Assert.Empty(verdict.Findings);
        Assert.Single(verdict.Unresolved);
    }

    /// <summary>
    /// A truncated walk that <i>did</i> find something broad reports it, and says the membership
    /// may be larger than shown.
    /// </summary>
    /// <remarks>
    /// The refusal above is about silence, not about incompleteness. What was found is still true,
    /// and <c>docs/decisions/0086</c> prefers a qualified statement to none.
    /// </remarks>
    [Fact]
    public void ATruncatedExpansionThatFoundSomethingBroadStillReportsIt()
    {
        var finding = Assert.Single(Judge(
            [Setting(LapsKey, DecryptorValue, WrapperGroup)],
            (sid, scope) => new PrincipalExpansion(
                sid, PrincipalExpansionOutcome.StoppedAtBudget,
                [Member(Everyone, [WrapperGroup, Everyone])])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(Everyone, evidence.BroadPrincipalSid);
        Assert.False(evidence.ExpansionWasComplete);
        Assert.False(evidence.IsComplete);
        Assert.Contains("did not finish", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A context carrying no expansion at all refuses.
    /// </summary>
    /// <remarks>
    /// The rule declares <c>PrincipalExpansion</c> as a required derived fact, so judging refuses a
    /// bundle that cannot supply it. Reaching the rule without one is a defect rather than a
    /// missing derivation, and it must not read as a clean policy.
    /// </remarks>
    [Fact]
    public void AContextWithoutAnExpansionRefuses()
    {
        var verdict = new LapsDecryptorBroadPrincipal().Judge(
            Policy(),
            new JudgingContext(
                Started,
                ProtectedPrincipals: null,
                Permissions: null,
                AttributeVisibility: null,
                MembersOfPrincipal: null,
                SchemaGuids: null,
                PrincipalNames: null,
                GpoMachineRegistrySettings: _ => new GpoRegistrySettings(
                    [], GpoSettingsOutcome.Read, null)));

        Assert.Empty(verdict.Findings);
        Assert.Single(verdict.Unresolved);
    }

    /// <summary>
    /// The rule refuses to be judged without a context at all.
    /// </summary>
    [Fact]
    public void JudgingWithoutAContextThrowsRatherThanReportingNothing()
    {
        Assert.Throws<InvalidOperationException>(
            () => new LapsDecryptorBroadPrincipal().Judge(Policy()));
    }

    // -------------------------------------------------------------------------------------------
    // What the rule declares
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The rule's declaration, read off the rule rather than restated from the document.
    /// </summary>
    [Fact]
    public void TheRuleDeclaresWhatItJudgesAndWhatItNeeds()
    {
        var definition = new LapsDecryptorBroadPrincipal().Definition;

        Assert.Equal("SEC-093", definition.Id);
        Assert.Equal(Severity.Critical, definition.Severity);
        Assert.Equal(["groupPolicyContainer"], definition.SubjectClasses);
        Assert.Contains(
            nameof(DerivedFactKind.PrincipalExpansion), definition.RequiredDerivedFacts);
    }

    // -------------------------------------------------------------------------------------------
    // The anchor: bytes a real policy editor wrote
    // -------------------------------------------------------------------------------------------

    /// <summary>
    /// The key path a real Windows LAPS Group Policy writes is the one the rule matches, proved
    /// against a <c>Registry.pol</c> produced by Windows rather than by this test.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This test exists because everything else here once agreed with a key that does not
    /// exist.</b> Until 2026-09-04 the rule matched <c>Policies\Microsoft\Windows\LAPS</c>, which
    /// is none of Microsoft's four documented LAPS policy roots and which no policy editor
    /// produces. Every fixture in this file was built from that same constant, so twenty-five tests
    /// passed and seven mutations fired against a rule that could never match a real policy: it
    /// found nothing, read that as "this policy configures no decryptor", and reported a policy
    /// handing decryption to Domain Users as clean.
    /// </para>
    /// <para>
    /// <b>Every check was sound and the whole circle was anchored to the wrong reference.</b> The
    /// specification, the code and the tests agreed with each other and none of them had ever been
    /// compared with a file Windows wrote. The bytes below are that comparison, and they are what
    /// makes the rest of this file mean anything.
    /// </para>
    /// <para>
    /// <b>Where these bytes came from.</b> Captured 2026-09-04 from
    /// <c>SYSVOL\...\Machine\Registry.pol</c> of a Group Policy Object created in the lab by
    /// <c>next/tools/Set-LabLapsDecryptor.ps1</c>, which sets the decryptor through Microsoft's own
    /// <c>Set-GPRegistryValue</c>. Nothing here is hand-built. The only value in the file is a
    /// security identifier the script chose, so the fixture carries no name out of the lab.
    /// </para>
    /// <para>
    /// <b>Parsed by the product's own parser</b>, so this covers the whole path from file to
    /// verdict: if <see cref="RegistryPolicyParser"/> stops decoding the key, or the rule stops
    /// matching it, this fails.
    /// </para>
    /// </remarks>
    [Fact]
    public void TheKeyPathAWindowsLapsPolicyActuallyWritesIsMatched()
    {
        var parsed = RegistryPolicyParser.ParsePolicyFile(RealRegistryPolicy());

        Assert.Empty(parsed.Errors);

        // The rule is offered exactly what capture would have put in the bundle.
        var finding = Assert.Single(Judge(
            parsed.Entries,
            Expands(PlantedDecryptorSid,
                [Member(PlantedDomainUsersSid, [PlantedDecryptorSid, PlantedDomainUsersSid])])));

        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);

        Assert.Equal(PlantedDecryptorSid, evidence.ConfiguredValue);
        Assert.Equal(PlantedDomainUsersSid, evidence.BroadPrincipalSid);
        Assert.Equal(Severity.Critical, finding.Severity);
    }

    /// <summary>
    /// The file really does carry Microsoft's Group Policy root, read out of it rather than
    /// asserted about it.
    /// </summary>
    /// <remarks>
    /// Separate from the test above so that a failure says which half broke: whether the file
    /// stopped containing the documented key, or the rule stopped matching it.
    /// </remarks>
    [Fact]
    public void TheCapturedPolicyFileCarriesMicrosoftsDocumentedGroupPolicyRoot()
    {
        var parsed = RegistryPolicyParser.ParsePolicyFile(RealRegistryPolicy());

        var entry = Assert.Single(parsed.Entries);

        Assert.Equal(
            @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS",
            entry.KeyPath,
            ignoreCase: true);

        Assert.Equal(DecryptorValue, entry.ValueName);
    }

    /// <summary>
    /// A decryptor written under one of Microsoft's <i>other</i> LAPS roots is not read as a Group
    /// Policy setting.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Microsoft states that policy settings are "never shared or inherited across policy key
    /// roots".</b> The CSP root is delivered by device management, local configuration is a
    /// machine's own registry, and the legacy root belongs to the predecessor product that SEC-091
    /// covers. A Group Policy Object's <c>Registry.pol</c> carries the Group Policy root, and
    /// reading any of the others out of it would report a setting that this policy does not apply.
    /// </para>
    /// <para>
    /// <b>This is the control on the fix.</b> Widening the match until the lab produced a finding
    /// would have been the easy repair, and it would have made the rule report settings no policy
    /// delivers. These three keys are the ones a careless widening would swallow.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(@"Software\Microsoft\Policies\LAPS")]
    [InlineData(@"Software\Microsoft\Windows\CurrentVersion\LAPS\Config")]
    [InlineData(@"Software\Policies\Microsoft Services\AdmPwd")]
    public void ADecryptorUnderAnotherLapsPolicyRootIsNotRead(string otherRoot)
    {
        AssertSilent([Setting(otherRoot, DecryptorValue, DomainUsers)], Never());
    }

    // -------------------------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------------------------

    private static IReadOnlyList<Finding> Judge(
        IReadOnlyList<RegistryPolicyEntry> settings,
        Func<string, string, PrincipalExpansion> expand) =>
        Verdict(settings, expand).Findings;

    /// <summary>
    /// Asserts that the rule looked, reached an answer, and had nothing to say.
    /// </summary>
    /// <remarks>
    /// <b>Asserting an empty findings list is not enough, and a mutation proved it.</b> A refusal
    /// carries no findings either, so <c>Assert.Empty(verdict.Findings)</c> passes just as happily
    /// when the rule gave up as when it cleared the policy - and those are opposite statements to
    /// an operator. Inverting the completeness check in the rule left every silence test here
    /// green until this also asserted that nothing was left unresolved.
    /// </remarks>
    private static void AssertSilent(
        IReadOnlyList<RegistryPolicyEntry> settings,
        Func<string, string, PrincipalExpansion> expand)
    {
        var verdict = Verdict(settings, expand);

        Assert.Empty(verdict.Findings);
        Assert.Empty(verdict.Unresolved);
        Assert.Empty(verdict.InputsNotCaptured);
    }

    private static RuleVerdict Verdict(
        IReadOnlyList<RegistryPolicyEntry> settings,
        Func<string, string, PrincipalExpansion> expand,
        GpoSettingsOutcome outcome = GpoSettingsOutcome.Read) =>
        new LapsDecryptorBroadPrincipal().Judge(Policy(), Context(settings, expand, outcome));

    private static JudgingContext Context(
        IReadOnlyList<RegistryPolicyEntry> settings,
        Func<string, string, PrincipalExpansion> expand,
        GpoSettingsOutcome outcome = GpoSettingsOutcome.Read) =>
        new(
            Started,
            ProtectedPrincipals: null,
            Permissions: null,
            AttributeVisibility: null,
            MembersOfPrincipal: expand,
            SchemaGuids: null,
            PrincipalNames: sid => sid == WrapperGroup ? "LAPS Decryptors" : null,
            GpoMachineRegistrySettings: _ => new GpoRegistrySettings(
                settings,
                outcome,
                outcome is GpoSettingsOutcome.Read ? null : "The share refused the folder."));

    /// <summary>An expansion of one principal, and a refusal for anything else asked about.</summary>
    private static Func<string, string, PrincipalExpansion> Expands(
        string root, IReadOnlyList<ExpandedPrincipal> members) =>
        (sid, scope) => sid == root
            ? new PrincipalExpansion(sid, PrincipalExpansionOutcome.Expanded, members)
            : throw new InvalidOperationException($"The rule expanded {sid}, which it should not.");

    /// <summary>
    /// An expansion that fails the test if it is called at all, for the cases where the rule should
    /// never reach one.
    /// </summary>
    private static Func<string, string, PrincipalExpansion> Never() =>
        (sid, scope) => throw new InvalidOperationException(
            $"The rule expanded {sid} when it had no decryptor to expand.");

    private static ExpandedPrincipal Member(string sid, IReadOnlyList<string> path) =>
        new(sid, Forest, path, true);

    /// <summary>One REG_SZ entry, written the way a Registry.pol file states one.</summary>
    private static RegistryPolicyEntry Setting(string keyPath, string valueName, string value) =>
        new(
            keyPath,
            valueName,
            (uint)RegistryValueType.String,
            Encoding.Unicode.GetBytes(value + '\0'));

    private static ObjectAttributes Policy() => Object(PolicyDn, "groupPolicyContainer");

    /// <summary>
    /// The security identifier the lab plant set as the decryptor, as the captured file states it.
    /// </summary>
    private const string PlantedDecryptorSid =
        "S-1-5-21-1834058357-2590327168-2246012571-142601";

    /// <summary>Domain Users in the lab the fixture was captured from.</summary>
    private const string PlantedDomainUsersSid =
        "S-1-5-21-1834058357-2590327168-2246012571-513";

    /// <summary>
    /// A <c>Registry.pol</c> written by Windows, byte for byte.
    /// </summary>
    /// <remarks>
    /// <b>Do not regenerate this by hand.</b> Its value is that no one in this repository wrote
    /// it: it came out of SYSVOL after <c>Set-GPRegistryValue</c> configured a real Group Policy
    /// Object. Editing it to make a test pass would restore exactly the closed loop that let a
    /// non-existent registry key survive twenty-five tests and seven mutations. If it needs
    /// replacing, capture a fresh one from a real policy.
    /// </remarks>
    private static byte[] RealRegistryPolicy() => Convert.FromBase64String(
        "UFJlZwEAAABbAFMAbwBmAHQAdwBhAHIAZQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEMAdQByAHIAZQBu"
        + "AHQAVgBlAHIAcwBpAG8AbgBcAFAAbwBsAGkAYwBpAGUAcwBcAEwAQQBQAFMAAAA7AEEARABQAGEAcwBzAHcAbwByAGQARQBuAGMA"
        + "cgB5AHAAdABpAG8AbgBQAHIAaQBuAGMAaQBwAGEAbAAAADsAAQAAADsAYgAAADsAUwAtADEALQA1AC0AMgAxAC0AMQA4ADMANAAw"
        + "ADUAOAAzADUANwAtADIANQA5ADAAMwAyADcAMQA2ADgALQAyADIANAA2ADAAMQAyADUANwAxAC0AMQA0ADIANgAwADEAAABdAA==");

    private static ObjectAttributes Object(string distinguishedName, string mostDerivedClass) =>
        new(
            distinguishedName,
            Guid.Parse("a1b2c3d4-0000-0000-0000-000000000001"),
            Started,
            EvidenceCompleteness.Complete,
            [
                new ObjectAttribute(
                    "objectClass",
                    AttributeCardinality.MultiValued,
                    [
                        new AttributeValue(0, "top", null),
                        new AttributeValue(1, "container", null),
                        new AttributeValue(2, mostDerivedClass, null),
                    ]),
                new ObjectAttribute(
                    "displayName",
                    AttributeCardinality.SingleValued,
                    [new AttributeValue(0, PolicyName, null)]),
            ],
            Forest);
}
