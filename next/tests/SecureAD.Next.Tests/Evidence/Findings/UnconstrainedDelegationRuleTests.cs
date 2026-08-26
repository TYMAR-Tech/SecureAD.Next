using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Evidence.Findings;

/// <summary>
/// The two unconstrained delegation rules, and the domain controller exclusion they share.
/// </summary>
/// <remarks>
/// <para>
/// <b>The values here are from a real forest.</b> The owner's lab holds three domain controllers
/// at <c>userAccountControl</c> 532480 with <c>primaryGroupID</c> 516, and one deliberately
/// planted user account, <c>lab.unconstrained</c>, at 524802 with <c>primaryGroupID</c> 513. Those
/// exact numbers are used below so the tests describe a forest that exists rather than one
/// invented to suit the code.
/// </para>
/// <para>
/// <b>532480 is 0x82000</b> - server trust plus trusted-for-delegation - which Microsoft publishes
/// as the default for a domain controller. <b>524802 is 0x80202</b> - trusted-for-delegation, a
/// normal account, and disabled.
/// </para>
/// </remarks>
public sealed class UnconstrainedDelegationRuleTests
{
    private const uint DomainControllerControl = 532480;
    private const uint PlantedUserControl = 524802;

    private static readonly UnconstrainedDelegationOnAccount OnAccount = new();
    private static readonly UnconstrainedDelegationOnNonDomainController OnComputer = new();

    private static PartitionCoverage SomeCoverage() => new(
        "DC=ph,DC=ad,DC=lab",
        NamingContextKind.Domain,
        "phdc.ph.ad.lab",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    /// <summary>
    /// An account as a bundle hands it back.
    /// </summary>
    /// <remarks>
    /// <b>Built in the read-side shape, because that is what a rule judges.</b> A rule runs over a
    /// sealed bundle and never over a capture in flight, so building capture-side objects here
    /// would prove the rules work against something they are never given.
    /// </remarks>
    private static ObjectAttributes Account(
        string name,
        string distinguishedName,
        uint? control,
        int? primaryGroup,
        string objectClass)
    {
        var attributes = new List<ObjectAttribute>
        {
            Single("sAMAccountName", name),
            new(
                "objectClass",
                AttributeCardinality.MultiValued,
                [new AttributeValue(0, "top", null), new AttributeValue(1, objectClass, null)]),
        };

        if (control is { } c)
        {
            attributes.Add(Single(
                "userAccountControl",
                c.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        if (primaryGroup is { } g)
        {
            attributes.Add(Single(
                "primaryGroupID",
                g.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        }

        return new ObjectAttributes(
            distinguishedName,
            Guid.NewGuid(),
            DateTimeOffset.UnixEpoch,
            EvidenceCompleteness.Complete,
            attributes);
    }

    /// <summary>
    /// One single-valued attribute, as a bundle stores it.
    /// </summary>
    /// <remarks>
    /// An attribute the object does not carry is absent from the list rather than present and
    /// empty, which is how a bundle hands it back: a null column produces no value.
    /// </remarks>
    private static ObjectAttribute Single(string ldapDisplayName, string value) =>
        new(ldapDisplayName, AttributeCardinality.SingleValued, [new AttributeValue(0, value, null)]);

    private static ObjectAttributes PlantedUser() => Account(
        "lab.unconstrained",
        "CN=lab.unconstrained,CN=Users,DC=ph,DC=ad,DC=lab",
        PlantedUserControl,
        513,
        "user");

    private static ObjectAttributes DomainController(string name) => Account(
        name,
        $"CN={name},OU=Domain Controllers,DC=ph,DC=ad,DC=lab",
        DomainControllerControl,
        516,
        "computer");

    /// <summary>
    /// The account the owner planted is found, by the rule that owns user-shaped accounts.
    /// </summary>
    [Fact]
    public void ThePlantedUserAccountIsFoundBySec010()
    {
        var found = OnAccount.Judge(PlantedUser()).Findings.Single();

        Assert.Equal("SEC-010", found.RuleId);
        Assert.Equal(Severity.High, found.Severity);
        Assert.Equal("lab.unconstrained", found.Subject.Key);
        Assert.Equal(FindingSubjectKind.Account, found.Subject.Kind);
        Assert.Contains("resource-based constrained delegation", found.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A user account is not a computer, so the computer rule is silent about it. The two rules
    /// partition on object class; neither hides the other.
    /// </summary>
    [Fact]
    public void ThePlantedUserAccountIsNotFoundBySec011()
    {
        Assert.Empty(OnComputer.Judge(PlantedUser()).Findings);
    }

    /// <summary>
    /// A member server with the flag is found, and carries the evidence it rested on.
    /// </summary>
    [Fact]
    public void AMemberServerWithTheFlagIsFoundBySec011()
    {
        var server = Account(
            "FILE01$",
            "CN=FILE01,OU=Servers,DC=ph,DC=ad,DC=lab",
            0x00081000,
            515,
            "computer");

        var found = OnComputer.Judge(server).Findings.Single();

        Assert.Equal("SEC-011", found.RuleId);
        var evidence = Assert.IsType<UnconstrainedDelegationEvidence>(found.Evidence);
        Assert.Equal(0x00081000u, evidence.UserAccountControl);
        Assert.True(evidence.IsComputer);
        Assert.False(evidence.DomainController.IsDomainController);
        Assert.Empty(OnAccount.Judge(server).Findings);
    }

    /// <summary>
    /// Every domain controller in the owner's forest is excluded. A domain controller requires
    /// this setting, so a finding against one is an instruction that cannot be followed.
    /// </summary>
    [Theory]
    [InlineData("ADDC")]
    [InlineData("BADC")]
    [InlineData("PHDC")]
    public void ADomainControllerIsExcluded(string name)
    {
        var controller = DomainController(name);

        Assert.Empty(OnComputer.Judge(controller).Findings);
        Assert.Empty(OnAccount.Judge(controller).Findings);
        Assert.True(DomainControllerSignals.Of(controller).IsDomainController);
    }

    /// <summary>
    /// An account without the flag is not a finding, whichever rule is asked.
    /// </summary>
    [Fact]
    public void AnAccountWithoutTheFlagIsNotAFinding()
    {
        var ordinary = Account("bob", "CN=bob,CN=Users,DC=ph,DC=ad,DC=lab", 512, 513, "user");

        Assert.Empty(OnAccount.Judge(ordinary).Findings);
        Assert.Empty(OnComputer.Judge(ordinary).Findings);
    }

    /// <summary>
    /// An object whose userAccountControl was never captured gets no verdict at all, rather than a
    /// clean one. Absence is not zero: the object either had no value or the run was refused it,
    /// and the directory does not tell the two apart. This is the distinction that gate 4 exists
    /// to force, and the reason a rule declares its inputs.
    /// </summary>
    [Fact]
    public void AnObjectMissingADeclaredInputGetsNoVerdictRatherThanACleanOne()
    {
        var unread = Account("ghost", "CN=ghost,CN=Users,DC=ph,DC=ad,DC=lab", null, 513, "user");

        var verdict = OnAccount.Judge(unread);

        Assert.Empty(verdict.Findings);
        Assert.False(verdict.IsComplete);
        Assert.Contains("userAccountControl", verdict.InputsNotCaptured);
    }

    /// <summary>
    /// An object carrying everything the rule declared reaches a verdict, even when that verdict
    /// is that nothing is wrong. Without this the check above would pass on a rule that never
    /// reached a verdict about anything.
    /// </summary>
    [Fact]
    public void AnObjectCarryingEveryDeclaredInputReachesAVerdict()
    {
        var ordinary = Account("bob", "CN=bob,CN=Users,DC=ph,DC=ad,DC=lab", 512, 513, "user");

        var verdict = OnAccount.Judge(ordinary);

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.InputsNotCaptured);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// A computer parked in the Domain Controllers container is excluded on that signal alone, and
    /// the disagreement between signals is recorded rather than resolved away.
    /// </summary>
    [Fact]
    public void SignalsThatDisagreeAreRecorded()
    {
        var imposter = Account(
            "NOTADC$",
            "CN=NOTADC,OU=Domain Controllers,DC=ph,DC=ad,DC=lab",
            0x00081000,
            515,
            "computer");

        var signals = DomainControllerSignals.Of(imposter);

        Assert.True(signals.IsDomainController);
        Assert.True(signals.SignalsDisagree);
        Assert.False(signals.ServerTrustAccountBit);
        Assert.True(signals.UnderDomainControllersOu);
        Assert.Empty(OnComputer.Judge(imposter).Findings);
    }

    /// <summary>
    /// A real domain controller is not reported as disagreeing with itself.
    /// </summary>
    [Fact]
    public void ARealDomainControllerShowsNoDisagreement()
    {
        Assert.False(DomainControllerSignals.Of(DomainController("PHDC")).SignalsDisagree);
    }

    /// <summary>
    /// A read-only domain controller is excluded too. The owner's forest has none, so this is the
    /// only thing standing between an RODC and a finding it cannot act on.
    /// </summary>
    [Fact]
    public void AReadOnlyDomainControllerIsExcluded()
    {
        var rodc = Account(
            "RODC01$",
            "CN=RODC01,OU=Branch,DC=ph,DC=ad,DC=lab",
            0x00081000,
            521,
            "computer");

        Assert.True(DomainControllerSignals.Of(rodc).PrimaryGroupIsDomainController);
        Assert.Empty(OnComputer.Judge(rodc).Findings);
    }

    /// <summary>
    /// An object with no objectGUID produces nothing. 0023 makes objectGUID part of a finding's
    /// identity, and a finding nothing can match is one no acceptance could ever attach to.
    /// </summary>
    [Fact]
    public void AnObjectWithNoGuidProducesNothing()
    {
        var nameless = Account(
            "nameless",
            "CN=nameless,CN=Users,DC=ph,DC=ad,DC=lab",
            PlantedUserControl,
            513,
            "user") with
        {
            ObjectGuid = null,
        };

        var verdict = OnAccount.Judge(nameless);

        Assert.Empty(verdict.Findings);
        Assert.True(verdict.IsComplete);
    }
}
