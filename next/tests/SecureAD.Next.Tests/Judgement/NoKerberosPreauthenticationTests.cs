using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-022 - an account that does not require Kerberos pre-authentication.
/// </summary>
/// <remarks>
/// <para>
/// <b>The bit under test is Microsoft's.</b> <c>ADS_UF_DONT_REQUIRE_PREAUTH</c> is
/// <c>0x400000</c>, decimal 4194304, published in the <c>ADS_USER_FLAG_ENUM</c> enumeration, the
/// <c>User-Account-Control</c> schema page and the UserAccountControl troubleshooting article.
/// </para>
/// <para>
/// <b>The values below are whole <c>userAccountControl</c> values, not the bare bit.</b> A test that
/// fed only <c>0x400000</c> would never notice a rule that matched on equality rather than on the
/// bit, and equality is the mistake this shape is most likely to make.
/// </para>
/// <para>
/// <b><c>0x400202</c> is the value the owner's lab actually holds.</b> The account
/// <c>lab.nopreauth</c> was planted in <c>ba.ad.lab</c> on 2026-09-01 by
/// <c>next/tools/Set-LabNoPreauthAccount.ps1</c> and read back at 4194818 - the flag, plus
/// <c>ADS_UF_NORMAL_ACCOUNT</c>, plus <c>ADS_UF_ACCOUNTDISABLE</c>. Using the number a real
/// directory produced rather than one invented to suit the code is why the disabled case here
/// describes something that exists.
/// </para>
/// </remarks>
public sealed class NoKerberosPreauthenticationTests
{
    private const uint NormalAccount = 0x00000200;
    private const uint WithoutPreauth = 0x00400200;
    private const uint WithoutPreauthDisabled = 0x00400202;

    private static readonly NoKerberosPreauthentication Rule = new();

    /// <summary>
    /// An account carrying the flag is reported.
    /// </summary>
    [Fact]
    public void AnAccountThatDoesNotRequirePreauthenticationIsReported()
    {
        var verdict = Rule.Judge(Account("svc-legacy", WithoutPreauth, "user"));

        Assert.True(verdict.IsComplete);
        var finding = Assert.Single(verdict.Findings);

        Assert.Equal("SEC-022", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("svc-legacy", finding.Subject.Key);

        var evidence = Assert.IsType<KerberosPreauthenticationEvidence>(finding.Evidence);
        Assert.Equal(WithoutPreauth, evidence.UserAccountControl);
        Assert.False(evidence.IsDisabled);
    }

    /// <summary>
    /// An ordinary account is not reported.
    /// </summary>
    /// <remarks>
    /// The negative control. Without it the rule could return a finding for every account and every
    /// other test here would still pass.
    /// </remarks>
    [Fact]
    public void AnAccountThatRequiresPreauthenticationIsNotReported()
    {
        var verdict = Rule.Judge(Account("alice", NormalAccount, "user"));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// A neighbouring flag does not fire the rule.
    /// </summary>
    /// <remarks>
    /// <b>The bits either side are the plausible confusion.</b> <c>0x200000</c> is
    /// <c>ADS_UF_USE_DES_KEY_ONLY</c> and <c>0x800000</c> is <c>ADS_UF_PASSWORD_EXPIRED</c>. An
    /// off-by-one in the constant would report accounts carrying one of those and this is what
    /// catches it.
    /// </remarks>
    [Theory]
    [InlineData(0x00200200u)]
    [InlineData(0x00800200u)]
    public void ANeighbouringFlagDoesNotFireTheRule(uint control)
    {
        var verdict = Rule.Judge(Account("bob", control, "user"));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// A disabled account is still reported, and the finding says so.
    /// </summary>
    /// <remarks>
    /// <b>This is the decision the predecessor made the other way.</b> It excluded disabled
    /// accounts. No Microsoft source states that a key distribution centre refuses an AS-REQ for a
    /// disabled account, so this product reports it and shows the operator the state instead of
    /// deciding for him on an unevidenced belief.
    /// </remarks>
    [Fact]
    public void ADisabledAccountIsStillReportedAndTheFindingSaysSo()
    {
        var verdict = Rule.Judge(Account("svc-retired", WithoutPreauthDisabled, "user"));

        var finding = Assert.Single(verdict.Findings);
        Assert.Contains("disabled", finding.Detail, StringComparison.Ordinal);

        var evidence = Assert.IsType<KerberosPreauthenticationEvidence>(finding.Evidence);
        Assert.True(evidence.IsDisabled);
    }

    /// <summary>
    /// A computer carrying the flag is reported too.
    /// </summary>
    /// <remarks>
    /// The rule declares both classes, so silence on a computer would be a rule that judged less
    /// than it said it did.
    /// </remarks>
    [Fact]
    public void AComputerCarryingTheFlagIsReported()
    {
        var verdict = Rule.Judge(Account("WS-014$", WithoutPreauth, "computer"));

        Assert.Single(verdict.Findings);
    }

    /// <summary>
    /// An object that did not carry the attribute produces no verdict, not a clean one.
    /// </summary>
    /// <remarks>
    /// <b>Silence and "nothing was wrong" must not be the same answer</b> - that is the whole point
    /// of <see cref="RuleVerdict.InputsNotCaptured"/>, and <c>docs/decisions/0002</c> forbids
    /// rendering an unavailable answer as an empty result.
    /// </remarks>
    [Fact]
    public void AnObjectMissingTheAttributeProducesNoVerdict()
    {
        var verdict = Rule.Judge(Account("carol", control: null, "user"));

        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Contains("userAccountControl", verdict.InputsNotCaptured);
    }

    /// <summary>
    /// A value that is present but not a number is not reported as an uncaptured attribute's twin -
    /// it stops the rule, and says which attribute stopped it.
    /// </summary>
    [Fact]
    public void AnUnreadableValueStopsTheRuleRatherThanBeingTreatedAsZero()
    {
        var verdict = Rule.Judge(AccountWithRawControl("dave", "not a number", "user"));

        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Contains("userAccountControl", verdict.InputsNotCaptured);
    }

    /// <summary>
    /// The rule declares no derived facts, so it is unaffected by the Wave 6 seam.
    /// </summary>
    [Fact]
    public void TheRuleAsksForNothingDerived() =>
        Assert.Empty(Rule.Definition.RequiredDerivedFacts);

    private static ObjectAttributes Account(string name, uint? control, string objectClass) =>
        AccountWithRawControl(
            name,
            control?.ToString(CultureInfo.InvariantCulture),
            objectClass);

    private static ObjectAttributes AccountWithRawControl(
        string name, string? control, string objectClass)
    {
        var attributes = new List<ObjectAttribute>
        {
            Single("sAMAccountName", name),
            new(
                "objectClass",
                AttributeCardinality.MultiValued,
                [new AttributeValue(0, "top", null), new AttributeValue(1, objectClass, null)]),
        };

        if (control is not null)
            attributes.Add(Single("userAccountControl", control));

        return new ObjectAttributes(
            $"CN={name},CN=Users,DC=ph,DC=ad,DC=lab",
            Guid.NewGuid(),
            DateTimeOffset.UnixEpoch,
            EvidenceCompleteness.Complete,
            attributes,
            DomainFqdn: "ad.lab");
    }

    private static ObjectAttribute Single(string ldapDisplayName, string value) =>
        new(ldapDisplayName, AttributeCardinality.SingleValued, [new AttributeValue(0, value, null)]);
}
