using System.Globalization;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-028, SEC-029 and SEC-033 - the account flags that weaken a credential.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every value here is a whole <c>userAccountControl</c>, never a bare bit.</b> A test that fed
/// only <c>0x20</c> would never notice a rule matching on equality rather than on the bit, and
/// equality is the mistake this shape is most likely to make. <c>0x200</c>
/// (<c>NORMAL_ACCOUNT</c>) is carried alongside throughout, which is what a real account looks
/// like.
/// </para>
/// <para>
/// <b>The flag values are Microsoft's</b>, from the list of property flags in the
/// UserAccountControl article: <c>PASSWD_NOTREQD</c> <c>0x0020</c>,
/// <c>ENCRYPTED_TEXT_PWD_ALLOWED</c> <c>0x0080</c>, <c>USE_DES_KEY_ONLY</c> <c>0x200000</c>,
/// <c>INTERDOMAIN_TRUST_ACCOUNT</c> <c>0x0800</c>.
/// </para>
/// </remarks>
public sealed class UnsecureAccountFlagRuleTests
{
    private const uint NormalAccount = 0x00000200;
    private const uint PasswordNotRequiredFlag = 0x00000020;
    private const uint ReversibleEncryption = 0x00000080;
    private const uint DesKeyOnly = 0x00200000;
    private const uint TrustAccount = 0x00000800;
    private const uint Disabled = 0x00000002;

    private static readonly PasswordNotRequired Sec028 = new();
    private static readonly ReversiblePasswordEncryption Sec029 = new();
    private static readonly DesEncryptionOnly Sec033 = new();

    /// <summary>
    /// Each rule reports an account carrying its own flag.
    /// </summary>
    [Fact]
    public void EachRuleReportsAnAccountCarryingItsFlag()
    {
        AssertReports(Sec028, "SEC-028", NormalAccount | PasswordNotRequiredFlag, Severity.High);
        AssertReports(Sec029, "SEC-029", NormalAccount | ReversibleEncryption, Severity.High);
        AssertReports(Sec033, "SEC-033", NormalAccount | DesKeyOnly, Severity.Medium);
    }

    /// <summary>
    /// An ordinary account is reported by none of them.
    /// </summary>
    /// <remarks>
    /// The negative control without which every rule here could return a finding for every account
    /// and every other test would still pass.
    /// </remarks>
    [Fact]
    public void AnOrdinaryAccountIsReportedByNoneOfThem()
    {
        foreach (var rule in new IObjectRule[] { Sec028, Sec029, Sec033 })
        {
            var verdict = rule.Judge(Account("alice", NormalAccount));

            Assert.True(verdict.IsComplete);
            Assert.Empty(verdict.Findings);
        }
    }

    /// <summary>
    /// No rule fires on another rule's flag.
    /// </summary>
    /// <remarks>
    /// <b>Three rules reading three bits of one integer is exactly where a copied constant hides.</b>
    /// Each rule is offered every other rule's flag and must stay silent, which no single-rule test
    /// can check.
    /// </remarks>
    [Fact]
    public void NoRuleFiresOnAnotherRulesFlag()
    {
        Assert.Empty(Sec028.Judge(Account("bob", NormalAccount | ReversibleEncryption)).Findings);
        Assert.Empty(Sec028.Judge(Account("bob", NormalAccount | DesKeyOnly)).Findings);

        Assert.Empty(Sec029.Judge(Account("bob", NormalAccount | PasswordNotRequiredFlag)).Findings);
        Assert.Empty(Sec029.Judge(Account("bob", NormalAccount | DesKeyOnly)).Findings);

        Assert.Empty(Sec033.Judge(Account("bob", NormalAccount | PasswordNotRequiredFlag)).Findings);
        Assert.Empty(Sec033.Judge(Account("bob", NormalAccount | ReversibleEncryption)).Findings);
    }

    /// <summary>
    /// A neighbouring flag does not fire a rule.
    /// </summary>
    /// <remarks>
    /// <b>The bits either side are the plausible confusion, and this is what catches a mistyped
    /// constant.</b> <c>0x10</c> is <c>LOCKOUT</c> and <c>0x40</c> is <c>PASSWD_CANT_CHANGE</c>
    /// around <c>PASSWD_NOTREQD</c>; <c>0x40</c> and <c>0x100</c>
    /// (<c>TEMP_DUPLICATE_ACCOUNT</c>) around <c>ENCRYPTED_TEXT_PWD_ALLOWED</c>; <c>0x100000</c>
    /// (<c>NOT_DELEGATED</c>) and <c>0x400000</c> (<c>DONT_REQ_PREAUTH</c>) around
    /// <c>USE_DES_KEY_ONLY</c>.
    /// </remarks>
    [Fact]
    public void ANeighbouringFlagDoesNotFireARule()
    {
        foreach (var neighbour in new uint[] { 0x10, 0x40 })
            Assert.Empty(Sec028.Judge(Account("carol", NormalAccount | neighbour)).Findings);

        foreach (var neighbour in new uint[] { 0x40, 0x100 })
            Assert.Empty(Sec029.Judge(Account("carol", NormalAccount | neighbour)).Findings);

        foreach (var neighbour in new uint[] { 0x100000, 0x400000 })
            Assert.Empty(Sec033.Judge(Account("carol", NormalAccount | neighbour)).Findings);
    }

    /// <summary>
    /// A trust account carrying "password not required" is not reported.
    /// </summary>
    /// <remarks>
    /// <b>Microsoft documents this as by design</b>, which is why it is excluded where SEC-022
    /// excluded nothing: "A Windows trust account is exempt from having a password through
    /// PASSWD_NOTREQD… because trust objects don't use the traditional password policy", and the
    /// flag "is set on INTERDOMAIN_TRUST_ACCOUNT accounts by default". Without this the rule fires
    /// on every trust in the forest, all of them by design and all of them false.
    /// </remarks>
    [Fact]
    public void ATrustAccountCarryingPasswordNotRequiredIsNotReported()
    {
        var verdict = Sec028.Judge(
            Account("CONTOSO$", TrustAccount | PasswordNotRequiredFlag));

        Assert.True(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
    }

    /// <summary>
    /// A non-trust account carrying the same flag is still reported.
    /// </summary>
    /// <remarks>
    /// The other half of the exclusion, and the half that stops it becoming an excuse. Without this
    /// a rule that excluded everything would satisfy the test above.
    /// </remarks>
    [Fact]
    public void ANonTrustAccountCarryingPasswordNotRequiredIsReported()
    {
        var verdict = Sec028.Judge(Account("svc-legacy", NormalAccount | PasswordNotRequiredFlag));

        Assert.Single(verdict.Findings);
    }

    /// <summary>
    /// The trust-account exclusion applies to SEC-028 only.
    /// </summary>
    /// <remarks>
    /// Microsoft's statement is about <c>PASSWD_NOTREQD</c> specifically. Nothing says a trust
    /// account is expected to carry reversible encryption or be restricted to DES, so excluding
    /// them there would hide a real misconfiguration behind a rule for a different flag.
    /// </remarks>
    [Fact]
    public void TheTrustExclusionAppliesToPasswordNotRequiredOnly()
    {
        Assert.Single(Sec029.Judge(Account("CONTOSO$", TrustAccount | ReversibleEncryption)).Findings);
        Assert.Single(Sec033.Judge(Account("CONTOSO$", TrustAccount | DesKeyOnly)).Findings);
    }

    /// <summary>
    /// A disabled account is reported, and the finding says so.
    /// </summary>
    /// <remarks>
    /// The flag survives re-enabling, so the exposure is dormant rather than absent - the same
    /// position SEC-022 took, for the same reason.
    /// </remarks>
    [Fact]
    public void ADisabledAccountIsReportedAndTheWordingSaysSo()
    {
        var verdict = Sec028.Judge(
            Account("svc-old", NormalAccount | PasswordNotRequiredFlag | Disabled));

        var finding = Assert.Single(verdict.Findings);

        Assert.True(Assert.IsType<UserAccountControlEvidence>(finding.Evidence).IsDisabled);
        Assert.Contains("currently disabled", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// The evidence carries the whole value, so one finding shows every flag the account has.
    /// </summary>
    /// <remarks>
    /// This is what the shared evidence kind buys: an operator reading the SEC-028 finding can see
    /// the same account is also DES-restricted, without a second finding in front of him.
    /// </remarks>
    [Fact]
    public void TheEvidenceCarriesTheWholeValueNotTheBitThatFired()
    {
        var control = NormalAccount | PasswordNotRequiredFlag | DesKeyOnly;

        var finding = Assert.Single(Sec028.Judge(Account("svc-both", control)).Findings);

        Assert.Equal(control, Assert.IsType<UserAccountControlEvidence>(finding.Evidence)
            .UserAccountControl);
    }

    /// <summary>
    /// An account with no userAccountControl gets no verdict, and the attribute is named.
    /// </summary>
    [Fact]
    public void AnAccountWithNoUserAccountControlIsNotJudged()
    {
        var verdict = Sec028.Judge(AccountWithRawControl("dave", null));

        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Contains("userAccountControl", verdict.InputsNotCaptured);
    }

    /// <summary>
    /// A userAccountControl that is not a number is not read as zero.
    /// </summary>
    /// <remarks>
    /// Zero would mean no flags set, which is a statement about the account the evidence does not
    /// support. It is an unread input instead.
    /// </remarks>
    [Fact]
    public void AUserAccountControlThatIsNotANumberIsNotReadAsZero()
    {
        var verdict = Sec028.Judge(AccountWithRawControl("erin", "not a number"));

        Assert.False(verdict.IsComplete);
        Assert.Empty(verdict.Findings);
        Assert.Contains("userAccountControl", verdict.InputsNotCaptured);
    }

    /// <summary>
    /// None of the three declares a derived fact, so all three judge an underived bundle.
    /// </summary>
    [Fact]
    public void NoneOfThemAsksForAnythingDerived()
    {
        Assert.Empty(Sec028.Definition.RequiredDerivedFacts);
        Assert.Empty(Sec029.Definition.RequiredDerivedFacts);
        Assert.Empty(Sec033.Definition.RequiredDerivedFacts);
    }

    private static void AssertReports(
        IObjectRule rule, string ruleId, uint control, Severity severity)
    {
        var verdict = rule.Judge(Account("svc-target", control));

        Assert.True(verdict.IsComplete);
        var finding = Assert.Single(verdict.Findings);

        Assert.Equal(ruleId, finding.RuleId);
        Assert.Equal(severity, finding.Severity);
        Assert.Equal("svc-target", finding.Subject.Key);
        Assert.Equal(control, Assert.IsType<UserAccountControlEvidence>(finding.Evidence)
            .UserAccountControl);
    }

    private static ObjectAttributes Account(string name, uint control) =>
        AccountWithRawControl(name, control.ToString(CultureInfo.InvariantCulture));

    private static ObjectAttributes AccountWithRawControl(string name, string? control)
    {
        var attributes = new List<ObjectAttribute>
        {
            Single("sAMAccountName", name),
            new(
                "objectClass",
                AttributeCardinality.MultiValued,
                [new AttributeValue(0, "top", null), new AttributeValue(1, "user", null)]),
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
