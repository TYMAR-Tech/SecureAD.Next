using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// A bundle written by capture, judged, and read back — the whole pipe.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything else tests one half against something built by hand.</b> The writing tests build
/// executions, the reading tests build stores, and the rule tests build objects. This is the only
/// place a real sealed bundle is written by <see cref="BundleWriter"/> and then judged, so it is
/// the only place a mismatch between what capture stores and what a rule expects can show up.
/// </para>
/// </remarks>
public sealed class JudgingEndToEndTests
{
    private const uint TrustedForDelegation = 0x00080000;
    private const uint OrdinaryAccount = 0x00000200;

    private static readonly DateTimeOffset Started = new(2026, 8, 26, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Finished = new(2026, 8, 26, 11, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// A planted account is found, all the way from a sealed bundle to a stored finding.
    /// </summary>
    [Fact]
    public void AnAccountTrustedForDelegationIsFoundInASealedBundle()
    {
        var directory = ABundleHolding(
            Account("svc-web", "CN=svc-web,OU=People,DC=contoso,DC=com", TrustedForDelegation, 513, "user"),
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"));

        var state = Judged(directory);

        Assert.Equal(JudgementRunState.Completed, state);

        var judgement = Read(directory);
        var finding = Assert.Single(judgement.Findings);

        Assert.Equal("SEC-010", finding.RuleId);
        Assert.Equal("svc-web", finding.Subject.Key);
    }

    /// <summary>
    /// A domain controller is not reported for a setting it requires.
    /// </summary>
    /// <remarks>
    /// The false positive that matters most: a rule that fires on every controller in a forest is
    /// a rule an operator learns to ignore.
    /// </remarks>
    [Fact]
    public void ADomainControllerIsNotReported()
    {
        var directory = ABundleHolding(
            Account(
                "DC01$",
                "CN=DC01,OU=Domain Controllers,DC=contoso,DC=com",
                TrustedForDelegation,
                516,
                "computer"));

        Assert.Equal(JudgementRunState.Completed, Judged(directory));
        Assert.Empty(Read(directory).Findings);
    }

    /// <summary>
    /// Both rules are recorded as having run, even the one that found nothing.
    /// </summary>
    /// <remarks>
    /// This is what keeps an empty findings list readable. Without it, a judged bundle and an
    /// unjudged one look identical.
    /// </remarks>
    [Fact]
    public void EveryScheduledRuleIsRecordedWhetherItFoundAnythingOrNot()
    {
        var directory = ABundleHolding(
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"));

        Judged(directory);

        var judgement = Read(directory);

        Assert.Empty(judgement.Findings);
        Assert.False(judgement.DidNotRun);
        Assert.Equal(2, judgement.RulesRun.Count);
        Assert.True(judgement.EveryRuleReachedEveryVerdict);
    }

    /// <summary>
    /// An object missing a declared input degrades the judging and says which attribute was absent.
    /// </summary>
    /// <remarks>
    /// The whole point of a rule declaring what it reads: the answer is *primaryGroupID was not
    /// captured* rather than silence.
    /// </remarks>
    [Fact]
    public void AnObjectMissingADeclaredInputDegradesTheJudgingAndNamesTheAttribute()
    {
        var directory = ABundleHolding(
            Account("ghost", "CN=ghost,OU=People,DC=contoso,DC=com", OrdinaryAccount, null, "user"));

        Assert.Equal(JudgementRunState.CompletedDegraded, Judged(directory));

        var judgement = Read(directory);

        Assert.False(judgement.EveryRuleReachedEveryVerdict);

        var indeterminate = judgement.RulesRun
            .Where(r => r.Outcome == RuleExecutionOutcome.Indeterminate)
            .ToList();

        Assert.NotEmpty(indeterminate);
        Assert.All(indeterminate, r =>
            Assert.Contains("primaryGroupID", r.MissingInputs.Select(m => m.Attribute)));
    }

    /// <summary>
    /// The judgement names the capture it was made against, so it cannot be read beside another.
    /// </summary>
    [Fact]
    public void TheJudgementIsBoundToTheBundleItJudged()
    {
        var directory = ABundleHolding(
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"));

        Judged(directory);

        var expected = BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash;

        Assert.Equal(expected, Read(directory).Description.EvidenceSeal);
    }

    /// <summary>
    /// Judging the same bundle again replaces the judgement rather than adding to it.
    /// </summary>
    [Fact]
    public void JudgingTwiceReplacesTheEarlierJudgement()
    {
        var directory = ABundleHolding(
            Account("svc-web", "CN=svc-web,OU=People,DC=contoso,DC=com", TrustedForDelegation, 513, "user"));

        Judged(directory);
        Judged(directory);

        Assert.Single(Read(directory).Findings);
    }

    private static JudgementRunState Judged(string directory)
    {
        var judged = JudgingRun.Judge(
            directory,
            [new UnconstrainedDelegationOnAccount(), new UnconstrainedDelegationOnNonDomainController()],
            Started,
            Started);

        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return judged.Value;
    }

    private static StoredJudgement Read(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);

        using var reader = opened.Value!;
        return reader.Read();
    }

    /// <summary>
    /// A sealed bundle holding the given objects, written the way capture writes one.
    /// </summary>
    private static string ABundleHolding(params EvidenceObject[] objects)
    {
        var directory = Path.Combine(
            Path.GetTempPath(), "securead-judging-e2e", Guid.NewGuid().ToString("N"));

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());

            foreach (var subject in objects)
                writer.WriteObject(subject);

            writer.Complete(OneDomainRead(), Finished);
        }

        return directory;
    }

    private static EvidenceObject Account(
        string name, string distinguishedName, uint? control, int? primaryGroup, string objectClass)
    {
        var attributes = new List<EvidenceAttribute>
        {
            new("sAMAccountName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(name)]),
            new(
                "objectClass",
                StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
        };

        if (control is { } c)
        {
            attributes.Add(new EvidenceAttribute(
                "userAccountControl",
                StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfText(c.ToString(System.Globalization.CultureInfo.InvariantCulture))]));
        }

        if (primaryGroup is { } g)
        {
            attributes.Add(new EvidenceAttribute(
                "primaryGroupID",
                StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfText(g.ToString(System.Globalization.CultureInfo.InvariantCulture))]));
        }

        return new EvidenceObject(
            SomeCoverage(), distinguishedName, Guid.NewGuid(), attributes, Started);
    }

    private static PartitionCoverage SomeCoverage() => new(
        "DC=contoso,DC=com",
        NamingContextKind.Domain,
        "dc01.contoso.com",
        ConnectionSecurityLevel.SignedAndSealed,
        12,
        4200,
        3,
        [],
        false);

    private static RunCoverage OneDomainRead() =>
        RunCoverage.Of(
            CoverageId.ForDomains("contoso.com", ["contoso.com"]),
            [DomainCoverage.Read("contoso.com")],
            [
                ForestPartitionCoverage.Read(
                    "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                ForestPartitionCoverage.Read(
                    "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
            ],
            SysvolCoverage.Of([]));
}
