using SecureAD.Kernel;
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

    [Theory]
    [InlineData("WP", true, false)]
    [InlineData("SW", false, true)]
    [InlineData("GW", true, true)]
    [InlineData("GA", true, true)]
    public void SealedGroupDescriptorProducesSeparateMembershipCapabilities(string rights, bool general, bool self)
    {
        var directory = TempDirectories.Create("membership-control-e2e");
        const string dn = "CN=DelegatedGroup,DC=contoso,DC=com";
        var subject = NotAnAccount(dn, "group");
        var descriptor = new System.Security.AccessControl.RawSecurityDescriptor($"O:SYG:SYD:(A;;{rights};;;WD)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            var id = writer.WriteObject(subject);
            writer.WriteSecurityDescriptor(id, bytes, SecureAD.Kernel.Security.AceNormalizer.Normalize(
                subject.ObjectGuid!.Value, SecureAD.Kernel.Security.SecurityDescriptorParser.Parse(bytes)));
            writer.Complete(OneDomainRead(), Finished);
        }
        Judged(directory);
        using var reader = JudgementReader.Open(directory).Value!;
        var page = reader.ReadControlEdges(dn, null, null, false, 0);
        var holder = reader.ReadControlEdges(null, "S-1-1-0", null, false, 0);
        Assert.True(page.ProductWasDerived);
        Assert.Equal(page.Edges.Select(edge => edge.Id), holder.Edges.Select(edge => edge.Id));
        Assert.Equal(general, page.Edges.Any(edge => edge.Capability == ControlCapability.CanModifyGroupMembership));
        Assert.Equal(self, page.Edges.Any(edge => edge.Capability == ControlCapability.CanAddSelfToGroup));
        if (general)
        {
            var edge = page.Edges.Single(edge => edge.Capability == ControlCapability.CanModifyGroupMembership);
            Assert.True(edge.IsComplete);
            Assert.Equal(ControlExpectedness.Unexpected, edge.Expectedness);
            Assert.Single(edge.Evidence);
        }
        if (self)
        {
            var edge = page.Edges.Single(edge => edge.Capability == ControlCapability.CanAddSelfToGroup);
            Assert.Equal(ControlEvaluationState.Unknown, edge.EvaluationState);
            Assert.Contains(edge.Preconditions, condition => condition.Name == "AddedMemberSid == RequesterSid");
            Assert.False(page.IsComplete);
        }
    }

    [Fact]
    public void SealedDescriptorProducesStoredControlEdgesThroughTheRealCoordinator()
    {
        var directory = TempDirectories.Create("control-edge-e2e");
        const string dn = "OU=Delegated,DC=contoso,DC=com";
        var subject = NotAnAccount(dn, "organizationalUnit");
        var descriptor = new System.Security.AccessControl.RawSecurityDescriptor("O:SYG:SYD:(A;;WDWO;;;WD)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());
            var id = writer.WriteObject(subject);
            writer.WriteSecurityDescriptor(id, bytes, SecureAD.Kernel.Security.AceNormalizer.Normalize(
                subject.ObjectGuid!.Value, SecureAD.Kernel.Security.SecurityDescriptorParser.Parse(bytes)));
            writer.Complete(OneDomainRead(), Finished);
        }
        Judged(directory);
        using var reader = JudgementReader.Open(directory).Value!;
        var page = reader.ReadControlEdges(dn, null, null, false, 0);
        Assert.True(page.ProductWasDerived);
        Assert.Equal(2, page.UnexpectedCount);
        Assert.Equal(2, page.Edges.Count(edge => edge.IsCounted));
        Assert.All(page.Edges.Where(edge => edge.IsCounted), edge => Assert.Equal(ControlEvaluationState.Established, edge.EvaluationState));
        Assert.Single(page.Edges.Single(edge => edge.Capability == ControlCapability.CanSetOwner).Evidence);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BuiltinAdministratorsUsesTheTargetsDomainThroughTheRealReader(bool childFirst)
    {
        var directory = TempDirectories.Create("builtin-control-scope");
        const string administrators = "S-1-5-32-544";
        var domains = new[] { (Name: "contoso.com", Sid: "S-1-5-21-1-2-3"), (Name: "child.contoso.com", Sid: "S-1-5-21-4-5-6") };
        var descriptor = new System.Security.AccessControl.RawSecurityDescriptor("O:SYG:SYD:(A;;WDWO;;;BA)");
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        using (var writer = BundleWriter.Create(directory, Started))
        {
            foreach (var domain in childFirst ? domains.Reverse() : domains)
            {
                var domainDn = string.Join(',', domain.Name.Split('.').Select(part => "DC=" + part));
                var coverage = new PartitionCoverage(domainDn, NamingContextKind.Domain, "dc01." + domain.Name,
                    ConnectionSecurityLevel.SignedAndSealed, 12, 4200, 3, [], false);
                writer.WriteCoverage(coverage);
                foreach (var (dn, objectClass, sid) in new[]
                {
                    (domainDn, "domainDNS", domain.Sid),
                    ("CN=Administrators,CN=Builtin," + domainDn, "group", administrators),
                })
                    writer.WriteObject(new EvidenceObject(coverage, dn, Guid.NewGuid(),
                    [
                        new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(objectClass)]),
                        new("objectSid", StoredAttributeCompleteness.Complete,
                            [EvidenceValue.OfBytes(SecureAD.Kernel.Security.Sid.ToBytes(sid)!)]),
                    ], Started));
                var target = new EvidenceObject(coverage, "OU=Delegated," + domainDn, Guid.NewGuid(),
                    [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("organizationalUnit")])], Started);
                var id = writer.WriteObject(target);
                writer.WriteSecurityDescriptor(id, bytes, SecureAD.Kernel.Security.AceNormalizer.Normalize(
                    target.ObjectGuid!.Value, SecureAD.Kernel.Security.SecurityDescriptorParser.Parse(bytes)));
            }
            writer.Complete(RunCoverage.Of(
                CoverageId.ForDomains("contoso.com", domains.Select(domain => domain.Name).ToArray()),
                domains.Select(domain => DomainCoverage.Read(domain.Name)).ToArray(),
                [
                    ForestPartitionCoverage.Read("CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
                ], SysvolCoverage.Of([])), Finished);
        }
        using var evidence = BundleReader.Open(directory).Value!;
        Judged(directory);
        using var reader = JudgementReader.Open(directory).Value!;
        foreach (var domain in domains)
        {
            var target = "OU=Delegated," + string.Join(',', domain.Name.Split('.').Select(part => "DC=" + part));
            var trustee = Assert.Single(evidence.ReadPermissions(target)!.Entries).Trustee;
            Assert.Null(trustee.DomainFqdn);
            Assert.Null(trustee.DistinguishedName);
            var shown = reader.ReadControlEdges(target, null, null, true, 0);
            var hidden = reader.ReadControlEdges(target, null, null, false, 0);
            var held = reader.ReadControlEdges(null, administrators, domain.Name, true, 0);
            Assert.Equal(2, shown.ExpectedCount);
            Assert.Equal(0, shown.UnknownCount);
            Assert.Equal(2, hidden.ExpectedCount);
            Assert.Empty(hidden.Edges);
            Assert.Equal(shown.Edges.Select(edge => edge.Id), held.Edges.Select(edge => edge.Id));
            Assert.All(shown.Edges, edge =>
            {
                Assert.Equal(domain.Name, edge.HolderScope);
                Assert.Equal(ControlExpectedness.Expected, edge.Expectedness);
                Assert.Equal(ControlExpectednessReason.ExpectedSameDomainControlPlane, edge.ExpectednessReason);
                Assert.Equal(2, edge.PrincipalCatalogueVersion);
            });
            Assert.All(shown.Edges.Where(edge => edge.IsCounted), edge => Assert.Equal(ControlEvaluationState.Established, edge.EvaluationState));
            Assert.Equal(ControlEvaluationState.Unknown, Assert.Single(shown.Edges.Where(edge => !edge.IsCounted)).EvaluationState);
        }
    }

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

    [Fact]
    public void AnExcludedDeclaredDomainMakesTheJudgementDegraded()
    {
        var directory = ABundleHoldingWithExcludedDomain(
            Account("bob", "CN=bob,DC=contoso,DC=com", OrdinaryAccount, 513, "user"));

        var state = Judged(directory);

        Assert.Equal(JudgementRunState.CompletedDegraded, state);
        Assert.Equal(JudgementRunState.CompletedDegraded, Read(directory).Description.State);
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

    /// <summary>
    /// An object the rule is not about does not make the judging look degraded.
    /// </summary>
    /// <remarks>
    /// <b>This is the defect a real forest found on 2026-08-26.</b> An organisational unit has no
    /// <c>userAccountControl</c> because it is not an account, and the rules were counting it as an
    /// object they could not read - 6,279 of 8,361, three in four. Every judging would have
    /// reported itself degraded, and an operator would have learned to ignore the one signal that
    /// says the findings are incomplete.
    /// </remarks>
    [Fact]
    public void AnObjectTheRuleIsNotAboutDoesNotDegradeTheJudging()
    {
        var directory = ABundleHolding(
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"),
            NotAnAccount("OU=People,DC=contoso,DC=com", "organizationalUnit"),
            NotAnAccount("CN=Builtin,DC=contoso,DC=com", "builtinDomain"));

        Assert.Equal(JudgementRunState.Completed, Judged(directory));

        var judgement = Read(directory);

        Assert.True(judgement.EveryRuleReachedEveryVerdict);
        Assert.All(judgement.RulesRun, r => Assert.Equal(0, r.ObjectsNotJudged));
        Assert.All(judgement.RulesRun, r => Assert.Equal(2, r.ObjectsNotApplicable));
        Assert.All(judgement.RulesRun, r => Assert.Equal(1, r.ObjectsJudged));
    }

    /// <summary>
    /// And an account genuinely missing a declared input still degrades it.
    /// </summary>
    /// <remarks>
    /// Without this, the check above would pass on a build that had stopped noticing gaps at all.
    /// </remarks>
    [Fact]
    public void AnAccountMissingADeclaredInputStillDegradesTheJudging()
    {
        var directory = ABundleHolding(
            NotAnAccount("OU=People,DC=contoso,DC=com", "organizationalUnit"),
            Account("ghost", "CN=ghost,OU=People,DC=contoso,DC=com", OrdinaryAccount, null, "user"));

        Assert.Equal(JudgementRunState.CompletedDegraded, Judged(directory));

        var judgement = Read(directory);

        Assert.All(judgement.RulesRun, r => Assert.Equal(1, r.ObjectsNotJudged));
        Assert.All(judgement.RulesRun, r => Assert.Equal(1, r.ObjectsNotApplicable));
    }

    /// <summary>
    /// A judging reports how far it has got.
    /// </summary>
    /// <remarks>
    /// <b>The predecessor took four to five hours over the owner's production forest.</b> A phase
    /// that long with nothing on screen is indistinguishable from one that has hung, and an
    /// operator who cannot tell the difference will kill a run that was working.
    /// </remarks>
    [Fact]
    public void AJudgingReportsHowFarItHasGot()
    {
        var directory = ABundleHolding(
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"));

        var reports = new Collected();

        JudgingRun.Judge(
            directory,
            [new UnconstrainedDelegationOnAccount()],
            Started,
            Started,
            reports,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.NotEmpty(reports.Reports);
    }

    /// <summary>
    /// The last thing a judging reports is everything it read.
    /// </summary>
    /// <remarks>
    /// Progress is reported in batches, so a run whose object count is not a whole number of
    /// batches would leave the operator looking at a total short of what was judged - and the
    /// difference between 4,999,000 and 4,999,317 is exactly the kind of discrepancy that makes
    /// someone doubt a number they should trust.
    /// </remarks>
    [Fact]
    public void TheLastProgressReportedIsEverythingThatWasRead()
    {
        var directory = ABundleHolding(
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"),
            Account("eve", "CN=eve,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"),
            NotAnAccount("OU=People,DC=contoso,DC=com", "organizationalUnit"));

        var reports = new Collected();

        JudgingRun.Judge(
            directory,
            [new UnconstrainedDelegationOnAccount()],
            Started,
            Started,
            reports,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.Equal(3, reports.Reports[^1].ObjectsRead);
    }

    /// <summary>
    /// Collects progress on the thread that reported it.
    /// </summary>
    /// <remarks>
    /// <b>Not <see cref="Progress{T}"/>, which raises its callback asynchronously.</b> Under a full
    /// suite the reports had not arrived by the time the assertion ran, so the test failed alone
    /// and passed in isolation - the shape of a flaky test, which is worse than no test because it
    /// teaches everyone to re-run the build.
    /// </remarks>
    private sealed class Collected : IProgress<JudgingRun.JudgingProgress>
    {
        public List<JudgingRun.JudgingProgress> Reports { get; } = [];

        public void Report(JudgingRun.JudgingProgress value) => Reports.Add(value);
    }

    /// <summary>
    /// A judging that is asked to stop, stops.
    /// </summary>
    [Fact]
    public void AJudgingStopsWhenItIsAskedTo()
    {
        var directory = ABundleHolding(
            Account("bob", "CN=bob,OU=People,DC=contoso,DC=com", OrdinaryAccount, 513, "user"));

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        Assert.Throws<OperationCanceledException>(() => JudgingRun.Judge(
            directory,
            [new UnconstrainedDelegationOnAccount()],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            cancelled.Token));
    }

    /// <summary>
    /// Cancelling a re-judging leaves the earlier judgement intact.
    /// </summary>
    /// <remarks>
    /// <b>This is what makes cancelling safe to offer.</b> A judging runs for hours, so an operator
    /// will stop one - and if stopping cost him the answer he already had, he would learn not to.
    /// The partial file is never renamed over the finished one, which is the same protection a
    /// crash gets.
    /// </remarks>
    [Fact]
    public void CancellingARejudgingLeavesTheEarlierJudgementIntact()
    {
        var directory = ABundleHolding(
            Account("svc-web", "CN=svc-web,OU=People,DC=contoso,DC=com", TrustedForDelegation, 513, "user"));

        Judged(directory);

        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        try
        {
            JudgingRun.Judge(
                directory,
                [new UnconstrainedDelegationOnAccount()],
                Started,
                Started,
                JudgingRun.NobodyIsWatching,
                RunLog.Discarded,
                cancelled.Token);
        }
        catch (OperationCanceledException)
        {
            // The cancellation is the point; what survives it is what this test is about.
        }

        Assert.Single(Read(directory).Findings);
    }

    private static JudgementRunState Judged(string directory)
    {
        var judged = JudgingRun.Judge(
            directory,
            [new UnconstrainedDelegationOnAccount(), new UnconstrainedDelegationOnNonDomainController()],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

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
        var directory = TempDirectories.Create("judging-e2e");

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());

            foreach (var subject in objects)
                writer.WriteObject(subject);

            writer.Complete(OneDomainRead(), Finished);
        }

        return directory;
    }

    private static string ABundleHoldingWithExcludedDomain(params EvidenceObject[] objects)
    {
        var directory = TempDirectories.Create("judging-e2e");

        using (var writer = BundleWriter.Create(directory, Started))
        {
            writer.WriteCoverage(SomeCoverage());

            foreach (var subject in objects)
                writer.WriteObject(subject);

            writer.Complete(
                RunCoverage.Of(
                    CoverageId.ForDomainsExcluding(
                        "contoso.com",
                        ["contoso.com", "child.contoso.com"],
                        ["child.contoso.com"]),
                    [
                        DomainCoverage.Read("contoso.com"),
                        DomainCoverage.Excluded(
                            "child.contoso.com",
                            ExclusionKind.ByChoice,
                            "Excluded for this reproduction."),
                    ],
                    [
                        ForestPartitionCoverage.Read(
                            "CN=Configuration,DC=contoso,DC=com", NamingContextKind.Configuration),
                        ForestPartitionCoverage.Read(
                            "CN=Schema,CN=Configuration,DC=contoso,DC=com", NamingContextKind.Schema),
                    ],
                    SysvolCoverage.Of([])),
                Finished);
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

    /// <summary>
    /// An object that is not a security principal: no <c>userAccountControl</c> and no
    /// <c>primaryGroupID</c>, because its class does not have them.
    /// </summary>
    private static EvidenceObject NotAnAccount(string distinguishedName, string objectClass) =>
        new(
            SomeCoverage(),
            distinguishedName,
            Guid.NewGuid(),
            [
                new EvidenceAttribute(
                    "objectClass",
                    StoredAttributeCompleteness.Complete,
                    [EvidenceValue.OfText("top"), EvidenceValue.OfText(objectClass)]),
            ],
            Started);

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
