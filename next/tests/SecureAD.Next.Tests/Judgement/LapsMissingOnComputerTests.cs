using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-091 against the cases its specification names.
/// </summary>
/// <remarks>
/// <para>
/// <b>These run the whole stage</b>, through the same <see cref="LapsBundle"/> SEC-094's tests use,
/// so the two rules are tested against one forest and the boundary between them is exercised rather
/// than assumed.
/// </para>
/// <para>
/// <b>The negative controls are the rule.</b> A rule reporting every computer would satisfy the
/// positive test below and would report an entire estate.
/// </para>
/// </remarks>
public sealed class LapsMissingOnComputerTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    private const string Timestamp = "133700000000000000";
    private const string ModernServer = "Windows Server 2022 Datacenter";
    private const string ModernServerBuild = "10.0 (20348)";
    private const string LegacyServer = "Windows Server 2016 Datacenter";
    private const string LegacyServerBuild = "10.0 (14393)";

    /// <summary>
    /// A computer carrying neither timestamp is reported, at Medium.
    /// </summary>
    [Fact]
    public void AComputerWithNeitherTimestampIsReported()
    {
        var finding = Assert.Single(Judge(Machine()));

        Assert.Equal("SEC-091", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);

        var evidence = Assert.IsType<LapsDeploymentEvidence>(finding.Evidence);
        Assert.Equal(LapsTimestampReading.Absent, evidence.WindowsLaps);
        Assert.Equal(LapsTimestampReading.Absent, evidence.LegacyLaps);
        Assert.Equal(ModernServer, evidence.Capability.Name);

        // The Entra ID blind spot is named where an operator will read it, because the product
        // cannot detect it and he can.
        Assert.Contains("Entra ID", finding.Detail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A computer managed by Windows LAPS is not reported.
    /// </summary>
    [Fact]
    public void AComputerManagedByWindowsLapsIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = Timestamp }));

    /// <summary>
    /// A computer managed by legacy Microsoft LAPS is not reported.
    /// </summary>
    /// <remarks>
    /// Either timestamp means something is rotating the password. Which product is doing it is a
    /// migration question, and it is SEC-094's.
    /// </remarks>
    [Fact]
    public void AComputerManagedByLegacyLapsIsNotReported() =>
        Assert.Empty(Judge(Machine() with { LegacyLapsExpiration = Timestamp }));

    /// <summary>
    /// A modern server carrying only the legacy timestamp is not reported here.
    /// </summary>
    /// <remarks>
    /// <b>The case the specification got wrong first, and the one <c>ph.ad.lab</c> actually
    /// contains.</b> It is SEC-094, not silence and not this rule.
    /// </remarks>
    [Fact]
    public void AModernServerWithOnlyTheLegacyTimestampIsNotReportedHere() =>
        Assert.Empty(Judge(Machine() with
        {
            OperatingSystem = ModernServer,
            OperatingSystemVersion = ModernServerBuild,
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// A client with no LAPS attribute is reported exactly as a server is.
    /// </summary>
    /// <remarks>
    /// <b>The scope decision of 2026-09-03, and the lab cannot exercise it</b> - every client in
    /// <c>ad.lab</c> is already managed. Without this test the decision would be unmeasured in both
    /// the suite and the forest.
    /// </remarks>
    [Fact]
    public void AClientWithNoLapsAttributeIsReportedAtTheSameSeverityAsAServer()
    {
        var finding = Assert.Single(Judge(Machine() with
        {
            Dn = "CN=WS01,OU=Clients,DC=ad,DC=lab",
            OperatingSystem = "Windows 11 Enterprise",
            OperatingSystemVersion = "10.0 (22631)",
        }));

        Assert.Equal(Severity.Medium, finding.Severity);

        var evidence = Assert.IsType<LapsDeploymentEvidence>(finding.Evidence);
        Assert.False(evidence.Capability.IsServer);
    }

    /// <summary>
    /// A domain controller with no LAPS attribute is not reported, including outside its container.
    /// </summary>
    /// <remarks>
    /// <b>The case the predecessor's distinguished-name test got wrong.</b> Its own backlog flagged
    /// the container match as brittle under <c>[IMP-DC-DETECT]</c>.
    /// </remarks>
    [Fact]
    public void ADomainControllerIsNotReportedEvenOutsideItsContainer() =>
        Assert.Empty(Judge(Machine() with
        {
            Dn = "CN=DC02,OU=Moved,DC=ad,DC=lab",
            UserAccountControl = 0x2000,
        }));

    /// <summary>
    /// A domain controller identified only by its primary group is not reported either.
    /// </summary>
    /// <remarks>
    /// The child-domain trap: a child domain's controller also holds a member-server computer
    /// account in the parent domain, so any one of the three signals has to be enough.
    /// </remarks>
    [Fact]
    public void ADomainControllerIdentifiedByItsPrimaryGroupIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            Dn = "CN=DC03,OU=Moved,DC=ad,DC=lab",
            UserAccountControl = 0x1000,
            PrimaryGroupId = 516,
        }));

    /// <summary>
    /// A user object is not reported.
    /// </summary>
    /// <remarks>
    /// Tested through the real <c>objectClass</c> chain. LAPS attributes live on the computer
    /// class - Microsoft: the <c>Update-LapsADSchema</c> cmdlet "adds the schema attributes to the
    /// directory and to the <c>mayContain</c> list on the computer schema class".
    /// </remarks>
    [Fact]
    public void AUserObjectIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            Dn = "CN=jsmith,CN=Users,DC=ad,DC=lab",
            ObjectClasses = ["top", "person", "organizationalPerson", "user"],
        }));

    /// <summary>
    /// A machine whose operating system is unknown is still reported.
    /// </summary>
    /// <remarks>
    /// <b>The deliberate asymmetry with SEC-094.</b> No LAPS at all is worth reporting whatever the
    /// machine is, so an unknown operating system does not stop this rule. It stops SEC-094,
    /// because that rule claims the machine could be running Windows LAPS.
    /// </remarks>
    [Fact]
    public void AMachineWithNoOperatingSystemIsStillReported()
    {
        var finding = Assert.Single(Judge(Machine() with
        {
            OperatingSystem = null,
            OperatingSystemVersion = null,
        }));

        var evidence = Assert.IsType<LapsDeploymentEvidence>(finding.Evidence);
        Assert.Equal(LapsCapabilityKind.Unknown, evidence.Capability.Kind);
        Assert.Equal(LapsCapabilityBasis.NothingToReadFrom, evidence.Capability.Basis);
        Assert.Null(evidence.Capability.IsServer);
    }

    /// <summary>
    /// A bundle sealed before the build number was captured is still judged, and says so.
    /// </summary>
    [Fact]
    public void AMachineWithNoBuildNumberIsJudgedFromItsNameAndRecordsThat()
    {
        var finding = Assert.Single(Judge(Machine() with
        {
            OperatingSystem = LegacyServer,
            OperatingSystemVersion = null,
        }));

        var evidence = Assert.IsType<LapsDeploymentEvidence>(finding.Evidence);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemName, evidence.Capability.Basis);
    }

    /// <summary>
    /// Where the forest withholds the attribute, nothing is reported and the rule says it could not
    /// judge.
    /// </summary>
    /// <remarks>
    /// <b>This is the test that protects a hardened estate.</b> Silence here is not a statement that
    /// the machine is managed, and a finding here would be a false accusation against a forest that
    /// did the more careful thing.
    /// </remarks>
    [Fact]
    public void AForestWithholdingTheTimestampProducesNoFindings()
    {
        var judgement = JudgeWhole(Machine(), confidential: true);

        Assert.Empty(judgement.Findings);

        var execution = Assert.Single(judgement.RulesRun);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Contains(
            LapsAttributes.WindowsLapsExpiration,
            execution.MissingInputs.Select(i => i.Attribute));
    }

    /// <summary>
    /// A disabled computer account is not reported.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The forest found this, not the suite.</b> The first <c>ad.lab</c> run reported
    /// <c>CN=BADC,CN=Computers,DC=ad,DC=lab</c> and <c>CN=PHDC,CN=Computers,DC=ad,DC=lab</c> at
    /// Medium, telling an operator to deploy Windows LAPS to them. Both carry
    /// <c>userAccountControl</c> 4098 - the value used here - and both are stale accounts left
    /// behind when those machines were promoted into child domains. There is no running machine, so
    /// the advice could not be followed.
    /// </para>
    /// <para>
    /// <b>Note what this case is not.</b> Neither object is identifiable as a domain controller from
    /// its own attributes: 4098 is a workstation trust account, the primary group is 515, and both
    /// sit in <c>CN=Computers</c>. <c>DomainControllerSignals</c> reads one object and cannot see
    /// the controller those names belong to in another domain, so the exclusion has to be the
    /// disabled state rather than the controller test.
    /// </para>
    /// </remarks>
    [Fact]
    public void ADisabledComputerAccountIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            Dn = "CN=BADC,CN=Computers,DC=ad,DC=lab",
            UserAccountControl = 4098,
        }));

    /// <summary>
    /// An enabled computer with the same shape is still reported, so the exclusion is not a blanket
    /// one.
    /// </summary>
    /// <remarks>
    /// A rule that excluded every computer would pass the test above. This is what stops that.
    /// </remarks>
    [Fact]
    public void AnEnabledComputerInTheSamePlaceIsStillReported() =>
        Assert.Single(Judge(Machine() with
        {
            Dn = "CN=BADC,CN=Computers,DC=ad,DC=lab",
            UserAccountControl = 0x1000,
        }));

    /// <summary>One object's shape, so each test states only what it changes.</summary>
    private sealed record Subject
    {
        public string Dn { get; init; } = "CN=FS01,OU=Servers,DC=ad,DC=lab";

        public IReadOnlyList<string> ObjectClasses { get; init; } =
            ["top", "person", "organizationalPerson", "user", "computer"];

        public string? OperatingSystem { get; init; } = ModernServer;
        public string? OperatingSystemVersion { get; init; } = ModernServerBuild;
        public string? WindowsLapsExpiration { get; init; }
        public string? LegacyLapsExpiration { get; init; }
        public uint UserAccountControl { get; init; } = 0x1000;
        public int? PrimaryGroupId { get; init; }
    }

    private static Subject Machine() => new();

    private static IReadOnlyList<Finding> Judge(Subject subject) =>
        JudgeWhole(subject, confidential: false).Findings;

    private static StoredJudgement JudgeWhole(Subject subject, bool confidential)
    {
        var directory = LapsBundle.Build(
            subject.Dn,
            subject.ObjectClasses,
            subject.OperatingSystem,
            subject.OperatingSystemVersion,
            subject.WindowsLapsExpiration,
            subject.LegacyLapsExpiration,
            subject.UserAccountControl,
            confidential,
            windowsLapsInSchema: true,
            Started,
            subject.PrimaryGroupId);

        Assert.True(
            Stage2aRun.Derive(
                directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched,
                RunLog.Discarded, CancellationToken.None).IsSuccess);

        var judged = JudgingRun.Judge(
            directory,
            [new LapsMissingOnComputer()],
            Started,
            Started,
            JudgingRun.NobodyIsWatching,
            RunLog.Discarded,
            CancellationToken.None);

        Assert.True(judged.IsSuccess, judged.Error?.Description);

        using var reader = JudgementReader.Open(directory).Value!;
        return reader.Read();
    }
}
