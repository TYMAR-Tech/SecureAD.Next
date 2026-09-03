using System.Globalization;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// SEC-094 against the cases its specification names.
/// </summary>
/// <remarks>
/// <para>
/// <b>These run the whole stage rather than calling the rule directly</b>, for the reason SEC-021's
/// tests give: a test handing the rule a fabricated <c>JudgingContext</c> would prove the rule agrees
/// with itself. Each builds a sealed bundle carrying a schema partition, derives it, judges it and
/// reads the judgement back - so the visibility answer this rule turns on is one the derivation
/// worked out from schema objects, not one a test asserted.
/// </para>
/// <para>
/// <b>The first test in this file is the one the rule most easily fails.</b> A machine that has been
/// migrated successfully carries both timestamps, because Microsoft's migration procedure never
/// clears the legacy attribute. A rule reading the legacy value as significant would report every
/// successfully migrated machine in the estate - the largest population in exactly the
/// organisations this rule is for - and would still pass every positive test below it.
/// </para>
/// </remarks>
public sealed class WindowsLapsNotAppliedOnCapableComputerTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    private const string Forest = "ad.lab";

    /// <summary>A FILETIME in 2024. What either product writes when it manages a machine.</summary>
    private const string Timestamp = "133700000000000000";

    /// <summary>Windows Server 2022, which Microsoft supports Windows LAPS on.</summary>
    private const string ModernServer = "Windows Server 2022 Datacenter";
    private const string ModernServerBuild = "10.0 (20348)";

    /// <summary>
    /// Windows Server 2016, which Microsoft never shipped Windows LAPS for. Its build is shared
    /// with Windows 10 1607, which is why the name is needed beside the number.
    /// </summary>
    private const string LegacyServer = "Windows Server 2016 Datacenter";
    private const string LegacyServerBuild = "10.0 (14393)";

    /// <summary>
    /// A migrated machine carries both timestamps and is not reported.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the rule.</b> Microsoft's migration procedure disables or removes the legacy
    /// policy and then the legacy software, and touches no directory attribute at any point - so
    /// <c>ms-Mcs-AdmPwdExpirationTime</c> survives indefinitely as residue on a machine that is
    /// being managed perfectly well by Windows LAPS.
    /// </para>
    /// <para>
    /// <b>What Microsoft names as success is present here</b>: <i>"you can look for the appearance
    /// of a new or updated <c>msLAPS-PasswordExpirationTime</c> attribute on the managed device's AD
    /// computer object."</i> The rule reports the absence of that confirmation, and nothing else.
    /// </para>
    /// </remarks>
    [Fact]
    public void AMigratedMachineCarryingBothTimestampsIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            WindowsLapsExpiration = Timestamp,
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// A modern-capable machine carrying only the legacy timestamp is reported, at Low.
    /// </summary>
    [Fact]
    public void AModernCapableMachineWithOnlyTheLegacyTimestampIsReported()
    {
        var finding = Assert.Single(Judge(Machine() with { LegacyLapsExpiration = Timestamp }));

        Assert.Equal("SEC-094", finding.RuleId);
        Assert.Equal(Severity.Low, finding.Severity);

        var evidence = Assert.IsType<LapsDeploymentEvidence>(finding.Evidence);
        Assert.Equal(LapsTimestampReading.Absent, evidence.WindowsLaps);
        Assert.Equal(LapsTimestampReading.Present, evidence.LegacyLaps);
        Assert.Equal(LapsCapabilityKind.WindowsLapsCapable, evidence.Capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, evidence.Capability.Basis);

        // The finding never asserts which of the two causes applies, because the evidence that
        // separates them is on the machine and not in the directory.
        Assert.Contains("emulation", finding.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "Group Policy is not applying", finding.Detail, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A machine carrying the modern timestamp alone is not reported.
    /// </summary>
    /// <remarks>The healthy state, and the commonest on an estate that finished its migration.</remarks>
    [Fact]
    public void AMachineCarryingTheModernTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with { WindowsLapsExpiration = Timestamp }));

    /// <summary>
    /// A machine carrying neither timestamp is not reported here.
    /// </summary>
    /// <remarks>That is SEC-091, and it is the more serious finding.</remarks>
    [Fact]
    public void AMachineCarryingNeitherTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine()));

    /// <summary>
    /// A Server 2016 machine carrying only the legacy timestamp is not reported.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The capability test is the whole exclusion.</b> Microsoft never backported Windows LAPS to
    /// Server 2016, so the absence of a modern timestamp says nothing about how the machine is
    /// configured. Reporting it would be reporting a machine for not running software Microsoft
    /// never shipped for it.
    /// </para>
    /// <para>
    /// <b>The lab contains two of these and they carry exactly the attribute pattern this rule
    /// looks for.</b> If the classifier is wrong they fire, which is why this control exists before
    /// the lab run rather than after it.
    /// </para>
    /// </remarks>
    [Fact]
    public void AServer2016MachineWithOnlyTheLegacyTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            OperatingSystem = LegacyServer,
            OperatingSystemVersion = LegacyServerBuild,
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// A Server 2016 machine carrying the modern timestamp is not reported either.
    /// </summary>
    /// <remarks>
    /// Microsoft says that operating system cannot run Windows LAPS, so the combination should not
    /// occur. It is a grid state rather than a finding: the machine is managed and there is no
    /// exposure to report, and <c>docs/decisions/0081</c> carries no Info severity.
    /// </remarks>
    [Fact]
    public void AServer2016MachineCarryingTheModernTimestampIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            OperatingSystem = LegacyServer,
            OperatingSystemVersion = LegacyServerBuild,
            WindowsLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// A domain controller carrying only the legacy timestamp is not reported.
    /// </summary>
    /// <remarks>
    /// <b>And it is excluded outside the Domain Controllers container</b>, which is the case the
    /// predecessor's distinguished-name test got wrong. <c>DomainControllerSignals</c> treats any of
    /// its three signals as enough, so the <c>SERVER_TRUST_ACCOUNT</c> bit alone settles it.
    /// </remarks>
    [Fact]
    public void ADomainControllerIsNotReportedEvenOutsideItsContainer() =>
        Assert.Empty(Judge(Machine() with
        {
            Dn = "CN=DC02,OU=Moved,DC=ad,DC=lab",
            UserAccountControl = 0x2000,
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// A machine nobody can identify is not reported.
    /// </summary>
    /// <remarks>
    /// <b>The deliberate asymmetry with SEC-091.</b> An unknown operating system does not stop
    /// SEC-091, because <i>no LAPS at all</i> is worth reporting whatever the machine is. It stops
    /// this rule, because this rule's entire claim is <i>this machine could be running Windows
    /// LAPS</i>, and that cannot be said about a machine nobody can identify.
    /// </remarks>
    [Fact]
    public void AMachineWhoseOperatingSystemIsUnknownIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            OperatingSystem = null,
            OperatingSystemVersion = null,
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// A user object is not reported, whatever it carries.
    /// </summary>
    [Fact]
    public void ANonComputerObjectIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            ObjectClasses = ["top", "person", "organizationalPerson", "user"],
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// Where the forest withholds the modern timestamp, nothing is reported and the rule says it
    /// could not judge.
    /// </summary>
    /// <remarks>
    /// <b>This is the test that protects a hardened estate, and it matters more here than in
    /// SEC-091.</b> If <c>msLAPS-PasswordExpirationTime</c> were confidential, every modern-capable
    /// machine carrying a legacy value would be reported and every one of those findings would be
    /// false. SEC-091 degrades to silence in that case; this rule degrades to a wall of wrong
    /// answers.
    /// </remarks>
    [Fact]
    public void AForestWithholdingTheModernTimestampProducesNoFindings()
    {
        var judgement = JudgeWhole(Machine() with { LegacyLapsExpiration = Timestamp }, Confidential: true);

        Assert.Empty(judgement.Findings);

        var execution = Assert.Single(judgement.RulesRun);
        Assert.Equal(RuleExecutionOutcome.Indeterminate, execution.Outcome);
        Assert.Contains(
            "msLAPS-PasswordExpirationTime",
            execution.MissingInputs.Select(i => i.Attribute));
    }

    /// <summary>
    /// A forest whose schema never carried the Windows LAPS extension produces no findings.
    /// </summary>
    /// <remarks>
    /// No machine in it can carry the attribute, so its absence is not evidence about any machine.
    /// Reporting here would report the whole estate for the state of its schema.
    /// </remarks>
    [Fact]
    public void AForestWithoutTheWindowsLapsExtensionProducesNoFindings() =>
        Assert.Empty(JudgeWhole(
            Machine() with { LegacyLapsExpiration = Timestamp },
            Confidential: false,
            WindowsLapsInSchema: false).Findings);

    /// <summary>
    /// A disabled computer account is not reported, even carrying exactly the attribute pattern this
    /// rule looks for.
    /// </summary>
    /// <remarks>
    /// Excluded for the reason SEC-091 gives, which the first <c>ad.lab</c> run raised: a disabled
    /// account has no running machine, so there is nothing for a Windows LAPS policy to reach and
    /// nothing to migrate.
    /// </remarks>
    [Fact]
    public void ADisabledComputerAccountIsNotReported() =>
        Assert.Empty(Judge(Machine() with
        {
            UserAccountControl = 4098,
            LegacyLapsExpiration = Timestamp,
        }));

    /// <summary>
    /// An enabled machine with the same attributes is still reported, so the exclusion is not a
    /// blanket one.
    /// </summary>
    [Fact]
    public void AnEnabledMachineWithTheSameAttributesIsStillReported() =>
        Assert.Single(Judge(Machine() with
        {
            UserAccountControl = 0x1000,
            LegacyLapsExpiration = Timestamp,
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

        /// <summary>An ordinary member server: WORKSTATION_TRUST_ACCOUNT.</summary>
        public uint UserAccountControl { get; init; } = 0x1000;
    }

    private static Subject Machine() => new();

    private static IReadOnlyList<Finding> Judge(Subject subject) =>
        JudgeWhole(subject, Confidential: false).Findings;

    private static StoredJudgement JudgeWhole(
        Subject subject,
        bool Confidential,
        bool WindowsLapsInSchema = true)
    {
        var directory = LapsBundle.Build(
            subject.Dn,
            subject.ObjectClasses,
            subject.OperatingSystem,
            subject.OperatingSystemVersion,
            subject.WindowsLapsExpiration,
            subject.LegacyLapsExpiration,
            subject.UserAccountControl,
            Confidential,
            WindowsLapsInSchema,
            Started);

        Assert.True(
            Stage2aRun.Derive(
                directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched,
                RunLog.Discarded, CancellationToken.None).IsSuccess);

        var judged = JudgingRun.Judge(
            directory,
            [new WindowsLapsNotAppliedOnCapableComputer()],
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
