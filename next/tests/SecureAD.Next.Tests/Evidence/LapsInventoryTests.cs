using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Evidence;

/// <summary>
/// The LAPS inventory: which machines are managed, by what, and which the rules leave alone.
/// </summary>
/// <remarks>
/// <para>
/// <b>The inventory exists because the findings store cannot answer the question.</b> <i>Which
/// machines have modern, which have legacy, which have none</i> includes the healthy ones, and a
/// findings store holds only what a rule reported. So this reads sealed evidence, and these tests
/// build a bundle and read it back.
/// </para>
/// <para>
/// <b>The test that matters most is <see cref="TheGridAndTheRuleAgreeAboutOneMachine"/>.</b> The
/// predecessor's LAPS feature tested for a domain controller three different ways in one screen. A
/// grid that classified a machine differently from the rule judging it would put two answers about
/// one computer in front of an operator with nothing to say which was right.
/// </para>
/// </remarks>
public sealed class LapsInventoryTests
{
    private static readonly DateTimeOffset Started = new(2026, 9, 3, 9, 0, 0, TimeSpan.Zero);

    private const string Timestamp = "133700000000000000";
    private const string ModernServer = "Windows Server 2022 Datacenter";
    private const string ModernServerBuild = "10.0 (20348)";
    private const string LegacyServer = "Windows Server 2016 Datacenter";
    private const string LegacyServerBuild = "10.0 (14393)";

    private const string Root = "DC=ad,DC=lab";

    [Fact]
    public void AMachineWithTheModernTimestampIsManagedByWindowsLaps() =>
        Assert.Equal(
            LapsManagement.WindowsLaps,
            Row(modern: Timestamp).Management);

    [Fact]
    public void AMachineWithOnlyTheLegacyTimestampIsManagedByLegacyLaps() =>
        Assert.Equal(
            LapsManagement.LegacyLaps,
            Row(legacy: Timestamp).Management);

    /// <summary>
    /// A machine carrying both timestamps is shown as migrated, not as two states at once.
    /// </summary>
    /// <remarks>
    /// The legacy attribute is never cleared by a migration, so this is the ordinary state of a
    /// successfully migrated estate rather than an anomaly.
    /// </remarks>
    [Fact]
    public void AMachineWithBothTimestampsIsMigrated() =>
        Assert.Equal(
            LapsManagement.Migrated,
            Row(modern: Timestamp, legacy: Timestamp).Management);

    [Fact]
    public void AMachineWithNeitherTimestampIsNotManaged() =>
        Assert.Equal(LapsManagement.NotManaged, Row().Management);

    /// <summary>
    /// A Server 2016 machine carrying the modern timestamp is shown as Unexpected.
    /// </summary>
    /// <remarks>
    /// <b>Microsoft says this cannot happen, and the grid is where it is said.</b> The machine is
    /// managed and there is no exposure, so it is not a finding - <c>docs/decisions/0081</c> carries
    /// no Info severity. It cannot occur in the lab either, which is why it needs a fixture.
    /// </remarks>
    [Fact]
    public void AMachineTooOldForWindowsLapsCarryingTheModernTimestampIsUnexpected() =>
        Assert.Equal(
            LapsManagement.Unexpected,
            Row(modern: Timestamp, os: LegacyServer, version: LegacyServerBuild).Management);

    /// <summary>
    /// A domain controller is listed rather than filtered out, and says it is one.
    /// </summary>
    /// <remarks>
    /// <b>This is the difference between the grid and the rules.</b> Both rules are silent about a
    /// domain controller; an operator who could not see it here would have no way to tell a machine
    /// the product deliberately ignored from one it never captured.
    /// </remarks>
    [Fact]
    public void ADomainControllerIsListedAndSaysSo()
    {
        var row = Row(uac: 0x82000, primaryGroupId: 516);

        Assert.True(row.DomainController.IsDomainController);
        Assert.False(row.IsJudged);
    }

    /// <summary>
    /// A disabled account is listed rather than filtered out, and says it is disabled.
    /// </summary>
    /// <remarks>
    /// The two objects the first <c>ad.lab</c> run reported as findings were of exactly this shape.
    /// This row is where they belong.
    /// </remarks>
    [Fact]
    public void ADisabledAccountIsListedAndSaysSo()
    {
        var row = Row(uac: 4098);

        Assert.True(row.IsDisabled);
        Assert.False(row.IsJudged);
        Assert.False(row.DomainController.IsDomainController);
    }

    [Fact]
    public void AnOrdinaryMemberServerIsInScopeOfTheRules()
    {
        var row = Row(uac: 0x1000);

        Assert.False(row.IsDisabled);
        Assert.False(row.DomainController.IsDomainController);
        Assert.True(row.IsJudged);
    }

    /// <summary>
    /// The grid and SEC-094 reach the same conclusion about one machine.
    /// </summary>
    /// <remarks>
    /// <b>The anchor that stops the two drifting apart.</b> The machine is a Server 2016 carrying
    /// only the legacy timestamp: the grid must call it <see cref="LapsManagement.LegacyLaps"/> and
    /// the rule must stay silent, and both answers rest on the same capability classification. If a
    /// second classifier ever appeared in either, this fails.
    /// </remarks>
    [Fact]
    public void TheGridAndTheRuleAgreeAboutOneMachine()
    {
        var directory = LapsBundle.Build(
            "CN=PH2016,OU=Servers,DC=ad,DC=lab",
            ["top", "person", "organizationalPerson", "user", "computer"],
            LegacyServer,
            LegacyServerBuild,
            windowsLapsExpiration: null,
            legacyLapsExpiration: Timestamp,
            userAccountControl: 0x1000,
            confidential: false,
            windowsLapsInSchema: true,
            Started);

        // What the grid says.
        using var reader = BundleReader.Open(directory).Value!;
        var listed = Assert.Single(
            reader.ListLapsComputers(Root, ListingScope.Subtree, 1).Computers);

        Assert.Equal(LapsManagement.LegacyLaps, listed.Management);
        Assert.Equal(LapsCapabilityKind.LegacyLapsOnly, listed.Capability.Kind);
        Assert.True(listed.IsJudged);
        reader.Dispose();

        // What the rule says about the same machine, through a whole derive and judge.
        Assert.True(
            Stage2aRun.Derive(
                directory, ExpansionBudget.Bulk, Started, Stage2aRun.Unwatched,
                RunLog.Discarded, CancellationToken.None).IsSuccess);

        Assert.True(
            JudgingRun.Judge(
                directory,
                [new WindowsLapsNotAppliedOnCapableComputer()],
                Started,
                Started,
                JudgingRun.NobodyIsWatching,
                RunLog.Discarded,
                CancellationToken.None).IsSuccess);

        using var judgement = JudgementReader.Open(directory).Value!;

        // The rule is silent, and the grid says why without the operator having to guess: the
        // machine is legacy-capable only, so no modern timestamp was ever expected of it.
        Assert.Empty(judgement.Read().Findings);
    }

    /// <summary>
    /// The listing counts every machine in scope, not the page it returned.
    /// </summary>
    [Fact]
    public void TheCountsCoverTheWholeListingAndNameEachState()
    {
        var directory = LapsBundle.BuildMany(
            [
                ("CN=WS01,OU=Clients,DC=ad,DC=lab", ModernServer, ModernServerBuild, Timestamp, null, 0x1000u),
                ("CN=FS01,OU=Servers,DC=ad,DC=lab", ModernServer, ModernServerBuild, null, Timestamp, 0x1000u),
                ("CN=FS02,OU=Servers,DC=ad,DC=lab", ModernServer, ModernServerBuild, null, null, 0x1000u),
                ("CN=OLD1,OU=Servers,DC=ad,DC=lab", LegacyServer, LegacyServerBuild, Timestamp, null, 0x1000u),
            ],
            Started);

        using var reader = BundleReader.Open(directory).Value!;
        var page = reader.ListLapsComputers(Root, ListingScope.Subtree, 1);

        Assert.Equal(4, page.Total);
        Assert.Equal(4, page.Computers.Count);
        Assert.True(page.ComputersAreComplete);
        Assert.Null(page.Shortfall);

        Assert.Equal(1, page.CountOf(LapsManagement.WindowsLaps));
        Assert.Equal(1, page.CountOf(LapsManagement.LegacyLaps));
        Assert.Equal(1, page.CountOf(LapsManagement.NotManaged));
        Assert.Equal(1, page.CountOf(LapsManagement.Unexpected));

        // A state nothing is in answers zero rather than being absent, so a caller never has to
        // work out whether it was measured.
        Assert.Equal(0, page.CountOf(LapsManagement.Migrated));
    }

    /// <summary>
    /// A group managed service account is not listed as a machine.
    /// </summary>
    /// <remarks>
    /// <b>Its <c>objectClass</c> chain contains <c>computer</c>.</b> Against <c>ad.lab</c> on
    /// 2026-09-03 the rules were offered 14 objects against 11 computers for exactly this reason,
    /// and a grid asking whether <c>computer</c> was merely present would show three accounts that
    /// have no local administrator password to manage.
    /// </remarks>
    [Fact]
    public void AGroupManagedServiceAccountIsNotListed()
    {
        var directory = LapsBundle.Build(
            "CN=TestgMSA,CN=Managed Service Accounts,DC=ad,DC=lab",
            ["top", "person", "organizationalPerson", "user", "computer",
             "msDS-GroupManagedServiceAccount"],
            operatingSystem: null,
            operatingSystemVersion: null,
            windowsLapsExpiration: null,
            legacyLapsExpiration: null,
            userAccountControl: 0x1000,
            confidential: false,
            windowsLapsInSchema: true,
            Started);

        using var reader = BundleReader.Open(directory).Value!;

        Assert.Empty(reader.ListLapsComputers(Root, ListingScope.Subtree, 1).Computers);
    }

    /// <summary>
    /// The scope an operator selected is honoured, so one OU can be watched during a rollout.
    /// </summary>
    [Fact]
    public void ThePageIsScopedToTheSelectedContainer()
    {
        var directory = LapsBundle.BuildMany(
            [
                ("CN=WS01,OU=Clients,DC=ad,DC=lab", ModernServer, ModernServerBuild, Timestamp, null, 0x1000u),
                ("CN=FS01,OU=Servers,DC=ad,DC=lab", ModernServer, ModernServerBuild, null, null, 0x1000u),
            ],
            Started);

        using var reader = BundleReader.Open(directory).Value!;
        var page = reader.ListLapsComputers("OU=Servers,DC=ad,DC=lab", ListingScope.Subtree, 1);

        Assert.Equal("FS01", Assert.Single(page.Computers).Name);
        Assert.Equal(1, page.Total);
    }

    /// <summary>One row, built without touching a database, for the classification cases.</summary>
    private static LapsComputer Row(
        string? modern = null,
        string? legacy = null,
        string os = ModernServer,
        string version = ModernServerBuild,
        uint uac = 0x1000,
        int? primaryGroupId = null) =>
        new(
            "CN=FS01,OU=Servers,DC=ad,DC=lab",
            "FS01",
            Guid.NewGuid(),
            "ad.lab",
            modern,
            legacy,
            os,
            version,
            uac,
            primaryGroupId);
}
