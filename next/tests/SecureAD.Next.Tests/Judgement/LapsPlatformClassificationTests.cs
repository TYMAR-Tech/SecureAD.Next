using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsPlatformClassificationTests
{
    private const string Root = "DC=ad,DC=lab";
    private const string Dn = "CN=SyntheticScout04,OU=Servers," + Root;
    private const string Timestamp = "133700000000000000";
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;

    public static IEnumerable<object[]> ServerFallbacks()
    {
        foreach (var version in new[]
        {
            "10.0", "10.0 (oops)", "10.0 ()", "10.0 ( )", "10.0 (",
            "10.0 (20348", "10.0 (2147483648)", "10.0 (-1)", "10.0 (0)",
        })
            yield return ["Windows Server 2022", version, LapsCapabilityKind.WindowsLapsCapable];
        yield return ["Windows Server 2019", "10.0", LapsCapabilityKind.WindowsLapsCapable];
        yield return ["Windows Server 2025", "10.0 (oops)", LapsCapabilityKind.WindowsLapsCapable];
        yield return ["Windows Server 2016", "10.0", LapsCapabilityKind.LegacyLapsOnly];
        yield return ["Windows Server vNext", "10.0", LapsCapabilityKind.Unknown];
    }

    [Theory]
    [MemberData(nameof(ServerFallbacks))]
    public void AServerWithoutAUsableBuildUsesItsNameOrRemainsUnknown(
        string name, string version, LapsCapabilityKind expected)
    {
        var capability = LapsCapability.Of(name, version);
        Assert.Equal(expected, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemName, capability.Basis);
        Assert.Equal((name, version), (capability.Name, capability.Version));
    }

    [Theory]
    [InlineData("Ubuntu 24.04.1 LTS", "24.04")]
    [InlineData("Ubuntu Server 24.04 LTS", "24.04")]
    [InlineData("Appliance OS", "10.0")]
    [InlineData("Appliance Server 2022", null)]
    public void ANonWindowsPlatformCannotBorrowWindowsVersionOrReleaseRules(string name, string? version)
    {
        var capability = LapsCapability.Of(name, version);
        Assert.Equal(LapsCapabilityKind.Unknown, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemName, capability.Basis);
        Assert.Equal((name, version), (capability.Name, capability.Version));
    }

    [Fact]
    public void AVersionWithoutACapturedFamilyRemainsUnknown()
    {
        var capability = LapsCapability.Of(null, "10.0 (20348)");
        Assert.Equal(LapsCapabilityKind.Unknown, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.NothingToReadFrom, capability.Basis);
        Assert.Null(capability.IsServer);
    }

    [Theory]
    [InlineData("Windows 10 Enterprise", "10.0", LapsCapabilityKind.WindowsLapsCapable)]
    [InlineData("Windows 11 Enterprise", "10.0 (oops)", LapsCapabilityKind.WindowsLapsCapable)]
    [InlineData("Windows 7 Enterprise", "6.1", LapsCapabilityKind.LegacyLapsOnly)]
    public void AWindowsClientStillUsesItsMajorVersionWithoutRequiringAServerBuild(
        string name, string version, LapsCapabilityKind expected)
    {
        var capability = LapsCapability.Of(name, version);
        Assert.Equal(expected, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, capability.Basis);
    }

    [Theory]
    [InlineData("10.0 (17762)", LapsCapabilityKind.LegacyLapsOnly)]
    [InlineData("10.0 (17763)", LapsCapabilityKind.WindowsLapsCapable)]
    public void AUsableServerBuildKeepsThePublishedServer2019Boundary(string version, LapsCapabilityKind expected)
    {
        var capability = LapsCapability.Of("Windows Server vNext", version);
        Assert.Equal(expected, capability.Kind);
        Assert.Equal(LapsCapabilityBasis.OperatingSystemVersion, capability.Basis);
    }

    [Theory]
    [InlineData("Windows 10 Enterprise", "10.0")]
    [InlineData("Windows Server 2022", "10.0 (20348)")]
    public void TheDisplayedVersionBasisDoesNotClaimABuildWasCaptured(string name, string version)
    {
        var saved = LapsInventoryStorage.CreateComputerResult(Computer(name, version));
        var displayed = new LapsComputerViewModel(saved);
        Assert.Equal("operating system version", displayed.CapabilityBasis);
        Assert.Equal(name, displayed.OperatingSystem);
    }

    public static IEnumerable<object[]> SavedPlatforms()
    {
        foreach (var (name, version) in new[]
        {
            ("Windows Server 2022", "10.0"),
            ("Windows Server 2022", "10.0 (oops)"),
            ("Ubuntu 24.04.1 LTS", "24.04"),
        })
            foreach (var modern in new[] { false, true })
                yield return [name, version, modern];
    }

    [Theory]
    [MemberData(nameof(SavedPlatforms))]
    public void NewSavedInventoryAndRuleUseTheSameCorrectedPlatformAnswer(string name, string version, bool modern)
    {
        var expected = name.StartsWith("Windows", StringComparison.Ordinal)
            ? LapsCapabilityKind.WindowsLapsCapable : LapsCapabilityKind.Unknown;
        var directory = LapsBundle.Build(Dn, ["top", "person", "organizationalPerson", "user", "computer"],
            name, version, modern ? Timestamp : null, modern ? null : Timestamp, 0x1000,
            confidential: false, windowsLapsInSchema: true, When, primaryGroupId: 515);
        var original = SelfMembershipDiscoveryTests.Hash(directory);
        var derived = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, When,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        var judged = JudgingRun.Judge(directory, [new WindowsLapsNotAppliedOnCapableComputer()],
            When, When, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        Assert.Equal(JudgementRunState.Completed, judged.Value);

        var page = SavedLapsTestRun.Read(directory, Root, ListingScope.Subtree);
        var computer = Assert.Single(page.Computers);
        Assert.Equal(1, page.Total);
        Assert.Equal(new LapsCapability(expected, LapsCapabilityBasis.OperatingSystemName, name, version),
            computer.Capability);
        var state = modern ? LapsValuePresence.WindowsOnly : LapsValuePresence.LegacyOnly;
        Assert.Equal(state, computer.ValuePresence);
        Assert.Equal(1, page.CountOf(state));
        Assert.Equal(0, page.CountOf(LapsValuePresence.WindowsOnLegacyOnly));
        Assert.Equal((name, version, modern ? Timestamp : null, modern ? null : Timestamp),
            (computer.OperatingSystem, computer.OperatingSystemVersion, computer.WindowsLaps.Raw, computer.LegacyLaps.Raw));
        var displayed = new LapsComputerViewModel(computer);
        Assert.Equal("operating system name", displayed.CapabilityBasis);
        Assert.Equal(expected == LapsCapabilityKind.Unknown ? "Unknown" : "Windows LAPS capable", displayed.Capability);

        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.Read();
        Assert.Equal(3, Assert.Single(saved.RulesRun).RuleVersion);
        if (!modern && expected is LapsCapabilityKind.WindowsLapsCapable)
        {
            var finding = Assert.Single(saved.Findings);
            Assert.Equal(("SEC-094", 3, Severity.Low), (finding.RuleId, finding.RuleVersion, finding.Severity));
            Assert.Equal(computer.Capability, Assert.IsType<LapsDeploymentEvidence>(finding.Evidence).Capability);
        }
        else
            Assert.Empty(saved.Findings);
        Assert.Equal(original, SelfMembershipDiscoveryTests.Hash(directory));
    }

    [Fact]
    public void CorrectedPlatformEligibilityHasItsOwnCalculationVersion() =>
        Assert.Equal(3, new WindowsLapsNotAppliedOnCapableComputer().Definition.Version);

    private static ObjectAttributes Computer(string name, string version) =>
        new(Dn, Guid.NewGuid(), When, EvidenceCompleteness.Complete,
        [
            new("objectClass", AttributeCardinality.MultiValued,
                [new(0, "top", null), new(1, "user", null), new(2, "computer", null)]),
            new("operatingSystem", AttributeCardinality.SingleValued, [new(0, name, null)]),
            new("operatingSystemVersion", AttributeCardinality.SingleValued, [new(0, version, null)]),
            new("userAccountControl", AttributeCardinality.SingleValued, [new(0, "4096", null)]),
            new("primaryGroupID", AttributeCardinality.SingleValued, [new(0, "515", null)]),
        ], "ad.lab");
}
