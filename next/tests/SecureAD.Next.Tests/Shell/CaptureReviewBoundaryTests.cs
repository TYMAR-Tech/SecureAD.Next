using System.Net;
using System.Reflection;
using System.Text.Json;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Connect;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class CaptureReviewBoundaryTests
{
    private const string Root = "DC=example,DC=com";
    private const string Configuration = "CN=Configuration," + Root;
    private const string Schema = "CN=Schema," + Configuration;
    private const string First = "dc01.example.com";
    private const string Second = "dc02.example.com";
    private const string Orphan = "DC=legacy," + Root;
    private const string OrphanDns = "departed.example.net";
    private const string FailedDomain = "DC=failed," + Root;

    [Theory]
    [InlineData("example.com")]
    [InlineData("renamed.example.net")]
    public async Task ASelectedGuiControllerSurvivesFreshDiscovery(string declaredDns)
    {
        var fixture = new Fixture(declaredDns);
        var screen = fixture.Screen();
        await screen.OpenAsync();
        var row = Assert.Single(screen.Domains);
        row.NamedController = Second;
        await screen.ValidateOverrideAsync(row);

        await screen.ReviewAsync();

        Assert.Equal(
            ((string?)null, Second, true),
            (screen.Problem, row.Plan.Controller, row.Plan.ControllerWasNamedByOperator));
    }

    [Fact]
    public async Task AnAnsweringControllerOutsideTheCandidateListIsStillRefused()
    {
        var fixture = new Fixture();
        const string outsider = "dc99.example.com";
        fixture.Connections.Answering(outsider, new ControllerModel(outsider));
        var screen = fixture.Screen();
        await screen.OpenAsync();
        var row = Assert.Single(screen.Domains);
        row.NamedController = outsider;
        await screen.ValidateOverrideAsync(row);

        await screen.ReviewAsync();

        Assert.Contains("forest does not list it as holding a writable replica", screen.Problem);
    }

    [Fact]
    public async Task AnOverrideForAnotherForestIsStillRefused()
    {
        var fixture = new Fixture();

        var result = await fixture.Launcher.PlanAsync(fixture.Library, null,
            new Dictionary<string, string> { ["another.example.net"] = Second }, CancellationToken.None);

        Assert.Equal("Capture.OverriddenDomainIsNotInThisForest", result.Error?.Code);
    }

    [Fact]
    public async Task TheLauncherRetainsTheDeclaredIdentityOfANoCandidateDomain()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();

        var result = await fixture.Launcher.PlanAsync(
            fixture.Library, null, new Dictionary<string, string>(), CancellationToken.None);

        Assert.Equal(OrphanDns, result.Value?.DomainDnsNames.GetValueOrDefault(Orphan));
    }

    [Fact]
    public async Task PreflightDoesNotApproveANoCandidateDomainWithoutAttestation()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();

        var report = await fixture.ReportAsync();

        Assert.False(report.RunMayProceed);
    }

    [Fact]
    public async Task TheCommandLineRefusesTheSameIncompleteForest()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var report = await fixture.ReportAsync();
        var describe = typeof(SecureAD.Cli.CommandLine).Assembly
            .GetType("SecureAD.Cli.Program", throwOnError: true)!
            .GetMethod("Describe", BindingFlags.Static | BindingFlags.NonPublic,
                [typeof(PreflightReport)])!;

        var exitCode = describe.Invoke(null, [report]);

        Assert.Equal(1, exitCode);
    }

    [Fact]
    public async Task TheRealLauncherRefusesCaptureWithoutTheRequiredAttestation()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();

        var result = await fixture.Launcher.RunAsync(fixture.Library, null,
            new Dictionary<string, string>(), [], 1, CancellationToken.None);

        Assert.Equal("Capture.ADomainHasNoCandidateControllers", result.Error?.Code);
    }

    [Fact]
    public async Task ExcludingAHealthyDomainDoesNotExcuseANoCandidateDomain()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        var root = Assert.Single(screen.Domains);
        root.IsIncluded = false;

        var result = await fixture.Launcher.RunAsync(fixture.Library, null,
            new Dictionary<string, string>(), [root.Attestation!], 1, CancellationToken.None);

        Assert.Equal("Capture.ADomainHasNoCandidateControllers", result.Error?.Code);
    }

    [Fact]
    public async Task AttestingOneNoCandidateDomainDoesNotExcuseAnother()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        fixture.NoCandidate("DC=other," + Root, "other.example.net");
        var report = await fixture.ReportAsync();

        var refusal = report.Refusal([Orphan]);

        Assert.Equal(
            "No writable controller was found for: other.example.net. Each domain needs an exclusion attestation before capture can start.",
            refusal?.Description);
    }

    [Fact]
    public async Task AttestingANoCandidateDomainDoesNotExcuseAFailedController()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        fixture.FailedController();
        var report = await fixture.ReportAsync();

        var refusal = report.Refusal([Orphan]);

        Assert.Equal("Capture.PreflightRefusedTheRun", refusal?.Code);
    }

    [Fact]
    public async Task TheGuiCanStartOnceEveryBlockingDomainIsAttested()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();

        await screen.OpenAsync();

        Assert.True(screen.CanStart);
    }

    [Fact]
    public async Task TheGuiDoesNotExcuseAnotherFailedDomainAfterAttestation()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        fixture.FailedController();
        var screen = fixture.Screen();

        await screen.OpenAsync();

        Assert.False(screen.CanStart);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AFailedFreshPassCannotReuseAnAttestedPermissionToStart(bool repeatPlanning)
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        fixture.Bootstrap.RefusesToRead.Add("CN=Partitions," + Configuration);

        await RepeatPassAsync(screen, repeatPlanning);

        Assert.False(screen.CanStart);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ACancelledFreshPassCannotReuseAnAttestedPermissionToStart(bool repeatPlanning)
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        fixture.BeforeConnections = screen.Stop;

        await RepeatPassAsync(screen, repeatPlanning);

        Assert.False(screen.CanStart);
    }

    [Fact]
    public async Task AFailedReviewOffersTheExistingRetry()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        fixture.Bootstrap.RefusesToRead.Add("CN=Partitions," + Configuration);

        await screen.ReviewAsync();

        Assert.True(screen.MayLookAgain);
    }

    private static Task RepeatPassAsync(NewAuditViewModel screen, bool repeatPlanning) =>
        repeatPlanning ? screen.OpenAsync() : screen.ReviewAsync();

    [Fact]
    public async Task AGuiAttestationPassesTheRealCapturePlanBoundary()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        var attestation = Assert.Single(screen.DomainsWithNoController).Attestation!;

        var result = await fixture.Launcher.RunAsync(fixture.Library, null,
            new Dictionary<string, string>(), [attestation], 1, CancellationToken.None);

        Assert.True(result.IsSuccess && result.Value!.ProducedABundle, result.Error?.Description);
    }

    [Fact]
    public async Task AnAttestationWithTheWrongDnsIdentityIsStillRefused()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        var attestation = Assert.Single(screen.DomainsWithNoController).Attestation! with
        {
            DomainFqdn = "example.com",
        };

        var result = await fixture.Launcher.RunAsync(fixture.Library, null,
            new Dictionary<string, string>(), [attestation], 1, CancellationToken.None);

        Assert.Equal("Capture.ExclusionDoesNotMatchDeclaredDomain", result.Error?.Code);
    }

    [Fact]
    public async Task SavedPreflightRetainsEveryDeclaredDomain()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var report = await fixture.ReportAsync();

        PreflightFile.Write(fixture.Library, report, DateTimeOffset.UnixEpoch);
        using var written = ReadPreflight(fixture.Library);

        Assert.Equal(new[] { "example.com", OrphanDns }, written.RootElement
            .GetProperty("DeclaredDomains").EnumerateArray().Select(domain => domain.GetString()));
    }

    [Fact]
    public async Task SavedPreflightNamesDomainsWithNoControllerSeparately()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var report = await fixture.ReportAsync();

        PreflightFile.Write(fixture.Library, report, DateTimeOffset.UnixEpoch);
        using var written = ReadPreflight(fixture.Library);

        Assert.Equal(OrphanDns, written.RootElement
            .GetProperty("DomainsWithNoCandidates").GetProperty(Orphan).GetString());
    }

    [Theory]
    [InlineData("RunMayProceed")]
    [InlineData("AllDomainsWereAsked")]
    public async Task SavedUnattestedPreflightDoesNotClaimReadinessOrAnswers(string field)
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var report = await fixture.ReportAsync();

        PreflightFile.Write(fixture.Library, report, DateTimeOffset.UnixEpoch);
        using var written = ReadPreflight(fixture.Library);

        Assert.False(written.RootElement.GetProperty(field).GetBoolean());
    }

    [Fact]
    public async Task TheRealCaptureSavesItsAcceptedAttestation()
    {
        var fixture = new Fixture();
        var directory = await CaptureWithGuiAttestationAsync(fixture);

        using var written = ReadPreflight(directory);

        Assert.Equal(OrphanDns, written.RootElement
            .GetProperty("Exclusions")[0].GetProperty("DomainFqdn").GetString());
    }

    [Theory]
    [InlineData("RunMayProceed", true)]
    [InlineData("AllDomainsWereAsked", false)]
    public async Task TheRealCaptureSavesPermissionToProceedWithoutInventingAnswers(string field, bool expected)
    {
        var fixture = new Fixture();
        var directory = await CaptureWithGuiAttestationAsync(fixture);

        using var written = ReadPreflight(directory);

        Assert.Equal(expected, written.RootElement.GetProperty(field).GetBoolean());
    }

    [Fact]
    public async Task SavedPreflightRejectsAnInvalidAttestation()
    {
        var fixture = new Fixture();
        fixture.NoCandidate();
        var report = await fixture.ReportAsync();
        var exclusion = new AttestedExclusion(Orphan, Orphan, ExclusionKind.ForWantOfCandidates,
            "outside-remit", null, "operator", "authoriser", DateTimeOffset.UnixEpoch);

        Assert.Throws<ArgumentException>(() => PreflightFile.Write(
            fixture.Library, report, DateTimeOffset.UnixEpoch,
            new Dictionary<string, AttestedExclusion> { [Orphan] = exclusion }));
    }

    private static JsonDocument ReadPreflight(string directory) =>
        JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "preflight.json")));

    private static async Task<string> CaptureWithGuiAttestationAsync(Fixture fixture)
    {
        fixture.NoCandidate();
        var screen = fixture.Screen();
        await screen.OpenAsync();
        var attestation = Assert.Single(screen.DomainsWithNoController).Attestation!;
        var result = await fixture.Launcher.RunAsync(fixture.Library, null,
            new Dictionary<string, string>(), [attestation], 1, CancellationToken.None);
        Assert.True(result.IsSuccess && result.Value!.ProducedABundle, result.Error?.Description);
        return result.Value!.BundleDirectory;
    }

    private sealed class Fixture
    {
        internal string Library { get; } = TempDirectories.Create("capture-review");
        internal ControllerModel Bootstrap { get; } = new(First);
        internal ForestModel Connections { get; } = new();
        internal FakeNewAuditDialog Dialogs { get; } = new();
        internal CaptureLauncher Launcher { get; }
        internal Action? BeforeConnections { get; set; }
        private readonly string _rootDns;

        internal Fixture(string rootDns = "example.com")
        {
            _rootDns = rootDns;
            Bootstrap.CrossReferences.RemoveAt(0);
            Bootstrap.CrossReferences.Insert(0, CrossReference.Domain(Root, rootDns));
            Add(Bootstrap, Schema);
            Add(Bootstrap, "CN=Partitions," + Configuration);
            Add(Bootstrap, Root);
            Add(Bootstrap, "CN=Password Settings Container,CN=System," + Root);
            RegisterController(First, Root);
            RegisterController(Second, Root);
            Connections.Answering(rootDns, Bootstrap).Answering(First, Bootstrap);
            var second = new ControllerModel(Second);
            Add(second, Root);
            Add(second, "CN=Password Settings Container,CN=System," + Root);
            Connections.Answering(Second, second);
            Launcher = new CaptureLauncher(Session);
        }

        internal void NoCandidate(string namingContext = Orphan, string dns = OrphanDns) =>
            Bootstrap.CrossReferences.Add(CrossReference.Domain(namingContext, dns));

        internal void FailedController()
        {
            Bootstrap.CrossReferences.Add(CrossReference.Domain(FailedDomain, "failed.example.com"));
            RegisterController("dc.failed.example.com", FailedDomain);
        }

        private void RegisterController(string host, string domain)
        {
            var server = $"CN={host},CN=Servers,CN=London,CN=Sites,{Configuration}";
            Add(Bootstrap, server, ("dNSHostName", [host]));
            Add(Bootstrap, "CN=NTDS Settings," + server, ("msDS-hasMasterNCs", [domain]));
        }

        internal CaptureSession Session(string library, int domainsAtOnce)
        {
            // Substitute only directory I/O. The real session still bootstraps, discovers,
            // validates identities, checks exclusions and writes the capture's preflight file.
            var constructor = typeof(CaptureSession)
                .GetConstructors(BindingFlags.Instance | BindingFlags.NonPublic).Single();
            Func<ConnectionSecurityLog, IDirectoryChannelFactory> connections = _ =>
            {
                BeforeConnections?.Invoke();
                return Connections;
            };
            return (CaptureSession)constructor.Invoke(
            [
                new RunLibrary(library, TimeProvider.System),
                DirectoryConnectionSettings.Default with { DomainsAtOnce = domainsAtOnce },
                TimeProvider.System,
                new Machine(_rootDns),
                Array.Empty<IPAddress>(),
                connections,
            ]);
        }

        internal NewAuditViewModel Screen()
        {
            var settings = new FakeSettingsStore();
            settings.Stored = settings.Stored with { RunLibraryPath = Library };
            var location = new RunLibraryLocation(settings);
            location.Load();
            var concurrency = new DomainConcurrency(settings);
            concurrency.Load();
            return new NewAuditViewModel(
                location, Launcher, Dialogs, new FakeRunOpener(),
                new FakeDerivationLauncher(), new FakeJudgingLauncher(), concurrency);
        }

        internal async Task<PreflightReport> ReportAsync()
        {
            var result = await Session(Library, 1).ValidateAsync(
                null, new Dictionary<string, string>(), CancellationToken.None);
            Assert.True(result.IsSuccess, result.Error?.Description);
            return result.Value!;
        }

        private static void Add(
            ControllerModel model, string dn, params (string Attribute, object[] Values)[] attributes) =>
            model.AddObject(dn,
                [("objectGUID", [Guid.NewGuid().ToByteArray()]), ("objectClass", ["top"]), .. attributes]);
    }

    private sealed record Machine(string DnsDomain) : IMachineDomain
    {
        public string? NetBiosDomain => null;
    }
}
