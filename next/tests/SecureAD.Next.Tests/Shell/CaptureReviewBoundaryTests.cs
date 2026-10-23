using System.Net;
using System.DirectoryServices.Protocols;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using System.Reflection;
using System.Text.Json;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Connect;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class CaptureReviewBoundaryTests
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
    [InlineData(false, false, 3, First)]
    [InlineData(true, false, 7, First)]
    [InlineData(false, true, 3, Second)]
    [InlineData(true, true, 7, Second)]
    public async Task TheWizardScopeControlsActualPagedCaptureAndFailover(
        bool includeEnatelSso, bool failover, int expectedObjects, string expectedController)
    {
        var fixture = new Fixture();
        fixture.ScopeObjects(failover);

        var directory = await CaptureScopeAsync(fixture, includeEnatelSso);

        using var database = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        database.Open();
        using var command = database.CreateCommand();
        command.CommandText = "SELECT COUNT(*) || '|' || MIN(p.controller) FROM captured_object o "
            + "JOIN partition_coverage p ON p.coverage_id=o.coverage_id WHERE o.distinguished_name LIKE 'CN=scope-%'";
        Assert.Equal($"{expectedObjects}|{expectedController}", command.ExecuteScalar());
    }

    [Theory]
    [InlineData(false, 6)]
    [InlineData(true, 2)]
    public void RecordedScopeSurvivesPreflightEvidenceAndDashboard(bool includeEnatelSso, int excludedCount) => OneThread.Run(async () =>
    {
        var fixture = new Fixture();
        fixture.ScopeObjects(failover: false);

        var directory = await CaptureScopeAsync(fixture, includeEnatelSso);

        using var reader = BundleReader.Open(directory).Value;
        using var preflight = ReadPreflight(directory);
        using var assets = new BundleAssetSource();
        var dashboard = new DashboardViewModel(assets);
        dashboard.Show(directory);
        await dashboard.ReadCompletion;
        Assert.Equal((excludedCount, excludedCount, !includeEnatelSso),
            (reader.Description.ExcludedObjectClasses.Count,
                preflight.RootElement.GetProperty("ExcludedObjectClasses").GetArrayLength(),
                dashboard.ObjectClassScopeStatement.Contains(", enatelSSOStorage,", StringComparison.Ordinal)));
    });

    private static Task<string> CaptureScopeAsync(Fixture fixture, bool includeEnatelSso) => Task.FromResult(OneThread.Run(async () =>
    {
        Assert.NotNull(SynchronizationContext.Current);
        var ownerThread = Environment.CurrentManagedThreadId;
        var progressThreads = new System.Collections.Concurrent.ConcurrentQueue<int>();
        var screen = fixture.Screen();
        screen.Progress.RecentReports.CollectionChanged += (_, _) =>
            progressThreads.Enqueue(Environment.CurrentManagedThreadId);
        await screen.OpenAsync();
        var row = Assert.Single(screen.Domains);
        row.NamedController = First;
        await screen.ValidateOverrideAsync(row);
        screen.IncludeEnatelSso = includeEnatelSso;
        await screen.StartAsync();
        Assert.NotEmpty(progressThreads);
        Assert.All(progressThreads, thread => Assert.Equal(ownerThread, thread));
        Assert.True(screen.BundleDirectory is not null, screen.Problem ?? screen.Report);
        return screen.BundleDirectory!;
    }));

    [Theory]
    [InlineData(false, false, 0)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 2)]
    [InlineData(true, true, 2)]
    public async Task VendorStorageClassIsFilteredRegardlessOfTheChildCn(
        bool includeEnatelSso, bool failover, long expectedStorageObjects)
    {
        var fixture = new Fixture();
        fixture.VendorStorageObjects(failover);
        var directory = await CaptureScopeAsync(fixture, includeEnatelSso);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(DISTINCT object_id) FROM objectclass_value "
            + "WHERE value='enatelSSOStorage' COLLATE NOCASE";
        Assert.Equal(expectedStorageObjects, command.ExecuteScalar());
        command.CommandText = "SELECT COUNT(*) FROM captured_object WHERE distinguished_name=$dn";
        command.Parameters.AddWithValue("$dn", "CN=enatelSSOStorageV3,CN=ordinary," + Root);
        Assert.Equal(1L, command.ExecuteScalar());
        command.CommandText = "SELECT COUNT(*) FROM captured_object o "
            + "JOIN partition_coverage p ON p.coverage_id=o.coverage_id "
            + "WHERE o.distinguished_name=$dn AND p.naming_context_kind='Schema'";
        command.Parameters["$dn"].Value = "CN=enatelSSOStorage," + Schema;
        Assert.Equal(1L, command.ExecuteScalar());
    }

    [Theory]
    [InlineData(false, false, 0)]
    [InlineData(false, true, 0)]
    [InlineData(true, false, 2)]
    [InlineData(true, true, 2)]
    public async Task AccountClassScopeControlsChildrenAcrossPagesAndFailover(
        bool includeEnatelSso, bool failover, long expectedAccounts)
    {
        var fixture = new Fixture();
        fixture.AccountMetadataObjects(failover);
        var directory = await CaptureScopeAsync(fixture, includeEnatelSso);
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(DISTINCT object_id) FROM objectclass_value "
            + "WHERE value='enatelSSOAccount' COLLATE NOCASE";
        Assert.Equal(expectedAccounts, command.ExecuteScalar());
        command.CommandText = "SELECT COUNT(DISTINCT object_id) FROM objectclass_value "
            + "WHERE value='enatelAdminProfile' COLLATE NOCASE";
        Assert.Equal(1L, command.ExecuteScalar());
        command.CommandText = "SELECT COUNT(*) FROM captured_object WHERE distinguished_name=$dn";
        command.Parameters.AddWithValue("$dn", "CN=enatelSSOAccount,CN=ordinary," + Root);
        Assert.Equal(1L, command.ExecuteScalar());
        command.Parameters["$dn"].Value = "CN=retained-ordinary,CN=enatelSSOStorageV3,CN=user," + Root;
        Assert.Equal(1L, command.ExecuteScalar());
    }

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
        private ControllerModel Secondary { get; } = new(Second);
        internal ForestModel Connections { get; } = new();
        internal FakeNewAuditDialog Dialogs { get; } = new();
        internal CaptureLauncher Launcher { get; }
        internal Action? BeforeConnections { get; set; }
        private Func<IDirectoryChannelFactory, IDirectoryChannelFactory>? DecorateConnections { get; set; }
        private readonly string _rootDns;

        internal Fixture(string rootDns = "example.com", bool analysisInputs = false)
        {
            _rootDns = rootDns;
            Bootstrap.CrossReferences.RemoveAt(0);
            Bootstrap.CrossReferences.Insert(0, CrossReference.Domain(Root, rootDns));
            Add(Bootstrap, Schema);
            Add(Bootstrap, "CN=Partitions," + Configuration);
            if (analysisInputs)
            {
                AdministrativeGroupCaptureFixture.AddTo(Bootstrap);
                DecorateConnections = inner => new NamingContextDirectory(inner);
            }
            else Add(Bootstrap, Root);
            Add(Bootstrap, "CN=Password Settings Container,CN=System," + Root);
            RegisterController(First, Root);
            RegisterController(Second, Root);
            Connections.Answering(rootDns, Bootstrap).Answering(First, Bootstrap);
            var second = Secondary;
            Add(second, Root);
            Add(second, "CN=Password Settings Container,CN=System," + Root);
            Connections.Answering(Second, second);
            Launcher = new CaptureLauncher(Session);
        }

        internal void ScopeObjects(bool failover)
        {
            string[] classes = ["user", "group", "unanticipatedSecurityExtension",
                "ENATELSSOACCOUNTPARAMETER", "enatelUserManagedAuth", "enatelSSOStorage", "enatelSSOAccount", "dnsNode", "dnsZone"];
            var byDn = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var at = 0; at < classes.Length; at++)
            {
                var dn = $"CN=scope-{at},{Root}";
                byDn.Add(dn, classes[at]);
                foreach (var model in new[] { Bootstrap, Secondary })
                    model.AddObject(dn, ("objectGUID", [Guid.NewGuid().ToByteArray()]),
                        ("objectClass", ["top", classes[at]]));
            }
            DecorateConnections = source => new ScopedDirectory(source, byDn, failover);
        }

        internal void VendorStorageObjects(bool failover)
        {
            // Quest KB 4256730: V2/V3 are CNs; both use objectClass=enatelSSOStorage.
            var classes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["CN=enatelSSOStorageV2,CN=user," + Root] = "enatelSSOStorage",
                ["CN=enatelSSOStorageV3,CN=user," + Root] = "ENATELSSOSTORAGE",
                ["CN=enatelSSOStorageV3,CN=ordinary," + Root] = "user",
                ["CN=enatelSSOStorage," + Schema] = "classSchema",
            };
            foreach (var model in new[] { Bootstrap, Secondary })
                foreach (var entry in classes)
                    model.AddObject(entry.Key, ("objectGUID", [Guid.NewGuid().ToByteArray()]),
                        ("objectClass", ["top", entry.Value]));
            DecorateConnections = source => new ScopedDirectory(source, classes, failover);
        }

        internal void AccountMetadataObjects(bool failover)
        {
            var classes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["CN=account-first,CN=enatelSSOStorageV3,CN=user," + Root] = "enatelSSOAccount",
                ["CN=retained-admin," + Root] = "enatelAdminProfile",
                ["CN=enatelSSOAccount,CN=ordinary," + Root] = "user",
                ["CN=retained-ordinary,CN=enatelSSOStorageV3,CN=user," + Root] = "user",
                ["CN=account-later,CN=enatelSSOStorageV2,CN=user," + Root] = "ENATELSSOACCOUNT",
            };
            foreach (var model in new[] { Bootstrap, Secondary })
                foreach (var entry in classes)
                    model.AddObject(entry.Key, ("objectGUID", [Guid.NewGuid().ToByteArray()]),
                        ("objectClass", ["top", entry.Value]));
            DecorateConnections = source => new ScopedDirectory(source, classes, failover);
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
                return DecorateConnections?.Invoke(Connections) ?? Connections;
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

    private sealed class ScopedDirectory(IDirectoryChannelFactory inner,
        IReadOnlyDictionary<string, string> classes, bool failover) : IDirectoryChannelFactory
    {
        public Result<IDirectoryChannel> Connect(CaptureUnit unit) => Wrap(inner.Connect(unit));
        public Result<IDirectoryChannel> Connect(string host) => Wrap(inner.Connect(host));
        private Result<IDirectoryChannel> Wrap(Result<IDirectoryChannel> opened) => opened.IsSuccess
            ? new ScopeChannel(opened.Value, classes, failover) : opened;
    }

    private sealed class ScopeChannel(IDirectoryChannel inner,
        IReadOnlyDictionary<string, string> classes, bool failover) : IDirectoryChannel
    {
        private DirectoryPage? _remaining;
        public string DomainController => inner.DomainController;
        public ConnectionSecurityLevel SecurityLevel => inner.SecurityLevel;
        public ReferralChasingOptions ReferralChasing => inner.ReferralChasing;
        public IReadOnlyList<string> SupportedControls => inner.SupportedControls;
        public IReadOnlyList<string> NamingContextsServed => inner.NamingContextsServed;
        public bool IsComplete => inner.IsComplete;
        public void Dispose() => inner.Dispose();

        public async Task<DirectoryPage> SendAsync(SearchRequest request, CancellationToken cancellationToken)
        {
            if (request.Scope != SearchScope.Subtree || request.DistinguishedName != Root)
                return await inner.SendAsync(request, cancellationToken);

            DirectoryPage page;
            if (_remaining is null)
            {
                var whole = await inner.SendAsync(request, cancellationToken);
                // Exercise named scope objects on both sides of the page boundary.
                whole = whole with { Entries = whole.Entries
                    .OrderBy(entry => classes.ContainsKey(entry.DistinguishedName) ? 0 : 1).ToArray() };
                _remaining = whole with { Entries = whole.Entries.Skip(4).ToArray() };
                page = whole with { Entries = whole.Entries.Take(4).ToArray(),
                    Completeness = PageCompleteness.MoreToCome, PagingCookie = [9, 1] };
            }
            else
            {
                if (failover && DomainController == First)
                    throw new LdapException(81, "Synthetic connection loss on the later page.");
                page = _remaining;
                _remaining = null;
            }

            // Simulate server-side NOT-objectClass clauses using the request itself, never the
            // product's chosen scope. Dropping a clause therefore makes extra objects arrive.
            var excluded = Regex.Matches((string)request.Filter, @"\(!\(objectClass=([^)]+)\)\)")
                .Select(match => match.Groups[1].Value).ToHashSet(StringComparer.OrdinalIgnoreCase);
            return page with { Entries = page.Entries.Where(entry =>
                !classes.TryGetValue(entry.DistinguishedName, out var name) || !excluded.Contains(name)).ToArray() };
        }
    }

    private sealed record Machine(string DnsDomain) : IMachineDomain
    {
        public string? NetBiosDomain => null;
    }
}
