using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Sysvol;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.EndToEnd;

public sealed class DomainFailoverTests(ITestOutputHelper output)
{
    private const string Domain = "DC=example,DC=com";
    private const string OtherDomain = "DC=child,DC=example,DC=com";
    private const string Configuration = "CN=Configuration," + Domain;
    private const string Schema = "CN=Schema," + Configuration;
    private const string Root = "dc0.example.com";
    private const string First = "dc1.example.com";
    private const string Next = "dc3.example.com";
    private const string Last = "dc2.example.com";
    private const string Other = "dc.child.example.com";

    [Fact]
    public async Task BusyRequestsExhaustTheirRetriesBeforeChangingController()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new LdapException(51);

        await CaptureAsync(forest);

        Assert.Equal(3, forest.Log.Saying("retrying a request").Count + 1);
    }

    [Fact]
    public async Task ExhaustionNamesTheOriginalFailureAndSealsNothing()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new LdapException(81);
        forest.Faults[Next] = () => new LdapException(51);
        forest.Faults[Last] = () => new LdapException(11);

        var run = await CaptureAsync(forest);

        Assert.Equal(
            (forest.Log.Errors.First().Error, RunOutcome.Failed, false,
                string.Join(",", First, First, Next, Last)),
            (run.Error, RunOutcomeFile.Read(run.BundleDirectory).Value!.Outcome,
                File.Exists(BundleLayout.EvidencePath(run.BundleDirectory)),
                string.Join(",", forest.Opened.Where(unit => unit.NamingContext == Domain)
                    .Select(unit => unit.DomainController))));
    }

    [Fact]
    public async Task FailedShardsAreDeletedEvenWhenThereIsNoReplacement()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new LdapException(81);
        forest.Faults[Next] = () => new LdapException(81);
        forest.Faults[Last] = () => new LdapException(81);

        var run = await CaptureAsync(forest);

        Assert.False(File.Exists(BundleLayout.ShardPath(run.BundleDirectory, BundleShard.Number(1))));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task SealedHistoryNamesEveryFailedControllerInAttemptOrder(int failures)
    {
        var forest = new AttemptForest();
        foreach (var controller in new[] { First, Next }.Take(failures))
            forest.Faults[controller] = () => new LdapException(81);

        var run = await CaptureAsync(forest);
        using var reader = BundleReader.Open(run.BundleDirectory).Value!;
        var history = reader.ReadDomainCaptureFailures().Value!;

        Assert.Equal(forest.Log.Errors.Select((entry, index) =>
                (Domain, RecordingRunLog.Value(entry.Detail, "controller"), index + 1, entry.Error)),
            history.Select(failure =>
                (failure.NamingContextDn, failure.Controller, failure.Attempt, failure.Error)));
    }

    [Fact]
    public async Task RecoveryIsVisibleInTheRunLog()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new LdapException(81);

        await CaptureAsync(forest);

        Assert.Equal([Other, Next], forest.Log.Saying("partition read")
            .Where(row => new[] { Domain, OtherDomain }.Contains(RecordingRunLog.Value(row, "namingContext")))
            .Select(row => RecordingRunLog.Value(row, "controller"))
            .OrderBy(controller => controller, StringComparer.Ordinal));
    }

    [Fact]
    public async Task ReplacementEvidenceContainsNoAbandonedObjectsOrPolicyInventory()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new LdapException(81);

        var run = await CaptureAsync(forest);

        Assert.Equal(
            [$"CN=replacement,{Domain}|{Next}|1000000000001", $"CN=unaffected,{OtherDomain}|{Other}|2000000000001"],
            Query(run.BundleDirectory,
                "SELECT o.distinguished_name || '|' || p.controller || '|' || o.object_id "
                + "FROM captured_object o JOIN partition_coverage p ON p.coverage_id = o.coverage_id "
                + "UNION ALL SELECT 'abandoned policy' FROM sysvol_gpo_coverage "
                + "UNION ALL SELECT 'abandoned trustee' FROM trustee WHERE sid = 'S-1-5-21-1-2-3-1001' "
                + "ORDER BY 1").AsEnumerable());
    }

    [Fact]
    public async Task AHealthyFirstControllerNeedsNeitherFailoverNorFailureHistory()
    {
        var forest = new AttemptForest();

        var run = await CaptureAsync(forest);
        using var reader = BundleReader.Open(run.BundleDirectory).Value!;

        Assert.Equal((First, 0, "Read"),
            (Assert.Single(forest.Opened.Where(unit => unit.NamingContext == Domain)).DomainController,
                reader.ReadDomainCaptureFailures().Value!.Count,
                Assert.Single(Query(run.BundleDirectory, "SELECT outcome FROM sysvol_gpo_coverage"))));
    }

    [Fact]
    public async Task CancellationDuringAnAttemptDoesNotTryAnotherController()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new OperationCanceledException();

        var run = await CaptureAsync(forest);

        Assert.Equal(((RunOutcome?)RunOutcome.Cancelled, First),
            (RunOutcomeFile.Read(run.BundleDirectory).Value?.Outcome,
                string.Join(",", forest.Opened.Where(unit => unit.NamingContext == Domain)
                    .Select(unit => unit.DomainController))));
    }

    [Fact]
    public async Task ASqliteFailureEscapesRatherThanTryingAnotherController()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new SqliteException("Synthetic persistence failure.", 19);

        await Assert.ThrowsAsync<SqliteException>(() => CaptureAsync(forest));
    }

    [Fact]
    public async Task AFailedControllerIsReplacedOnlyAfterItsOwnRestart()
    {
        var forest = new AttemptForest();
        forest.Faults[First] = () => new LdapException(81);

        await CaptureAsync(forest);

        Assert.Equal([First, First, Next], forest.Opened.Where(unit => unit.NamingContext == Domain)
            .Select(unit => unit.DomainController));
    }

    private async Task<CaptureRunResult> CaptureAsync(
        AttemptForest forest, CancellationToken cancellationToken = default)
    {
        var plan = CapturePlan.For(Root, "example.com", Configuration, Schema,
            [(Domain, "example.com", First), (OtherDomain, "child.example.com", Other)],
            [Configuration, Schema, Domain, OtherDomain], [],
            new Dictionary<string, IReadOnlyList<string>> { [Domain] = [Next, Last] }).Value!;
        var directory = Path.Combine(Path.GetTempPath(), "securead-failover-" + Guid.NewGuid().ToString("N"));
        output.WriteLine(directory);
        forest.Directory = directory;
        return await new CaptureRun(forest, forest.Sysvol,
            new ImmediateTimeProvider(), forest.Log, domainsAtOnce: 1)
            .RunAsync(plan, directory, new Dictionary<string, AttestedExclusion>(), cancellationToken);
    }

    private sealed class AttemptForest : IDirectoryChannelFactory
    {
        private readonly Dictionary<string, ControllerModel> _models = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, Func<Exception>> Faults { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<CaptureUnit> Opened { get; } = [];
        public RecordingRunLog Log { get; } = new();
        public InMemorySysvolFileReader Sysvol { get; } = new();
        public string Directory { get; set; } = "";

        public AttemptForest()
        {
            _models[Root] = new ControllerModel(Root);
            foreach (var (host, name, domain) in new[]
            {
                (First, "abandoned", Domain), (Next, "replacement", Domain),
                (Last, "last", Domain), (Other, "unaffected", OtherDomain),
            })
            {
                var model = new ControllerModel(host);
                model.AddObject($"CN={name},{domain}",
                    ("objectGUID", [Guid.NewGuid().ToByteArray()]),
                    ("objectClass", ["top", "user"]),
                    ("nTSecurityDescriptor", [Descriptor()]));
                _models[host] = model;
            }

            var policy = Guid.NewGuid();
            var path = @"\\example.com\SYSVOL\example.com\Policies\{" + policy + "}";
            _models[First] = new ControllerModel(First);
            _models[First].AddObject($"CN=abandoned,{Domain}",
                ("objectGUID", [policy.ToByteArray()]),
                ("objectClass", ["top", "container", "groupPolicyContainer"]),
                ("gPCFileSysPath", [path]),
                ("nTSecurityDescriptor", [Descriptor("S-1-5-21-1-2-3-1001")]));
            Sysvol.WithDescriptor(path, "", Descriptor());
        }

        public Result<IDirectoryChannel> Connect(CaptureUnit unit)
        {
            Opened.Add(unit);
            var inner = _models[unit.DomainController].Connections().Connect(unit).Value!;
            return new AttemptChannel(inner, Faults.GetValueOrDefault(unit.DomainController));
        }

        public Result<IDirectoryChannel> Connect(string domainController) =>
            throw new InvalidOperationException("Capture must not rediscover controllers.");

        private static byte[] Descriptor(string trustee = "BA")
        {
            var descriptor = new RawSecurityDescriptor($"O:SYG:SYD:(A;;RP;;;{trustee})");
            var bytes = new byte[descriptor.BinaryLength];
            descriptor.GetBinaryForm(bytes, 0);
            return bytes;
        }
    }

    private static string[] Query(string directory, string sql)
    {
        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var rows = new List<string>();
        while (reader.Read())
            rows.Add(reader.GetString(0));
        return rows.ToArray();
    }

    private sealed class AttemptChannel(IDirectoryChannel inner, Func<Exception>? failure) : IDirectoryChannel
    {
        private int _requests;
        public string DomainController => inner.DomainController;
        public ConnectionSecurityLevel SecurityLevel => inner.SecurityLevel;
        public ReferralChasingOptions ReferralChasing => inner.ReferralChasing;
        public IReadOnlyList<string> SupportedControls => inner.SupportedControls;
        public IReadOnlyList<string> NamingContextsServed => inner.NamingContextsServed;
        public bool IsComplete => inner.IsComplete;
        public void Dispose() => inner.Dispose();

        public async Task<DirectoryPage> SendAsync(SearchRequest request, CancellationToken cancellationToken)
        {
            if (++_requests > 1 && failure is not null)
                throw failure();
            var page = await inner.SendAsync(request, cancellationToken);
            return failure is null ? page : page with
            {
                Completeness = PageCompleteness.MoreToCome,
                PagingCookie = [1],
            };
        }
    }
}
