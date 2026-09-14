using System.Collections.Concurrent;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Capture;
using SecureAD.Next.Tests.Sysvol;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.EndToEnd;

public sealed class CaptureRunSealingCancellationTests(ITestOutputHelper output)
{
    [Fact]
    public async Task StopFromTheSealingLogRecordsCancellationAsync()
    {
        using var scenario = new Scenario(output, "sealing the bundle");

        await scenario.RunAsync();

        Assert.Equal(RunOutcome.Cancelled, RunOutcomeFile.Read(scenario.Directory).Value?.Outcome);
    }

    [Fact]
    public async Task StopFromTheSealingLogRecordsTheApprovedExplanationAsync()
    {
        using var scenario = new Scenario(output, "sealing the bundle");

        await scenario.RunAsync();

        Assert.Equal("The run was stopped while sealing the bundle; no bundle was published.",
            RunOutcomeFile.Read(scenario.Directory).Value?.Detail);
    }

    [Fact]
    public async Task StopFromTheSealingLogDoesNotPublishSuccessAsync()
    {
        using var scenario = new Scenario(output, "sealing the bundle");

        var result = await scenario.RunAsync();

        Assert.Equal((RunCompletion.Ended, false, false),
            (result.Outcome, File.Exists(BundleLayout.EvidencePath(scenario.Directory)),
                scenario.Messages.Contains("bundle sealed")));
    }

    [Fact]
    public async Task ACancelledSealReturnsWithThePartialFileReleasedAsync()
    {
        using var scenario = new Scenario(output, "sealing the bundle");

        await scenario.RunAsync();

        using var exclusive = File.Open(BundleLayout.PartialPath(scenario.Directory),
            FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(exclusive.Length > 0);
    }

    [Fact]
    public async Task StopAfterPublicationDoesNotRelabelTheCaptureAsync()
    {
        using var scenario = new Scenario(output, "bundle sealed");

        var result = await scenario.RunAsync();

        Assert.Equal((true, RunCompletion.Sealed), (scenario.CancellationRequested, result.Outcome));
    }

    [Fact]
    public async Task StopAfterPublicationLeavesIntactEvidenceWithoutACancellationMarkerAsync()
    {
        using var scenario = new Scenario(output, "bundle sealed");

        await scenario.RunAsync();

        Assert.Equal((SealState.Intact, false),
            (BundleSealing.Verify(scenario.Directory).State, File.Exists(BundleLayout.OutcomePath(scenario.Directory))));
    }

    private sealed class Scenario : IRunLog, IDisposable
    {
        private readonly CancellationTokenSource _cancellation = new();
        private readonly string _cancelOn;
        public string Directory { get; } = Path.Combine(Path.GetTempPath(), "securead-p216-capture-" + Guid.NewGuid().ToString("N"));
        public ConcurrentQueue<string> Messages { get; } = new();
        public bool CancellationRequested => _cancellation.IsCancellationRequested;

        public Scenario(ITestOutputHelper output, string cancelOn)
        {
            _cancelOn = cancelOn;
            output.WriteLine(Directory);
        }

        public Task<CaptureRunResult> RunAsync() => Task.Run(async () =>
        {
            // Keep the capture and driver off the runner's synchronization context, as in P-225.
            var controller = new ControllerModel();
            controller.AnswersTo.Add("example.com");
            controller.AddObject("CN=Alice,DC=example,DC=com",
                ("objectClass", ["user"]), ("objectGUID", [Guid.NewGuid().ToByteArray()]));
            var plan = CapturePlan.For(
                controller.DomainController, "example.com", "CN=Configuration,DC=example,DC=com",
                "CN=Schema,CN=Configuration,DC=example,DC=com",
                [("DC=example,DC=com", "example.com", controller.DomainController)],
                controller.NamingContexts, ["DC=DomainDnsZones,DC=example,DC=com"],
                new Dictionary<string, IReadOnlyList<string>>()).Value;
            var run = new CaptureRun(controller.Connections(), new InMemorySysvolFileReader(),
                TimeProvider.System, this, domainsAtOnce: 1);
            return await run.RunAsync(plan, Directory, new Dictionary<string, AttestedExclusion>(), _cancellation.Token);
        });

        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> details)
        {
            Messages.Enqueue(message);
            if (message == _cancelOn)
                _cancellation.Cancel();
        }

        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> details) =>
            throw new InvalidOperationException(error.Description);

        public void Dispose() => _cancellation.Dispose();
    }
}
