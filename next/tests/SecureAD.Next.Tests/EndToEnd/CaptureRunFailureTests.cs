using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
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

public sealed class CaptureRunFailureTests(ITestOutputHelper output)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ATerminalFailureCancelsAnActiveDomain(bool queued)
    {
        var scenario = new FailureScenario(output, queued: queued);

        await scenario.FailAsync();

        Assert.True(scenario.CancellationObserved.Task.IsCompletedSuccessfully);
    }

    [Fact]
    public async Task ATerminalFailureDoesNotStartQueuedDomains()
    {
        var scenario = new FailureScenario(output, queued: true);

        await scenario.FailAsync();

        Assert.Equal(2, scenario.OpenedDomains.Count);
    }

    [Fact]
    public async Task AControllerTurnWaiterDoesNotStartAfterFailure()
    {
        var scenario = new FailureScenario(output, sharedHost: true);

        await scenario.FailAsync();

        Assert.Single(scenario.OpenedDomains.Where(unit => unit.DomainController == FailureScenario.SharedHost));
    }

    [Fact]
    public async Task TheTriggeringFailureSurvivesAnEarlierDomainsCancellation()
    {
        var scenario = new FailureScenario(output);

        var run = await scenario.FailAsync();

        Assert.Equal(scenario.Errors.Single(), run.Error);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheSavedOutcomeIsFailedRatherThanInternallyCancelled(bool queued)
    {
        var scenario = new FailureScenario(output, queued: queued);

        var run = await scenario.FailAsync();

        Assert.Equal(RunOutcome.Failed, RunOutcomeFile.Read(run.BundleDirectory).Value?.Outcome);
    }

    [Fact]
    public async Task AnAutomaticStopIsNotAttributedToTheOperator()
    {
        var scenario = new FailureScenario(output);

        await scenario.FailAsync();

        Assert.Equal(["partition stopped because another domain failed"], scenario.StopMessages);
    }

    [Fact]
    public async Task AFailedRunReturnsWithEveryChannelDisposed()
    {
        var scenario = new FailureScenario(output);

        await scenario.FailAsync();

        Assert.Empty(scenario.ActiveChannels);
    }

    [Fact]
    public async Task AFailedRunReturnsWithEveryOutputFileReleased()
    {
        var scenario = new FailureScenario(output, sharedHost: true);

        await scenario.FailAsync();

        Assert.Empty(scenario.LockedOutputFiles());
    }

    [Fact]
    public async Task ACompletedShardIsRetainedWithoutPublishingEvidence()
    {
        var scenario = new FailureScenario(output, completedDomain: true);

        var run = await scenario.FailAsync();

        Assert.Equal((true, false),
            (File.Exists(BundleLayout.ShardPath(run.BundleDirectory, BundleShard.Number(1))),
                File.Exists(BundleLayout.EvidencePath(run.BundleDirectory))));
    }

    [Fact]
    public async Task SuccessfulNextControllerRecoveryDoesNotStopTheOtherDomain()
    {
        var scenario = new FailureScenario(output, recover: true);

        var run = await scenario.RecoverAsync();

        Assert.True(run.ProducedABundle);
    }

    [Fact]
    public async Task AnOperatorStopRemainsAnOperatorCancellation()
    {
        var scenario = new FailureScenario(output);

        var run = await scenario.CancelAsync();

        Assert.Equal((RunOutcome.Cancelled, "partition stopped by the operator"),
            (RunOutcomeFile.Read(run.BundleDirectory).Value!.Outcome,
                string.Join(",", scenario.StopMessages.Distinct(StringComparer.Ordinal))));
    }

    private sealed class FailureScenario : IDirectoryChannelFactory, IRunLog
    {
        private const string Forest = "example.com";
        private const string Root = "dc0.example.com";
        private const string FirstDomain = "DC=one,DC=example,DC=com";
        private const string FailedDomain = "DC=two,DC=example,DC=com";
        private const string ExtraDomain = "DC=three,DC=example,DC=com";
        private const string Configuration = "CN=Configuration,DC=example,DC=com";
        private const string Schema = "CN=Schema," + Configuration;
        private const string Replacement = "replacement.example.com";
        public const string SharedHost = "shared.example.com";

        private readonly ITestOutputHelper _output;
        private readonly bool _queued;
        private readonly bool _sharedHost;
        private readonly bool _completedDomain;
        private readonly bool _recover;
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "securead-p215-" + Guid.NewGuid().ToString("N"));
        private readonly ConcurrentDictionary<Channel, byte> _active = new();
        private readonly ConcurrentQueue<string> _notes = new();
        private readonly TaskCompletionSource _blockedReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _failingReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _allowFailure = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseCleanup = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _completedWritten = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _recoveredWritten = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _admitted;
        private int _sharedAdmitted;

        public FailureScenario(ITestOutputHelper output, bool queued = false, bool sharedHost = false,
            bool completedDomain = false, bool recover = false)
        {
            _output = output;
            _queued = queued;
            _sharedHost = sharedHost;
            _completedDomain = completedDomain;
            _recover = recover;
            output.WriteLine(_directory);
        }

        public ConcurrentQueue<CaptureUnit> OpenedDomains { get; } = new();
        public ConcurrentQueue<AuditError> Errors { get; } = new();
        public TaskCompletionSource CancellationObserved { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IEnumerable<object> ActiveChannels => _active.Keys;
        public IEnumerable<string> StopMessages => _notes.Where(message => message.StartsWith("partition stopped", StringComparison.Ordinal));

        public Task<CaptureRunResult> FailAsync() => ExecuteAsync(operatorStop: false, recover: false);
        public Task<CaptureRunResult> RecoverAsync() => ExecuteAsync(operatorStop: false, recover: true);
        public Task<CaptureRunResult> CancelAsync() => ExecuteAsync(operatorStop: true, recover: false);

        private async Task<CaptureRunResult> ExecuteAsync(bool operatorStop, bool recover)
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var caller = new CancellationTokenSource();
            var run = new CaptureRun(this, new InMemorySysvolFileReader(), TimeProvider.System, this,
                domainsAtOnce: _sharedHost || _completedDomain ? 3 : 2)
                .RunAsync(Plan(), _directory, new Dictionary<string, AttestedExclusion>(), caller.Token);
            try
            {
                await _blockedReady.Task.WaitAsync(deadline.Token);
                if (_completedDomain)
                    await _completedWritten.Task.WaitAsync(deadline.Token);

                if (operatorStop)
                {
                    await _failingReady.Task.WaitAsync(deadline.Token);
                    await caller.CancelAsync();
                }
                else
                    _allowFailure.TrySetResult();

                if (recover)
                {
                    _releaseCleanup.TrySetResult();
                    await Task.WhenAny(_recoveredWritten.Task, run).WaitAsync(deadline.Token);
                    _releaseRead.TrySetResult();
                }
                else
                {
                    await CancellationObserved.Task.WaitAsync(deadline.Token);
                }

                _releaseCleanup.TrySetResult();
                return await run.WaitAsync(deadline.Token);
            }
            finally
            {
                // A deliberately broken cancellation path must fail, not leave a synthetic read
                // or writer alive after the test. The deadline is a test safety net, not a timing
                // assertion or a capture budget.
                _allowFailure.TrySetResult();
                _releaseRead.TrySetResult();
                _releaseCleanup.TrySetResult();
                await caller.CancelAsync();
                try
                {
                    await run;
                }
                catch (OperationCanceledException) when (caller.IsCancellationRequested)
                {
                    _output.WriteLine("Synthetic capture cancellation observed during test cleanup.");
                }
            }
        }

        private CapturePlan Plan()
        {
            var domains = new List<(string NamingContext, string DnsName, string Controller)>();
            if (_completedDomain)
                domains.Add((ExtraDomain, "three.example.com", "dc3.example.com"));
            domains.Add((FirstDomain, "one.example.com", _sharedHost ? SharedHost : "dc1.example.com"));
            domains.Add((FailedDomain, "two.example.com", "dc2.example.com"));
            if (_queued || _sharedHost)
                domains.Add((ExtraDomain, "three.example.com", _sharedHost ? SharedHost : "dc3.example.com"));
            var failover = new Dictionary<string, IReadOnlyList<string>>();
            if (_recover)
                failover[FailedDomain] = [Replacement];
            return CapturePlan.For(Root, Forest, Configuration, Schema, domains,
                [Configuration, Schema, .. domains.Select(domain => domain.NamingContext)], [], failover).Value;
        }

        public Result<IDirectoryChannel> Connect(CaptureUnit unit)
        {
            var role = Role.Success;
            if (unit.Kind == NamingContextKind.Domain)
            {
                OpenedDomains.Enqueue(unit);
                if (_queued)
                {
                    // Admission order is not plan order. Assign the first two actual readers
                    // these roles so the fixture always has one blocked, one failing, and one
                    // queued, whichever tasks the scheduler runs first.
                    role = Interlocked.Increment(ref _admitted) switch
                    {
                        1 => Role.Blocked,
                        2 => Role.Failing,
                        _ => Role.Success,
                    };
                }
                else if (unit.DomainController == SharedHost)
                    role = Interlocked.Increment(ref _sharedAdmitted) == 1 ? Role.Blocked : Role.Success;
                else if (unit.NamingContext == FirstDomain)
                    role = Role.Blocked;
                else if (unit.NamingContext == FailedDomain && unit.DomainController != Replacement)
                    role = Role.Failing;
            }

            var model = new ControllerModel(unit.DomainController);
            model.AddObjects(1, unit.NamingContext);
            var channel = new Channel(this, model.Connections().Connect(unit).Value, role);
            _active.TryAdd(channel, 0);
            return channel;
        }

        public Result<IDirectoryChannel> Connect(string domainController) =>
            throw new InvalidOperationException("Synthetic capture must use the approved units, not discover controllers.");

        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            _notes.Enqueue(message);
            if (message == "domain written to its own database")
            {
                var domain = RecordingRunLog.Value(detail, "namingContext");
                if (domain == ExtraDomain && _completedDomain)
                    _completedWritten.TrySetResult();
                if (domain == FailedDomain && _recover)
                    _recoveredWritten.TrySetResult();
            }
        }

        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) => Errors.Enqueue(error);

        public IEnumerable<string> LockedOutputFiles()
        {
            var locked = new List<string>();
            foreach (var path in Directory.EnumerateFiles(_directory))
            {
                try
                {
                    using var file = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                }
                catch (IOException failure)
                {
                    locked.Add(path + ": " + failure.Message);
                }
            }
            return locked;
        }

        private enum Role { Success, Blocked, Failing }

        private sealed class Channel(FailureScenario scenario, IDirectoryChannel inner, Role role) : IDirectoryChannel
        {
            private DirectoryPage? _lastPage;
            public string DomainController => inner.DomainController;
            public ConnectionSecurityLevel SecurityLevel => inner.SecurityLevel;
            public ReferralChasingOptions ReferralChasing => inner.ReferralChasing;
            public IReadOnlyList<string> SupportedControls => inner.SupportedControls;
            public IReadOnlyList<string> NamingContextsServed => inner.NamingContextsServed;
            public bool IsComplete => inner.IsComplete;

            public async Task<DirectoryPage> SendAsync(SearchRequest request, CancellationToken cancellationToken)
            {
                if (role == Role.Failing)
                {
                    scenario._failingReady.TrySetResult();
                    await scenario._blockedReady.Task.WaitAsync(cancellationToken);
                    await scenario._allowFailure.Task.WaitAsync(cancellationToken);
                    return (await inner.SendAsync(request, cancellationToken)) with { Completeness = PageCompleteness.NotPaged };
                }
                if (role != Role.Blocked)
                    return await inner.SendAsync(request, cancellationToken);
                if (_lastPage is null)
                {
                    var page = await inner.SendAsync(request, cancellationToken);
                    _lastPage = page with { Entries = [], Completeness = PageCompleteness.LastPage, PagingCookie = [] };
                    return page with { Completeness = PageCompleteness.MoreToCome, PagingCookie = [1] };
                }

                scenario._blockedReady.TrySetResult();
                try
                {
                    await scenario._releaseRead.Task.WaitAsync(cancellationToken);
                    return _lastPage;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    scenario.CancellationObserved.TrySetResult();
                    await scenario._releaseCleanup.Task;
                    throw;
                }
            }

            public void Dispose()
            {
                inner.Dispose();
                scenario._active.TryRemove(this, out _);
            }
        }
    }
}
