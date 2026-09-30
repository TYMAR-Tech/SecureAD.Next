using System.Collections.Concurrent;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class JudgingStatusTests
{
    [Fact]
    public void TimerReportsWithoutAnyProgressCallbacks()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);

        clock.Advance(TimeSpan.FromMinutes(3));

        Assert.Equal(3, log.Lines.Count(line => line.Message == "judging status"));
    }

    [Fact]
    public void BlockedRuleKeepsItsIdentityAndElapsedTime()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.Report(new(0) { Phase = JudgingPhase.EvaluatingObjects });
        status.BeginRule("TEST-BLOCKED");

        clock.Advance(TimeSpan.FromMinutes(2));

        var line = log.Lines.Last();
        Assert.Equal(("TEST-BLOCKED", "120000", "0", "120000"),
            (line.Value("rule"), line.Value("operationMs"), line.Value("objects"), line.Value("sinceObjectCompletedMs")));
    }

    [Fact]
    public void DetailIncludesTheRuleThatHasNotReturned()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.BeginRule("TEST-BLOCKED");

        clock.Advance(JudgingStatus.DetailInterval);

        var line = Assert.Single(log.Lines.Where(line => line.Message == "rule work so far"));
        Assert.Equal(("TEST-BLOCKED", "0", "300000"),
            (line.Value("rule"), line.Value("completedMs"), line.Value("activeMs")));
    }

    [Fact]
    public void CompletedAndActiveRuleTimeAreNotAddedTwice()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.BeginRule("TEST-RULE");
        clock.Advance(TimeSpan.FromMinutes(1));
        status.EndRule("TEST-RULE", TimeSpan.FromMinutes(1), 1, 0);
        status.CompleteObject(1);
        status.BeginRule("TEST-RULE");

        clock.Advance(TimeSpan.FromMinutes(4));

        var line = Assert.Single(log.Lines.Where(line => line.Message == "rule work so far"));
        Assert.Equal(("60000", "240000", "1"),
            (line.Value("completedMs"), line.Value("activeMs"), line.Value("judged")));
    }

    [Fact]
    public void ReportsCountsBelowTheUiProgressBoundary()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.CompleteObject(7);

        clock.Advance(JudgingStatus.Interval);
        clock.Advance(JudgingStatus.Interval);

        Assert.Equal(new[] { "7", "0" }, log.Lines.Select(line => line.Value("sinceLast")));
    }

    [Fact]
    public void APhaseChangeDoesNotInventCompletedObjects()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.CompleteObject(7);
        status.BeginRule("TEST-RULE");
        status.EndRule("TEST-RULE", TimeSpan.FromSeconds(1), 1, 0);
        status.Report(new(7) { Phase = JudgingPhase.EvaluatingRequesters });

        clock.Advance(JudgingStatus.Interval);

        var line = Assert.Single(log.Lines);
        Assert.Equal(("EvaluatingRequesters", "none", "7"),
            (line.Value("operation"), line.Value("rule"), line.Value("objects")));
    }

    [Fact]
    public void NoMessagesArriveAfterDisposal()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.Dispose();

        clock.Advance(TimeSpan.FromMinutes(10));

        Assert.Empty(log.Lines);
    }

    [Fact]
    public void ReportingFailureDisablesRetriesWithoutEscapingTimer()
    {
        var log = new FailingLog();
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);

        clock.Advance(TimeSpan.FromMinutes(3));

        Assert.Equal(1, log.Attempts);
    }

    [Fact]
    public void AccountingIsDueByElapsedTimeNotObjectCount()
    {
        var clock = new TimerClock();
        using var status = new JudgingStatus(new StatusLog(), JudgingRun.NobodyIsWatching, clock);
        clock.Advance(JudgingStatus.DetailInterval);

        Assert.Equal((true, false), (status.AccountingDue(), status.AccountingDue()));
    }

    [Fact]
    public void QueuedCallbackCannotWriteAfterDisposal()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        status.Dispose();

        clock.FireQueuedCallback();

        Assert.Empty(log.Lines);
    }

    [Fact]
    public void CancellationUnwindsReporterBeforeLogLifetimeEnds()
    {
        var log = new StatusLog();
        var clock = new TimerClock();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() =>
        {
            using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
            cancellation.Token.ThrowIfCancellationRequested();
        });

        clock.FireQueuedCallback();

        Assert.Empty(log.Lines);
    }

    [Fact]
    public async Task WorkerCanUpdateWhileReporterIsWriting()
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var log = new StatusLog(_ =>
        {
            entered.Set();
            if (!release.Wait(TimeSpan.FromSeconds(5))) throw new InvalidOperationException("Test log release timed out");
        });
        var clock = new TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock);
        var reporting = Task.Run(() => clock.Advance(JudgingStatus.Interval));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            await Task.Run(() => status.CompleteObject(3)).WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            release.Set();
            await reporting;
        }
    }

    [Fact]
    public async Task RealJudgingReportsARuleBeforeItReturns()
    {
        var directory = Bundle();
        using var reported = new ManualResetEventSlim();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(85));
        var log = new StatusLog(line =>
        {
            if (line.Message == "judging status" && line.Value("rule") == "TEST-BLOCKED") reported.Set();
        });
        var rule = new WaitingRule(reported, cancellation.Token);
        var task = Task.Run(() => JudgingRun.Judge(directory, [rule], Started, Started,
            JudgingRun.NobodyIsWatching, log, cancellation.Token));
        try
        {
            var result = await task.WaitAsync(TimeSpan.FromSeconds(90));
            Assert.True(result.IsSuccess, result.Error?.Description);
            Assert.Contains(log.Lines, line => line.Message == "judging status"
                && line.Value("rule") == "TEST-BLOCKED" && line.Value("objects") == "0");
        }
        finally
        {
            cancellation.Cancel();
            reported.Set();
            await task;
        }
    }

    private sealed class WaitingRule(ManualResetEventSlim reported, CancellationToken token) : IRule
    {
        public RuleDefinition Definition { get; } = new("TEST-BLOCKED", "Held diagnostic test rule", Severity.Low,
            1, [], ["objectClass"], []);
        public RuleVerdict Judge(ObjectAttributes subject)
        {
            reported.Wait(token);
            return RuleVerdict.Judged([]);
        }
        public RuleVerdict Judge(ObjectAttributes subject, JudgingContext context) => Judge(subject);
    }

    internal sealed record Line(string Message, IReadOnlyList<RunLogDetail> Detail)
    {
        internal string? Value(string name) => Detail.FirstOrDefault(item => item.Name == name).Value;
    }

    internal sealed class StatusLog(Action<Line>? observed = null) : IRunLog
    {
        internal ConcurrentQueue<Line> Lines { get; } = new();
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            var line = new Line(message, detail.ToArray());
            Lines.Enqueue(line);
            observed?.Invoke(line);
        }
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) { }
    }

    private sealed class FailingLog : IRunLog
    {
        internal int Attempts { get; private set; }
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            Attempts++;
            throw new IOException("Simulated unavailable log");
        }
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) { }
    }

    internal sealed class TimerClock : TimeProvider
    {
        private long _ticks;
        private TestTimer? _timer;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            _timer = new TestTimer(callback, state, _ticks + dueTime.Ticks, period.Ticks);
        internal void Advance(TimeSpan elapsed)
        {
            var until = _ticks + elapsed.Ticks;
            while (_timer is { Disposed: false } timer && timer.Next <= until)
            {
                _ticks = timer.Next;
                timer.Next += timer.Period;
                timer.Callback(timer.State);
            }
            _ticks = until;
        }
        internal void FireQueuedCallback() => _timer!.Callback(_timer.State);
        private sealed class TestTimer(TimerCallback callback, object? state, long next, long period) : ITimer
        {
            internal TimerCallback Callback { get; } = callback;
            internal object? State { get; } = state;
            internal long Next { get; set; } = next;
            internal long Period { get; } = period;
            internal bool Disposed { get; private set; }
            public bool Change(TimeSpan dueTime, TimeSpan period) => throw new NotSupportedException();
            public void Dispose() => Disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
