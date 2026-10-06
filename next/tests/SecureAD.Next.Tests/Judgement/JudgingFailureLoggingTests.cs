using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class JudgingFailureLoggingTests
{
    [Fact]
    public void ProductionFailureIsDurableBeforeUnwindAndKeepsThePreviousPublication()
    {
        var directory = ReadyBundle();
        var prior = Publish(directory);
        var evidenceHash = Hash(BundleLayout.EvidencePath(directory));
        var derivationFile = Directory.GetFiles(directory, "derivation.*.db").Single();
        var derivationHash = Hash(derivationFile);
        var failure = new InvalidOperationException("injected proof failure", new IOException("inner diagnostic detail"));
        var opened = RunLogFile.Open(directory, "terminal-failure-test", TimeProvider.System);
        Assert.True(opened.IsSuccess);
        var recordedBeforeUnwind = false;
        CapturedLog log;
        using (var file = opened.Value)
        {
            log = new CapturedLog(file);
            log.BeforeWrite = line =>
            {
                if (line.Message == "path-requester-phase" && line.Value("phase") == "WritingProofs"
                    && line.Value("completed") == "False")
                    recordedBeforeUnwind = log.Lines.Any(entry => entry.Error?.Code == "Evidence.JudgingException");
            };
            var thrown = Assert.Throws<InvalidOperationException>(() => Run(directory, log,
                new Watching(value =>
                {
                    if (value.RequesterPhase == PathRequesterWorkPhase.WritingProofs) ThrowInjected(failure);
                }), CancellationToken.None));
            Assert.Same(failure, thrown);
            Assert.Contains(nameof(ThrowInjected), thrown.StackTrace);
        }

        Assert.True(recordedBeforeUnwind);
        var terminal = Assert.Single(log.Lines.Where(line => line.Error?.Code == "Evidence.JudgingException"));
        var build = Assert.Single(log.Lines.Where(line => line.Message == "judging build"));
        var generation = Assert.Single(log.Lines.Where(line => line.Message == "judging generation"));
        Assert.Equal(ErrorSeverity.Failed, terminal.Error!.Severity);
        Assert.Equal(build.Value("attempt"), terminal.Value("attempt"));
        Assert.Equal(generation.Value("generation"), terminal.Value("generation"));
        Assert.NotEqual(prior.Generation.ToString("D"), terminal.Value("generation"));
        Assert.Equal(generation.Value("evidenceSeal"), terminal.Value("evidenceSeal"));
        Assert.Equal(generation.Value("derivationGeneration"), terminal.Value("derivationGeneration"));
        Assert.NotEqual("none", terminal.Value("derivationGeneration"));
        Assert.Equal("WritingFindings", terminal.Value("phase"));
        Assert.Equal("WritingProofs", terminal.Value("requesterPhase"));
        Assert.Equal("NotStarted", terminal.Value("publication"));
        Assert.Equal(typeof(InvalidOperationException).FullName, terminal.Value("exceptionType"));
        Assert.Contains("inner diagnostic detail", terminal.Value("exception"));
        Assert.Contains(nameof(ThrowInjected), terminal.Value("exception"));
        var text = File.ReadAllText(BundleLayout.RunLogPath(directory));
        Assert.Contains("ERROR", text);
        Assert.Contains("Evidence.JudgingException", text);
        Assert.Contains("injected proof failure", text);
        Assert.Contains("inner diagnostic detail", text);
        Assert.Contains(nameof(ThrowInjected), text);
        Assert.Equal(prior.Marker, File.ReadAllBytes(Path.Combine(directory, "judgement.current.json")));
        using var reopened = JudgementReader.Open(directory).Value;
        Assert.Equal(prior.Generation, reopened.Read().Description.GenerationId);
        Assert.Equal(evidenceHash, Hash(BundleLayout.EvidencePath(directory)));
        Assert.Equal(derivationHash, Hash(derivationFile));
    }

    [Fact]
    public void CancellationIsRecordedWithoutBecomingFailureOrReplacingThePreviousResult()
    {
        var directory = ReadyBundle();
        var prior = Publish(directory);
        using var cancellation = new CancellationTokenSource();
        var log = new CapturedLog(RunLog.Discarded);
        var thrown = Assert.Throws<OperationCanceledException>(() => Run(directory, log,
            new Watching(value =>
            {
                if (value.RequesterPhase == PathRequesterWorkPhase.WritingProofs) cancellation.Cancel();
            }), cancellation.Token));
        Assert.Equal(cancellation.Token, thrown.CancellationToken);
        var terminal = Assert.Single(log.Lines.Where(line => line.IsTerminal));
        Assert.Equal("judging cancelled", terminal.Message);
        Assert.Null(terminal.Error);
        Assert.Equal("Cancelled", terminal.Value("outcome"));
        Assert.Equal("True", terminal.Value("cancellationRequested"));
        Assert.Equal("WritingProofs", terminal.Value("requesterPhase"));
        Assert.Equal("NotStarted", terminal.Value("publication"));
        Assert.Equal(prior.Marker, File.ReadAllBytes(Path.Combine(directory, "judgement.current.json")));
    }

    [Fact]
    public void ReturnedRefusalRecordsTheOriginalErrorWithoutInventingAGeneration()
    {
        var directory = TempDirectories.Create("judging-refusal-log");
        var log = new CapturedLog(RunLog.Discarded);
        var result = Run(directory, log, JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.False(result.IsSuccess);
        var terminal = Assert.Single(log.Lines.Where(line => line.IsTerminal));
        Assert.Same(result.Error, terminal.Error);
        Assert.Equal("Failed", terminal.Value("outcome"));
        Assert.Equal(result.Error.Context ?? "none", terminal.Value("errorContext"));
        Assert.Equal("none", terminal.Value("generation"));
        Assert.Equal("none", terminal.Value("evidenceSeal"));
        Assert.Equal("none", terminal.Value("derivationGeneration"));
        Assert.Equal("NotStarted", terminal.Value("publication"));
        Assert.Equal("PreparingInputs", terminal.Value("phase"));
        Assert.False(File.Exists(Path.Combine(directory, "judgement.current.json")));
    }

    [Fact]
    public void RefusalSurvivesAnUnexpectedLoggingFailure()
    {
        var attempts = 0;
        var log = new CapturedLog(RunLog.Discarded)
        {
            BeforeWrite = line =>
            {
                if (line.IsTerminal)
                {
                    attempts++;
                    throw new FormatException("failed refusal sink");
                }
            }
        };
        var result = Run(TempDirectories.Create("judging-refusal-broken-log"), log,
            JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.False(result.IsSuccess);
        Assert.Equal(1, attempts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BrokenExceptionSinkDoesNotReplaceTheOriginalException(bool cancellation)
    {
        var attempts = 0;
        var log = new CapturedLog(RunLog.Discarded)
        {
            BeforeWrite = line =>
            {
                if (line.IsTerminal)
                {
                    attempts++;
                    throw new FormatException("failed exception sink");
                }
            }
        };
        Exception original = cancellation ? new OperationCanceledException("original cancellation")
            : new InvalidOperationException("original failure");
        var thrown = Record.Exception(() => Run(ReadyBundle(), log,
            new Watching(value =>
            {
                if (value.RequesterPhase == PathRequesterWorkPhase.WritingProofs) ThrowInjected(original);
            }), CancellationToken.None));
        Assert.Same(original, thrown);
        Assert.Equal(1, attempts);
        Assert.Contains(nameof(ThrowInjected), thrown!.StackTrace);
    }

    [Theory]
    [InlineData("attempt")]
    [InlineData("generation")]
    [InlineData("evidenceSeal")]
    [InlineData("derivationGeneration")]
    [InlineData("phase")]
    [InlineData("operation")]
    [InlineData("rule")]
    [InlineData("objects")]
    [InlineData("elapsedMs")]
    public void FailureContextComesFromTheActiveAttempt(string field)
    {
        var log = new CapturedLog(RunLog.Discarded);
        var clock = new JudgingStatusTests.TimerClock();
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, PostPassMemory.Read);
        var generation = Guid.NewGuid();
        var derivation = Guid.NewGuid();
        var evidence = new string('B', 64);
        status.RecordGeneration(generation, evidence, derivation);
        status.Report(new(7) { Phase = JudgingPhase.EvaluatingObjects, JudgementGenerationId = Guid.NewGuid() });
        status.BeginRule("TEST-FAILED");
        status.CompleteObject(7);
        clock.Advance(TimeSpan.FromSeconds(5));
        ObserveException(status, new InvalidOperationException("context sentinel"));
        var terminal = Assert.Single(log.Lines.Where(line => line.IsTerminal));
        var expected = field switch
        {
            "attempt" => status.AttemptId.ToString("D"),
            "generation" => generation.ToString("D"),
            "evidenceSeal" => evidence,
            "derivationGeneration" => derivation.ToString("D"),
            "phase" => "EvaluatingObjects",
            "operation" => "rules",
            "rule" => "TEST-FAILED",
            "objects" => "7",
            "elapsedMs" => "5000",
            _ => throw new InvalidOperationException("Unknown fixture field.")
        };
        Assert.Equal(expected, terminal.Value(field));
    }

    [Fact]
    public void UnrequestedCancellationIsNotReportedAsACallerRequest()
    {
        var log = new CapturedLog(RunLog.Discarded);
        using var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching,
            new JudgingStatusTests.TimerClock(), PostPassMemory.Read);
        ObserveException(status, new OperationCanceledException("different cancellation source"));
        Assert.Equal("False", Assert.Single(log.Lines).Value("cancellationRequested"));
    }

    [Fact]
    public void AnInterruptedPublicationIsNotReportedAsDefinitelyUnpublished()
    {
        var directory = ReadyBundle();
        var prior = Publish(directory);
        var failure = new InvalidOperationException("publication boundary sentinel");
        var log = new CapturedLog(RunLog.Discarded);
        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => Run(directory, log,
            new Watching(value =>
            {
                if (value.Phase == JudgingPhase.PublishingJudgement) ThrowInjected(failure);
            }), CancellationToken.None)));
        var terminal = Assert.Single(log.Lines.Where(line => line.IsTerminal));
        Assert.Equal("Unconfirmed", terminal.Value("publication"));
        Assert.Equal("none", terminal.Value("requesterPhase"));
        Assert.Equal(prior.Marker, File.ReadAllBytes(Path.Combine(directory, "judgement.current.json")));
    }

    [Fact]
    public void AFailureAfterPublicationDoesNotClaimThatTheResultWasLost()
    {
        var directory = ReadyBundle();
        var failure = new InvalidOperationException("after publication sentinel");
        var log = new CapturedLog(RunLog.Discarded)
        {
            BeforeWrite = line =>
            {
                if (line.Message == "finished") ThrowInjected(failure);
            }
        };
        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() =>
            Run(directory, log, JudgingRun.NobodyIsWatching, CancellationToken.None)));
        var terminal = Assert.Single(log.Lines.Where(line => line.IsTerminal));
        Assert.Equal("Published", terminal.Value("publication"));
        using var saved = JudgementReader.Open(directory).Value;
        Assert.Equal(saved.Read().Description.GenerationId.ToString("D"), terminal.Value("generation"));
    }

    [Fact]
    public void SuccessfulJudgingDoesNotProduceATerminalFailure()
    {
        var log = new CapturedLog(RunLog.Discarded);
        var result = Run(ReadyBundle(), log, JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.DoesNotContain(log.Lines, line => line.IsTerminal);
        Assert.Contains(log.Lines, line => line.Message == "finished");
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BusyReporterDefersFailureWithoutBlockingOrMasking(bool brokenDeferredSink)
    {
        using var entered = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var terminalAttempts = 0;
        var log = new CapturedLog(RunLog.Discarded)
        {
            BeforeWrite = line =>
            {
                if (line.Message == "judging status")
                {
                    entered.Set();
                    if (!release.Wait(TimeSpan.FromSeconds(15)))
                        throw new InvalidOperationException("Reporter release timed out.");
                }
                if (line.IsTerminal)
                {
                    terminalAttempts++;
                    if (brokenDeferredSink) throw new FormatException("Deferred sink failed.");
                }
            }
        };
        var clock = new JudgingStatusTests.TimerClock();
        var status = new JudgingStatus(log, JudgingRun.NobodyIsWatching, clock, PostPassMemory.Read);
        var reporting = Task.Run(() => clock.Advance(JudgingStatus.Interval));
        Task? failing = null;
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            failing = Task.Run(() => ObserveException(status, new InvalidOperationException("deferred original")));
            await failing.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.DoesNotContain(log.Lines, line => line.IsTerminal);
            status.Report(new(0) { Phase = JudgingPhase.ReadingResults });
        }
        finally
        {
            release.Set();
            await reporting;
            if (failing is not null) await failing;
            status.Dispose();
        }
        Assert.Equal(1, terminalAttempts);
        if (brokenDeferredSink)
            Assert.DoesNotContain(log.Lines, line => line.IsTerminal);
        else
            Assert.Equal("PreparingInputs", Assert.Single(log.Lines.Where(line => line.IsTerminal)).Value("phase"));
    }

    private static string ReadyBundle()
    {
        var directory = Bundle();
        var derived = Stage2aRun.Derive(directory, ExpansionBudget.Bulk, Started,
            Stage2aRun.Unwatched, RunLog.Discarded, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        return directory;
    }

    private static (Guid Generation, byte[] Marker) Publish(string directory)
    {
        var result = Run(directory, RunLog.Discarded, JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        return (reader.Read().Description.GenerationId, File.ReadAllBytes(Path.Combine(directory, "judgement.current.json")));
    }

    private static Result<JudgementRunState> Run(string directory, IRunLog log,
        IProgress<JudgingRun.JudgingProgress> progress, CancellationToken cancellationToken) =>
        JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled, Started, Started,
            progress, log, cancellationToken, null);

    private static void ObserveException(JudgingStatus status, Exception original)
    {
        Exception? caught = null;
        try
        {
            try { ThrowInjected(original); }
            catch (Exception error) when (status.RecordException(error, false)) { throw; }
        }
        catch (Exception error) { caught = error; }
        Assert.Same(original, caught);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInjected(Exception failure) => throw failure;

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private sealed record Line(string Message, AuditError? Error, IReadOnlyList<RunLogDetail> Detail)
    {
        internal bool IsTerminal => Value("outcome") is "Failed" or "Cancelled";
        internal string? Value(string name) => Detail.FirstOrDefault(item => item.Name == name).Value;
    }

    private sealed class CapturedLog(IRunLog sink) : IRunLog
    {
        internal List<Line> Lines { get; } = [];
        internal Action<Line>? BeforeWrite { get; set; }
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            var line = new Line(message, null, detail.ToArray());
            BeforeWrite?.Invoke(line);
            sink.Note(phase, message, detail);
            Lines.Add(line);
        }
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail)
        {
            var line = new Line(error.Code, error, detail.ToArray());
            BeforeWrite?.Invoke(line);
            sink.Record(phase, error, detail);
            Lines.Add(line);
        }
    }

    private sealed class Watching(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => report(value);
    }
}
