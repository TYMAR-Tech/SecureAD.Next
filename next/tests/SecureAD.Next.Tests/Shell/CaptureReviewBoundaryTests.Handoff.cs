using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Audit.Connect;
using SecureAD.Cli;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Evidence;
using SecureAD.Shell.Services;
using Xunit;
using ReadbackCounts = SecureAD.Next.Tests.Shell.OpenedRunResultsTests.ReadbackCounts;
using static SecureAD.Next.Tests.Evidence.CapturePublicationProtectionTests;

namespace SecureAD.Next.Tests.Shell;

public sealed partial class CaptureReviewBoundaryTests
{
    [Fact]
    public async Task CaptureCompletionAutomaticAnalysisAndViewingShareThePublishedCapture()
    {
        var fixture = new Fixture(analysisInputs: true);
        var account = "CN=Captured account," + Root;
        var identity = Guid.Parse("3bb2e5ac-b5ec-48d5-9935-fd6de436f825");
        fixture.Bootstrap.AddObject(account, ("objectGUID", [identity.ToByteArray()]),
            ("objectClass", ["top", "user"]), ("userAccountControl", ["4194818"]),
            ("objectSid", [Sid.ToBytes("S-1-5-21-1111111111-2222222222-3333333333-1100")!]), ("primaryGroupID", ["513"]));
        using var sessions = new RunProtectionSessions();
        using var counts = new ReadbackCounts(fixture.Library);
        var directory = await CaptureProtected(fixture, sessions);
        Assert.Equal((0L, 0L, 0L, 0L), CaptureChecks(counts));
        Assert.Equal(1L, counts.EvidenceFormatChecks);

        var derived = await new DerivationLauncher(sessions).RunAsync(directory, Stage2aRun.Unwatched, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        var judged = await new JudgingLauncher(null, PathRequesterPolicy.Disabled, sessions).RunAsync(directory,
            JudgingRun.NobodyIsWatching, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        using (var selected = sessions.Acquire(directory))
        using (var evidence = BundleReader.Open(selected.Files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value).Value)
        using (var judgement = JudgementReader.Open(selected.Files.Analysis(AnalysisStoreKind.Judgement,
            StoreSegmentRole.Judgement, CancellationToken.None).Value).Value)
        {
            Assert.Equal(identity, evidence.ReadObjectIdentity(account)!.ObjectGuid);
            var finding = Assert.Single(judgement.Read().Findings, value => value.RuleId == "SEC-022");
            Assert.Equal((account, Severity.High), (finding.DistinguishedName, finding.Severity));
        }
        using var source = new BundleAssetSource(sessions);
        source.SelectRun(directory);
        Assert.True(source.ReadInventory(directory).IsSuccess);
        Assert.Equal(identity, source.ReadObjectIdentity(directory, account).Value!.ObjectGuid);
        Assert.Equal((0L, 0L, 0L, 0L), CaptureChecks(counts));
        Assert.Equal((2L, 1L, 1L), (counts.EvidenceFormatChecks, counts.DerivationVerifications, counts.JudgementVerifications));
        await source.CloseRunAsync();
        AssertReleased(directory);
    }

    [Fact]
    public async Task CaptureOnlyViewingDoesNotAnalyseAndLaterAnalysisVerifiesAfterRelease()
    {
        var fixture = new Fixture();
        using var sessions = new RunProtectionSessions();
        using var counts = new ReadbackCounts(fixture.Library);
        var directory = await CaptureProtected(fixture, sessions);
        using var source = new BundleAssetSource(sessions);
        source.SelectRun(directory);
        Assert.True(source.ReadInventory(directory).IsSuccess);
        Assert.False(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).IsSuccess);
        Assert.False(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).IsSuccess);
        Assert.Equal((0L, 0L, 0L, 0L), CaptureChecks(counts));
        await source.CloseRunAsync();
        AssertReleased(directory);

        var derived = await new DerivationLauncher(sessions).RunAsync(directory, Stage2aRun.Unwatched, CancellationToken.None);
        Assert.True(derived.IsSuccess, derived.Error?.Description);
        Assert.Equal(1L, counts.EvidenceVerifications);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CliCaptureKeepsPublicationProtectionThroughItsRequestedStagesThenCloses(bool captureOnly)
    {
        var fixture = new Fixture(analysisInputs: true);
        using var counts = new ReadbackCounts(fixture.Library);
        string? directory = null;
        ProtectedRunFiles? owner = null;
        var options = CommandLine.Parse(captureOnly ? ["--library", fixture.Library, "--capture"] : ["--library", fixture.Library])!;
        var exit = await Program.RunAsync(options, CancellationToken.None, null, async (protect, token) =>
        {
            var result = await CaptureIntoOwner(fixture, path => owner = protect(path), token);
            directory = result.Value.BundleDirectory;
            return result;
        }, PathRequesterPolicy.Disabled);

        Assert.Equal(0, exit);
        Assert.NotNull(directory);
        using var retained = Assert.IsType<ProtectedRunFiles>(owner);
        Assert.Throws<ObjectDisposedException>(() => retained.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        Assert.Equal((0L, 0L, 0L, 0L), CaptureChecks(counts));
        Assert.Equal((captureOnly ? 0L : 1L, captureOnly ? 0L : 1L),
            (counts.DerivationVerifications, counts.JudgementVerifications));
        Assert.Equal(!captureOnly, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).IsSuccess);
        Assert.Equal(!captureOnly, AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).IsSuccess);
        AssertReleased(directory);
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("failure")]
    [InlineData("throw")]
    public async Task CliCaptureClosesItsOwnerOnCancellationFailureAndUnexpectedExit(string ending)
    {
        var fixture = new Fixture();
        using var stopping = new CancellationTokenSource();
        string? directory = null;
        ProtectedRunFiles? owner = null;
        var unexpected = new InvalidOperationException("Synthetic failure after capture publication.");
        async Task<int> Run() => await Program.RunAsync(CommandLine.Parse(["--library", fixture.Library])!, stopping.Token,
            null, async (protect, token) =>
            {
                var result = await CaptureIntoOwner(fixture, path => owner = protect(path), token);
                directory = result.Value.BundleDirectory;
                if (ending == "throw") throw unexpected;
                if (ending == "failure") return Result<CaptureRunResult>.Failure(Failures.Any("Synthetic capture handoff refusal."));
                stopping.Cancel();
                return result;
            }, PathRequesterPolicy.Disabled);

        if (ending == "throw") Assert.Same(unexpected, await Assert.ThrowsAsync<InvalidOperationException>(Run));
        else Assert.Equal(ending == "cancel" ? 130 : 1, await Run());
        Assert.NotNull(directory);
        using var retained = Assert.IsType<ProtectedRunFiles>(owner);
        Assert.Throws<ObjectDisposedException>(() => retained.Capture(StoreSegmentRole.Evidence, CancellationToken.None));
        Assert.True(AnalysisStoreLifecycle.ResolveCapture(directory).IsSuccess);
        Assert.False(AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).IsSuccess);
        AssertReleased(directory);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrCancelledCaptureKeepsThePreviousCompletedHandoff(bool cancel)
    {
        var fixture = new Fixture();
        using var sessions = new RunProtectionSessions();
        var directory = await CaptureProtected(fixture, sessions);
        ProtectedStoreFile original;
        using (var reading = sessions.Acquire(directory))
            original = reading.Files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value;
        var failing = new Fixture();
        using var stopping = new CancellationTokenSource();
        var connections = 0;
        failing.BeforeConnections = () =>
        {
            if (++connections != 2) return;
            if (cancel) stopping.Cancel();
            else
            {
                failing.Bootstrap.FailuresBeforeAnswering = 1;
                failing.Bootstrap.FailWithCode = 50;
                failing.Bootstrap.FailsAsServerResult = true;
            }
        };
        var result = await new CaptureLauncher(failing.Session, sessions).RunAsync(failing.Library, null,
            new Dictionary<string, string>(), [], 1, stopping.Token);

        Assert.Equal(2, connections);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.False(result.Value.ProducedABundle);
        AssertReleased(result.Value.BundleDirectory);
        Assert.Throws<IOException>(() => File.Open(BundleLayout.EvidencePath(directory), FileMode.Open,
            FileAccess.ReadWrite, FileShare.ReadWrite));
        using var viewing = sessions.TakeForViewing(directory);
        Assert.Same(original, viewing.Files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value);
    }

    [Fact]
    public async Task ClosingTheCaptureHandoffWaitsForItsActualEvidenceReader()
    {
        var fixture = new Fixture();
        using var sessions = new RunProtectionSessions();
        var directory = await CaptureProtected(fixture, sessions);
        var viewing = sessions.TakeForViewing(directory);
        using var reader = BundleReader.Open(viewing.Files.Capture(StoreSegmentRole.Evidence, CancellationToken.None).Value).Value;

        var closing = viewing.DisposeAsync().AsTask();
        Assert.False(closing.IsCompleted);
        Assert.Throws<IOException>(() => File.Open(BundleLayout.EvidencePath(directory), FileMode.Open,
            FileAccess.ReadWrite, FileShare.ReadWrite));
        reader.Dispose();
        await closing.WaitAsync(TimeSpan.FromSeconds(5));
        AssertReleased(directory);
    }

    private static async Task<string> CaptureProtected(Fixture fixture, RunProtectionSessions sessions)
    {
        var result = await new CaptureLauncher(fixture.Session, sessions).RunAsync(fixture.Library, null,
            new Dictionary<string, string>(), [], 1, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.True(result.Value.ProducedABundle);
        return result.Value.BundleDirectory;
    }

    private static Task<Result<CaptureRunResult>> CaptureIntoOwner(Fixture fixture, Func<string, ProtectedRunFiles> protect,
        CancellationToken token) => fixture.Session(fixture.Library, 1).RunAsync(null, new Dictionary<string, string>(),
            new Dictionary<string, AttestedExclusion>(), null, CaptureObjectScope.Default, CaptureOptions.Default, token, protect);

    private sealed class NamingContextDirectory(IDirectoryChannelFactory inner) : IDirectoryChannelFactory
    {
        public Result<IDirectoryChannel> Connect(CaptureUnit unit) => Wrap(inner.Connect(unit));
        public Result<IDirectoryChannel> Connect(string host) => Wrap(inner.Connect(host));
        private static Result<IDirectoryChannel> Wrap(Result<IDirectoryChannel> opened) =>
            opened.IsSuccess ? new NamingContextChannel(opened.Value) : opened;
    }

    private sealed class NamingContextChannel(IDirectoryChannel inner) : IDirectoryChannel
    {
        public string DomainController => inner.DomainController;
        public ConnectionSecurityLevel SecurityLevel => inner.SecurityLevel;
        public ReferralChasingOptions ReferralChasing => inner.ReferralChasing;
        public IReadOnlyList<string> SupportedControls => inner.SupportedControls;
        public IReadOnlyList<string> NamingContextsServed => inner.NamingContextsServed;
        public bool IsComplete => inner.IsComplete;
        public void Dispose() => inner.Dispose();

        public async Task<DirectoryPage> SendAsync(SearchRequest request, CancellationToken cancellationToken)
        {
            var page = await inner.SendAsync(request, cancellationToken);
            if (request.Scope != SearchScope.Subtree) return page;
            // Configuration and Schema are separate naming contexts, not domain-search results.
            var children = NamingContextsServed.Where(context =>
                context.EndsWith("," + request.DistinguishedName, StringComparison.OrdinalIgnoreCase)).ToArray();
            return page with { Entries = page.Entries.Where(entry => !children.Any(context =>
                entry.DistinguishedName.Equals(context, StringComparison.OrdinalIgnoreCase)
                || entry.DistinguishedName.EndsWith("," + context, StringComparison.OrdinalIgnoreCase))).ToArray() };
        }
    }
}
