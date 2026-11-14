using System.Collections.Concurrent;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;
using Xunit;

namespace SecureAD.Next.Tests.Capture;

public sealed class CaptureProgressTests
{
    [Fact]
    public void AnUnreportedPolicyInventoryIsDifferentFromAnObservedZero()
    {
        var reports = new Reports();
        var tracker = new CaptureProgressTracker(Plan(), reports);
        tracker.Start();
        var unreported = Assert.Single(reports.Values);
        Assert.Null(unreported.PoliciesTotal);
        tracker.PolicyInventory(0);
        var empty = tracker.Current;
        Assert.Equal(0L, empty.PoliciesTotal);
        tracker.PolicyInventory(4);
        Assert.Equal(4L, tracker.Current.PoliciesTotal);
        Assert.Equal(0L, empty.PoliciesTotal);
        Assert.Null(unreported.PoliciesTotal);
    }

    [Fact]
    public async Task PageReportsObserveWrittenObjectsWithoutAddingQueriesOrPerObjectNotifications()
    {
        var model = new ControllerModel();
        model.AddObjects(2_500, "DC=example,DC=com");
        var sink = new RecordingSink();
        var capture = new PartitionCapture(model.Connections(), sink, new ImmediateTimeProvider(), new RecordingRunLog());
        var reports = new List<long>();
        var result = await capture.ReadAsync(Unit(), CancellationToken.None, reports.Add);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal([0L, 1_000L, 2_000L, 2_500L], reports);
        Assert.Equal(3, model.RequestsReceived);
        Assert.Equal(2_500, sink.Received.Count);
        Assert.Equal(result.Value.ObjectsRead, reports[^1]);
    }

    [Fact]
    public void SnapshotsRetainUnknownAndCurrentAttemptCountsWithoutMutatingEarlierReports()
    {
        var reports = new Reports();
        var plan = Plan();
        var tracker = new CaptureProgressTracker(plan, reports);
        tracker.Start();
        var original = Assert.Single(reports.Values);
        Assert.All(original.Scopes, scope => Assert.Null(scope.ObjectsRead));
        var domain = plan.Units.Single(unit => unit.Kind == NamingContextKind.Domain);
        tracker.Scope(domain, CaptureReadState.Reading, 1_000);
        tracker.Scope(domain, CaptureReadState.Reading, 0);
        tracker.Scope(domain, CaptureReadState.ReadComplete, 250);
        var current = tracker.Current.Scopes.Single(scope => scope.IsDomain);
        Assert.Equal((250L, CaptureReadState.ReadComplete), (current.ObjectsRead, current.State));
        Assert.All(original.Scopes, scope => Assert.Null(scope.ObjectsRead));
        var list = Assert.IsAssignableFrom<IList<CaptureScopeProgress>>(original.Scopes);
        Assert.Throws<NotSupportedException>(() => list[0] = list[0] with { ObjectsRead = 999 });
        Assert.Equal("example.com", current.DisplayName);
        Assert.Equal(2, original.Scopes.Count(scope => !scope.IsDomain));
    }

    [Fact]
    public void ConcurrentScopeReportsStayOrderedAndSealingNeverChangesDirectoryReadState()
    {
        var reports = new Reports();
        var plan = Plan();
        var tracker = new CaptureProgressTracker(plan, reports);
        tracker.Start();
        Parallel.ForEach(plan.Units, unit =>
        {
            for (var count = 0; count < 12; count++) tracker.Scope(unit, CaptureReadState.Reading, count);
            tracker.Scope(unit, CaptureReadState.ReadComplete, 12);
        });
        tracker.PolicyInventory(3);
        tracker.Policies(2);
        tracker.Phase(CaptureWorkPhase.Sealing);
        var all = reports.Values.ToArray();
        Assert.Equal(Enumerable.Range(1, all.Length).Select(value => (long)value), all.Select(value => value.Sequence));
        Assert.All(tracker.Current.Scopes, scope => Assert.Equal((12L, CaptureReadState.ReadComplete), (scope.ObjectsRead, scope.State)));
        Assert.Equal((CaptureWorkPhase.Sealing, 2L, 3L),
            (tracker.Current.Phase, tracker.Current.PoliciesProcessed, tracker.Current.PoliciesTotal));
        Assert.Contains(all, report => report.Scopes.Any(scope => scope.State == CaptureReadState.Reading));
    }

    internal static CapturePlan Plan() => CapturePlan.For(
        "dc01.example.com", "example.com", "CN=Configuration,DC=example,DC=com",
        "CN=Schema,CN=Configuration,DC=example,DC=com",
        [("DC=example,DC=com", "example.com", "dc01.example.com")],
        ["CN=Configuration,DC=example,DC=com", "CN=Schema,CN=Configuration,DC=example,DC=com", "DC=example,DC=com"],
        [], new Dictionary<string, IReadOnlyList<string>>()).Value;

    private static CaptureUnit Unit() => CaptureUnit.Create("DC=example,DC=com", NamingContextKind.Domain, "dc01.example.com").Value;

    internal sealed class Reports : IProgress<CaptureProgress>
    {
        internal ConcurrentQueue<CaptureProgress> Values { get; } = new();
        public void Report(CaptureProgress value) => Values.Enqueue(value);
    }
}
