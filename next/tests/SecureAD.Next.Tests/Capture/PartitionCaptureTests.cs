using System.DirectoryServices.Protocols;
using SecureAD.Audit.Capture;
using SecureAD.Evidence;
using Xunit;
using SecureAD.Kernel.Capture;

namespace SecureAD.Next.Tests.Capture;

/// <summary>
/// A clock that does not wait, and remembers what it was asked to wait for.
///
/// <para>
/// The retry policy waits five seconds, then ten, then twenty. A test that honoured those would
/// take half a minute to prove one thing, so the waits are asked for and recorded rather than
/// served - which also lets a test check that the backoff doubled, which is the part of the policy
/// that matters to a controller under load.
/// </para>
/// </summary>
internal sealed class ImmediateTimeProvider : TimeProvider
{
    public List<TimeSpan> Waits { get; } = [];

    public override ITimer CreateTimer(
        TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        Waits.Add(dueTime);
        return base.CreateTimer(callback, state, TimeSpan.Zero, period);
    }
}

/// <summary>
/// Inventory row B6: the loop that reads one naming context whole.
///
/// <para>
/// The failure every test here circles is one failure. A paged search ends when the controller says
/// there is no more to send; a client that chased a subordinate referral is told that on its first
/// page, wrongly, and nothing in the answer says so. The loop therefore refuses to make the claim
/// unless the connection has told it that chasing was off, and the pair of tests
/// <see cref="AConnectionThatChasesReferralsIsRefusedBeforeAnyRequestIsSent"/> and
/// <see cref="TheSameControllerIsReadWhenChasingIsOff"/> is the evidence that the check is what
/// stops it rather than something else.
/// </para>
/// </summary>
public sealed class PartitionCaptureTests
{
    private static CaptureUnit Unit(string dn = "DC=example,DC=com") =>
        CaptureUnit.Create(dn, NamingContextKind.Domain, "dc01.example.com").Value;

    private static (PartitionCapture Capture, RecordingSink Sink, ImmediateTimeProvider Time)
        CaptureOver(ControllerModel model)
    {
        var sink = new RecordingSink();
        var time = new ImmediateTimeProvider();
        return (new PartitionCapture(model.Connections(), sink, time), sink, time);
    }

    [Fact]
    public async Task APartitionLargerThanAPageIsReadToTheEnd()
    {
        var model = new ControllerModel();
        model.AddObjects(2_500, "DC=example,DC=com");
        var (capture, sink, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(3, read.Value.PagesRead);
        Assert.Equal(2_500, read.Value.ObjectsRead);
        Assert.Equal(2_500, sink.Received.Count);
    }

    [Fact]
    public async Task AConnectionThatChasesReferralsIsRefusedBeforeAnyRequestIsSent()
    {
        var model = new ControllerModel { ReferralChasing = ReferralChasingOptions.All };
        model.AddObjects(2_500, "DC=example,DC=com");
        var (capture, sink, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal("Capture.ReferralPolicyNotAppliedToConnection", read.Error!.Code);
        Assert.Equal(0, model.RequestsReceived);
        Assert.Empty(sink.Received);
    }

    [Fact]
    public async Task TheSameControllerIsReadWhenChasingIsOff()
    {
        var model = new ControllerModel { ReferralChasing = ReferralChasingOptions.None };
        model.AddObjects(2_500, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);
    }

    /// <summary>
    /// The one this row exists for, stated as plainly as a test can state it.
    ///
    /// <para>
    /// A controller holding nine thousand objects reports the search finished after the first
    /// thousand. That is exactly what a client sees when a referral was chased, and it is also
    /// exactly what a partition of a thousand objects looks like. The loop believes it, because
    /// there is nothing in the answer to disbelieve - Microsoft's account of the defect is that the
    /// controller sent a good bookmark and the client library threw it away. So this test records
    /// what the loop does <i>and</i> that the only thing standing between it and a false report is
    /// the referral check above.
    /// </para>
    /// </summary>
    [Fact]
    public async Task AControllerThatSaysItIsFinishedIsBelieved()
    {
        var model = new ControllerModel { ClaimToBeFinishedAfterOnePage = true };
        model.AddObjects(9_000, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess);
        Assert.Equal(1_000, read.Value.ObjectsRead);
    }

    /// <summary>
    /// The second line of the referral defence is only sent where the controller advertises it, so
    /// a connection that cannot say what it advertises would drop it and say nothing.
    /// </summary>
    [Fact]
    public async Task AConnectionThatCannotSayWhatTheControllerAdvertisesIsRefused()
    {
        var model = new ControllerModel { CapabilitiesWereRead = false };
        model.AddObjects(10, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal("Capture.ControllerCapabilitiesWereNotRead", read.Error!.Code);
        Assert.Equal(0, model.RequestsReceived);
    }

    [Fact]
    public async Task AnAnswerWithNoPagingControlIsNotTheLastPage()
    {
        var model = new ControllerModel { AnswerWithoutThePagingControl = true };
        model.AddObjects(10, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal("Capture.PagedSearchWasNotPaged", read.Error!.Code);
    }

    /// <summary>
    /// An empty page is not the end. Microsoft records that a controller may return one and still
    /// report success, meaning it could not build a page this time and has not finished, and that
    /// the client should keep asking.
    /// </summary>
    [Fact]
    public async Task AnEmptyPageWithAFreshBookmarkIsFollowed()
    {
        var model = new ControllerModel { BeginWithAnEmptyPage = true };
        model.AddObjects(10, "DC=example,DC=com");
        var (capture, sink, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(10, sink.Received.Count);
        Assert.Equal(2, read.Value.PagesRead);
    }

    [Fact]
    public async Task ABookmarkHandedStraightBackIsRefusedRatherThanResent()
    {
        var model = new ControllerModel { RepeatTheCookie = true };
        model.AddObjects(2_500, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal("Capture.PagedSearchRepeatedItsCookie", read.Error!.Code);
    }

    [Fact]
    public async Task ContinuationReferencesReachTheCoverageRecord()
    {
        var model = new ControllerModel();
        model.References.Add("ldap://dc01.example.com/DC=child,DC=example,DC=com");
        model.AddObjects(5, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(
            ["ldap://dc01.example.com/DC=child,DC=example,DC=com"],
            read.Value.ContinuationReferences);
    }

    /// <summary>
    /// A group larger than a controller will serve at once arrives whole or not at all. Run at the
    /// 1,500 default and again at the 5,000 hardcoded ceiling, because both are real configurations
    /// and both are smaller than the group.
    /// </summary>
    [Theory]
    [InlineData(1_500)]
    [InlineData(5_000)]
    public async Task AGroupTooLargeForOneResponseIsFinishedBeforeItIsHandedOn(int maxValRange)
    {
        var attribute = CapturedAttributeCatalog.RangeLiable[0];
        var members = Enumerable
            .Range(0, 10_000)
            .Select(i => (object)$"CN=member{i},DC=example,DC=com")
            .ToArray();

        var model = new ControllerModel { MaxValRange = maxValRange };
        model.AddObject("CN=Big,DC=example,DC=com", (attribute.LdapDisplayName, members));
        var (capture, sink, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);

        var values = Assert.Single(
            sink.Received[0].Attributes.Where(a =>
                a.LdapDisplayName == attribute.LdapDisplayName));

        Assert.Equal(AttributeCompleteness.Complete, values.Completeness);
        Assert.Equal(10_000, values.Values.Count);
        Assert.Equal(9, read.Value.AttributeBlocksFetched);
    }

    [Fact]
    public async Task ARangeRetrievalIsIssuedOnTheConnectionAlreadyPagingThePartition()
    {
        var attribute = CapturedAttributeCatalog.RangeLiable[0];
        var members = Enumerable
            .Range(0, 3_000)
            .Select(i => (object)$"CN=member{i},DC=example,DC=com")
            .ToArray();

        var model = new ControllerModel();
        model.AddObject("CN=Big,DC=example,DC=com", (attribute.LdapDisplayName, members));
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(1, model.ConnectionsOpened);
    }

    [Fact]
    public async Task AControllerSayingItIsBusyIsAskedThreeTimesAndThenTheRunEnds()
    {
        var model = new ControllerModel { FailuresBeforeAnswering = 99, FailWithCode = 51 };
        model.AddObjects(5, "DC=example,DC=com");
        var (capture, _, time) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal(3, model.RequestsReceived);
        Assert.Equal(1, model.ConnectionsOpened);
        Assert.Equal([TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10)], time.Waits);
    }

    [Fact]
    public async Task AFailureThatEndedTheConversationReadsTheNamingContextAgainFromTheStart()
    {
        var model = new ControllerModel { FailuresBeforeAnswering = 1, FailWithCode = 81 };
        model.AddObjects(5, "DC=example,DC=com");
        var (capture, sink, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.Equal(2, model.ConnectionsOpened);
        Assert.Equal(5, sink.Received.Count);
    }

    [Fact]
    public async Task ANamingContextIsReadAgainOnlyOnce()
    {
        var model = new ControllerModel { FailuresBeforeAnswering = 99, FailWithCode = 81 };
        model.AddObjects(5, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal(2, model.ConnectionsOpened);
    }

    [Fact]
    public async Task AConnectionToAnotherControllerIsRefused()
    {
        var model = new ControllerModel("dc99.example.com");
        model.AddObjects(5, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        var read = await capture.ReadAsync(Unit(), CancellationToken.None);

        Assert.False(read.IsSuccess);
        Assert.Equal("Capture.ConnectionIsToAnotherController", read.Error!.Code);
    }

    [Fact]
    public async Task ACancelledCaptureStopsRatherThanFinishing()
    {
        var model = new ControllerModel();
        model.AddObjects(2_500, "DC=example,DC=com");
        var (capture, _, _) = CaptureOver(model);

        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => capture.ReadAsync(Unit(), cancellation.Token));
    }
}
