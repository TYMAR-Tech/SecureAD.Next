using System.Security.AccessControl;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// What automatic discovery finds, and — more importantly — what it refuses to claim.
/// </summary>
/// <remarks>
/// The anchor for these checks is deliberately outside the scheduler: each case starts from a
/// synthetic sealed bundle whose captured evidence is known, and asks what a customer would be
/// told. A scheduler that quietly skipped an unreadable descriptor would still pass a test that
/// only counted the answers it produced.
/// </remarks>
public sealed class SelfMembershipDiscoveryCoverageTests
{
    private const string Self = "bf9679c0-0de6-11d0-a285-00aa003049e2";

    /// <summary>Without an approved production budget, nothing is scanned and the store says so.</summary>
    /// <remarks>
    /// This is the shipping state: no numerical automatic-discovery limit has been measured or
    /// approved, so normal judging performs no discovery. The distinction that matters is that an
    /// empty requester product must not read as "no one can add themselves to anything".
    /// </remarks>
    [Fact]
    public void WithNoConfiguredBudgetNothingIsScannedAndTheStoreDoesNotClaimOtherwise()
    {
        var summary = Summary(Judged(SelfMembershipDiscoveryTests.Bundle(), budget: null));

        Assert.Equal(SelfMembershipDiscoveryMode.Automatic, summary.Discovery.Mode);
        Assert.Equal("NotStarted", summary.Verdict);
        Assert.False(summary.Discovery.InputScanCompleted);
        Assert.Equal(0, summary.AssessmentsStored);
        Assert.Equal(0, summary.Discovery.PairsDiscovered);
        Assert.Equal(0, summary.Discovery.ObjectsVisited);
        Assert.Equal(SelfMembershipDiscoveryReason.ProductionBudgetNotConfigured,
            Assert.Single(summary.Discovery.Limitations).Reason);
    }

    /// <summary>A deny and an unrecognised entry are discovered, not filtered out as uninteresting.</summary>
    /// <remarks>
    /// Discovering only established allows would produce a screen that lists the safe cases and
    /// silently omits the ones an administrator most needs to see.
    /// </remarks>
    [Theory]
    [InlineData("D:(OA;;SW;" + Self + ";;{0})", ControlEvaluationState.Established)]
    [InlineData("D:(OD;;SW;" + Self + ";;{0})", ControlEvaluationState.NotEstablished)]
    [InlineData("D:(OD;;SW;" + Self + ";;{0})(OA;;SW;" + Self + ";;{0})", ControlEvaluationState.NotEstablished)]
    public void RelevantDeniesAreDiscoveredRatherThanSkipped(string dacl, ControlEvaluationState expected)
    {
        var answers = Assessments(Judged(SelfMembershipDiscoveryTests.Bundle(
            "O:SYG:SY" + string.Format(dacl, SelfMembershipDiscoveryTests.UserSid))));

        Assert.Equal(2, answers.Count);
        Assert.All(answers, value => Assert.Equal(expected, value.Authorization));
    }

    /// <summary>Permissions that were never captured are a coverage limitation, not a negative answer.</summary>
    /// <remarks>
    /// An <b>empty</b> DACL is different and is not covered here: it is a real answer meaning nobody
    /// holds the right. Evidence that was never read cannot say that, so it names its gap instead.
    /// </remarks>
    [Fact]
    public void PermissionsThatWereNeverCapturedAreRecordedAsALimitation()
    {
        var directory = Judged(SelfMembershipDiscoveryTests.Bundle(targetDescriptor: false));
        var summary = Summary(directory);

        Assert.Empty(Assessments(directory));
        Assert.Equal(0, summary.AssessmentsStored);
        Assert.Equal(0, summary.Discovery.PairsDiscovered);
        Assert.Contains(summary.Discovery.Limitations,
            item => item.Reason == SelfMembershipDiscoveryReason.DescriptorUnavailable);
    }

    /// <summary>A NULL DACL grants everyone everything and is recorded as a coverage limitation.</summary>
    [Fact]
    public void ANullDaclIsRecordedRatherThanExpandedIntoRequesters()
    {
        var directory = Judged(SelfMembershipDiscoveryTests.Bundle("O:SYG:SY", users: 3));
        var summary = Summary(directory);

        Assert.Empty(Assessments(directory));
        Assert.Equal(0, summary.Discovery.PairsDiscovered);
        Assert.Contains(summary.Discovery.Limitations,
            item => item.Reason == SelfMembershipDiscoveryReason.BroadTrustee);
    }

    /// <summary>A broad runtime trustee does not become every captured user.</summary>
    /// <remarks>
    /// <c>Authenticated Users</c> has no captured membership to walk. Expanding it into a requester
    /// per account would invent concrete claims the evidence does not support, so the scan records
    /// that it could not enumerate the trustee and moves on.
    /// </remarks>
    [Fact]
    public void ABroadTrusteeIsNotExpandedIntoEveryCapturedUser()
    {
        var summary = Summary(Judged(SelfMembershipDiscoveryTests.Bundle(
            "O:SYG:SYD:(OA;;SW;" + Self + ";;AU)", users: 4)));

        Assert.Equal(0, summary.Discovery.PairsDiscovered);
        Assert.Equal(0, summary.AssessmentsStored);
        Assert.Contains(summary.Discovery.Limitations,
            item => item.Reason == SelfMembershipDiscoveryReason.BroadTrustee);
        Assert.True(summary.Discovery.InputScanCompleted);
    }

    /// <summary>A group whose membership was not captured names its gap instead of reading as empty.</summary>
    [Theory]
    [InlineData(false, -2147483646, SelfMembershipDiscoveryReason.MembershipNotCaptured)]
    [InlineData(true, null, SelfMembershipDiscoveryReason.GroupTypeMissing)]
    [InlineData(true, -2147483644, SelfMembershipDiscoveryReason.UnsupportedRoute)]
    public void MissingOrUnsupportedGroupEvidenceIsNamed(bool membership, int? groupType,
        SelfMembershipDiscoveryReason reason)
    {
        var summary = Summary(Judged(GroupHeldBundle(membership, groupType)));

        Assert.Contains(summary.Discovery.Limitations, item => item.Reason == reason);
        Assert.True(summary.Discovery.InputScanCompleted);
    }

    /// <summary>Reaching a configured limit keeps what was found and records where it stopped.</summary>
    /// <remarks>
    /// Decision 0102's shape: a partial scan is retained and admits it, rather than being discarded
    /// or presented as a complete picture.
    /// </remarks>
    [Fact]
    public void AProcessingStopRetainsWhatWasFoundAndSaysWhereItStopped()
    {
        var summary = Summary(Judged(GroupHeldBundle(true, -2147483646, users: 4),
            new SelfMembershipDiscoveryBudget(100, 1000, 1000, 2)));

        Assert.Equal(2, summary.Discovery.PairsDiscovered);
        Assert.Equal(4, summary.AssessmentsStored);
        Assert.False(summary.Discovery.InputScanCompleted);
        Assert.Equal("ProcessingStopped", summary.Verdict);
        var stop = Assert.Single(summary.Discovery.Limitations.Where(item => item.IsProcessingStop));
        Assert.Equal(SelfMembershipDiscoveryReason.PairBudgetExceeded, stop.Reason);
        Assert.Equal(SelfMembershipDiscoveryTests.TargetDn, stop.TargetDn);
    }

    /// <summary>Every discovered pair is asked about adding and removing its own account.</summary>
    /// <remarks>
    /// Missing membership does not prove absence, so a removal question is scheduled whether or not
    /// the captured group lists the requester today.
    /// </remarks>
    [Fact]
    public void EveryPairIsAskedBothOperationsForItsOwnAccountOnly()
    {
        var answers = Assessments(Judged(GroupHeldBundle(true, -2147483646, users: 3)));

        Assert.Equal(6, answers.Count);
        foreach (var pair in answers.GroupBy(value => value.Request.RequesterDn, StringComparer.OrdinalIgnoreCase))
        {
            Assert.Equal([SelfMembershipOperation.Add, SelfMembershipOperation.Remove],
                pair.Select(value => value.Request.Operation).Order());
            Assert.All(pair, value =>
            {
                Assert.Null(value.Request.MemberDn);
                Assert.Equal(ControlEvaluationState.Established, value.OwnAccount);
            });
        }
    }

    /// <summary>The same evidence and the same budget stop at the same place, twice.</summary>
    [Fact]
    public void DiscoveryIsDeterministicForTheSameEvidenceAndBudget()
    {
        var budget = new SelfMembershipDiscoveryBudget(100, 1000, 1000, 2);
        var first = Summary(Judged(GroupHeldBundle(true, -2147483646, users: 4), budget));
        var second = Summary(Judged(GroupHeldBundle(true, -2147483646, users: 4), budget));

        Assert.Equal(first.Discovery with { Limitations = [] }, second.Discovery with { Limitations = [] });
        Assert.Equal(first.Discovery.Limitations, second.Discovery.Limitations);
        Assert.Equal(first.AssessmentsStored, second.AssessmentsStored);
    }

    /// <summary>A judging that failed publishes nothing, and the previous answers stay previous.</summary>
    [Fact]
    public void ACancelledJudgingLeavesTheEarlierGenerationUntouched()
    {
        var directory = SelfMembershipDiscoveryTests.Bundle();
        SelfMembershipDiscoveryTests.Derive(directory);
        var first = Summary(Judged(directory, SelfMembershipDiscoveryTests.TestBudget));

        using var stopping = new CancellationTokenSource();
        stopping.Cancel();
        Assert.Throws<OperationCanceledException>(() => JudgingRun.Judge(directory, [],
            SelfMembershipDiscoveryTests.TestBudget, SelfMembershipDiscoveryTests.Started,
            SelfMembershipDiscoveryTests.Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, stopping.Token));

        var current = Summary(directory);
        Assert.Equal(first.GenerationId, current.GenerationId);
        Assert.Equal(first.AssessmentsStored, current.AssessmentsStored);
    }

    private static string GroupHeldBundle(bool membership, long? groupType, int users = 1) =>
        SelfMembershipDiscoveryTests.Bundle(
            "O:SYG:SYD:(OA;;SW;" + Self + ";;S-1-5-21-1-2-3-1200)", membership, users, groupType: groupType);

    /// <summary>
    /// Judges with the budget given. <paramref name="budget"/> is passed through exactly as supplied,
    /// including <c>null</c>, so a test asking about "no configured budget" genuinely gets none.
    /// </summary>
    private static string Judged(string directory, SelfMembershipDiscoveryBudget? budget) =>
        JudgedCore(directory, budget);

    private static string Judged(string directory) =>
        JudgedCore(directory, SelfMembershipDiscoveryTests.TestBudget);

    private static string JudgedCore(string directory, SelfMembershipDiscoveryBudget? budget)
    {
        if (!File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation)))
            SelfMembershipDiscoveryTests.Derive(directory);
        var judged = JudgingRun.Judge(directory, [], budget,
            SelfMembershipDiscoveryTests.Started, SelfMembershipDiscoveryTests.Started,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(judged.IsSuccess, judged.Error?.Description);
        return directory;
    }

    private static SelfMembershipSummary Summary(string directory)
    {
        using var reader = JudgementReader.Open(directory).Value!;
        return reader.ReadSelfMembershipSummary()!;
    }

    private static IReadOnlyList<SelfMembershipAssessment> Assessments(string directory)
    {
        using var reader = JudgementReader.Open(directory).Value!;
        return reader.ReadSelfMembershipAssessments(SelfMembershipDiscoveryTests.TargetDn, null).Assessments;
    }

    }
