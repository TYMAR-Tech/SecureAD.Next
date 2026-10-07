using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class Tier0PathTests
{
    [Fact]
    public void Tier0OverviewPagesCoverSavedIdentitiesOnceWithoutLoadingRoutes()
    {
        var directory = Captured(depth: 55);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var before = Snapshot(directory);
        var rows = new List<Tier0OverviewRow>();
        Tier0OverviewMark? after = null;
        var summary = reader.ReadTier0RunSummary()!;
        do
        {
            var page = reader.ReadTier0Overview(after, CancellationToken.None)!;
            Assert.Equal(summary, page.Summary);
            Assert.InRange(page.Objects.Count, 1, 50);
            rows.AddRange(page.Objects);
            after = page.Next;
        } while (after is not null);
        Assert.Equal(summary.RecordedSubjects, rows.Count);
        Assert.Equal(rows.Count, rows.Select(row => row.Subject.DistinguishedName).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(55, Assert.Single(rows, row => row.Subject.DistinguishedName == UserDn).Distance.SupportedDistance);
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void Tier0OverviewRejectsForeignContinuationAndCancellation()
    {
        var directory = Captured(depth: 55);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var mark = reader.ReadTier0Overview(null, CancellationToken.None)!.Next!;
        Assert.Throws<ArgumentException>(() => reader.ReadTier0Overview(mark with { GenerationId = Guid.NewGuid() }, CancellationToken.None));
        Assert.Throws<ArgumentException>(() => reader.ReadTier0Overview(mark with { CalculationFingerprint = new('f', 64) }, CancellationToken.None));
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => reader.ReadTier0Overview(null, stop.Token));
    }

    [Theory]
    [InlineData(UserDn, 3)]
    [InlineData(CoreDn, 0)]
    [InlineData(TargetDn, null)]
    public void Tier0SelectedBrowsingRetainsSavedDistancesAndBoundSteps(string target, int? length)
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        using var reader = Open(directory);
        var result = reader.ReadTier0RouteDetails(target, CancellationToken.None)!;
        Assert.Equal(length, result.Distance.SupportedDistance);
        Assert.Equal(length ?? 0, result.ShortestSteps.Count);
        Assert.Equal(reader.ReadBestSupportedRoute(target)!.Steps, result.BestSteps);
        Assert.Equal(reader.Description.GenerationId, result.GenerationId);
        Assert.Equal(reader.Description.EvidenceSeal, result.EvidenceSeal);
        Assert.Equal(reader.ReadTier0RunSummary()!.CalculationFingerprint, result.CalculationFingerprint);
    }

    [Fact]
    public void Tier0SelectedBrowsingDoesNotReadAnotherSubjectsBrokenBestProof()
    {
        var directory = Captured(depth: 3);
        Derive(directory);
        Judge(directory);
        Mutate(directory, $"UPDATE tier0_best_route SET fingerprint=zeroblob(32) WHERE target='{TargetDn}'");
        using var reader = Open(directory);
        var before = Snapshot(directory);
        Tier0RouteDetails? selected = null;
        Assert.Null(Record.Exception(() => selected = reader.ReadTier0RouteDetails(UserDn, CancellationToken.None)));
        Assert.Equal(3, selected!.ShortestSteps.Count);
        Assert.Throws<InvalidDataException>(() => reader.ReadTier0RouteDetails(TargetDn, CancellationToken.None));
        Assert.Equal(before, Snapshot(directory));
    }

    [Fact]
    public void Tier0UnavailableBrowsingKeepsUnassessedAnswersAndAbsentSubjectsExplicit()
    {
        var directory = Captured();
        Judge(directory);
        using var reader = Open(directory);
        var page = reader.ReadTier0Overview(null, CancellationToken.None)!;
        Assert.All(page.Objects, row =>
        {
            Assert.Equal(Tier0DistanceVerdict.NotAssessed, row.Distance.Verdict);
            Assert.Null(row.Distance.SupportedDistance);
            Assert.Null(row.BestGrade);
        });
        Assert.Null(reader.ReadTier0RouteDetails("CN=Absent,DC=contoso,DC=com", CancellationToken.None));
    }
}
