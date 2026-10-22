using SecureAD.Judgement;
using SecureAD.Kernel;
using Xunit;
using static SecureAD.Next.Tests.Judgement.JudgingStatusTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class JudgingWorkProgressTests
{
    private static readonly Guid Generation = Guid.Parse("54bc7d68-b9f7-4186-806e-70fe79db9870");

    [Fact]
    public void DistinctRequesterAnswersAreSummedWithoutCountingPrerequisitesOrResources()
    {
        var reports = new Reports();
        using var status = Status(reports, new TimerClock());
        using (var own = status.BeginPostPass("Preparing membership prerequisites", Generation))
        {
            own.Counter("answersSaved", 0);
            own.Counter("uniquePrerequisites", 100_000);
            own.Counter("answersSaved", 2);
            own.Counter("resourcesProcessed", 50);
            own.Complete();
        }
        using (var dacl = status.BeginPostPass("Evaluating requester resource batches", Generation))
        {
            dacl.Counter("answersSaved", 0);
            dacl.Counter("answersSaved", 3);
            dacl.Complete();
        }
        var progress = reports.Values.Last(value => value.WorkUnit == JudgingWorkUnit.RequesterAssessments);
        Assert.Equal(5, progress.WorkCompleted);
        Assert.Equal(44, progress.ObjectsRead);
        Assert.Equal(Generation, progress.JudgementGenerationId);
        Assert.DoesNotContain(reports.Values, value => value.WorkCompleted is 50 or 100_000);
    }

    [Fact]
    public void WorkUsesExistingPageBatchesAndFlushesTheFinalShortBatchWithoutTimerHeartbeats()
    {
        var reports = new Reports();
        var clock = new TimerClock();
        using var status = Status(reports, clock);
        var page = PathRequesterWorkPlan.PageSize;
        using (var diagnostic = status.BeginPostPass("Matching saved answers", Generation))
        {
            for (var index = 0; index <= page * 3 + 7; index++) diagnostic.Counter("objectsProcessed", index);
            diagnostic.Complete();
        }
        var work = reports.Values.Where(value => value.WorkUnit == JudgingWorkUnit.PathObjects).ToArray();
        Assert.Equal([0L, (long)page, page * 2L, page * 3L, page * 3L + 7], work.Select(value => value.WorkCompleted!.Value));
        var before = reports.Values.Count;
        clock.Advance(TimeSpan.FromMinutes(3));
        Assert.Equal(before, reports.Values.Count);
    }

    [Fact]
    public void SelectingQuestionsIsNotReportedAsCompletedRequesterAssessments()
    {
        var reports = new Reports();
        using var status = Status(reports, new TimerClock());
        using (var diagnostic = status.BeginPostPass("Selecting account checks", Generation))
        {
            diagnostic.Counter("identityNodesIndexed", 20);
            diagnostic.Counter("resourcesProcessed", 1);
            diagnostic.Counter("questionsConsidered", 1_280);
            diagnostic.Counter("distinctQuestions", 100);
            diagnostic.Counter("resourcesProcessed", 2);
            diagnostic.Complete();
        }
        var last = reports.Values.Last();
        Assert.Equal((JudgingWorkUnit.QuestionsConsidered, 1_280L), (last.WorkUnit, last.WorkCompleted));
        Assert.DoesNotContain(reports.Values, value => value.WorkUnit == JudgingWorkUnit.RequesterAssessments);
    }

    [Fact]
    public void UnavailableOwnershipTargetsStillCountAsWorkNotAsSuccessfulAnswers()
    {
        var reports = new Reports();
        using var status = Status(reports, new TimerClock());
        using (var diagnostic = status.BeginPostPass("ownership-assessment", Generation))
        {
            diagnostic.Targets(2);
            diagnostic.TargetFinished();
            diagnostic.TargetFinished(available: false);
            diagnostic.Complete();
        }
        var last = reports.Values.Last();
        Assert.Equal((JudgingWorkUnit.OwnershipTargets, 2L), (last.WorkUnit, last.WorkCompleted));
    }

    private static JudgingStatus Status(Reports reports, TimerClock clock)
    {
        var status = new JudgingStatus(new StatusLog(), reports, clock, PostPassMemory.Read);
        status.RecordGeneration(Generation, "evidence", null);
        status.CompleteObject(44);
        status.Report(new(44) { Phase = JudgingPhase.WritingFindings, RequesterPhase = PathRequesterWorkPhase.RequesterDacl });
        return status;
    }

    private sealed class Reports : IProgress<JudgingRun.JudgingProgress>
    {
        internal List<JudgingRun.JudgingProgress> Values { get; } = [];
        public void Report(JudgingRun.JudgingProgress value) => Values.Add(value);
    }
}
