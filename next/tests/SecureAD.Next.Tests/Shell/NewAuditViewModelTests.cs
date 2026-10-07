using SecureAD.Audit.Connect;
using SecureAD.Derivation;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The New Audit window: the domain table, the override, the PDC emulator prompt, and Start.
///
/// <para>
/// <b>The standing rule of this screen is that nothing on it may state a fact the run did not
/// measure.</b> Three of <c>S-40</c>'s findings - <c>F-S40-8</c>, <c>F-S40-10</c> and
/// <c>F-S40-11</c> - were one mistake made three times: an unasked question rendered as a negative
/// answer. A window is more exposed to that than a command line is, not less, which is why the
/// unknown cases are tested here rather than assumed.
/// </para>
/// </summary>
public sealed class NewAuditViewModelTests
{
    private readonly FakeSettingsStore _settings = new();
    private readonly FakeCaptureLauncher _capture = new();
    private readonly FakeNewAuditDialog _dialogs = new();
    private readonly FakeRunOpener _opener = new();
    private readonly FakeDerivationLauncher _deriving = new();
    private readonly FakeJudgingLauncher _judging = new();

    [Fact]
    public void GppPasswordScanningStartsUnchecked()
    {
        Assert.False(Screen().ScanGppPasswords);
    }

    [Fact]
    public void GppPasswordScanningExplainsItsCostAndAnUnscannedVerdict()
    {
        var screen = Screen();

        Assert.Equal(
            "Scan Group Policy XML for legacy stored passwords",
            screen.ScanGppPasswordsLabel);
        Assert.Contains("significant SYSVOL time", screen.ScanGppPasswordsHelp, StringComparison.Ordinal);
        Assert.Contains("Not scanned - not Passed", screen.ScanGppPasswordsHelp, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheGppPasswordChoiceReachesTheCaptureLauncher(bool scanGppPasswords)
    {
        var screen = await Planned();
        screen.ScanGppPasswords = scanGppPasswords;

        await screen.StartAsync();

        Assert.Equal((bool?)scanGppPasswords, _capture.AskedToScanGppPasswords);
    }

    [Fact]
    public void GppPasswordScanningIsNotRememberedByANewWizard()
    {
        var first = Screen();
        first.ScanGppPasswords = true;

        Assert.False(Screen().ScanGppPasswords);
    }

    [Fact]
    public void EnatelInclusionStartsUnchecked()
    {
        Assert.False(Screen().IncludeEnatelSso);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheEnatelChoiceReachesTheCaptureLauncher(bool includeEnatelSso)
    {
        var screen = await Planned();
        screen.IncludeEnatelSso = includeEnatelSso;

        await screen.StartAsync();

        Assert.Equal((bool?)includeEnatelSso, _capture.AskedToIncludeEnatelSso);
    }

    [Fact]
    public void EnatelInclusionIsNotRememberedByANewWizard()
    {
        var first = Screen();
        first.IncludeEnatelSso = true;

        var next = Screen();

        Assert.False(next.IncludeEnatelSso);
    }

    [Fact]
    public void ARunningAuditCannotHaveItsObjectScopeChanged()
    {
        var screen = Screen();
        screen.IsCapturing = true;

        screen.IncludeEnatelSso = true;

        Assert.False(screen.IncludeEnatelSso);
    }

    [Fact]
    public void AFinishedAuditCannotHaveItsObjectScopeChanged()
    {
        var screen = Screen();
        screen.HasFinished = true;

        screen.IncludeEnatelSso = true;

        Assert.False(screen.IncludeEnatelSso);
    }

    [Fact]
    public void IncludingEnatelLeavesOnlyDnsInTheDisplayedExclusions()
    {
        var screen = Screen();

        screen.IncludeEnatelSso = true;

        Assert.Equal(["dnsNode", "dnsZone"], screen.ExcludedObjectClasses);
    }

    [Fact]
    public void ChangingEnatelInclusionRefreshesTheDisplayedExclusions()
    {
        var screen = Screen();
        var changed = new List<string?>();
        screen.PropertyChanged += (_, args) => changed.Add(args.PropertyName);

        screen.IncludeEnatelSso = true;

        Assert.Contains(nameof(NewAuditViewModel.ExcludedObjectClasses), changed);
    }

    /// <summary>
    /// Where the derivation and the judging record that they ran, in the order they ran.
    /// </summary>
    /// <remarks>
    /// Handed to both fakes so the order between them can be asserted. Neither can observe the
    /// other, and the order is the thing worth holding: a judging that ran first would be resting on
    /// facts that had not been derived yet.
    /// </remarks>
    private readonly List<string> _order = [];

    /// <summary>
    /// The refusal that must survive the trip to a window. <c>ControllerSelection</c> refuses a
    /// named controller the forest does not list for that domain, and never falls back to the
    /// ranked choice - a pinned controller that was quietly not the pinned controller defeats the
    /// point of pinning.
    /// </summary>
    private const string Refusal =
        "dc99.ad.lab was named as the controller to read DC=ad,DC=lab from, and the forest does "
        + "not list it as holding a writable replica of that domain.";

    /// <summary>
    /// Discovery fills the table without contacting a single domain's controller.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two halves of the opening pass are separable and this proves it, by letting the second
    /// half fail: the table is still filled from the first, and every answer the second would have
    /// established reads as unasked rather than as no.
    /// </para>
    /// <para>
    /// Have the plan half contact controllers, or have a failed check half wipe the table, and this
    /// fails.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheTableIsFilledBeforeAnyControllerIsContacted()
    {
        var screen = await Planned();

        var row = Assert.Single(screen.Domains);

        Assert.Equal(Forests.Root, row.NamingContext);
        Assert.False(row.Plan.WasPreflighted);
    }

    /// <summary>
    /// Opening the window asks every domain, without the operator pressing anything.
    /// </summary>
    /// <remarks>
    /// The press this replaced asked an operator to ask for something he had already asked for by
    /// opening a window called New Audit. Remove either half of the opening pass and this fails.
    /// </remarks>
    [Fact]
    public async Task OpeningTheWindowWorksTheWholeThingOutWithoutAPress()
    {
        var screen = Screen();

        await screen.OpenAsync();

        Assert.Equal(1, _capture.TimesPlanned);
        Assert.Equal(1, _capture.TimesChecked);
        Assert.True(Assert.Single(screen.Domains).Plan.WasPreflighted);
    }

    /// <summary>
    /// The pass the window began can be stopped.
    /// </summary>
    /// <remarks>
    /// Opening the window is now a network act against every domain in the forest, begun without
    /// being asked for. A Stop that were only enabled during a capture would leave killing the
    /// process as the way out of it.
    /// </remarks>
    [Fact]
    public async Task ThePassTheWindowBeganCanBeStopped()
    {
        var screen = Screen();

        _capture.WhileChecking = screen.Stop;

        await screen.OpenAsync();

        Assert.True(screen.WasStopped);
    }

    /// <summary>
    /// A stopped pass leaves what it reached, and calls the rest unasked rather than unreachable.
    /// </summary>
    /// <remarks>
    /// A domain nobody put a question to has no answer, and rendering one is what
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> forbids. Cancelling is not a
    /// finding about the customer's forest.
    /// </remarks>
    [Fact]
    public async Task AStoppedPassLeavesWhatItReachedAndAsksNothingOfTheRest()
    {
        var screen = Screen();

        _capture.WhileChecking = screen.Stop;

        await screen.OpenAsync();

        var row = Assert.Single(screen.Domains);

        Assert.False(row.Plan.WasPreflighted);
        Assert.Equal("Not asked yet.", row.Connection);
    }

    // Five tests stood here and were superseded when the Review step became a dialog.
    //
    // OpeningTheWindowLandsOnDomainsAndNotOnReview and TheRunStartsOnTheDomainsStep both held one
    // property - opening the window is never one click from a capture - by asserting which step was
    // showing. The steps are gone and the property is not, so it is now held by
    // OpeningTheWindowIsNeverOneClickFromACapture against what actually matters: no capture, and no
    // review, until he asks for one.
    //
    // CheckingEveryDomainMovesToReview asserted the step changed. What was worth keeping was that
    // the domains are asked again rather than the opening pass being trusted, which is now
    // ReviewingAsksEveryDomainAgain.
    //
    // ARunCannotStartFromTheDomainsStep and ARunCanStartOnceEveryDomainHasAnswered asserted
    // CanStart either side of a step change. CanStart no longer knows about steps; what it still
    // refuses is a run with an unanswered exclusion, which AnUnansweredExclusionStopsTheReviewBeing
    // Offered holds directly.
    //
    // TheStepsAreAListRatherThanAChainOfConditions is not superseded, because the property is gone
    // rather than moved. It asserted the step order was data so a third step could arrive by being
    // added to a list. No third step ever arrived, and what the second one was reaching for turned
    // out to be a summary of the whole run rather than another page of the same one.

    [Fact]
    public async Task ARunIsCapturedIntoTheChosenLibrary()
    {
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(@"D:\audits", _capture.AskedForRoot);
    }

    [Fact]
    public async Task ASealedRunReportsWhereItsEvidenceIs()
    {
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains(@"D:\audits\run", screen.Report, StringComparison.Ordinal);
    }

    /// <summary>
    /// A run that happened and produced nothing is not a run that failed to start.
    /// </summary>
    [Fact]
    public async Task ARunThatProducedNoBundleSaysSoAndSaysWhereToLook()
    {
        _capture.Outcome = new CaptureOutcome(ProducedABundle: false, @"D:\audits\run");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("without a sealed bundle", screen.Report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AStoppedRunIsReportedAsStoppedRatherThanFailed()
    {
        _capture.Cancels = true;
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("Stopped", screen.Report, StringComparison.Ordinal);
    }

    /// <summary>
    /// A capture that sealed evidence is judged without being asked for.
    /// </summary>
    /// <remarks>
    /// <b>The decision to audit was the decision to judge</b> - the owner's shape, 2026-08-26. An
    /// operator who has waited hours for a capture should not come back to a second button and
    /// another wait he never agreed to.
    /// </remarks>
    [Fact]
    public async Task EvidenceThatWasSealedIsJudgedWithoutBeingAskedFor()
    {
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(@"D:\audits\run", _judging.AskedFor);
    }

    /// <summary>
    /// A run that sealed nothing is not judged.
    /// </summary>
    /// <remarks>
    /// There is no evidence for a rule to read, so a judging would be reading a directory that
    /// holds an account of why the run stopped and nothing else.
    /// </remarks>
    [Fact]
    public async Task ARunThatSealedNothingIsNotJudged()
    {
        _capture.Outcome = new CaptureOutcome(ProducedABundle: false, @"D:\audits\run");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.False(_judging.WasRun);
    }

    /// <summary>
    /// A capture that sealed evidence is derived from without being asked for.
    /// </summary>
    /// <remarks>
    /// <b>The same shape judging has, and for the same reason</b> - the owner's shape, 2026-08-26.
    /// The decision to audit was the decision to derive, so there is no second button and no second
    /// wait the operator never agreed to.
    /// </remarks>
    [Fact]
    public async Task EvidenceThatWasSealedIsDerivedFromWithoutBeingAskedFor()
    {
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(@"D:\audits\run", _deriving.AskedFor);
    }

    /// <summary>
    /// A run that sealed nothing is not derived from.
    /// </summary>
    /// <remarks>
    /// There is no evidence to read the nesting out of, so a derivation would be opening a directory
    /// that holds an account of why the run stopped and nothing else.
    /// </remarks>
    [Fact]
    public async Task ARunThatSealedNothingIsNotDerivedFrom()
    {
        _capture.Outcome = new CaptureOutcome(ProducedABundle: false, @"D:\audits\run");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.False(_deriving.WasRun);
    }

    // ---------------------------------------------------------------------------------------
    // Capture and analyse, or capture only. The owner's shape, 2026-09-22: a capture of a real
    // forest takes hours, and until this was offered a defect in deriving or judging arrived at
    // the end of them, against a directory that had already moved on. It is what the command
    // line's --capture has always offered; this is the same thing in the window.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An operator who chooses nothing gets a finished audit. The run that stops early is the one
    /// he has to ask for, not the other way round.
    /// </summary>
    [Fact]
    public async Task ARunCapturesAndAnalysesUnlessAskedOtherwise()
    {
        var screen = await Opened();

        Assert.True(screen.CaptureAndAnalyse);
        Assert.False(screen.CaptureOnly);
    }

    /// <summary>
    /// The two answers are one choice, so taking one gives up the other.
    /// </summary>
    [Fact]
    public async Task TakingOneAnswerGivesUpTheOther()
    {
        var screen = await Opened();

        screen.CaptureOnly = true;

        Assert.False(screen.CaptureAndAnalyse);
    }

    /// <summary>
    /// A capture-only run still seals its evidence. That is the whole point of it: the evidence is
    /// the thing that took hours and cannot be got back, and it is complete.
    /// </summary>
    [Fact]
    public async Task ACaptureOnlyRunStillSealsItsEvidence()
    {
        var screen = await Opened();
        screen.CaptureOnly = true;

        await screen.StartAsync();

        Assert.Equal(@"D:\audits\run", screen.BundleDirectory);
    }

    [Fact]
    public async Task ACaptureOnlyRunDerivesNothing()
    {
        var screen = await Opened();
        screen.CaptureOnly = true;

        await screen.StartAsync();

        Assert.False(_deriving.WasRun);
    }

    [Fact]
    public async Task ACaptureOnlyRunJudgesNothing()
    {
        var screen = await Opened();
        screen.CaptureOnly = true;

        await screen.StartAsync();

        Assert.False(_judging.WasRun);
    }

    /// <summary>
    /// <b>Absence, never zero.</b> A run nobody judged has no findings, no derived principals and
    /// no objects judged - and showing those as counters reading nothing is the failure
    /// <c>docs/decisions/0002-absent-view-means-degraded-run.md</c> exists to prevent: a clean
    /// number is the more reassuring of the two readings, and an operator will take it.
    /// </summary>
    /// <remarks>
    /// This asserts the two flags the view gates those blocks on, so a capture-only completion
    /// screen has nowhere to put a zero rather than being trusted to leave one blank.
    /// </remarks>
    [Fact]
    public async Task ACaptureOnlyRunShowsNoAnalysisCountersAtAll()
    {
        var screen = await Opened();
        screen.CaptureOnly = true;

        await screen.StartAsync();

        Assert.False(screen.HasDerivationReport);
        Assert.False(screen.HasJudgingReport);
        Assert.Empty(screen.Findings);
    }

    /// <summary>
    /// Changing his mind back leaves the run doing what it would have done anyway.
    /// </summary>
    /// <remarks>
    /// The negative control for the four cases above: without it they would all still pass if the
    /// choice had disabled analysis permanently rather than for the run he asked it of.
    /// </remarks>
    [Fact]
    public async Task ChoosingToAnalyseAfterAllLeavesTheRunDerivingAndJudging()
    {
        var screen = await Opened();
        screen.CaptureOnly = true;

        screen.CaptureAndAnalyse = true;
        await screen.StartAsync();

        Assert.True(_deriving.WasRun);
        Assert.True(_judging.WasRun);
    }

    /// <summary>
    /// What the screen says this run will do must go on describing the run that happened.
    /// </summary>
    /// <remarks>
    /// A choice still editable after the fact would let a finished capture-only run read as one
    /// that analysed, with no analysis behind it.
    /// </remarks>
    [Fact]
    public async Task TheChoiceCannotBeChangedOnceTheRunHasFinished()
    {
        var screen = await Opened();
        await screen.StartAsync();

        screen.CaptureOnly = true;

        Assert.True(screen.CaptureAndAnalyse);
    }

    /// <summary>
    /// Deriving happens before judging.
    /// </summary>
    /// <remarks>
    /// <b>The order is the whole of why this is wired in at all.</b> What deriving produces are
    /// facts about more than one object, which is what a rule reading a group's membership will
    /// rest on. A judging that ran first would find nothing written and would reach its verdicts
    /// from an empty set - and an empty set that should have held a closure reads as a clean
    /// result, which is the failure the derive stage exists to prevent.
    /// </remarks>
    [Fact]
    public async Task DerivingHappensBeforeJudging()
    {
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(["deriving", "judging"], _order);
    }

    /// <summary>
    /// What the derivation produced is put in front of the operator.
    /// </summary>
    [Fact]
    public async Task WhatTheDerivationProducedIsReported()
    {
        _deriving.Outcome = new DerivingOutcome(
            DerivationRunState.Completed,
            Principals: 4_795,
            NestingEdges: 12_004,
            EveryPhaseThatRanSucceeded: true);

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("4,795", screen.DerivationReport, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ACompletedDerivationDoesNotClaimUnpersistedClosuresWereCompleted()
    {
        _deriving.Outcome = new DerivingOutcome(
            DerivationRunState.Completed,
            Principals: 4_795,
            NestingEdges: 12_004,
            EveryPhaseThatRanSucceeded: true);

        var screen = await Opened();

        await screen.StartAsync();

        Assert.DoesNotContain("Every closure was completed", screen.DerivationReport, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StoppingDuringDerivationSaysTheEvidenceWasAlreadySealed()
    {
        _deriving.Cancels = true;
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("evidence", screen.Report, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sealed", screen.Report, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("recorded why it stopped", screen.Report, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// A derivation where a part could not be completed says so rather than reporting a whole one.
    /// </summary>
    /// <remarks>
    /// <b>The same thing an audit tool cannot do, one stage earlier.</b> A closure that was cut
    /// short looks exactly like a closure that found nothing, and every rule resting on it inherits
    /// the difference without being told about it.
    /// </remarks>
    [Fact]
    public async Task ADerivationThatCouldNotBeCompletedSaysSo()
    {
        _deriving.Outcome = new DerivingOutcome(
            DerivationRunState.CompletedDegraded,
            Principals: 100,
            NestingEdges: 2,
            EveryPhaseThatRanSucceeded: false);

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("not working from the whole picture", screen.DerivationReport, StringComparison.Ordinal);
    }

    /// <summary>
    /// A derivation that could not be done does not stop the judging.
    /// </summary>
    /// <remarks>
    /// <b>Every rule that exists today reads one object and needs nothing derived.</b> Withholding
    /// findings that do not depend on a closure because the closure could not be built would cost
    /// the operator the whole judging to punish a stage none of it used.
    /// </remarks>
    [Fact]
    public async Task ADerivationThatCouldNotBeDoneDoesNotStopTheJudging()
    {
        _deriving.Fails = Failures.Any("The derivation store could not be written.");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.True(_judging.WasRun);
    }

    /// <summary>
    /// Evidence that was sealed is still offered when the derivation could not be done.
    /// </summary>
    /// <remarks>
    /// <b>The evidence is the thing that cannot be got back.</b> The facts can be derived from it
    /// again whenever the defect is fixed, so the run is not thrown away over a stage that can be
    /// repeated for nothing.
    /// </remarks>
    [Fact]
    public async Task EvidenceIsStillOfferedWhenTheDerivationCouldNotBeDone()
    {
        _deriving.Fails = Failures.Any("The derivation store could not be written.");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal("View results", screen.LeaveLabel);
        Assert.Contains("sealed and is safe", screen.DerivationReport, StringComparison.Ordinal);
    }

    /// <summary>
    /// A defect in deriving does not stop the judging.
    /// </summary>
    /// <remarks>
    /// <b>This is the shape of the first fault the wiring produced.</b> Deriving threw a SQLite
    /// constraint violation on a real forest, and because it was awaited inside the run's own try
    /// it skipped the judging and was reported as a run that failed. The findings never depended on
    /// the closures, so a defect in the newest stage took down the part that was working.
    /// </remarks>
    [Fact]
    public async Task ADefectInDerivingDoesNotStopTheJudging()
    {
        _deriving.Throws = new InvalidOperationException("UNIQUE constraint failed.");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.True(_judging.WasRun);
    }

    /// <summary>
    /// A defect after the seal does not tell the operator his evidence does not exist.
    /// </summary>
    /// <remarks>
    /// <b>The run's catch-all speaks for a capture, and it is no longer the only thing in the
    /// try.</b> An operator told no bundle was sealed would capture the forest a second time -
    /// hours, against a directory that has moved on - to replace evidence he already had.
    /// </remarks>
    [Fact]
    public async Task ADefectAfterTheSealDoesNotClaimNoBundleWasSealed()
    {
        _judging.Throws = new InvalidOperationException("The judgement store fell over.");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.DoesNotContain("No bundle was sealed", screen.Report, StringComparison.Ordinal);
        Assert.Contains(@"D:\audits\run", screen.Report, StringComparison.Ordinal);
    }

    /// <summary>
    /// What the judging found is put in front of the operator.
    /// </summary>
    [Fact]
    public async Task WhatTheJudgingFoundIsReported()
    {
        _judging.Outcome = new JudgingOutcome(
            JudgementRunState.Completed,
            ObjectsJudged: 4_795,
            new Dictionary<Severity, int> { [Severity.High] = 13 },
            CouldNotDecide: []);

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(13, screen.Findings[Severity.High]);
        Assert.Contains("4,795", screen.JudgingReport, StringComparison.Ordinal);
    }

    /// <summary>
    /// A judging where a rule could not reach a verdict says so rather than reporting a clean
    /// result.
    /// </summary>
    /// <remarks>
    /// <b>This is the one thing an audit tool cannot do.</b> A count that omits what a rule could
    /// not read looks exactly like a count that found nothing, and a customer makes a security
    /// decision on the difference.
    /// </remarks>
    [Fact]
    public async Task AJudgingThatCouldNotFinishEveryRuleSaysSo()
    {
        _judging.Outcome = new JudgingOutcome(
            JudgementRunState.CompletedDegraded,
            ObjectsJudged: 100,
            new Dictionary<Severity, int>(),
            CouldNotDecide: []);

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("not the whole picture", screen.JudgingReport, StringComparison.Ordinal);
    }

    /// <summary>
    /// A degraded judging names what stopped it, not merely that something did.
    /// </summary>
    /// <remarks>
    /// <b>"At least one rule could not reach a verdict" leaves an administrator nowhere to go.</b>
    /// The reasons say what to capture, or say plainly that Microsoft's own documentation is the
    /// obstacle and re-running will not help - which is the difference between an afternoon spent
    /// usefully and one spent re-reading a forest that was fine.
    /// </remarks>
    [Fact]
    public async Task ADegradedJudgingNamesWhatStoppedIt()
    {
        _judging.Outcome = new JudgingOutcome(
            JudgementRunState.CompletedDegraded,
            ObjectsJudged: 100,
            new Dictionary<Severity, int>(),
            CouldNotDecide:
            [
                new UnresolvedCount("Microsoft's own documentation contradicts itself.", 41),
                new UnresolvedCount("Permissions could not be read.", 7),
            ]);

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("contradicts itself", screen.JudgingReport, StringComparison.Ordinal);
        Assert.Contains("41", screen.JudgingReport, StringComparison.Ordinal);
        Assert.Contains("Permissions could not be read", screen.JudgingReport, StringComparison.Ordinal);
    }

    /// <summary>
    /// Evidence that was sealed is still offered when the judging could not be done.
    /// </summary>
    /// <remarks>
    /// <b>The evidence is the thing that cannot be got back.</b> It took hours and read a forest
    /// that has moved on since; a judgement can be made again from it whenever the defect is fixed.
    /// Throwing the capture away because the judging failed would cost the operator the expensive
    /// half to punish the cheap one.
    /// </remarks>
    [Fact]
    public async Task EvidenceIsStillOfferedWhenTheJudgingCouldNotBeDone()
    {
        _judging.Fails = Failures.Any("The judgement store could not be written.");
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal("View results", screen.LeaveLabel);
        Assert.Contains("sealed and is safe", screen.JudgingReport, StringComparison.Ordinal);
    }

    /// <summary>
    /// The operator sees how far the judging has got.
    /// </summary>
    [Fact]
    public void HowFarTheJudgingHasGotIsShown() => OneThread.Run(async () =>
    {
        _judging.Reports = [2_000];
        var screen = await Opened();

        // Deliver posted progress before the fake launcher's queued completion, as a window does.
        // An unconstrained scheduler can finish judging first; late progress is correctly ignored.
        var reportedWhileJudging = false;
        screen.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(screen.ObjectsJudged) && screen.ObjectsJudged == 2_000)
                reportedWhileJudging = screen.IsJudging;
        };

        await screen.StartAsync();

        Assert.True(reportedWhileJudging);
        Assert.Equal(2_000, screen.ObjectsJudged);
    });

    // A domain the forest names no controller for used to stop the run outright, proved here by
    // ADomainTheForestNamesNoControllerForStopsTheRun. That rule was standing in for an attestation
    // nothing had built yet. 0054 makes such a domain an exclusion rather than a gap and 0062 gives
    // it something to be accounted for with, so the rule is now narrower and truer: it stops the run
    // while nobody has answered for it, and not once somebody has. The two halves are
    // AnUnreadableDomainNobodyAnsweredForStopsTheRun and
    // AnUnreadableDomainThatWasAttestedLetsTheRunStart, below.

    [Fact]
    public async Task ADomainThatCouldNotBeReadStopsTheRun()
    {
        _capture.Check = new AuditCheck(RunMayProceed: false, [Forests.Answers()]);

        var screen = await Opened();

        Assert.False(screen.CanStart);
    }

    // The override, and the refusal that must not be softened.

    [Fact]
    public async Task AControllerAnOperatorNamesIsCarriedIntoTheRun()
    {
        var screen = await Opened();
        Assert.Single(screen.Domains).NamedController = "dc02.ad.lab";

        await screen.StartAsync();

        Assert.Equal("dc02.ad.lab", _capture.AskedWithOverrides["ad.lab"]);
    }

    /// <summary>
    /// Checking a typed controller contacts that controller and does not plan the forest again.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is finding <c>F-S41-4</c>. Each press used to cost a full discovery pass - a bootstrap
    /// connection, the configuration partition, and the candidate list for every domain - to answer
    /// a question about one machine. An operator correcting a typo in a nine-domain forest paid for
    /// the whole forest every time.
    /// </para>
    /// <para>
    /// The count of planning passes is asserted, not just the count of checks: a check that were
    /// added alongside the old pass rather than in place of it would satisfy every other assertion
    /// here while costing exactly what it did before.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task CheckingATypedControllerCostsOneMachineAndNotAForest()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc02.ad.lab";

        var plannedByLoading = _capture.TimesPlanned;

        await screen.ValidateOverrideAsync(row);

        Assert.Equal(1, _capture.NamedControllersChecked);
        Assert.Equal(plannedByLoading, _capture.TimesPlanned);
        Assert.Equal(("dc02.ad.lab", Forests.Root), _capture.LastNamedControllerCheck);
    }

    /// <summary>
    /// A forest that cannot be reached on opening says so, rather than leaving an empty table.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There is no button left to press. The window works itself out on opening, so a failure that
    /// only set a field somewhere would leave an operator looking at an empty table with nothing to
    /// point at and no reason given - which is the worst thing this screen could do.
    /// </para>
    /// <para>
    /// The audit layer's words are passed through unchanged, because they name the stage that
    /// failed and those stages have different remedies: a name that did not resolve, a controller
    /// that rejected the account, and one that let the run in and would not answer send an operator
    /// to three different places.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AForestThatCannotBeReachedOnOpeningSaysSoRatherThanShowingAnEmptyTable()
    {
        const string Reason = "ad.lab did not answer on any port that was tried.";

        _capture.PlanFails = Failures.Any(Reason);

        var screen = Screen();
        await screen.OpenAsync();

        Assert.NotNull(screen.Notice);

        Assert.Equal(Reason, screen.Notice!.Detail);
        Assert.Equal(Reason, screen.Problem);
        Assert.True(screen.MayLookAgain);
    }

    /// <summary>
    /// A pass that failed can be run again without closing the window.
    /// </summary>
    /// <remarks>
    /// Nothing was written, so there is nothing to undo. Making an operator close a modal and
    /// reopen it to retry a network act is a way of telling him the product cannot recover from
    /// anything.
    /// </remarks>
    [Fact]
    public async Task APassThatCouldNotFinishCanBeRunAgain()
    {
        _capture.PlanFails = Failures.Any("Nothing answered.");

        var screen = Screen();
        await screen.OpenAsync();

        Assert.True(screen.MayLookAgain);

        _capture.PlanFails = null;
        await screen.OpenAsync();

        Assert.False(screen.MayLookAgain);
        Assert.Single(screen.Domains);
    }

    /// <summary>
    /// The rung is shown in words rather than as the name the type spells it with.
    /// </summary>
    /// <remarks>
    /// Found on the first filled table: every cell on the row was ordinary English except this one,
    /// which read <c>SignedAndSealed</c>. The stored value is unchanged - bundles must keep reading
    /// the same way in six months - and only the rendering differs.
    /// </remarks>
    [Fact]
    public void TheRungIsShownInWordsRatherThanAsAnEnumName()
    {
        var row = new DomainRowViewModel(
            Forests.Domain().With(
                Forests.Answers() with { RungReached = "SignedAndSealed" },
                new Dictionary<string, string>(),
                thisMachinesSite: null),
            _ => Task.CompletedTask,
            (_, _) => { });

        Assert.Equal("Signed and sealed", row.Connection);
    }

    /// <summary>
    /// A row is headed by the name the forest declared for the domain, not by two spellings of it.
    /// </summary>
    /// <remarks>
    /// The table used to head a row <c>DC=ph,DC=ad,DC=lab</c> above a line saying
    /// <c>ph.ad.lab</c> - one domain, two spellings, and an operator left to work out they are the
    /// same place. Where the forest declared no name to pair with, the naming context stands, which
    /// is what it did before.
    /// </remarks>
    [Fact]
    public void ARowIsHeadedByTheNameTheForestDeclaredForTheDomain()
    {
        var named = new DomainRowViewModel(
            Forests.Domain() with { DnsName = "ad.lab" },
            _ => Task.CompletedTask,
            (_, _) => { });

        var unpaired = new DomainRowViewModel(
            Forests.Domain(), _ => Task.CompletedTask, (_, _) => { });

        Assert.Equal("ad.lab", named.Domain);
        Assert.Equal(Forests.Root, unpaired.Domain);
    }

    /// <summary>
    /// The library refuses an ineligible name, and this window says exactly what the library said.
    /// Softening it into a warning would leave the operator with a run against a controller he did
    /// not name.
    /// </summary>
    [Fact]
    public async Task AnIneligibleControllerIsRefusedInTheLibrarysOwnWords()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc99.ad.lab";
        _capture.NamedController = new NamedControllerView(IsUsable: false, Refusal);

        await screen.ValidateOverrideAsync(row);

        Assert.Equal(Refusal, row.Problem);
    }

    [Fact]
    public async Task AnIneligibleControllerStopsTheRunFromStarting()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc99.ad.lab";
        _capture.NamedController = new NamedControllerView(IsUsable: false, Refusal);

        await screen.ValidateOverrideAsync(row);

        Assert.False(screen.CanStart);
    }

    /// <summary>
    /// A refusal does not take the preflight away with it. Asking the questions again is how an
    /// operator recovers, so it stays available exactly when everything else is refused.
    /// </summary>
    /// <remarks>
    /// <b>Found in the field on 2026-09-23, mid-capture against a production forest.</b> Review was
    /// gated on <c>CanStart</c>, and a refused controller sets <c>RunMayProceed</c> false - which by
    /// design only a fresh preflight restores, and the fresh preflight is Review. So the one action
    /// that could clear the refusal sat behind it. The operator named a good controller, was told it
    /// served the domain, and still could not go on; no button on the screen could recover it.
    /// </remarks>
    [Fact]
    public async Task ARefusedControllerStillLetsThePreflightBePutAgain()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc99.ad.lab";
        _capture.NamedController = new NamedControllerView(IsUsable: false, Refusal);

        await screen.ValidateOverrideAsync(row);

        Assert.False(screen.CanStart);
        Assert.True(screen.CanReview);
        Assert.True(screen.ReviewCommand.CanExecute(null));
    }

    /// <summary>
    /// A refused name is not quietly replaced by the ranked choice: the operator is told, by name,
    /// and what he asked for stays in front of him.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The predecessor fell back silently, so an operator who mistyped a host name got a successful
    /// run against a controller he did not name, with nothing recording the substitution.
    /// </para>
    /// <para>
    /// <b>This used to assert that the box was cleared, on the reasoning that holding him in a
    /// refusal whose only exit is closing the window trades one bad outcome for another. The owner
    /// reversed it on 2026-09-22 (P-265), and the reasoning was wrong in two ways.</b> Clearing put
    /// the domain back on the ranked controller and then displayed that controller in the column
    /// beside the refusal, so the screen appeared to hand back the very host it had just refused -
    /// which is what the owner hit in production. And it was the silent fallback itself, moved up
    /// into the window from the layer where <c>ControllerSelection</c> forbids it.
    /// </para>
    /// <para>
    /// There is an exit, and it is not closing the window: editing the box withdraws the refusal,
    /// which the test below holds.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task ARefusedNameIsNotQuietlyReplacedByTheRankedChoice()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc99.ad.lab";
        _capture.NamedController = new NamedControllerView(IsUsable: false, Refusal);

        await screen.ValidateOverrideAsync(row);

        Assert.NotNull(screen.Notice);

        Assert.Contains("dc99.ad.lab", screen.Notice!.Title, StringComparison.Ordinal);
        Assert.Equal("dc99.ad.lab", row.NamedController);
        Assert.False(_capture.WasRun);
    }

    /// <summary>
    /// A check that passed says so, rather than saying nothing.
    /// </summary>
    /// <remarks>
    /// <b>The defect the owner reported from production.</b> A good check cleared the refusal and
    /// returned, so pressing Validate on a working controller looked exactly like pressing nothing
    /// - and the only way to see the button do anything was to make it fail.
    /// </remarks>
    [Fact]
    public async Task AControllerThatPassedIsSaidToHavePassed()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc02.ad.lab";

        await screen.ValidateOverrideAsync(row);

        Assert.Equal(Established.Yes, row.ControllerCheck);
        Assert.NotEqual(string.Empty, row.ControllerCheckText);
    }

    /// <summary>
    /// A refused check is left standing on the row, not only in a dialog that can be dismissed.
    /// </summary>
    [Fact]
    public async Task ARefusedControllerIsSaidToHaveBeenRefused()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc99.ad.lab";
        _capture.NamedController = new NamedControllerView(IsUsable: false, Refusal);

        await screen.ValidateOverrideAsync(row);

        Assert.Equal(Established.No, row.ControllerCheck);
        Assert.NotEqual(string.Empty, row.ControllerCheckText);
    }

    /// <summary>
    /// An empty box establishes nothing, and says nothing.
    /// </summary>
    /// <remarks>
    /// The negative control for the two above: blank is reserved for the unasked question, so a
    /// cell that spoke here would make the other two states meaningless.
    /// </remarks>
    [Fact]
    public async Task AnEmptyBoxEstablishesNothingAndSaysNothing()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);

        await screen.ValidateOverrideAsync(row);

        Assert.Equal(Established.NotEstablished, row.ControllerCheck);
        Assert.Equal(string.Empty, row.ControllerCheckText);
    }

    /// <summary>
    /// Editing the name withdraws what was established about the old one.
    /// </summary>
    /// <remarks>
    /// <b>A check vouches for the host that was asked about and for no other.</b> A state left
    /// standing over an edited name would have this screen reporting a controller as proved when a
    /// different one had been, which is the stale-answer failure one field along.
    /// </remarks>
    [Fact]
    public async Task EditingTheNameWithdrawsWhatWasEstablishedAboutTheOldOne()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc02.ad.lab";
        await screen.ValidateOverrideAsync(row);
        Assert.Equal(Established.Yes, row.ControllerCheck);

        row.NamedController = "dc03.ad.lab";

        Assert.Equal(Established.NotEstablished, row.ControllerCheck);
    }

    /// <summary>
    /// Editing the name withdraws a refusal too, which is the exit from one.
    /// </summary>
    /// <remarks>
    /// Without this an operator who mistyped a host would be held by a refusal about a name no
    /// longer in the box, and the run could never start.
    /// </remarks>
    [Fact]
    public async Task EditingTheNameWithdrawsARefusal()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);
        row.NamedController = "dc99.ad.lab";
        _capture.NamedController = new NamedControllerView(IsUsable: false, Refusal);
        await screen.ValidateOverrideAsync(row);
        Assert.Equal(Refusal, row.Problem);

        row.NamedController = "dc02.ad.lab";

        Assert.Null(row.Problem);
    }

    // The PDC emulator prompt, narrowed.

    /// <summary>
    /// The forest names somewhere else this domain could have been read from, so the operator can
    /// act on the warning.
    /// </summary>
    [Fact]
    public void ThePdcEmulatorPromptAppearsWhereTheDomainHasAlternatives()
    {
        var row = Row(readFromPdcEmulator: true, alternatives: [Forests.Other]);

        Assert.NotNull(row.PdcEmulatorWarning);
    }

    /// <summary>
    /// A warning that fires on every domain of a single-controller forest teaches an operator to
    /// click past warnings, and the next one he clicks past will matter. The record of it is not
    /// narrowed - only the prompting is.
    /// </summary>
    [Fact]
    public void ThePdcEmulatorPromptDoesNotAppearWhereTheDomainHasNoAlternatives()
    {
        var row = Row(readFromPdcEmulator: true, alternatives: []);

        Assert.Null(row.PdcEmulatorWarning);
    }

    [Fact]
    public void ThePdcEmulatorPromptDoesNotAppearWhereTheDomainIsNotReadFromIt()
    {
        var row = Row(readFromPdcEmulator: false, alternatives: [Forests.Other]);

        Assert.Null(row.PdcEmulatorWarning);
    }

    // Nothing on screen may state a fact the run did not measure.

    /// <summary>
    /// The case the owner's own lab produces on every run: no subnets declared, so no machine can
    /// be placed in a site by address.
    /// </summary>
    [Fact]
    public async Task AMachineWithNoSiteSaysSoRatherThanNamingOne()
    {
        var screen = await Opened();

        Assert.Contains("declares no subnets", screen.SiteDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// A forest that declares subnets and a forest that declares none are different faults with
    /// different remedies, and one sentence covering both sends an operator to the wrong place.
    /// </summary>
    [Fact]
    public async Task AMachineInNoDeclaredSubnetIsToldWhichFaultItIs()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            SiteKnowledge = SiteKnowledge.NoSubnetContainsThisMachine,
        };

        var screen = await Opened();

        Assert.Contains("none of the subnets", screen.SiteDescription, StringComparison.Ordinal);
    }

    /// <summary>
    /// A run with no site of its own has measured nothing about where a controller is relative to
    /// it. Rendering that as "another site" is a claim about a customer's forest the product did
    /// not make.
    /// </summary>
    [Fact]
    public async Task AControllerIsNotReportedAsElsewhereByARunWithNoSite()
    {
        var screen = await Opened();

        Assert.DoesNotContain(
            "is not this machine's site",
            Assert.Single(screen.Domains).Site,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task AControllerWhoseSiteWasNotComparedSaysThatItWasNot()
    {
        var screen = await Opened();

        Assert.Contains(
            "not known",
            Assert.Single(screen.Domains).Site,
            StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The four answers before preflight. An empty column would read as "no" on a screen, which is
    /// the whole of <c>F-S40-8</c>.
    /// </summary>
    [Fact]
    public async Task AQuestionNotYetPutIsShownAsNotYetPutRatherThanAsNo()
    {
        var screen = await Planned();
        var row = Assert.Single(screen.Domains);

        Assert.Equal("Not asked yet.", row.ServesThePartition);
    }

    [Fact]
    public async Task ThePdcEmulatorIsNotReportedAsAbsentBeforeItIsEstablished()
    {
        var screen = await Planned();

        Assert.Equal("Not asked yet.", Assert.Single(screen.Domains).PdcEmulator);
    }

    /// <summary>
    /// A PDC emulator read that failed leaves the question with no answer.
    /// <c>0055</c> forbids either unestablished state rendering as "holds no role".
    /// </summary>
    [Fact]
    public void APdcEmulatorThatCouldNotBeEstablishedIsNotReportedAsHoldingNoRole()
    {
        var row = new DomainRowViewModel(
            Forests.Domain().With(
                Forests.Answers() with { IsThisDomainsPdcEmulator = Established.NotEstablished },
                new Dictionary<string, string>(),
                thisMachinesSite: null),
            _ => Task.CompletedTask,
            (_, _) => { });

        Assert.Equal("Could not be established.", row.PdcEmulator);
    }

    /// <summary>
    /// A controller nothing answered from has told the product nothing about how it protects
    /// connections. Reporting that walk as a refusal of every protected rung is <c>F-S35-1</c>.
    /// </summary>
    [Fact]
    public void AControllerNothingAnsweredFromIsNotReportedAsRefusingProtection()
    {
        var row = new DomainRowViewModel(
            Forests.Domain().With(
                Forests.Answers() with { Answered = Established.No, RungReached = null },
                new Dictionary<string, string>(),
                thisMachinesSite: null),
            _ => Task.CompletedTask,
            (_, _) => { });

        Assert.Equal("Nothing answered", row.Connection);
        Assert.Contains("nothing is known", row.ConnectionDetail, StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain the forest names one controller for and a domain whose alternatives were considered
    /// and not preferred are different facts, and a message covering both says neither.
    /// </summary>
    [Fact]
    public async Task ADomainWithOneControllerSaysThereIsNowhereElseToGo()
    {
        var screen = await Opened();

        Assert.Contains(
            "only controller",
            Assert.Single(screen.Domains).Failover,
            StringComparison.Ordinal);
    }

    private DomainRowViewModel Row(bool readFromPdcEmulator, string[] alternatives) =>
        new(
            Forests.Domain().With(
                Forests.Answers(readFromPdcEmulator, alternatives),
                new Dictionary<string, string>(),
                thisMachinesSite: null),
            _ => Task.CompletedTask,
            (_, _) => { });

    // =====================================================================================
    // The exclusion attestation. 0062 settles what it asks for, 0059 that it is asked every
    // run, 0054 that a domain with no candidates is one of these too, and 0063 that the two
    // kinds are never shown alike.
    // =====================================================================================

    /// <summary>
    /// Unticking a domain asks the operator to account for it before it leaves the run.
    /// </summary>
    /// <remarks>
    /// The whole of <c>0062</c> rests on the question being put. A tick box that took a domain out
    /// on its own would be the exclusion without the attestation, which is the liability waiver
    /// <c>0049</c> warned against wearing the shape of a feature.
    /// </remarks>
    [Fact]
    public async Task UntickingADomainAsksTheOperatorToAccountForIt()
    {
        var screen = await Opened();

        Assert.Single(screen.Domains).IsIncluded = false;

        var asked = Assert.Single(_dialogs.Attestations);

        Assert.Equal(DomainInclusion.ExcludedByChoice, asked.Kind);
    }

    /// <summary>
    /// An operator who walks away from the dialog gets the domain back, rather than a silent
    /// exclusion.
    /// </summary>
    /// <remarks>
    /// <c>0059</c> makes the friction the control. A dismissed dialog that still excluded the
    /// domain would produce exactly the unattested exclusion the record exists to prevent, and it
    /// would look like the operator had chosen it.
    /// </remarks>
    [Fact]
    public async Task ADismissedAttestationLeavesTheDomainInTheRun()
    {
        _dialogs.Statement = null;

        var screen = await Opened();
        var row = Assert.Single(screen.Domains);

        row.IsIncluded = false;

        Assert.True(row.IsIncluded);
        Assert.Equal(DomainInclusion.Included, row.Inclusion);
        Assert.Null(row.Attestation);
    }

    /// <summary>
    /// A completed attestation takes the domain out and keeps everything <c>0062</c> asked for.
    /// </summary>
    [Fact]
    public async Task AnAttestedExclusionKeepsEverythingTheRecordAsksFor()
    {
        _dialogs.Statement = new ExclusionStatement(
            ExclusionReason.CredentialsNotHeld, "Waiting on the forest team.", "R. Zamus");

        var screen = await Opened();
        var row = Assert.Single(screen.Domains);

        row.IsIncluded = false;

        var attestation = Assert.IsType<ExclusionAttestation>(row.Attestation);

        Assert.Equal(ExclusionReason.CredentialsNotHeld, attestation.Reason);
        Assert.Equal("Waiting on the forest team.", attestation.Note);
        Assert.Equal("R. Zamus", attestation.AuthorisedBy);
        Assert.Equal(SignedInAccount.Name(), attestation.RunBy);
        Assert.NotEqual(default, attestation.MadeUtc);
    }

    /// <summary>
    /// The account is captured rather than typed, so it is never the operator's to get wrong.
    /// </summary>
    /// <remarks>
    /// <c>0062</c>: a name an operator types for himself is a name he can get wrong. The dialog is
    /// given no opportunity to supply one - <see cref="ExclusionStatement"/> has no field for it -
    /// and this proves the run stamps it instead.
    /// </remarks>
    [Fact]
    public async Task TheAccountBehindAnExclusionIsCapturedRatherThanTyped()
    {
        var screen = await Opened();

        Assert.Single(screen.Domains).IsIncluded = false;

        Assert.Equal(
            SignedInAccount.Name(),
            Assert.Single(screen.Exclusions).Attestation!.RunBy);
    }

    /// <summary>
    /// Putting a domain back drops what was stated for it rather than keeping it to offer again.
    /// </summary>
    /// <remarks>
    /// <c>0059</c> refuses to carry a reason forward or pre-fill one. A reason kept against a
    /// domain that is back in the run is the stale attestation that record exists to prevent,
    /// waiting to be re-applied without being read.
    /// </remarks>
    [Fact]
    public async Task PuttingADomainBackDropsWhatWasStatedForIt()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);

        row.IsIncluded = false;
        Assert.NotNull(row.Attestation);

        row.IsIncluded = true;

        Assert.Null(row.Attestation);
        Assert.Empty(screen.Exclusions);
    }

    /// <summary>
    /// Putting a domain back asks nothing, because reading it is not a decision to account for.
    /// </summary>
    [Fact]
    public async Task PuttingADomainBackAsksTheOperatorNothing()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);

        row.IsIncluded = false;
        row.IsIncluded = true;

        Assert.Single(_dialogs.Attestations);
    }

    /// <summary>
    /// A domain the forest names no controller for is attested when the window works itself out,
    /// without the operator having to find it.
    /// </summary>
    /// <remarks>
    /// It has no tick to untick, so nothing else would ever raise the question. <c>0054</c> makes
    /// it an exclusion rather than a gap, and an exclusion nobody is asked about is one nobody
    /// accounts for.
    /// </remarks>
    [Fact]
    public async Task ADomainWithNoControllerIsAttestedWhenTheWindowWorksItselfOut()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        var asked = Assert.Single(_dialogs.Attestations);

        Assert.Equal("DC=orphan,DC=ad,DC=lab", asked.Domain);
        Assert.Equal(DomainInclusion.ExcludedForWantOfCandidates, asked.Kind);
        Assert.NotNull(Assert.Single(screen.DomainsWithNoController).Attestation);
    }

    /// <summary>
    /// Several unreadable domains are put to the operator one at a time, each named.
    /// </summary>
    /// <remarks>
    /// One dialog covering three domains would collect one reason and one authorising name for
    /// three different situations, and <c>0062</c>'s closed list exists so that an exclusion can be
    /// counted and compared per domain later.
    /// </remarks>
    [Fact]
    public async Task EveryUnreadableDomainIsPutToTheOperatorSeparately()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=one,DC=ad,DC=lab", "DC=two,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        Assert.Equal(2, _dialogs.Attestations.Count);
        Assert.Equal(
            ["DC=one,DC=ad,DC=lab", "DC=two,DC=ad,DC=lab"],
            _dialogs.Attestations.Select(a => a.Domain));
    }

    /// <summary>
    /// A second pass does not ask again about a domain already accounted for.
    /// </summary>
    /// <remarks>
    /// <c>0059</c> re-asks every <i>run</i>, not every pass. Asking again inside one run would
    /// train an operator to click through the dialog, which is the behaviour that record is
    /// written to prevent.
    /// </remarks>
    [Fact]
    public async Task AnAlreadyAttestedDomainIsNotAskedAboutAgainInTheSameRun()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();
        await screen.OpenAsync();

        Assert.Single(_dialogs.Attestations);
    }

    /// <summary>
    /// An unreadable domain the operator walked away from stays out and stops the run.
    /// </summary>
    /// <remarks>
    /// The one asymmetry with a domain excluded by choice, and it is not an inconsistency: there is
    /// nothing to put this domain back into, because the forest names no controller to read it
    /// from. So it cannot be re-included, and <c>0054</c> will not let it leave silently either.
    /// </remarks>
    [Fact]
    public async Task AnUnreadableDomainNobodyAnsweredForStopsTheRun()
    {
        _dialogs.Statement = null;
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        Assert.Null(Assert.Single(screen.DomainsWithNoController).Attestation);
        Assert.Equal(1, screen.UnattestedExclusionCount);
        Assert.False(screen.CanStart);
    }

    /// <summary>
    /// Once it has been accounted for, the same run may start.
    /// </summary>
    /// <remarks>
    /// The other half of the rule above, and the one that shows the guard is the attestation rather
    /// than the domain: nothing about the forest changed between the two tests.
    /// </remarks>
    [Fact]
    public async Task AnUnreadableDomainThatWasAttestedLetsTheRunStart()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        Assert.Equal(0, screen.UnattestedExclusionCount);
        Assert.True(screen.CanStart);
    }

    /// <summary>
    /// A domain excluded by choice and one with no controller are never described alike.
    /// </summary>
    /// <remarks>
    /// <c>0063</c>. Two different states with two different remedies: one is a decision the
    /// operator can reverse, the other is a fact about the forest he cannot. A screen that worded
    /// them the same would send him looking in the wrong place.
    /// </remarks>
    [Fact]
    public async Task ADomainExcludedByChoiceIsNotDescribedLikeOneWithNoController()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();
        Assert.Single(screen.Domains).IsIncluded = false;

        var byChoice = screen.Exclusions.Single(
            e => e.Kind == DomainInclusion.ExcludedByChoice);
        var unreadable = screen.Exclusions.Single(
            e => e.Kind == DomainInclusion.ExcludedForWantOfCandidates);

        Assert.NotEqual(byChoice.Why, unreadable.Why);
    }

    /// <summary>
    /// Every attestation reaches the run that was started.
    /// </summary>
    /// <remarks>
    /// <c>0062</c> requires the whole attestation reach the bundle. This proves the shell hands it
    /// over; <c>BundleWriterTests</c> proves what the bundle does with it.
    /// </remarks>
    [Fact]
    public async Task EveryAttestationIsCarriedIntoTheRun()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(
            ["DC=orphan,DC=ad,DC=lab"],
            _capture.AskedWithExclusions.Select(e => e.NamingContext));
    }

    /// <summary>
    /// The ceiling the operator chose is the one the run is started with.
    /// </summary>
    /// <remarks>
    /// <b>The defect this exists to catch is a number that is stated and then dropped.</b> The
    /// review screen tells an operator how his forest will be read; if the setting were not carried
    /// into the call, the screen would say one thing and the capture would do another, and nothing
    /// else in the shell would notice. Both halves are asserted deliberately - that the screen says
    /// it, and that the run receives it - because either alone passes while the other is broken.
    /// </remarks>
    [Fact]
    public async Task TheChosenCeilingIsTheOneTheRunIsStartedWith()
    {
        _settings.Stored = new ShellSettings(@"D:\audits", 2);

        var screen = await Opened();

        Assert.Equal(
            "It will be read on its own.",
            screen.Review.ConcurrencyStatement);

        await screen.StartAsync();

        Assert.Equal(2, _capture.AskedWithDomainsAtOnce);
    }

    /// <summary>
    /// An operator who has chosen nothing still starts a run with a usable ceiling.
    /// </summary>
    /// <remarks>
    /// <b>Never zero, and this is where that would surface.</b> An unstated setting resolves to the
    /// capture's own default; a run started with zero would wait for ever while the screen showed a
    /// capture in progress.
    /// </remarks>
    [Fact]
    public async Task ARunStartedWithoutAChosenCeilingUsesTheDefault()
    {
        var screen = await Opened();

        await screen.StartAsync();

        Assert.Equal(
            DirectoryConnectionSettings.DefaultDomainsAtOnce,
            _capture.AskedWithDomainsAtOnce);

        Assert.NotEqual(0, _capture.AskedWithDomainsAtOnce);
    }

    /// <summary>
    /// A domain the operator took out is not read by the run he started.
    /// </summary>
    [Fact]
    public async Task ADomainTakenOutIsCarriedIntoTheRunAsAnExclusion()
    {        var screen = await Opened();
        Assert.Single(screen.Domains).IsIncluded = false;

        await screen.ReviewAsync();
        await screen.StartAsync();

        var carried = Assert.Single(_capture.AskedWithExclusions);

        Assert.Equal(Forests.Root, carried.NamingContext);
        Assert.Equal(DomainInclusion.ExcludedByChoice, carried.Kind);
    }

    /// <summary>
    /// A reason's stored identifier is not derived from the sentence an operator read.
    /// </summary>
    /// <remarks>
    /// <c>0062</c> puts a reason on the footing <c>0024</c> sets for rule identifiers: the wording
    /// may be improved, the meaning may not. Deriving one from the other would make rewording a
    /// sentence silently rewrite what runs already recorded appear to say.
    /// </remarks>
    [Fact]
    public void AReasonsStoredNameIsNotItsWording()
    {
        foreach (var reason in ExclusionReasons.All)
        {
            Assert.NotEqual(ExclusionReasons.Wording(reason), ExclusionReasons.WireName(reason));
            Assert.NotEmpty(ExclusionReasons.WireName(reason));
        }
    }

    /// <summary>
    /// Every reason in the closed list is offered, and each is offered once.
    /// </summary>
    [Fact]
    public void EveryReasonInTheClosedListIsOfferedExactlyOnce()
    {
        Assert.Equal(
            Enum.GetValues<ExclusionReason>().Order(),
            ExclusionReasons.All.Order());
    }

    // =====================================================================================
    // F-0056-1: how much this run will not establish, before it commits.
    // =====================================================================================

    /// <summary>
    /// The count of unestablished facts is derived from the states the table renders.
    /// </summary>
    /// <remarks>
    /// A total counted from a second list beside the cells would be a number an operator cannot
    /// reconcile with the rows in front of him. Derived here from the row's own
    /// <see cref="DomainRowViewModel.FactStates"/> rather than pinned to a literal, so a column
    /// added or removed moves both together.
    /// </remarks>
    [Fact]
    public async Task TheCountOfWhatWillNotBeEstablishedComesFromTheStatesTheTableShows()
    {
        var screen = await Planned();

        Assert.Equal(
            screen.Domains.Sum(d => d.FactStates.Count(s => s == FactState.NotEstablished)),
            screen.UnestablishedFactCount);
    }

    /// <summary>
    /// Before anything has been worked out, the total says so rather than showing zero.
    /// </summary>
    /// <remarks>
    /// The standing rule of this screen. A count of unestablished facts is itself a fact, and a
    /// confident "0 facts this run will not establish" over a forest nobody has looked at is the
    /// screen stating something the run did not measure.
    /// </remarks>
    [Fact]
    public void ATotalThatCannotBeComputedSaysSoRatherThanShowingZero()
    {
        var screen = Screen();

        Assert.False(screen.HasPlan);
        Assert.DoesNotContain("0", screen.UnestablishedFactSummary, StringComparison.Ordinal);
        Assert.Contains("Not known yet", screen.UnestablishedFactSummary, StringComparison.Ordinal);
    }

    /// <summary>
    /// A domain leaving the run counts as establishing none of its facts.
    /// </summary>
    /// <remarks>
    /// It is the point of the number. An operator about to commit hours to a capture is told how
    /// much of the forest it will not speak for, and a domain nobody reads contributes all of it.
    /// </remarks>
    [Fact]
    public async Task AnExcludedDomainCountsAsEstablishingNoneOfItsFacts()
    {
        var screen = await Opened();
        var row = Assert.Single(screen.Domains);

        row.IsIncluded = false;

        Assert.Equal(DomainRowViewModel.FactsPerDomain, screen.UnestablishedFactCount);
    }

    /// <summary>
    /// The number of facts a domain has and the number counted for an absent one agree.
    /// </summary>
    /// <remarks>
    /// A domain with no controller has no row to count, so its contribution is a constant. Bound to
    /// the row's own list here, so adding a column cannot leave the constant behind.
    /// </remarks>
    [Fact]
    public async Task TheFactsCountedForAnAbsentDomainMatchTheFactsARowCarries()
    {
        var screen = await Opened();

        Assert.Equal(
            DomainRowViewModel.FactsPerDomain,
            Assert.Single(screen.Domains).FactStates.Count);
    }

    /// <summary>
    /// An exclusion nobody has answered for is not shown as though somebody had.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The window decides what to show from booleans rather than by testing an object for null
    /// through a visibility converter. <c>Shown</c> is a <c>BooleanToVisibilityConverter</c>, and a
    /// binding it cannot convert does not fail loudly - WPF falls back to <i>visible</i>. Bound to
    /// the attestation object itself, the screen would have shown "authorised by" with an empty
    /// name against an exclusion nobody had answered for.
    /// </para>
    /// <para>
    /// That is the standing rule of this screen in its smallest form: nothing states a fact the run
    /// did not measure.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AnUnansweredExclusionIsNotShownAsAuthorised()
    {
        _dialogs.Statement = null;
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        var unreadable = Assert.Single(screen.DomainsWithNoController);
        var listed = Assert.Single(screen.Exclusions);

        Assert.False(unreadable.IsAttested);
        Assert.True(unreadable.IsExcludedWithoutAttestation);
        Assert.False(listed.IsAttested);
        Assert.Null(listed.AuthorisedBy);
        Assert.True(screen.HasUnattestedExclusions);
    }

    /// <summary>
    /// Once it has been answered for, the same row says so.
    /// </summary>
    [Fact]
    public async Task AnAnsweredExclusionSaysWhoAuthorisedIt()
    {
        _dialogs.Statement = new ExclusionStatement(
            ExclusionReason.OutsideThisAuditsRemit, Note: null, "R. Zamus");

        var screen = await Opened();
        Assert.Single(screen.Domains).IsIncluded = false;

        var listed = Assert.Single(screen.Exclusions);

        Assert.True(listed.IsAttested);
        Assert.False(listed.HasNote);
        Assert.Equal("R. Zamus", listed.AuthorisedBy);
        Assert.False(screen.HasUnattestedExclusions);
    }

    /// <summary>
    /// A capture that throws is reported, and does not take the application down.
    /// </summary>
    /// <remarks>
    /// Found in the lab: a defect in the audit layer reached the dispatcher unhandled and killed
    /// the process mid-run. The operator lost the window, the plan he had just worked through, and
    /// any account of what went wrong beyond a Windows crash dialog. Nothing is swallowed - the
    /// failure's own words are put in front of him and left on the screen.
    /// </remarks>
    [Fact]
    public async Task ARunThatThrowsIsReportedRatherThanTakingTheWindowDown()
    {
        _capture.Throws = new InvalidOperationException("No coverage was reported for ba.ad.lab.");

        var screen = await Opened();

        await screen.StartAsync();

        Assert.Contains("ba.ad.lab", screen.Report, StringComparison.Ordinal);
        Assert.Contains("No bundle was sealed", screen.Report, StringComparison.Ordinal);
        Assert.False(screen.IsCapturing);
        Assert.NotNull(screen.Notice);
        Assert.Contains("could not finish", screen.Notice!.Title, StringComparison.Ordinal);
    }

    /// <summary>
    /// The list of what is leaving the run keeps its identity and is filled before anything
    /// derived from it is announced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Found in the lab: the Review step drew the heading "Leaving this run" with nothing under it.
    /// The list was a computed property returning a fresh instance on every read, rebuilt while the
    /// panel holding it was still collapsed - and an items control told its source changed while it
    /// cannot measure has no reason to look again once it can.
    /// </para>
    /// <para>
    /// A view model test cannot see a window draw, so what is held here is the shape the fix
    /// depends on: one collection instance for the life of the screen, populated by the time the
    /// flag that reveals it is raised.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheListOfWhatIsLeavingTheRunKeepsOneIdentity()
    {
        var screen = await Opened();
        var before = screen.Exclusions;

        Assert.Empty(before);
        Assert.False(screen.HasExclusions);

        Assert.Single(screen.Domains).IsIncluded = false;

        Assert.Same(before, screen.Exclusions);
        Assert.True(screen.HasExclusions);
        Assert.Equal(Forests.Root, Assert.Single(screen.Exclusions).Domain);
    }

    /// <summary>
    /// Opening the window is never one click from a capture.
    /// </summary>
    /// <remarks>
    /// The two-step wizard provided this by keeping Start on a second page, and it is provided the
    /// same way again: the window opens on the domains, and Start exists only on the review screen
    /// reached by pressing Next. What changed between them is that the second screen now states
    /// something the first cannot.
    /// </remarks>
    [Fact]
    public async Task OpeningTheWindowIsNeverOneClickFromACapture()
    {
        var screen = await Opened();

        Assert.True(screen.IsOnDomains);
        Assert.False(screen.IsOnReview);
        Assert.False(_capture.WasRun);
    }

    /// <summary>
    /// A run does not begin merely by moving to the review screen.
    /// </summary>
    /// <remarks>
    /// Next carries the operator to what the run will and will not do. It does not commit him to
    /// it: Start is a separate press, on the screen that told him what he is starting.
    /// </remarks>
    [Fact]
    public async Task ReachingTheReviewScreenStartsNothing()
    {
        var screen = await Opened();

        await screen.ReviewAsync();

        Assert.True(screen.IsOnReview);
        Assert.False(_capture.WasRun);
    }

    /// <summary>
    /// Going back from the review leaves the window exactly as it was.
    /// </summary>
    /// <remarks>
    /// Nothing has been written at that moment, so there is nothing to undo and no reason to make
    /// an operator close the window to change one controller.
    /// </remarks>
    [Fact]
    public async Task GoingBackFromTheReviewStartsNothing()
    {
        var screen = await Opened();

        await screen.ReviewAsync();
        Assert.True(screen.CanGoBack);

        screen.Back();

        Assert.True(screen.IsOnDomains);
        Assert.False(_capture.WasRun);
        Assert.True(screen.CanStart);
    }

    /// <summary>
    /// Reviewing asks every domain again rather than trusting the opening pass.
    /// </summary>
    /// <remarks>
    /// What an operator does on this screen is change controllers, so the answers on screen may
    /// have been established about machines the run will no longer read. Reviewing with them would
    /// carry a measurement of one controller under the name of another.
    /// </remarks>
    [Fact]
    public async Task ReviewingAsksEveryDomainAgain()
    {
        var screen = await Opened();

        Assert.Equal(1, _capture.TimesChecked);

        await screen.ReviewAsync();

        Assert.Equal(2, _capture.TimesChecked);
    }

    /// <summary>
    /// The review states what the run will read, what it will not, and what it cannot say.
    /// </summary>
    [Fact]
    public async Task TheReviewStatesWhatTheRunWillAndWillNotDo()
    {
        var screen = await Opened();
        Assert.Single(screen.Domains).IsIncluded = false;

        await screen.ReviewAsync();

        var review = screen.Review;

        Assert.NotEmpty(review.ForestFqdn);
        Assert.Empty(review.WillBeRead);
        Assert.Equal(Forests.Root, Assert.Single(review.WillNotBeRead).Domain);
        Assert.NotEmpty(review.UnestablishedFactSummary);
    }

    /// <summary>
    /// A run carrying an exclusion nobody answered for never reaches the review screen.
    /// </summary>
    /// <remarks>
    /// The same rule Start enforces, enforced one screen earlier: there is no point walking an
    /// operator through a summary when the answer at the end of it has to be no.
    /// </remarks>
    [Fact]
    public async Task AnUnansweredExclusionStopsTheReviewBeingReached()
    {
        _dialogs.Statement = null;
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        Assert.False(screen.CanStart);

        await screen.ReviewAsync();

        Assert.True(screen.IsOnDomains);
        Assert.False(_capture.WasRun);
    }

    // ---------------------------------------------------------------------------------------
    // The details panel, and the mark that stops trimming a column from hiding something.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Everything the table stopped carrying is one press away, for every domain at once.
    /// </summary>
    [Fact]
    public async Task DetailsShowsEveryDomainAtOnce()
    {
        var screen = await Opened();

        screen.ShowDetails();

        Assert.Equal(screen.Domains, screen.Details?.Domains);
    }

    /// <summary>
    /// The panel puts itself away, since there is no window whose closing would do it.
    /// </summary>
    /// <remarks>
    /// It became a panel over the audit surface rather than a window over the shell in
    /// <c>0071</c>, which took away the close box and the Escape key that used to do this for
    /// free. Without a Close that works, an operator who opened it is looking at a scrim he
    /// cannot get out from behind.
    /// </remarks>
    [Fact]
    public async Task ClosingTheDetailsPanelPutsItAway()
    {
        var screen = await Opened();

        screen.ShowDetails();
        Assert.True(screen.HasDetails);

        screen.Details!.Close();

        Assert.Null(screen.Details);
        Assert.False(screen.HasDetails);
    }

    /// <summary>
    /// The way out of the opening pass stops being offered once the pass has ended.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Found on screen, not by a test.</b> Stop sat in the footer of a finished screen with
    /// nothing running, drawn in the colour <c>0070</c> reserves for the exit of something that is
    /// running. An operator reading that footer is told a capture is under way when none is.
    /// </para>
    /// <para>
    /// <b>The cause was a missing announcement, not a wrong value.</b> <c>CanStop</c> is computed
    /// from <c>IsBusy</c>, and nothing told the screen to look at it again when the pass ended, so
    /// the button held whatever it had read at load. It survived while the wizard was its own
    /// window because the binding happened to be evaluated before the pass began; hosting it in
    /// the shell changed that order and the latch showed.
    /// </para>
    /// <para>
    /// So the announcement is what is asserted, not just the value. Reading <c>CanStop</c> alone
    /// would pass against exactly the bug this records.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheWayOutOfTheOpeningPassIsWithdrawnWhenThePassEnds()
    {
        var screen = Screen();

        var announced = new List<string?>();
        screen.PropertyChanged += (_, e) => announced.Add(e.PropertyName);

        await screen.OpenAsync();

        Assert.False(screen.IsBusy);
        Assert.False(screen.CanStop);
        Assert.Contains(nameof(NewAuditViewModel.CanStop), announced);
    }

    /// <summary>
    /// A domain with an unanswered question is worth attention, not just one with a bad answer.
    /// </summary>
    /// <remarks>
    /// <c>0056</c> has three states and the third is not a quiet success. A domain nobody could
    /// answer for must not sit behind a button that looks clean, because the column that would have
    /// shown it is no longer on the table.
    /// </remarks>
    [Fact]
    public async Task ADomainWithAnUnansweredQuestionIsWorthAttention()
    {
        var screen = await Planned();

        var row = Assert.Single(screen.Domains);

        Assert.Contains(row.FactStates, s => s == FactState.NotEstablished);
        Assert.True(row.NeedsAttention);
        Assert.True(screen.AnyDomainNeedsAttention);
    }

    /// <summary>
    /// A domain the forest names no controller for is a row of the table, not a note beneath it.
    /// </summary>
    /// <remarks>
    /// It lived in a list under the table until that area was cleared, and would have vanished from
    /// the domain screen entirely. A domain missing from an audit with nothing saying it is missing
    /// is the one outcome this product must not produce, so it is a row - and an operator counting
    /// rows gets the number the forest declared rather than the number that happened to be
    /// readable.
    /// </remarks>
    [Fact]
    public async Task ADomainWithNoControllerIsARowOfTheTable()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        Assert.Equal(2, screen.Rows.Count);
        Assert.Contains(screen.Rows, r => r.NamingContext == "DC=orphan,DC=ad,DC=lab");
    }

    /// <summary>
    /// That row refuses the controls it cannot honour.
    /// </summary>
    /// <remarks>
    /// There is nothing to tick such a domain back into and no controller to prefer over another,
    /// so the tick box and the override are not offered. A control that did nothing would be the
    /// screen offering a choice the product cannot make good on.
    /// </remarks>
    [Fact]
    public async Task ADomainWithNoControllerOffersNoChoiceItCannotHonour()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        var orphan = Assert.Single(
            screen.Rows.Where(r => r.NamingContext == "DC=orphan,DC=ad,DC=lab"));

        Assert.False(orphan.MayChangeInclusion);
        Assert.False(orphan.MayNameAController);
        Assert.False(orphan.IsIncluded);
        Assert.True(orphan.NeedsAttention);
    }

    /// <summary>
    /// It says the forest names no controller rather than leaving the cell blank.
    /// </summary>
    /// <remarks>
    /// An empty cell in a column of host names reads as a value that failed to load. This is not a
    /// failure to find something out - it is something the run found out.
    /// </remarks>
    [Fact]
    public async Task ADomainWithNoControllerSaysSoRatherThanShowingNothing()
    {
        _capture.Plan = Forests.OneDomain() with
        {
            DomainsWithNoCandidates = ["DC=orphan,DC=ad,DC=lab"],
        };

        var screen = await Opened();

        var orphan = Assert.Single(
            screen.Rows.Where(r => r.NamingContext == "DC=orphan,DC=ad,DC=lab"));

        Assert.NotEmpty(orphan.Controller);
        Assert.Contains("None named", orphan.Controller, StringComparison.Ordinal);
    }

    /// <summary>
    /// A finished run says where the evidence is, and no longer says reading it is unbuilt.
    /// </summary>
    /// <remarks>
    /// <b>This assertion was reversed on 2026-08-21.</b> It used to require the words "not built
    /// yet", which were true when written: no screen read a bundle. Assets reads them now and the
    /// run library opens one, so the sentence had outlived its premise and the screen was telling
    /// an operator his evidence was unreachable immediately after producing it. The path stays,
    /// because knowing where a run landed is useful whether or not it can be opened from here.
    /// </remarks>
    [Fact]
    public async Task AFinishedRunSaysWhereTheEvidenceIs()
    {
        var screen = await Opened();

        await screen.ReviewAsync();
        await screen.StartAsync();

        Assert.True(screen.HasFinished);
        Assert.Contains(@"D:\audits\run", screen.ResultsNote, StringComparison.Ordinal);
        Assert.DoesNotContain("not built", screen.ResultsNote, StringComparison.Ordinal);
    }

    /// <summary>
    /// A run that sealed evidence offers to show it, on the control that ends the wizard.
    /// </summary>
    /// <remarks>
    /// <b>The footer is one control whose label changes</b>, not three buttons. Before a capture it
    /// discards a plan; after one that sealed evidence it offers to view what was captured. The
    /// owner chose this shape on 2026-08-21 over adding a second footer button.
    /// </remarks>
    [Fact]
    public async Task AFinishedRunOffersToViewWhatItCaptured()
    {
        var screen = await Opened();

        Assert.Equal("Discard", screen.LeaveLabel);

        await screen.ReviewAsync();
        await screen.StartAsync();

        Assert.Equal("View results", screen.LeaveLabel);
    }

    /// <summary>
    /// Viewing the results opens the run that was just captured, and leaves the wizard.
    /// </summary>
    /// <remarks>
    /// <b>The same seam the run library uses</b>, so there is one way a run gets opened rather than
    /// two that can drift. Leaving as well is the point of the shape: the wizard has nothing left
    /// to say once the evidence is being read somewhere else.
    /// </remarks>
    [Fact]
    public async Task ViewingResultsOpensTheRunThatWasJustCaptured()
    {
        var screen = await Opened();

        await screen.ReviewAsync();
        await screen.StartAsync();

        screen.Leave();

        Assert.Equal(@"D:\audits\run", _opener.Opened);
        Assert.Equal(1, _dialogs.TimesLeft);
    }

    /// <summary>
    /// The audit is left before the run is opened, so the operator lands in Assets.
    /// </summary>
    /// <remarks>
    /// <b>This is an ordering test, and the order is load-bearing.</b> Both acts navigate: leaving
    /// the audit sends the shell Home - <c>ShellViewModel.Leave</c> does <c>Show(ShellSection.Home)</c>
    /// - and opening a run sends it to Assets. Whichever runs last decides where the operator
    /// actually ends up.
    /// <para>
    /// <b>Found in the lab on 2026-08-21, by the owner, after the tests passed.</b> The first
    /// version opened the run and then left, so Home won and View results took him to the wrong
    /// screen. <c>ViewingResultsOpensTheRunThatWasJustCaptured</c> asserted that the opener was
    /// called and that the audit was left exactly once, and both were true - it could not see the
    /// order, because neither fake models the shell's section. Asserting afterwards that two things
    /// happened cannot distinguish which happened first, which is why this observes the moment.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheAuditIsLeftBeforeTheRunIsOpened()
    {
        var screen = await Opened();

        await screen.ReviewAsync();
        await screen.StartAsync();

        var leftWhenOpened = -1;
        _opener.WhenOpening = () => leftWhenOpened = _dialogs.TimesLeft;

        screen.Leave();

        Assert.Equal(@"D:\audits\run", _opener.Opened);
        Assert.Equal(1, leftWhenOpened);
    }

    /// <summary>
    /// Discarding a plan that never ran opens nothing.
    /// </summary>
    /// <remarks>
    /// The negative control for the pair above. One control does two jobs, so the guard has to show
    /// it does not do the second one early - a wizard that opened a run the operator abandoned
    /// would be showing him evidence from somebody else's capture.
    /// </remarks>
    [Fact]
    public async Task DiscardingAPlanThatNeverRanOpensNothing()
    {
        var screen = await Opened();

        screen.Leave();

        Assert.Null(_opener.Opened);
        Assert.Equal(1, _dialogs.TimesLeft);
    }

    /// <summary>
    /// A run that sealed nothing is not offered results to view.
    /// </summary>
    /// <remarks>
    /// <b>A run can finish and seal nothing.</b> <c>CaptureOutcome.ProducedABundle</c> false with a
    /// directory means the run recorded what happened but wrote no evidence, so there is nothing to
    /// open. Offering to view results there would be the product claiming a capability it does not
    /// have on that run - the same fault the disabled button was built to avoid.
    /// </remarks>
    [Fact]
    public async Task ARunThatSealedNothingIsNotOfferedResultsToView()
    {
        _capture.Outcome = new CaptureOutcome(ProducedABundle: false, @"D:\audits\run");

        var screen = await Opened();
        await screen.StartAsync();

        Assert.True(screen.HasFinished);
        Assert.Equal("Done", screen.LeaveLabel);

        screen.Leave();

        Assert.Null(_opener.Opened);
    }

    /// <summary>
    /// A finished run cannot be walked back to the domain screen.
    /// </summary>
    /// <remarks>
    /// Evidence has been written by then. Offering Back would suggest the run could be changed and
    /// re-made, when what it actually produced is already sealed on disk.
    /// </remarks>
    [Fact]
    public async Task AFinishedRunDoesNotOfferTheWayBack()
    {
        var screen = await Opened();

        await screen.ReviewAsync();
        Assert.True(screen.CanGoBack);

        await screen.StartAsync();

        Assert.False(screen.CanGoBack);
    }

    private async Task<NewAuditViewModel> Opened()
    {
        var screen = Screen();
        await screen.OpenAsync();
        return screen;
    }

    /// <summary>
    /// The window as it stands when discovery answered and the per-domain pass did not.
    /// </summary>
    /// <remarks>
    /// The state in which the preflight questions have genuinely not been put, which is what the
    /// three-state rendering has to be judged against. Reaching it by letting the second half fail
    /// keeps the two halves separable in the test as they are in the code.
    /// </remarks>
    private async Task<NewAuditViewModel> Planned()
    {
        _capture.CheckFails = Failures.Any("Nothing answered.");

        var screen = Screen();
        await screen.OpenAsync();
        return screen;
    }

    // A Reviewed() helper stood here, opening the window and then moving to the Review step so that
    // CanStart was true. There is no such state now: the window works itself out on opening, and
    // reviewing is the act that starts the run rather than a page reached before it. Tests that
    // wanted a startable screen use Opened(); the one that wants a started run calls StartAsync.

    private NewAuditViewModel Screen()
    {
        // Only the path, so a test that arranged a concurrency ceiling still has one. This wrote a
        // whole fresh record until 2026-09-13, which was lossless while there was one setting and
        // silently discarded the other as soon as there were two.
        _settings.Stored = _settings.Stored with { RunLibraryPath = @"D:\audits" };

        var location = new RunLibraryLocation(_settings);
        location.Load();

        // Loaded, exactly as the composition root loads it. An unloaded ceiling reports the default
        // whatever the settings file says, which would have made the test that proves the operator's
        // choice reaches the run pass against a value nobody chose.
        var concurrency = new DomainConcurrency(_settings);
        concurrency.Load();

        _deriving.Order = _order;
        _judging.Order = _order;

        return new NewAuditViewModel(
            location, _capture, _dialogs, _opener, _deriving, _judging, concurrency);
    }
}
