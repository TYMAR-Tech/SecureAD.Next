using System.Windows.Data;
using SecureAD.Evidence.Run;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The run library screen.
///
/// <para>
/// These tests exist for one distinction. "You have no runs", "I do not know where to look" and "I
/// could not read the library" are three different sentences, and only the first is a statement
/// about the operator's evidence. A screen that showed an empty grid for all three would assert the
/// first in two cases where it is not known.
/// </para>
/// </summary>
public sealed class RunLibraryViewModelTests
{
    private readonly FakeSettingsStore _settings = new();
    private readonly FakeRunCatalog _catalog = new();

    /// <summary>
    /// The operator's answer to a confirmation. Declining by default, so a test that means to
    /// delete something has to say so and one that forgets cannot delete by accident.
    /// </summary>
    private readonly FakeConfirmation _confirmation = new();

    /// <summary>Where a run would be opened, without a window existing.</summary>
    private readonly FakeRunOpener _opener = new();

    /// <summary>Deriving and judging, without a bundle on disk or hours of work.</summary>
    private readonly FakeDerivationLauncher _deriving = new();
    private readonly FakeJudgingLauncher _judging = new();

    [Fact]
    public void WithNoLibraryChosenNothingIsClaimedAboutRuns()
    {
        var screen = Screen();

        screen.Refresh();

        Assert.False(screen.IsEmpty);
    }

    [Fact]
    public void WithNoLibraryChosenTheOperatorIsToldWhy()
    {
        var screen = Screen();

        screen.Refresh();

        Assert.False(string.IsNullOrWhiteSpace(screen.Problem));
    }

    [Fact]
    public void WithNoLibraryChosenTheCatalogIsNotAsked()
    {
        var screen = Screen();

        screen.Refresh();

        Assert.Null(_catalog.AskedFor);
    }

    [Fact]
    public void AReadableLibraryHoldingNothingIsReportedAsEmpty()
    {
        var screen = Screen(@"D:\audits");

        screen.Refresh();

        Assert.True(screen.IsEmpty);
    }

    [Fact]
    public void AnUnreadableLibraryIsNotReportedAsEmpty()
    {
        _catalog.Fails = Failures.Any("The drive is not there.");
        var screen = Screen(@"D:\audits");

        screen.Refresh();

        Assert.False(screen.IsEmpty);
    }

    [Fact]
    public void AnUnreadableLibrarySurfacesTheReason()
    {
        _catalog.Fails = Failures.Any("The drive is not there.");
        var screen = Screen(@"D:\audits");

        screen.Refresh();

        Assert.Equal("The drive is not there.", screen.Problem);
    }

    [Fact]
    public void TheRunsFoundAreListed()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");

        screen.Refresh();

        Assert.Equal("a-20260101-000000", Assert.Single(screen.Runs).Identifier);
    }

    [Fact]
    public void TheCatalogIsAskedAboutTheChosenLibrary()
    {
        var screen = Screen(@"D:\audits");

        screen.Refresh();

        Assert.Equal(@"D:\audits", _catalog.AskedFor);
    }

    /// <summary>
    /// A failure must not leave the previous library's runs on screen beside the error, which would
    /// attribute one library's evidence to another.
    /// </summary>
    [Fact]
    public void AFailedRefreshClearsWhatWasShownBefore()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        _catalog.Fails = Failures.Any("The drive is not there.");
        screen.Refresh();

        Assert.Empty(screen.Runs);
    }

    [Fact]
    public void ASucceedingRefreshClearsAnEarlierProblem()
    {
        _catalog.Fails = Failures.Any("The drive is not there.");
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        _catalog.Fails = null;
        screen.Refresh();

        Assert.Null(screen.Problem);
    }

    /// <summary>
    /// A selection is a pointer into the list a refresh discards. Left alone, the details card
    /// would go on describing a run this library may no longer hold.
    /// </summary>
    [Fact]
    public void ARefreshDropsTheSelection()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.Refresh();

        Assert.Null(screen.Selected);
    }

    [Fact]
    public void WithNothingSelectedThereIsNothingToDetail()
    {
        var screen = Screen(@"D:\audits");

        Assert.False(screen.HasSelection);
    }

    [Fact]
    public void SelectingARunGivesTheCardSomethingToShow()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        screen.Selected = screen.Runs[0];

        Assert.True(screen.HasSelection);
    }

    /// <summary>Opening a run hands its directory to whatever reads bundles.</summary>
    [Fact]
    public void OpeningARunHandsOverItsDirectory()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.OpenRun();

        Assert.Equal(@"D:\audits\a", _opener.Opened);
    }

    /// <summary>
    /// A run that ended badly wrote no evidence, so there is nothing to open and the operator is
    /// told that rather than a reader being handed a directory it will fail on.
    /// </summary>
    [Fact]
    public void ARunThatEndedBadlyHasNothingToOpen()
    {
        _catalog.Runs.Add(Failed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.OpenRun();

        Assert.Null(_opener.Opened);
        Assert.NotNull(screen.Problem);
    }

    /// <summary>A run that ended in an error, so it has no sealed evidence.</summary>
    private static RunListing Failed(string identifier, string path) =>
        new(
            identifier,
            path,
            RunState.Failed,
            "The drive filled up.",
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            RunAnnotation.None,
            Scope: null,
            new RunProducts(HasDerivedFacts: false, HasJudgement: false));

    /// <summary>Marking a run as the baseline records it against that run.</summary>
    [Fact]
    public void MarkingABaselineRecordsItAgainstTheRun()
    {
        _catalog.Runs.Add(Scoped("a-20260101-000000", @"D:\audits\a", "scope-one"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.MarkAsBaseline();

        Assert.True(_catalog.Annotated!.Value.Annotation.IsBaseline);
        Assert.Equal(@"D:\audits\a", _catalog.Annotated!.Value.BundleDirectory);
    }

    /// <summary>
    /// A run whose scope could not be established has no group to be the baseline of, and is told
    /// so rather than silently doing nothing.
    /// </summary>
    [Fact]
    public void ARunWithNoKnownScopeCannotBeABaseline()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.MarkAsBaseline();

        Assert.Null(_catalog.Annotated);
        Assert.NotNull(screen.Problem);
    }

    /// <summary>
    /// Saving a name carries the baseline mark through.
    ///
    /// <para>
    /// Both live in one row, so a save built from the typed boxes alone would clear the mark. An
    /// operator correcting a spelling would have un-baselined his own run with nothing on screen
    /// suggesting that was what Save did.
    /// </para>
    /// </summary>
    [Fact]
    public void SavingANameDoesNotClearTheBaselineMark()
    {
        _catalog.Runs.Add(
            Scoped("a-20260101-000000", @"D:\audits\a", "scope-one", isBaseline: true));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.TypedName = "Quarterly review";
        screen.SaveAnnotation();

        Assert.True(_catalog.Annotated!.Value.Annotation.IsBaseline);
    }

    /// <summary>
    /// A sealed run with a known scope, so it has a group to be the baseline of.
    /// </summary>
    private static RunListing Scoped(
        string identifier, string path, string identity, bool isBaseline = false) =>
        new(
            identifier,
            path,
            RunState.Sealed,
            null,
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            new RunAnnotation(null, null, isBaseline),
            RunScope.Of(identity, [DomainCoverage.Read("contoso.com")]),
            new RunProducts(HasDerivedFacts: true, HasJudgement: true));

    /// <summary>
    /// A sealed run as the library would list it. The moment is recorded, because a sealed run
    /// always has one; nothing in this class depends on its value. The scope is absent, which is
    /// what a listing carries for a run whose bundle it could not open.
    /// </summary>
    private static RunListing Listed(string identifier, string path) =>
        new(
            identifier,
            path,
            RunState.Sealed,
            null,
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            RunAnnotation.None,
            Scope: null,
            new RunProducts(HasDerivedFacts: true, HasJudgement: true));

    /// <summary>
    /// What the operator typed reaches the run he had selected, and not some other run.
    /// </summary>
    [Fact]
    public void WhatTheOperatorTypesIsSavedAgainstTheSelectedRun()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        screen.TypedName = "Quarterly review";
        screen.SaveAnnotation();

        Assert.Equal(@"D:\audits\a", _catalog.Annotated!.Value.BundleDirectory);
        Assert.Equal("Quarterly review", _catalog.Annotated!.Value.Annotation.Name);
    }

    /// <summary>
    /// A save that failed must say so. Silently discarding what somebody typed is worse than
    /// refusing it, because he walks away believing it was kept.
    /// </summary>
    [Fact]
    public void ASaveThatFailedIsReported()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        _catalog.AnnotationFails = Failures.Any("The disk is read-only.");
        screen.TypedName = "Quarterly review";
        screen.SaveAnnotation();

        Assert.Equal("The disk is read-only.", screen.Problem);
    }

    /// <summary>
    /// Deleting asks once, and the question names the run so the operator can see which of several
    /// timestamps he picked.
    /// </summary>
    [Fact]
    public void DeletingAsksOnceAndNamesTheRun()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];
        var name = screen.Selected.Name;

        _confirmation.Answer = true;
        screen.DeleteRun();

        Assert.Equal(1, _confirmation.TimesAsked);
        Assert.Contains(name, _confirmation.Asked!.Value.Question, StringComparison.Ordinal);
    }

    /// <summary>
    /// An operator who declines still has his run. The whole point of the prompt is that answering
    /// no is a real answer.
    /// </summary>
    [Fact]
    public void DecliningTheConfirmationKeepsTheRun()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        _confirmation.Answer = false;
        screen.DeleteRun();

        Assert.Null(_catalog.Deleted);
        Assert.NotEmpty(screen.Runs);
    }

    /// <summary>Confirming removes the run, and the list stops showing it.</summary>
    [Fact]
    public void ConfirmingDeletesTheRunAndItLeavesTheList()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];
        var path = screen.Selected.Path;

        _confirmation.Answer = true;
        screen.DeleteRun();

        Assert.Equal(path, _catalog.Deleted);
        Assert.DoesNotContain(screen.Runs, run => run.Path == path);
    }

    /// <summary>
    /// A deletion that failed leaves the run listed and says why.
    ///
    /// <para>
    /// Dropping the row anyway would tell the operator he had recovered space he still has not,
    /// and the ordinary cause - something else holding the bundle open - is one he can act on.
    /// </para>
    /// </summary>
    [Fact]
    public void ADeletionThatFailedLeavesTheRunListedAndSaysWhy()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];
        var path = screen.Selected.Path;

        _catalog.DeletionFails = Failures.Any("Something still has the run open.");
        _confirmation.Answer = true;
        screen.DeleteRun();

        Assert.Equal("Something still has the run open.", screen.Problem);
        Assert.Contains(screen.Runs, run => run.Path == path);
    }

    /// <summary>
    /// With nothing selected there is no run to delete, and nothing may ask about one. A prompt
    /// naming no run is how an operator comes to confirm something he cannot see.
    /// </summary>
    [Fact]
    public void WithNothingSelectedNothingIsDeletedAndNothingIsAsked()
    {
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        screen.DeleteRun();

        Assert.Equal(0, _confirmation.TimesAsked);
        Assert.Null(_catalog.Deleted);
    }

    /// <summary>
    /// A run whose scope could not be established is not folded in with the runs whose scope is
    /// known. <i>We could not tell</i> and <i>the whole forest</i> must not look alike.
    /// </summary>
    [Fact]
    public void ARunWhoseScopeIsUnknownIsGroupedApart()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        Assert.Equal(
            "Scope not established - these runs could not be opened",
            screen.Runs[0].GroupHeading);
    }

    /// <summary>
    /// The grouped view is what the screen binds to, and it groups on the run's own evidence
    /// identity rather than on anything the shell works out for itself.
    /// </summary>
    [Fact]
    public void TheRunsAreGroupedByScope()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        var grouping = Assert.Single(screen.RunsView.GroupDescriptions);
        Assert.Equal(
            nameof(RunSummaryViewModel.GroupKey),
            ((PropertyGroupDescription)grouping).PropertyName);
    }

    /// <summary>
    /// With nothing selected there is no run to annotate, and the command must not guess at one.
    /// </summary>
    [Fact]
    public void WithNothingSelectedNothingIsSaved()
    {
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        screen.TypedName = "Quarterly review";
        screen.SaveAnnotation();

        Assert.Null(_catalog.Annotated);
    }

    /// <summary>
    /// A run written after the library was last read can still be selected.
    /// </summary>
    /// <remarks>
    /// <b>This is the case a plain selection cannot reach.</b> A capture that has just finished
    /// wrote a bundle the listed runs know nothing about, so looking for its row without reading the
    /// library again finds nothing. The wizard sends an operator straight to it, so the row has to
    /// be there by the time he arrives.
    /// </remarks>
    [Fact]
    public void ARunWrittenSinceTheLastReadCanBeAdopted()
    {
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        Assert.Empty(screen.Runs);

        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));

        screen.Adopt(@"D:\audits\a");

        Assert.Equal(@"D:\audits\a", screen.Selected?.Path);
        Assert.Null(screen.Problem);
    }

    /// <summary>
    /// A run the library does not hold says so rather than selecting nothing in silence.
    /// </summary>
    /// <remarks>
    /// The case where a run was written somewhere other than the library this screen is pointed at.
    /// Left silent, an operator would arrive at an empty screen with no way to tell that from a run
    /// that captured nothing - which is the one thing an audit tool must not leave ambiguous.
    /// </remarks>
    [Fact]
    public void ARunTheLibraryDoesNotHoldSaysSo()
    {
        _catalog.Runs.Add(Listed("a-20260101-000000", @"D:\audits\a"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        screen.Adopt(@"E:\elsewhere\b");

        Assert.Null(screen.Selected);
        Assert.NotNull(screen.Problem);
        Assert.Contains(@"E:\elsewhere\b", screen.Problem, StringComparison.Ordinal);
    }

    /// <summary>
    /// A sealed run holding whichever analysis products a test needs.
    /// </summary>
    /// <remarks>
    /// The scope is absent, which is what a listing carries for a run whose bundle it could not
    /// open. Nothing in the analysis cases depends on it.
    /// </remarks>
    private static RunListing SealedRun(string identifier, string path, RunProducts products) =>
        new(
            identifier,
            path,
            RunState.Sealed,
            null,
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            RunAnnotation.None,
            Scope: null,
            products);

    /// <summary>A run whose evidence is sealed and which nothing has been made from.</summary>
    /// <remarks>
    /// What <c>--capture</c> has always produced, and what the review page's <i>Capture only</i>
    /// now produces too. It is complete evidence, not a failure.
    /// </remarks>
    private static RunListing CaptureOnly(string identifier, string path) =>
        SealedRun(identifier, path, new RunProducts(HasDerivedFacts: false, HasJudgement: false));

    /// <summary>A run holding derived facts that nothing has judged.</summary>
    private static RunListing AwaitingJudgement(string identifier, string path) =>
        SealedRun(identifier, path, new RunProducts(HasDerivedFacts: true, HasJudgement: false));

    /// <summary>A run that has been judged.</summary>
    private static RunListing AlreadyJudged(string identifier, string path) =>
        SealedRun(identifier, path, new RunProducts(HasDerivedFacts: true, HasJudgement: true));

    private RunLibraryViewModel Selecting(RunListing run)
    {
        _catalog.Runs.Add(run);
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];
        return screen;
    }

    [Fact]
    public void ARunHoldingNothingIsOfferedADerivation()
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));

        Assert.True(screen.CanDerive);
    }

    [Fact]
    public void ARunThatAlreadyHoldsFactsIsNotOfferedADerivation()
    {
        var screen = Selecting(AwaitingJudgement("a-20260101-000000", @"D:\audits\a"));

        Assert.False(screen.CanDerive);
    }

    /// <summary>
    /// Judging rests on derived facts, so a run holding none is offered deriving first rather than
    /// a judging that would rest on nothing.
    /// </summary>
    [Fact]
    public void ARunHoldingNoFactsIsNotOfferedAJudging()
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));

        Assert.False(screen.CanJudge);
    }

    [Fact]
    public void ARunHoldingFactsAndNoJudgementIsOfferedAJudging()
    {
        var screen = Selecting(AwaitingJudgement("a-20260101-000000", @"D:\audits\a"));

        Assert.True(screen.CanJudge);
    }

    [Fact]
    public void AnAlreadyJudgedRunIsNotOfferedASecondJudging()
    {
        var screen = Selecting(AlreadyJudged("a-20260101-000000", @"D:\audits\a"));

        Assert.False(screen.CanJudge);
    }

    [Fact]
    public void DerivingReadsTheSelectedRunsBundle() => OneThread.Run(async () =>
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));

        await screen.DeriveFactsAsync();

        Assert.Equal(@"D:\audits\a", _deriving.AskedFor);
    });

    [Fact]
    public void JudgingReadsTheSelectedRunsBundle() => OneThread.Run(async () =>
    {
        var screen = Selecting(AwaitingJudgement("a-20260101-000000", @"D:\audits\a"));

        await screen.JudgeAsync();

        Assert.Equal(@"D:\audits\a", _judging.AskedFor);
    });

    [Fact]
    public void WithNothingSelectedNothingIsDerived() => OneThread.Run(async () =>
    {
        var screen = Screen(@"D:\audits");
        screen.Refresh();

        await screen.DeriveFactsAsync();

        Assert.False(_deriving.WasRun);
    });

    /// <summary>
    /// A second judging is refused before anything is opened, rather than started and left to
    /// discover part way through that it is overwriting a judgement.
    /// </summary>
    [Fact]
    public void AnAlreadyJudgedRunIsRefusedAndNothingIsJudged() => OneThread.Run(async () =>
    {
        var screen = Selecting(AlreadyJudged("a-20260101-000000", @"D:\audits\a"));

        await screen.JudgeAsync();

        Assert.False(_judging.WasRun);
    });

    /// <summary>
    /// The refusal is said, not merely enacted by a button that will not press.
    /// </summary>
    [Fact]
    public void AnAlreadyJudgedRunSaysWhyItWasRefused() => OneThread.Run(async () =>
    {
        var screen = Selecting(AlreadyJudged("a-20260101-000000", @"D:\audits\a"));

        await screen.JudgeAsync();

        Assert.Contains("already been judged", screen.Problem, StringComparison.Ordinal);
    });

    /// <summary>
    /// A run with no facts is sent to derive them rather than told only that judging is unavailable.
    /// </summary>
    [Fact]
    public void ARunHoldingNoFactsIsToldToDeriveThemFirst() => OneThread.Run(async () =>
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));

        await screen.JudgeAsync();

        Assert.False(_judging.WasRun);
        Assert.Contains("Derive facts from it first", screen.Problem, StringComparison.Ordinal);
    });

    /// <summary>
    /// <b>The failure this screen exists to prevent.</b> The library is a list the operator goes on
    /// clicking through while an hour-long judging runs, so the selection when one returns is
    /// frequently not the run that was read. An outcome written under whatever happens to be
    /// selected then would attribute one run's results to another.
    /// </summary>
    [Fact]
    public void AnOutcomeNamesTheRunItReadAndNotTheOneSelectedWhenItFinished() =>
        OneThread.Run(async () =>
        {
            _catalog.Runs.Add(CaptureOnly("a-20260101-000000", @"D:\audits\a"));
            _catalog.Runs.Add(CaptureOnly("b-20260202-000000", @"D:\audits\b"));
            var screen = Screen(@"D:\audits");
            screen.Refresh();
            screen.Selected = screen.Runs[0];

            _deriving.WhileRunning = () => screen.Selected = screen.Runs[1];

            await screen.DeriveFactsAsync();

            Assert.Contains("a-20260101-000000", screen.AnalysisStatus, StringComparison.Ordinal);
            Assert.DoesNotContain(
                "b-20260202-000000", screen.AnalysisStatus, StringComparison.Ordinal);
        });

    /// <summary>
    /// And his selection is left where he put it. Forcing it back to the analysed run would yank
    /// the screen out from under him.
    /// </summary>
    [Fact]
    public void TheSelectionTheOperatorMadeDuringAnAnalysisSurvivesIt() => OneThread.Run(async () =>
    {
        _catalog.Runs.Add(CaptureOnly("a-20260101-000000", @"D:\audits\a"));
        _catalog.Runs.Add(CaptureOnly("b-20260202-000000", @"D:\audits\b"));
        var screen = Screen(@"D:\audits");
        screen.Refresh();
        screen.Selected = screen.Runs[0];

        _deriving.WhileRunning = () => screen.Selected = screen.Runs[1];

        await screen.DeriveFactsAsync();

        Assert.Equal(@"D:\audits\b", screen.Selected?.Path);
    });

    /// <summary>
    /// The library is read again afterwards, so the analysed run's row stops saying it holds
    /// nothing. Left unread, the screen would go on offering a derivation that has already happened.
    /// </summary>
    [Fact]
    public void AnAnalysedRunsRowIsReadAgainRatherThanAssumed() => OneThread.Run(async () =>
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));

        // What the derivation publishes is what the library will find when it reads again.
        _deriving.WhileRunning = () =>
        {
            _catalog.Runs.Clear();
            _catalog.Runs.Add(AwaitingJudgement("a-20260101-000000", @"D:\audits\a"));
        };

        await screen.DeriveFactsAsync();

        Assert.False(screen.Runs[0].MayDerive);
        Assert.True(screen.Runs[0].MayJudge);
    });

    /// <summary>
    /// Nothing else is offered while an analysis runs. Two at once over one bundle would have them
    /// writing the same store.
    /// </summary>
    [Fact]
    public void NoSecondAnalysisIsOfferedWhileOneIsRunning() => OneThread.Run(async () =>
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));
        var offeredMidRun = true;

        _deriving.WhileRunning = () => offeredMidRun = screen.CanDerive;

        await screen.DeriveFactsAsync();

        Assert.False(offeredMidRun);
    });

    /// <summary>
    /// Stop reaches the launcher, and what it leaves behind claims nothing was derived.
    /// </summary>
    /// <remarks>
    /// The fake observes the token it is handed, so this proves the screen's own cancellation is
    /// wired to the work rather than only that a flag was set on the screen.
    /// </remarks>
    [Fact]
    public void StoppingAnAnalysisLeavesNoClaimThatItHappened() => OneThread.Run(async () =>
    {
        var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));

        _deriving.WhileRunning = screen.StopAnalysis;

        await screen.DeriveFactsAsync();

        Assert.Contains("deriving was stopped", screen.AnalysisStatus, StringComparison.Ordinal);
        Assert.DoesNotContain("principals", screen.AnalysisStatus, StringComparison.Ordinal);
    });

    /// <summary>
    /// A derivation that refuses says so and says the evidence is still safe - it took hours and
    /// read a forest that has moved on, and it is the thing the operator cannot get back.
    /// </summary>
    [Fact]
    public void ADerivationThatRefusesSurfacesTheReasonAndSaysTheEvidenceIsSafe() =>
        OneThread.Run(async () =>
        {
            var screen = Selecting(CaptureOnly("a-20260101-000000", @"D:\audits\a"));
            _deriving.Fails = Failures.Any("The derivation store is locked.");

            await screen.DeriveFactsAsync();

            Assert.Contains(
                "The derivation store is locked.", screen.AnalysisStatus, StringComparison.Ordinal);
            Assert.Contains("sealed", screen.AnalysisStatus, StringComparison.Ordinal);
        });

    /// <summary>
    /// A defect in judging costs the judging and nothing else. Left to escape it would reach the
    /// dispatcher unhandled and take the window down with it.
    /// </summary>
    [Fact]
    public void ADefectInJudgingIsReportedRatherThanThrown() => OneThread.Run(async () =>
    {
        var screen = Selecting(AwaitingJudgement("a-20260101-000000", @"D:\audits\a"));
        _judging.Throws = new InvalidOperationException("the rule schedule was empty");

        await screen.JudgeAsync();

        Assert.Contains(
            "the rule schedule was empty", screen.AnalysisStatus, StringComparison.Ordinal);
        Assert.False(screen.IsAnalysing);
    });

    private RunLibraryViewModel Screen(string? chosenPath = null)
    {
        _settings.Stored = new ShellSettings(chosenPath, DomainsAtOnce: null);

        var location = new RunLibraryLocation(_settings);
        location.Load();

        return new RunLibraryViewModel(
            location, _catalog, _confirmation, _opener, _deriving, _judging);
    }
}
