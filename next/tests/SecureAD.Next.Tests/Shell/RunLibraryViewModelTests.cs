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
            Scope: null);

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

    private RunLibraryViewModel Screen(string? chosenPath = null)
    {
        _settings.Stored = new ShellSettings(chosenPath);

        var location = new RunLibraryLocation(_settings);
        location.Load();

        return new RunLibraryViewModel(location, _catalog, _confirmation);
    }
}
