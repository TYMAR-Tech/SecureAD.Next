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
    /// always has one; nothing in this class depends on its value.
    /// </summary>
    private static RunListing Listed(string identifier, string path) =>
        new(
            identifier,
            path,
            RunState.Sealed,
            null,
            new RunMoment(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), Recorded: true),
            RunAnnotation.None);

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

        return new RunLibraryViewModel(location, _catalog);
    }
}
