using SecureAD.Shell.Services;
using SecureAD.Shell.Settings;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

/// <summary>
/// The home screen, and the choosing of a run library.
///
/// <para>
/// The product has no default run library path by decision <c>0025</c>, so the interesting states
/// here are "not chosen yet" and "chosen but could not be saved". The second must not be presented
/// as success, because a path adopted in memory and lost on restart changes the product's behaviour
/// with nothing explaining why.
/// </para>
/// <para>
/// Starting a run is no longer this screen's, and the cases that covered it moved with it to
/// <c>NewAuditViewModelTests</c>.
/// </para>
/// </summary>
public sealed class HomeViewModelTests
{
    private readonly FakeSettingsStore _settings = new();
    private readonly FakeFolderPicker _picker = new();
    private readonly FakeNewAuditDialog _newAudit = new();
    private readonly FakeRunCatalog _catalog = new();

    [Fact]
    public void AnUnconfiguredInstallationHasNoLibrary()
    {
        Assert.False(Screen().Location.IsChosen);
    }

    [Fact]
    public void AnUnconfiguredInstallationExplainsItselfRatherThanShowingAnEmptyPath()
    {
        Assert.Contains("chosen", Screen().LibraryDescription, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ChoosingALibraryAsksTheOperator()
    {
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.True(_picker.WasAsked);
    }

    [Fact]
    public void AChosenLibraryIsAdopted()
    {
        _picker.Answer = @"D:\audits";
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.Equal(@"D:\audits", screen.Location.Path);
    }

    [Fact]
    public void AChosenLibraryIsStored()
    {
        _picker.Answer = @"D:\audits";
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.Equal(@"D:\audits", _settings.Stored.RunLibraryPath);
    }

    [Fact]
    public void AChosenLibraryIsShownInPlaceOfTheExplanation()
    {
        _picker.Answer = @"D:\audits";
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.Equal(@"D:\audits", screen.LibraryDescription);
    }

    [Fact]
    public void CancellingLeavesTheLibraryAlone()
    {
        _picker.Answer = null;
        _settings.Stored = new ShellSettings(@"D:\audits");
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.Equal(@"D:\audits", screen.Location.Path);
    }

    /// <summary>
    /// The case that must not look like success.
    /// </summary>
    [Fact]
    public void APathThatCouldNotBeStoredIsNotAdopted()
    {
        _picker.Answer = @"D:\audits";
        _settings.WriteFails = Failures.Any("The settings file is read-only.");
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.Null(screen.Location.Path);
    }

    [Fact]
    public void APathThatCouldNotBeStoredSaysWhy()
    {
        _picker.Answer = @"D:\audits";
        _settings.WriteFails = Failures.Any("The settings file is read-only.");
        var screen = Screen();

        screen.ChooseLibraryCommand.Execute(null);

        Assert.Equal("The settings file is read-only.", screen.Location.Problem);
    }

    /// <summary>
    /// Unreadable settings are not a new installation, and must not be silently reset.
    /// </summary>
    [Fact]
    public void UnreadableSettingsAreReportedRatherThanTreatedAsUnconfigured()
    {
        _settings.ReadFails = Failures.Any("The settings file could not be read.");

        Assert.Equal("The settings file could not be read.", Screen().Location.Problem);
    }

    /// <summary>
    /// A run cannot be started before there is somewhere to put it.
    /// </summary>
    /// <remarks>
    /// Opening a wizard whose every action refuses would teach an operator that this product's
    /// refusals are noise, which is expensive in a tool whose refusals are the point.
    /// </remarks>
    [Fact]
    public void AnAuditCannotBeStartedUntilARunLibraryIsChosen()
    {
        Assert.False(Screen().NewAuditCommand.CanExecute(null));
    }

    [Fact]
    public void ChoosingALibraryMakesAnAuditStartable()
    {
        _picker.Answer = @"D:\audits";

        var home = Screen();
        home.ChooseLibraryCommand.Execute(null);

        Assert.True(home.NewAuditCommand.CanExecute(null));
    }

    [Fact]
    public void StartingAnAuditPutsOneOnTheAuditSurface()
    {
        _picker.Answer = @"D:\audits";

        var home = Screen();
        home.ChooseLibraryCommand.Execute(null);
        home.NewAuditCommand.Execute(null);

        Assert.Equal(1, _newAudit.TimesOpened);
    }

    [Fact]
    public void NothingStartsAnAuditUntilTheOperatorAsksForOne()
    {
        _picker.Answer = @"D:\audits";

        var home = Screen();
        home.ChooseLibraryCommand.Execute(null);

        Assert.Equal(0, _newAudit.TimesOpened);
    }

    private HomeViewModel Screen()
    {
        var location = new RunLibraryLocation(_settings);
        location.Load();

        return new HomeViewModel(
            location, _picker, _newAudit, new RunLibraryViewModel(location, _catalog));
    }
}
