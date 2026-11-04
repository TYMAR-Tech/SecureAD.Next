using System.Windows;
using System.Windows.Controls;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using SecureAD.Shell.ViewModels;
using Xunit;
using static SecureAD.Next.Tests.Shell.ObjectNavigationViewTests;

namespace SecureAD.Next.Tests.Shell;

[Collection("Finding window resources")]
public sealed class DuplicateSpnDetailTests
{
    [Fact]
    public void OpeningShowsCapturedConflictsWithoutReadingOriginalRegistrationValues()
    {
        var (model, source, _) = Model(2);
        var row = Assert.Single(model.Findings);
        Assert.Empty(source.DuplicateSpnReads);
        model.OpenFinding(row);
        var details = model.FindingDetails!;
        var panel = Assert.IsType<DuplicateSpnViewModel>(details.DuplicateSpn);
        Assert.False(details.ShowsSavedDescription);
        Assert.False(details.ShowsStandardIdentity);
        Assert.Equal("SEC-026", details.Finding!.Rule);
        Assert.Equal("High", details.Finding.Severity);
        Assert.Equal(2, panel.Owners.Owners.Count);
        Assert.Single(panel.Owners.Owners, owner => owner.IsSubject);
        Assert.Equal("Same name", panel.AffectedObject);
        Assert.Null(panel.Registrations);
        Assert.Single(source.DuplicateSpnReads);
        Assert.Null(source.DuplicateSpnReads[0].Position);
        Assert.Empty(source.ControlQueries);
        Assert.Empty(source.PathQueries);
        Assert.Equal(RuleGuidanceCatalogue.For("SEC-026")!.WhyItMatters, details.Finding.WhyItMatters);
        Assert.Equal(RuleGuidanceCatalogue.For("SEC-026")!.WhatToDo, details.Finding.WhatToDo);
    }

    [Fact]
    public void OwnerOccurrenceAndSpnPagesRemainIndependentAndReachable() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(51, matches: 2, copies: 2);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DuplicateSpn!;
        Assert.Equal(50, panel.Owners.Owners.Count);
        panel.Owners.NextPageCommand.Execute(null);
        await panel.Owners.ReadCompletion;
        Assert.Single(panel.Owners.Owners);
        Assert.Equal("Page 2", panel.Owners.PageLabel);
        panel.LoadRegistrationsCommand.Execute(null);
        await panel.RegistrationReadCompletion;
        var registrations = panel.Registrations!;
        Assert.Equal(50, registrations.Registrations.Count);
        Assert.Equal("Page 1", registrations.PageLabel);
        Assert.Single(panel.Owners.Owners);
        registrations.NextPageCommand.Execute(null);
        await registrations.ReadCompletion;
        Assert.Equal("Page 2", registrations.PageLabel);
        registrations.PreviousPageCommand.Execute(null);
        await registrations.ReadCompletion;
        Assert.Equal("Page 1", registrations.PageLabel);
        var oldOwners = panel.Owners;
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("SPN 2", panel.SpnLabel);
        Assert.Equal("HTTP/HOST1:1433/SERVICE", panel.MatchKey);
        Assert.Null(panel.Registrations);
        Assert.Empty(oldOwners.Owners);
        Assert.Empty(registrations.Registrations);
        Assert.Equal(50, panel.Owners.Owners.Count);
        panel.PreviousPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("SPN 1", panel.SpnLabel);
        Assert.Contains(source.DuplicateSpnReads, read => read.Position?.Kind == DuplicateSpnPageKind.CapturedRegistrations);
    });

    [Theory]
    [InlineData("missing")]
    [InlineData("subject")]
    [InlineData("generation")]
    [InlineData("page")]
    [InlineData("null-context")]
    public void InvalidInitialDetailsAreRefusedInsteadOfFallingBackToRawProse(string defect)
    {
        var (model, source, _) = Model(2);
        var read = source.DuplicateSpnRead!;
        source.DuplicateSpnRead = (reference, position) =>
        {
            if (defect == "missing") return Result<SavedDuplicateSpn>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "MissingSavedDuplicate", ErrorSeverity.Failed, SavedDuplicateSpn.InvalidDetails, null));
            var page = read(reference, position).Value;
            return Result<SavedDuplicateSpn>.Success(defect switch
            {
                "subject" => page with { Context = page.Context with { AffectedObject = page.Context.AffectedObject with { ObjectGuid = Guid.NewGuid() } } },
                "generation" => page with { Context = page.Context with { Reference = reference with { GenerationId = Guid.NewGuid() } } },
                "null-context" => page with { Context = null! },
                _ => page with { SpnIndex = 99 },
            });
        };
        model.OpenFinding(Assert.Single(model.Findings));
        Assert.Equal(SavedDuplicateSpn.InvalidDetails, model.FindingDetails!.Refusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Null(model.FindingDetails.DuplicateSpn);
    }

    [Fact]
    public void BothFindingEntryPointsKeepTheSameAffectedObjectAndReturnContext() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(2);
        var row = Assert.Single(model.Findings);
        model.SelectedFinding = row;
        source.Attributes = FakeAssetSource.CapturedObject(row.DistinguishedName, row.ObjectClass) with { ObjectGuid = row.Saved.ObjectGuid };
        source.Permissions = ControlEdgeDeriverTests.Permissions(row.DistinguishedName);
        model.OpenFinding(row);
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        model.CloseFindingDetails();
        model.OpenFinding(Assert.Single(section.Findings));
        Assert.Equal(row.Saved.Reference, model.FindingDetails!.Finding!.Saved.Reference);
        Assert.NotNull(model.FindingDetails.DuplicateSpn);
        Assert.Equal(2, source.DuplicateSpnReads.Count);
        Assert.Same(row, model.SelectedFinding);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
    });

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedChildPagesPreserveTheSelectedPageAndCanBeRetried(bool originals) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(51, copies: 2);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DuplicateSpn!;
        if (originals)
        {
            panel.LoadRegistrationsCommand.Execute(null);
            await panel.RegistrationReadCompletion;
        }
        var child = originals ? panel.Registrations! : panel.Owners;
        var read = source.DuplicateSpnRead!;
        source.DuplicateSpnRead = (reference, position) =>
        {
            var answer = read(reference, position).Value;
            return Result<SavedDuplicateSpn>.Success(answer with { MatchKey = "HTTP/ANOTHER-SERVICE" });
        };
        child.NextPageCommand.Execute(null);
        await child.ReadCompletion;
        Assert.True(child.HasRefusal);
        Assert.Equal("Page 1", child.PageLabel);
        Assert.Equal(50, originals ? child.Registrations.Count : child.Owners.Count);
        source.DuplicateSpnRead = read;
        child.NextPageCommand.Execute(null);
        await child.ReadCompletion;
        Assert.False(child.HasRefusal);
        Assert.Equal("Page 2", child.PageLabel);
    });

    [Fact]
    public void MissingOriginalRegistrationsAreExplicitAndRetryable() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(2);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DuplicateSpn!;
        var read = source.DuplicateSpnRead!;
        source.DuplicateSpnRead = (_, _) => Result<SavedDuplicateSpn>.Failure(AuditError.Create(ErrorCategory.Evidence,
            "UnavailableOriginalRegistrations", ErrorSeverity.Failed, SavedDuplicateSpn.InvalidDetails, null));
        panel.LoadRegistrationsCommand.Execute(null);
        await panel.RegistrationReadCompletion;
        Assert.Equal(SavedDuplicateSpn.InvalidDetails, panel.RegistrationRefusal);
        Assert.Null(panel.Registrations);
        Assert.Equal(2, panel.Owners.Owners.Count);
        Assert.True(panel.LoadRegistrationsCommand.CanExecute(null));
        source.DuplicateSpnRead = read;
        panel.LoadRegistrationsCommand.Execute(null);
        await panel.RegistrationReadCompletion;
        Assert.False(panel.HasRegistrationRefusal);
        Assert.Equal(2, panel.Registrations!.Registrations.Count);
    });

    [Fact]
    public void ChangingSpnDiscardsLateOriginalsAndDoesNotBlockTheNewAction() => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(2, matches: 2);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DuplicateSpn!;
        var first = source.DuplicateSpnRead!(Assert.Single(model.Findings).Saved.Reference!.Value, null).Value;
        var original = source.DuplicateSpnRead(first.Context.Reference, first.Position with { Kind = DuplicateSpnPageKind.CapturedRegistrations }).Value;
        var released = new TaskCompletionSource<Result<SavedDuplicateSpn>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedDuplicateSpn> answer
            && answer.IsSuccess && answer.Value.Kind == DuplicateSpnPageKind.CapturedRegistrations
                ? Complete(released.Task) : Task.FromResult(value);
        panel.LoadRegistrationsCommand.Execute(null);
        var pending = panel.RegistrationReadCompletion;
        panel.NextPageCommand.Execute(null);
        await panel.ReadCompletion;
        Assert.Equal("SPN 2", panel.SpnLabel);
        Assert.False(panel.IsLoadingRegistrations);
        Assert.True(panel.LoadRegistrationsCommand.CanExecute(null));
        released.SetResult(Result<SavedDuplicateSpn>.Success(original));
        await pending;
        Assert.Null(panel.Registrations);
    });

    [Fact]
    public void LimitationsStaySeparateFromTheKnownDuplicateAndUnloadedOriginals()
    {
        const string limit = "The capture did not record every declared unit as read; forest-wide uniqueness is not established.";
        var (model, _, _) = Model(2, limitations: [limit]);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DuplicateSpn!;
        Assert.True(panel.HasLimitations);
        Assert.Equal(new[] { limit }, panel.Limitations);
        Assert.Null(panel.Registrations);
        Assert.Equal(2, panel.Owners.Owners.Count);
        Assert.Equal(SavedDuplicateSpn.LimitationsNote, panel.LimitationsNote);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ClosedOrExpiredWindowsCannotPublishLateOriginalRegistrations(bool expire) => OneThread.Run(async () =>
    {
        var (model, source, _) = Model(2);
        model.OpenFinding(Assert.Single(model.Findings));
        var details = model.FindingDetails!;
        var panel = details.DuplicateSpn!;
        var position = source.DuplicateSpnReads[0].Reference;
        var first = source.DuplicateSpnRead!(position, null).Value;
        var values = source.DuplicateSpnRead(position, first.Position with { Kind = DuplicateSpnPageKind.CapturedRegistrations }).Value;
        var released = new TaskCompletionSource<Result<SavedDuplicateSpn>>(TaskCreationOptions.RunContinuationsAsynchronously);
        source.CompleteRead = (value, _) => value is Result<SavedDuplicateSpn> ? Complete(released.Task) : Task.FromResult(value);
        panel.LoadRegistrationsCommand.Execute(null);
        var pending = panel.RegistrationReadCompletion;
        Assert.False(pending.IsCompleted);
        if (expire) source.IsCurrent = false; else model.CloseFindingDetails();
        released.SetResult(Result<SavedDuplicateSpn>.Success(values));
        await pending;
        Assert.Null(panel.Registrations);
        Assert.Null(details.DuplicateSpn);
        Assert.Empty(panel.Owners.Owners);
    });

    [Theory]
    [InlineData(900)]
    [InlineData(1300)]
    public void RealWindowShowsExactValuesAndOnlyTheRequestedRegistrationSection(int width) => OnSta(() =>
    {
        var (model, _, _) = Model(2, copies: 2);
        model.OpenFinding(Assert.Single(model.Findings));
        var panel = model.FindingDetails!.DuplicateSpn!;
        var view = FindingsViewTests.View(model, "FindingDetailView.xaml");
        var host = new Window { Content = view, Width = width, Height = 750, Left = -20000, Top = -20000,
            ShowActivated = false, ShowInTaskbar = false };
        try
        {
            host.Show();
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured duplicate service names");
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "HTTP/HOST0:1433/SERVICE");
            Assert.Single(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "This finding's object");
            Assert.DoesNotContain(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured registration values");
            panel.LoadRegistrationsCommand.Execute(null);
            Assert.True(panel.RegistrationReadCompletion.IsCompletedSuccessfully);
            Layout(view, width, 700);
            Assert.Contains(Descendants<TextBlock>(view), value => value.IsVisible && value.Text == "Captured registration values");
            Assert.Contains(Descendants<TextBox>(view), value => value.IsVisible && value.Text == "Captured SPN: http/host0:1433/service");
            Assert.DoesNotContain(Descendants<TextBox>(view), value => value.IsVisible && value.Text.Contains("Original raw proof", StringComparison.Ordinal));
            foreach (var label in new[] { "Previous SPN", "Next SPN", "View captured registrations", "Open affected object", "Close" })
                Assert.Contains(Descendants<Button>(view), value => value.IsVisible && Equals(value.Content, label));
        }
        finally { host.Close(); }
    });

    private static async Task<object> Complete(Task<Result<SavedDuplicateSpn>> task) => await task;

    internal static (AssetsViewModel Model, FakeAssetSource Source, DuplicateSpnEvidence Evidence) Model(int owners, int matches = 1,
        int copies = 1, IReadOnlyList<string>? limitations = null)
    {
        var (evidence, _) = DuplicateSpnReadTests.Fixture(owners, matches, copies);
        if (limitations is not null) evidence = evidence with { Limitations = limitations };
        var source = new FakeAssetSource { FindingsPage = new([DuplicateSpnReadTests.Finding(evidence)], null, 1),
            FilterValues = new([Severity.High], ["SEC-026"], 1) };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\duplicate-spn", false);
        var selected = Assert.Single(model.Findings).Saved;
        source.DuplicateSpnRead = (_, position) => Result<SavedDuplicateSpn>.Success(DuplicateSpnReadTests.Project(evidence, selected, position));
        return (model, source, evidence);
    }
}
