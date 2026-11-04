using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class FindingNavigationTests
{
    [Fact]
    public void OpeningAndClosingPreserveTheExactGridQuestionAndSelection()
    {
        var (model, source) = Model();
        model.SeverityFilter = "High";
        model.RuleFilter = "SEC-022";
        model.NextFindingsCommand.Execute(null);
        var selected = model.Findings[1];
        model.SelectedFinding = selected;
        var rows = model.Findings.ToArray();
        var page = model.FindingsPageNumber;
        var scope = model.Selected;
        var reads = source.FindingsReads;
        model.OpenFinding(selected);
        Assert.True(model.FindingDetails!.ReadCompletion.IsCompletedSuccessfully);
        Assert.Equal(selected.Saved, model.FindingDetails.Finding!.Saved);
        Assert.False(model.HasObjectPresentation);
        Assert.Equal((selected.Saved.Reference!.Value, false), Assert.Single(source.FindingSelections));
        model.CloseFindingDetails();
        Assert.False(model.HasFindingPresentation);
        Assert.Same(selected, model.SelectedFinding);
        Assert.Equal(rows, model.Findings.ToArray());
        Assert.Equal(page, model.FindingsPageNumber);
        Assert.Same(scope, model.Selected);
        Assert.Equal("High", model.SeverityFilter);
        Assert.Equal("SEC-022", model.RuleFilter);
        Assert.Equal(reads, source.FindingsReads);
    }

    [Fact]
    public async Task ObjectEntryAndAffectedObjectActionReuseTheExistingObjectAndSection()
    {
        var (model, source) = Model();
        var selected = model.Findings[1];
        source.Attributes = FakeAssetSource.CapturedObject(selected.DistinguishedName, "user") with { ObjectGuid = selected.Saved.ObjectGuid };
        model.OpenFinding(selected);
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        var opened = Assert.IsType<ObjectViewModel>(model.Opened);
        opened.Show(ObjectSectionCatalog.Findings);
        await opened.ReadCompletion;
        var section = Assert.IsType<FindingsSectionViewModel>(opened.Content);
        var objectRow = section.Findings[1];
        section.SelectedFinding = objectRow;
        model.CloseFindingDetails();
        model.OpenFinding(objectRow);
        Assert.Equal(objectRow.Saved, model.FindingDetails!.Finding!.Saved);
        var reads = source.Reads.ToArray();
        model.OpenAffectedObjectCommand.Execute(null);
        Assert.Same(opened, model.Opened);
        Assert.Same(section, opened.Content);
        Assert.Same(objectRow, section.SelectedFinding);
        Assert.Equal(reads, source.Reads.ToArray());
        model.CloseFindingDetails();
        Assert.Same(section, opened.Content);
    }

    [Theory]
    [InlineData("reference")]
    [InlineData("object")]
    [InlineData("subject")]
    [InlineData("rule")]
    public void ASubstitutedSavedAnswerIsRefused(string changed)
    {
        var (model, source) = Model();
        var selected = model.Findings[0];
        source.SelectedFindingRead = (_, _) => Result<FindingListItem>.Success(changed switch
        {
            "reference" => selected.Saved with { Reference = new(Guid.NewGuid(), 1) },
            "object" => selected.Saved with { ObjectGuid = Guid.NewGuid() },
            "subject" => selected.Saved with { Subject = new(FindingSubjectKind.Account, "another account") },
            _ => selected.Saved with { RuleId = "SEC-028" },
        });
        model.OpenFinding(selected);
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.False(model.FindingDetails.HasFinding);
        Assert.Contains("does not match", model.FindingDetails.Refusal, StringComparison.Ordinal);
        Assert.False(model.HasObjectPresentation);
        Assert.Equal(2, model.Findings.Count);
    }

    [Fact]
    public void MissingSavedIdentityIsAnExplicitRefusal()
    {
        var (model, source) = Model();
        model.OpenFinding(new FindingRowViewModel(model.Findings[0].Saved with { Reference = null }, source.CaptureReadValidity()));
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.Contains("no saved identity", model.FindingDetails.Refusal, StringComparison.Ordinal);
        Assert.Empty(source.FindingSelections);
    }

    [Fact]
    public void MembershipIsNotLoadedOrFormattedUntilRequested()
    {
        var (model, source) = Model(membership: true);
        var selected = model.Findings[0];
        Assert.True(selected.HasMembershipEvidence);
        Assert.Null(selected.Saved.Membership);
        Assert.Empty(source.FindingSelections);
        model.OpenFinding(selected);
        var details = model.FindingDetails!;
        Assert.True(details.HasFinding);
        Assert.Null(details.MembershipDetails);
        Assert.Null(details.MembershipCompleteness);
        Assert.False(Assert.Single(source.FindingSelections).Membership);
        details.LoadMembershipCommand.Execute(null);
        Assert.True(details.ReadCompletion.IsCompletedSuccessfully);
        Assert.Equal(new[] { false, true }, source.FindingSelections.Select(read => read.Membership));
        Assert.Contains("routes were not derived", details.MembershipCompleteness, StringComparison.Ordinal);
        Assert.Contains("not every possible path", details.MembershipDetails, StringComparison.Ordinal);
        Assert.Null(selected.Saved.Membership);
        Assert.False(details.LoadMembershipCommand.CanExecute(null));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ReadFailureRemainsVisibleAndDoesNotTurnIntoAnEmptyResult(bool membership)
    {
        var (model, source) = Model(membership);
        var selected = model.Findings[0];
        if (membership) model.OpenFinding(selected);
        source.SelectedFindingRead = (_, _) => Result<FindingListItem>.Failure(AuditError.Create(
            ErrorCategory.Shell, "ExpectedRefusal", ErrorSeverity.Failed, "Saved facts are unavailable.", "test"));
        if (membership) model.FindingDetails!.LoadMembershipCommand.Execute(null);
        else model.OpenFinding(selected);
        var details = model.FindingDetails!;
        Assert.Equal("Saved facts are unavailable.", membership ? details.MembershipRefusal : details.Refusal);
        Assert.Equal(membership, details.HasFinding);
        Assert.Null(details.MembershipDetails);
        Assert.Equal(2, model.Findings.Count);
    }

    [Theory]
    [InlineData(false, "close")]
    [InlineData(false, "replace")]
    [InlineData(false, "run")]
    [InlineData(true, "close")]
    [InlineData(true, "replace")]
    [InlineData(true, "run")]
    public async Task LateAnswersCannotReappearAfterCloseReplacementOrRunChange(bool membership, string action)
    {
        var (model, source) = Model(membership);
        if (membership) model.OpenFinding(model.Findings[0]);
        var release = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? answer = null;
        CancellationToken observed = default;
        source.CompleteRead = (value, token) =>
        {
            if (value is not Result<FindingDetailContent>) return Task.FromResult(value);
            answer = value;
            observed = token;
            return release.Task;
        };
        if (membership) model.FindingDetails!.LoadMembershipCommand.Execute(null);
        else model.OpenFinding(model.Findings[0]);
        var old = model.FindingDetails!;
        var pending = old.ReadCompletion;
        Assert.NotNull(answer);
        source.CompleteRead = null;
        if (action == "close") model.CloseFindingDetails();
        else if (action == "run") model.Clear();
        else model.OpenFinding(model.Findings[1]);
        Assert.True(observed.IsCancellationRequested);
        release.SetResult(answer);
        await pending;
        Assert.False(old.HasFinding);
        Assert.Null(old.MembershipDetails);
        if (action == "replace") Assert.Equal(model.Findings[1].Saved, model.FindingDetails!.Finding!.Saved);
        else Assert.False(model.HasFindingPresentation);
    }

    [Fact]
    public void ChangedGenerationIsRefusedBeforePublishingARead()
    {
        var (model, _) = Model();
        var selected = model.Findings[0];
        var current = true;
        Task<Result<FindingDetailContent>> Read(bool membership, CancellationToken token)
        {
            current = false;
            return Task.FromResult(Result<FindingDetailContent>.Success(FindingDetailContent.FromSaved(selected.Saved)));
        }
        var details = new FindingDetailViewModel(selected, Read, () => current);
        Assert.True(details.HasRefusal);
        Assert.False(details.HasFinding);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SuspendedDetailsRejectLateAnswersEvenWhenTheReaderIgnoresCancellation(bool membership)
    {
        var (model, source) = Model(membership);
        var selected = model.Findings[0];
        var content = FindingDetailContent.FromSaved(source.ReadSelectedFinding(
            @"C:\offline-fixture\finding-navigation", selected.Saved.Reference!.Value, membership).Value);
        var release = new TaskCompletionSource<Result<FindingDetailContent>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var delay = !membership;
        var details = new FindingDetailViewModel(selected, (_, _) => delay ? release.Task
            : Task.FromResult(Result<FindingDetailContent>.Success(FindingDetailContent.FromSaved(selected.Saved))), () => true);
        if (membership)
        {
            Assert.True(details.HasFinding);
            delay = true;
            details.LoadMembershipCommand.Execute(null);
        }
        var pending = details.ReadCompletion;
        Assert.False(pending.IsCompleted);
        details.Suspend();
        release.SetResult(Result<FindingDetailContent>.Success(content));
        await pending;
        Assert.False(details.HasFinding);
        Assert.Null(details.MembershipDetails);
        Assert.Null(details.MembershipCompleteness);
    }

    [Fact]
    public void AffectedObjectNavigationRefusesAnExpiredGeneration()
    {
        var (model, source) = Model();
        model.OpenFinding(model.Findings[0]);
        source.IsCurrent = false;
        model.OpenAffectedObjectCommand.Execute(null);
        Assert.False(model.HasObjectPresentation);
        Assert.True(model.FindingDetails!.HasRefusal);
        Assert.False(model.FindingDetails.HasFinding);
    }

    [Fact]
    public async Task AffectedObjectNavigationRefusesAReusedNameWithAnotherObjectIdentity()
    {
        var (model, source) = Model();
        var selected = model.Findings[0];
        source.Attributes = FakeAssetSource.CapturedObject(selected.DistinguishedName, "user") with { ObjectGuid = Guid.NewGuid() };
        model.OpenFinding(selected);
        model.OpenAffectedObjectCommand.Execute(null);
        await model.ObjectReadCompletion;
        Assert.False(model.HasOpenObject);
        Assert.True(model.HasObjectRefusal);
        Assert.Contains("saved object identity", model.ObjectRefusal!.Detail, StringComparison.Ordinal);
        Assert.True(model.FindingDetails!.HasFinding);
    }

    private static (AssetsViewModel Model, FakeAssetSource Source) Model(bool membership = false)
    {
        var first = ObjectFindingsPagingTests.Finding(1);
        if (membership) first = first with
        {
            RuleId = "SEC-021",
            Evidence = new KerberoastableAccountEvidence("S-1-5-21-11-22-33-1100", ["HTTP/service"], 512)
            { MembershipRoutes = MembershipRouteSummary.NotDerived },
        };
        var source = new FakeAssetSource
        {
            FindingsPage = new([first, ObjectFindingsPagingTests.Finding(2)],
                new FindingsPageMark(3, first.RuleId, first.DistinguishedName, 2), 1),
            FilterValues = new([Severity.High], [first.RuleId], 1),
        };
        var model = new AssetsViewModel(source) { Pane = AssetsPane.Findings };
        model.Show(@"C:\offline-fixture\finding-navigation", false);
        return (model, source);
    }
}
