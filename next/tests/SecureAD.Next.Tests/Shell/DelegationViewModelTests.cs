using SecureAD.Evidence;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Shell.ViewModels;
using Xunit;

namespace SecureAD.Next.Tests.Shell;

public sealed class DelegationViewModelTests
{
    private const string Bundle = @"C:\synthetic-runs\delegations";
    private const string Domain = "DC=contoso,DC=com";
    private const string Target = "OU=People," + Domain;
    private static readonly DelegationPrincipal Principal = new(4, "S-1-5-21-1-2-3-1100", "Helpdesk",
        "CN=Helpdesk," + Domain, "contoso.com");

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ASolePrincipalIsSelectedAndEnablesSearchWithoutCancellingItsRead(bool captureWasComplete)
    {
        var (screen, source) = Model();
        source.DelegationPrincipals = new DelegationPrincipalPage([Principal], null, captureWasComplete);
        var readToken = CancellationToken.None;
        source.CompleteRead = (value, token) =>
        {
            readToken = token;
            return Task.FromResult(value);
        };
        screen.DelegationPrincipalSearch = "Helpdesk";

        await screen.FindDelegationPrincipalCommand.ExecuteAsync(null);

        Assert.Same(Assert.Single(screen.DelegationPrincipals), screen.SelectedDelegationPrincipal);
        Assert.True(screen.FindDelegationsCommand.CanExecute(null));
        Assert.False(readToken.IsCancellationRequested);
        Assert.Equal(!captureWasComplete, screen.DelegationPrincipalStatus.Contains(DelegationText.Get("CaptureShort"), StringComparison.Ordinal));
        Assert.Empty(source.DelegationQueries);
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(2, false)]
    [InlineData(1, true)]
    public async Task AmbiguousOrEmptySearchesRequireSelectionAndForgetTheOldIdentity(int matches, bool more)
    {
        var (screen, source) = Model();
        screen.DelegationPrincipalSearch = "Helpdesk";
        await screen.FindDelegationPrincipalCommand.ExecuteAsync(null);
        Assert.NotNull(screen.SelectedDelegationPrincipal);
        var principals = Enumerable.Range(0, matches).Select(index => Principal with
        {
            ObjectId = index + 4,
            Sid = $"S-1-5-21-1-2-3-{1100 + index}",
        }).ToArray();
        source.DelegationPrincipals = new DelegationPrincipalPage(principals,
            more ? new(new string('a', 64), "Helpdesk", 4) : null, true);

        await screen.FindDelegationPrincipalCommand.ExecuteAsync(null);

        Assert.Equal(matches, screen.DelegationPrincipals.Count);
        Assert.Null(screen.SelectedDelegationPrincipal);
        Assert.False(screen.FindDelegationsCommand.CanExecute(null));
    }

    [Fact]
    public async Task OnePrincipalOnTheLastPageIsNotTheOnlyMatch()
    {
        var (screen, source) = Model();
        source.DelegationPrincipals = new DelegationPrincipalPage(
            [Principal, Principal with { ObjectId = 5, Sid = "S-1-5-21-1-2-3-1101" }],
            new(new string('a', 64), "Helpdesk", 5), true);
        screen.DelegationPrincipalSearch = "Helpdesk";
        await screen.FindDelegationPrincipalCommand.ExecuteAsync(null);
        screen.SelectedDelegationPrincipal = screen.DelegationPrincipals[0];
        source.DelegationPrincipals = new DelegationPrincipalPage(
            [Principal with { ObjectId = 6, Sid = "S-1-5-21-1-2-3-1102" }], null, true);

        await screen.NextDelegationPrincipalsCommand.ExecuteAsync(null);

        Assert.Single(screen.DelegationPrincipals);
        Assert.Null(screen.SelectedDelegationPrincipal);
        Assert.False(screen.FindDelegationsCommand.CanExecute(null));
    }

    [Theory]
    [InlineData("cancel")]
    [InlineData("run")]
    [InlineData("pane")]
    [InlineData("text")]
    public async Task CancelledOrSupersededPrincipalSearchCannotSelectALateMatch(string change)
    {
        var (screen, source) = Model();
        var delayed = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? answer = null;
        source.CompleteRead = (value, _) => { answer = value; return delayed.Task; };
        screen.DelegationPrincipalSearch = "Helpdesk";
        var search = screen.FindDelegationPrincipalCommand.ExecuteAsync(null);
        source.CompleteRead = null;
        switch (change)
        {
            case "cancel": screen.CancelDelegationSearchCommand.Execute(null); break;
            case "run": screen.Show(@"C:\synthetic-runs\another", false); break;
            case "pane": screen.Pane = AssetsPane.Objects; break;
            case "text": screen.DelegationPrincipalSearch = "different"; break;
        }
        delayed.SetResult(answer!);
        await search;

        Assert.Null(screen.SelectedDelegationPrincipal);
        Assert.Empty(screen.DelegationPrincipals);
        Assert.False(screen.FindDelegationsCommand.CanExecute(null));
    }

    [Fact]
    public void ArrivalDoesNotSearchOrLoadJudgementAndMakesTheDirectOnlyBoundaryVisible()
    {
        var (screen, source) = Model();

        Assert.True(screen.ShowsDelegationsListing);
        Assert.False(screen.ShowsDirectoryTree);
        Assert.False(screen.IncludeInheritedDelegations);
        Assert.Equal(DelegationPermission.All, screen.DelegationPermissionFilter.Value);
        Assert.Empty(source.Reads);
        Assert.Empty(source.DelegationQueries);
        Assert.False(screen.HasDelegationAnswer);
        Assert.Contains("No search has been completed", screen.DelegationStatus);
        Assert.Contains("Only entries naming the selected SID", DelegationText.Boundary);
        Assert.Contains("Permissions through other groups", DelegationText.Boundary);
        Assert.Contains("not an effective access check", DelegationText.Heading);
    }

    [Fact]
    public async Task SearchUsesChosenIdentityAndFiltersWithoutReadingJudgement()
    {
        var (screen, source) = Model();
        await SelectPrincipal(screen);
        screen.DelegationPermissionFilter = screen.DelegationPermissions.Single(choice => choice.Value == DelegationPermission.ResetPassword);
        screen.IncludeInheritedDelegations = true;

        await screen.FindDelegationsCommand.ExecuteAsync(null);

        var query = Assert.Single(source.DelegationQueries).Query;
        Assert.Equal(new(Principal, DelegationPermission.ResetPassword, true), query);
        Assert.True(screen.HasDelegationAnswer);
        Assert.Equal(Target, Assert.Single(screen.Delegations).RecordedOn);
        Assert.Equal(["DelegationPrincipals", "Delegations"], source.Reads);
        Assert.Equal(0, source.FindingsReads);
        Assert.Empty(source.ControlQueries);
        Assert.Contains("not attempted", screen.DelegationCoverage);
        Assert.Contains("Page 1: 1 recorded entries on this page", screen.DelegationStatus);
    }

    [Fact]
    public async Task CompletedSearchCollapsesToAnEditableSummaryWithoutDiscardingTheAnswer()
    {
        var (screen, source) = Model();
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);

        Assert.False(screen.IsDelegationSearchEditing);
        Assert.False(screen.ShowsDelegationSearchEditor);
        Assert.True(screen.ShowsDelegationSearchSummary);
        Assert.Contains("Helpdesk", screen.DelegationSearchSummary, StringComparison.Ordinal);
        Assert.Contains(DelegationText.Get(screen.IncludeGroupHeldPermissions ? "GroupHeldIncluded" : "DirectOnly"),
            screen.DelegationSearchSummary, StringComparison.Ordinal);

        screen.EditDelegationSearchCommand.Execute(null);

        Assert.True(screen.IsDelegationSearchEditing);
        Assert.True(screen.ShowsDelegationSearchEditor);
        Assert.False(screen.ShowsDelegationSearchSummary);
        Assert.True(screen.HasDelegationAnswer);
        Assert.Single(screen.Delegations);
        Assert.Single(source.DelegationQueries);
    }

    [Fact]
    public async Task DelegationDisplayedPageFilterDoesNotChangeTheSavedAnswer()
    {
        var (screen, source) = Model();
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        Assert.Single(screen.VisibleDelegations);

        screen.DelegationResultSearch = "no displayed match";

        Assert.Empty(screen.VisibleDelegations);
        Assert.True(screen.HasDelegationAnswer);
        Assert.Single(screen.Delegations);
        Assert.Single(source.DelegationQueries);
    }

    [Theory]
    [InlineData("principal")]
    [InlineData("permission")]
    [InlineData("inheritance")]
    [InlineData("search")]
    public async Task ChangingTheQuestionCannotLeaveThePreviousAnswerVisible(string change)
    {
        var (screen, _) = Model();
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        Assert.True(screen.HasDelegationAnswer);
        if (change == "principal") screen.SelectedDelegationPrincipal = new(Principal with { Sid = "S-1-5-21-1-2-3-1200" });
        if (change == "permission") screen.DelegationPermissionFilter = screen.DelegationPermissions[1];
        if (change == "inheritance") screen.IncludeInheritedDelegations = true;
        if (change == "search") screen.DelegationPrincipalSearch = "different";

        Assert.False(screen.HasDelegationAnswer);
        Assert.Empty(screen.Delegations);
        Assert.False(screen.NextDelegationsCommand.CanExecute(null));
        Assert.Contains("No search has been completed", screen.DelegationStatus);
    }

    [Fact]
    public async Task RefusalsNeverBecomeNoMatchingPermissions()
    {
        var (screen, source) = Model();
        source.Delegations = (_, _) => Result<DelegationPage>.Failure(AuditError.Create(ErrorCategory.Evidence,
            "SyntheticRefusal", ErrorSeverity.Failed, "Synthetic corrupt descriptor", Bundle));
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);

        Assert.True(screen.HasViewRefusal);
        Assert.Contains("Synthetic corrupt descriptor", screen.ViewRefusal!.Detail);
        Assert.False(screen.HasDelegationAnswer);
        Assert.DoesNotContain("No matching", screen.DelegationStatus);
    }

    [Fact]
    public async Task EmptyResultsStillStateCaptureGapsAndExcludedScope()
    {
        var (screen, source) = Model();
        source.Delegations = (_, _) => Result<DelegationPage>.Success(new([], null,
            new(false, ["dnsNode"], 2, 5, 1, 3)));
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);

        Assert.True(screen.HasDelegationAnswer);
        Assert.Contains("No matching recorded entries", screen.DelegationStatus);
        Assert.Contains("group-derived permissions", screen.DelegationStatus);
        Assert.Contains("2 objects with unreadable", screen.DelegationCoverage);
        Assert.Contains("5 objects with permissions not attempted", screen.DelegationCoverage);
        Assert.Contains("1 incomplete descriptors", screen.DelegationCoverage);
        Assert.Contains("dnsNode", screen.DelegationCoverage);
        Assert.Contains("did not read all declared", screen.DelegationCoverage);
    }

    [Fact]
    public async Task CancelledAndLateAnswersCannotReappear()
    {
        var (screen, source) = Model();
        await SelectPrincipal(screen);
        var delayed = new TaskCompletionSource<object>(TaskCreationOptions.RunContinuationsAsynchronously);
        object? captured = null;
        source.CompleteRead = (value, _) => { captured = value; return delayed.Task; };
        var search = screen.FindDelegationsCommand.ExecuteAsync(null);
        Assert.True(screen.IsLoading);
        Assert.True(screen.CancelDelegationSearchCommand.CanExecute(null));
        screen.CancelDelegationSearchCommand.Execute(null);
        delayed.SetResult(captured!);
        await search;

        Assert.False(screen.HasDelegationAnswer);
        Assert.False(screen.IsLoading);
        Assert.Empty(screen.Delegations);
        Assert.Contains("cancelled", screen.DelegationStatus);
    }

    [Fact]
    public async Task ChangedProtectedLifetimeIsRefusedBeforeAnyAnswerIsShown()
    {
        var (screen, source) = Model();
        await SelectPrincipal(screen);
        source.IsCurrent = false;
        await screen.FindDelegationsCommand.ExecuteAsync(null);

        Assert.True(screen.HasViewRefusal);
        Assert.False(screen.HasDelegationAnswer);
        Assert.Empty(screen.Delegations);
    }

    [Fact]
    public async Task PagerUsesBoundContinuationsAndPreviousReturnsTheSameQuestion()
    {
        var (screen, source) = Model();
        DelegationPageMark? next = null;
        source.Delegations = (query, after) =>
        {
            next ??= new(new string('a', 64), query, 8, 9, 99);
            return Result<DelegationPage>.Success(new([Entry(after is null ? 0 : 100)],
                after is null ? next : null, Coverage()));
        };
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        Assert.False(screen.PreviousDelegationsCommand.CanExecute(null));
        Assert.True(screen.NextDelegationsCommand.CanExecute(null));
        await screen.NextDelegationsCommand.ExecuteAsync(null);
        Assert.Equal(next, source.DelegationQueries[1].After);
        Assert.Contains("Page 2", screen.DelegationStatus);
        Assert.False(screen.NextDelegationsCommand.CanExecute(null));
        await screen.PreviousDelegationsCommand.ExecuteAsync(null);

        Assert.Null(source.DelegationQueries[2].After);
        Assert.Contains("Page 1", screen.DelegationStatus);
        Assert.Equal(0, screen.Delegations[0].Source.Entry.Ordinal);
    }

    [Fact]
    public async Task PermissionDetailsOpenTheActualTargetAndReturningDoesNotResearch()
    {
        var (screen, source) = Model();
        source.Attributes = FakeAssetSource.CapturedObject(Target, "organizationalUnit");
        source.Permissions = new(Target, DescriptorAvailability.Read, null, null,
            DaclState.Present, DaclCompleteness.Complete, true, false, [Entry().Entry], []);
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        screen.SelectedDelegation = screen.Delegations[0];
        screen.OpenDelegationDetailsCommand.Execute(null);
        await screen.ReadCompletion;

        Assert.Equal(Target, source.OpenedObject);
        Assert.True(screen.HasOpenObject);
        Assert.Equal(ObjectSectionCatalog.Permissions, screen.Opened!.Selected!.Key);
        Assert.True(screen.ShowsDelegationsListing);
        screen.CloseObject();
        Assert.True(screen.ShowsDelegationsListing);
        Assert.True(screen.HasDelegationAnswer);
        Assert.Single(source.DelegationQueries);
    }

    [Fact]
    public async Task RunChangesForgetPrincipalsAndResultRows()
    {
        var (screen, _) = Model();
        await SelectPrincipal(screen);
        await screen.FindDelegationsCommand.ExecuteAsync(null);
        screen.Show(@"C:\synthetic-runs\another", false);

        Assert.Empty(screen.DelegationPrincipals);
        Assert.Null(screen.SelectedDelegationPrincipal);
        Assert.Empty(screen.Delegations);
        Assert.False(screen.HasDelegationAnswer);
    }

    [Theory]
    [InlineData("AccessAllowed", "Allow")]
    [InlineData("AccessDeniedObject", "Deny")]
    [InlineData("AccessAllowedCallback", "Conditional Allow; condition not evaluated")]
    [InlineData("AccessDeniedCallbackObject", "Conditional Deny; condition not evaluated")]
    [InlineData("UnknownType", "Unsupported entry type: UnknownType")]
    public void RowTypesNeverTurnDeniesConditionsOrUnsupportedEntriesIntoProvenGrants(string type, string expected)
    {
        var entry = Entry();
        var row = new DelegationRowViewModel(entry with
        {
            Entry = entry.Entry with { AceType = type, IsInherited = true, AccessMask = 0x10000000 },
            ScopeQualification = "Unresolved user scope",
        }, PermissionVocabulary.Shipped);

        Assert.Equal(expected, row.EntryType);
        Assert.Equal("Inherited", row.Inheritance);
        Assert.Contains("shorthand - may not be enforced", row.Permission);
        Assert.Contains("Unresolved user scope", row.AppliesTo);
        Assert.Contains("0x10000000", row.Detail);
        Assert.Contains("Original entry position", row.Detail);
    }

    internal static (AssetsViewModel Screen, FakeAssetSource Source) Model()
    {
        var source = new FakeAssetSource
        {
            Tree = new([new(Domain, "contoso", null, TreeNodeOrigin.Partition, [])], []),
            DelegationPrincipals = Result<DelegationPrincipalPage>.Success(new([Principal], null, true)),
            Delegations = (_, _) => Result<DelegationPage>.Success(new([Entry()], null, Coverage())),
        };
        var screen = new AssetsViewModel(source) { Pane = AssetsPane.Delegations, IncludeGroupHeldPermissions = false };
        screen.Show(Bundle, false);
        return (screen, source);
    }

    internal static async Task SelectPrincipal(AssetsViewModel screen)
    {
        screen.DelegationPrincipalSearch = "Helpdesk";
        await screen.FindDelegationPrincipalCommand.ExecuteAsync(null);
        screen.SelectedDelegationPrincipal = Assert.Single(screen.DelegationPrincipals);
    }

    private static DelegationCoverage Coverage() => new(true, [], 0, 4, 0, 0);
    private static DelegationEntry Entry(int ordinal = 0) => new(Target, "contoso.com", 8,
        new(ordinal, "AccessAllowed", new(Principal.Sid, Principal.Name, Principal.DistinguishedName, Principal.DomainFqdn, null, null, null),
            0x100, "00299570-246d-11d0-a768-00aa006e0529", null, false, 0, 0, true, false, []),
        DaclCompleteness.Complete, null);
}
