using System.IO;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    private sealed record ListingQuestion(AssetsPane Pane, string Bundle, string? Container,
        ListingScope? Scope, int Page, FindingsQuery? Findings, string? Search, GroupInventoryQuery? Groups, LapsQuery? Laps);

    private readonly Dictionary<AssetsPane, (ListingQuestion Question, Func<bool> IsCurrent)> _pages = [];
    private readonly Stack<ObjectPageMark?> _objectPages = [];
    private ObjectPageMark? _objectNext;

    private void ResetObjectPaging()
    {
        _objectPages.Clear();
        _objectNext = null;
        PageNumber = 1;
    }

    private ListingQuestion Question() => new(Pane, BundlePath!,
        Pane is AssetsPane.Delegations or AssetsPane.Tier0 || IsObjectSearch ? null : Selected?.DistinguishedName,
        Pane is AssetsPane.Objects or AssetsPane.Laps && !IsObjectSearch ? Scope : null,
        Pane == AssetsPane.Objects ? IsObjectSearch ? _objectSearchBack.Count + 1 : PageNumber : Pane == AssetsPane.Groups ? _groupBack.Count + 1 : Pane == AssetsPane.Tier0 ? _tier0Back.Count + 1 : Pane == AssetsPane.Laps ? LapsPageNumber : 1,
        Pane == AssetsPane.Findings ? FindingsAsked() : null,
        IsObjectSearch ? _objectSearchQuery : null, Pane == AssetsPane.Groups ? GroupQuestion() : null,
        Pane == AssetsPane.Laps && Selected is not null ? LapsQuestion(Selected.DistinguishedName) : null);

    private void LoadVisible()
    {
        if (!_resetting) ReadCompletion = LoadVisibleAsync();
    }

    private async Task LoadVisibleAsync()
    {
        if (!_active || _resetting || !HasLooked || _captureIsRunning || BundlePath is null)
            return;

        var question = Question();
        ClearListing(question.Pane);
        if (question.Pane is AssetsPane.Objects or AssetsPane.Laps && question.Container is null && question.Search is null)
        {
            CancelRead();
            Announce();
            return;
        }

        switch (question.Pane)
        {
            case AssetsPane.Tier0:
                await LoadTier0Async(question);
                break;
            case AssetsPane.Groups:
                await LoadGroupsAsync(question);
                break;
            case AssetsPane.Delegations:
                CancelRead();
                Announce();
                break;
            case AssetsPane.Objects:
                if (question.Search is not null)
                {
                    await ReadObjectSearchPageAsync(_objectSearchAfter, 0);
                    break;
                }
                var objectAfter = _objectPages.TryPeek(out var objectPosition) ? objectPosition : null;
                await ReadViewAsync(question.Bundle,
                    reader => reader.ListObjects(question.Bundle, question.Container!, question.Scope!.Value, objectAfter),
                    (page, current) =>
                    {
                        foreach (var row in page.Objects) Objects.Add(new ListedObjectViewModel(row));
                        Total = page.Total;
                        Shortfall = page.ObjectsAreComplete ? null : page.Shortfall;
                        _objectNext = page.Next;
                        RememberPage(question, current);
                    }, saved: false);
                break;
            case AssetsPane.Laps:
                var lapsAfter = _lapsBack.TryPeek(out var previous) ? previous : null;
                await ReadViewAsync(question.Bundle,
                    reader => reader.ListLapsComputers(question.Bundle, question.Laps!, lapsAfter),
                    (page, current) =>
                    {
                        foreach (var row in page.Computers) LapsComputers.Add(new LapsComputerViewModel(row));
                        foreach (var state in Enum.GetValues<LapsManagement>())
                            LapsCounts.Add(new LapsCountViewModel(state, page.CountOf(state)));
                        SelectedLapsComputer = LapsComputers.FirstOrDefault();
                        _lapsNext = page.Next;
                        LapsTotal = page.Total;
                        LapsShortfall = page.ComputersAreComplete ? null : page.Shortfall;
                        RememberPage(question, current);
                        AnnounceLaps();
                    }, saved: true);
                break;
            case AssetsPane.Findings:
                var needsFilters = _filterValidity?.Invoke() != true;
                if (needsFilters)
                {
                    _resetting = true;
                    Severities.Clear();
                    Rules.Clear();
                    _resetting = false;
                    _filterValidity = null;
                }
                await ReadViewAsync(question.Bundle, reader =>
                {
                    FindingsFilterValues? filters = null;
                    if (needsFilters)
                    {
                        var choices = reader.ReadFindingsFilterValues(question.Bundle);
                        if (!choices.IsSuccess)
                            return Result<(FindingListPage Page, FindingsFilterValues? Filters, Tier0FindingSummary? Summary)>.Failure(choices.Error);
                        filters = choices.Value;
                    }
                    var page = reader.ReadFindingsList(question.Bundle, question.Findings!);
                    if (!page.IsSuccess)
                        return Result<(FindingListPage Page, FindingsFilterValues? Filters, Tier0FindingSummary? Summary)>.Failure(page.Error);
                    var summary = reader.ReadTier0FindingSummary(question.Bundle);
                    return summary.IsSuccess
                        ? Result<(FindingListPage Page, FindingsFilterValues? Filters, Tier0FindingSummary? Summary)>.Success((page.Value, filters, summary.Value))
                        : Result<(FindingListPage Page, FindingsFilterValues? Filters, Tier0FindingSummary? Summary)>.Failure(summary.Error);
                }, (read, current) =>
                {
                    if (read.Filters is { } filters)
                    {
                        _resetting = true;
                        Severities.Add(Any);
                        Rules.Add(Any);
                        foreach (var severity in filters.Severities) Severities.Add(severity.ToString());
                        foreach (var rule in filters.Rules) Rules.Add(rule);
                        _filterValidity = current;
                        _resetting = false;
                    }
                    foreach (var row in read.Page.Findings) Findings.Add(new FindingRowViewModel(row));
                    _findingsFrom = read.Page.Next;
                    NothingWasFound = read.Page.NothingWasFound;
                    Tier0SummaryText = SavedPathText.Summary(read.Summary);
                    RememberPage(question, current);
                }, saved: true);
                break;
        }
    }

    private void RememberPage(ListingQuestion question, Func<bool> current)
    {
        _pages[question.Pane] = (question, current);
        _listingReady = true;
    }

    private async Task ReadViewAsync<T>(string bundle, Func<IAssetReader, Result<T>> read,
        Action<T, Func<bool>> apply, bool saved, bool tree = false)
    {
        CancelRead();
        using var navigation = NavigationDiagnostics.Begin(bundle,
            tree ? "open directory tree" : saved ? $"read saved {Pane}" : $"read captured {Pane}");
        var revision = _revision;
        var pending = new CancellationTokenSource();
        _pending = pending;
        ViewRefusal = null;
        IsLoading = true;
        LoadingText = NavigationText.Get(saved ? "SavedLoading" : "CapturedLoading");
        Announce();
        AnnounceFindings();
        try
        {
            var result = await _assets.ReadAsync(bundle, (reader, token) =>
            {
                var answer = read(reader);
                token.ThrowIfCancellationRequested();
                return (Answer: answer, Current: reader.CaptureReadValidity());
            }, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested || !_active)
            {
                navigation.Complete("cancelled", null);
                return;
            }
            IsLoading = false;
            if (!result.Answer.IsSuccess)
            {
                RefuseView(result.Answer.Error.Description, tree);
                navigation.Complete("refused", result.Answer.Error.Code);
            }
            else if (!result.Current())
            {
                RefuseView(SavedPathText.Get("GenerationChanged"), tree);
                navigation.Complete("refused", "generation changed");
            }
            else
            {
                apply(result.Answer.Value, result.Current);
                navigation.Complete("success", null);
            }
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested)
        {
            navigation.Complete("cancelled", null);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidDataException or InvalidOperationException or ArgumentException
            or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _revision && !pending.IsCancellationRequested && _active)
            {
                RefuseView(error.Message, tree);
                navigation.Complete("refused", error.GetType().Name);
            }
        }
        finally
        {
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                IsLoading = false;
                Announce();
                AnnounceFindings();
            }
            pending.Dispose();
        }
    }

    private void RefuseView(string reason, bool tree = false)
    {
        _listingReady = false;
        ViewRefusal = new Notice(NavigationText.Get("Refused"), reason);
        if (tree) Refusal = ViewRefusal;
        else if (Pane == AssetsPane.Findings) FindingsRefusal = ViewRefusal;
        else if (Pane == AssetsPane.Laps) LapsRefusal = ViewRefusal;
    }

    private void CancelRead()
    {
        _revision++;
        var pending = _pending;
        _pending = null;
        pending?.Cancel();
        IsLoading = false;
    }

    /// <summary>Stops Assets work before another shell section becomes visible.</summary>
    public void Suspend()
    {
        _active = false;
        CancelRead();
        ClearListings();
        ViewRefusal = null;
        Announce();
        AnnounceFindings();
    }

    private void ClearListings()
    {
        foreach (var pane in Enum.GetValues<AssetsPane>()) ClearListing(pane);
    }

    private void ClearListing(AssetsPane pane)
    {
        _pages.Remove(pane);
        if (pane == Pane) _listingReady = false;
        switch (pane)
        {
            case AssetsPane.Tier0:
                Tier0Objects.Clear();
                Tier0OverviewStatus = Tier0OverviewCoverage = Tier0ObjectLimitation = "";
                Tier0ClassifiedCount = Tier0OtherSupportedCount = Tier0UnresolvedCount = Tier0UnassessedCount = 0;
                Tier0HasLimitations = false;
                break;
            case AssetsPane.Groups:
                Groups.Clear();
                GroupTotal = 0;
                GroupQualification = null;
                break;
            case AssetsPane.Delegations:
                ClearDelegationSearch();
                break;
            case AssetsPane.Objects:
                Objects.Clear();
                Total = 0;
                Shortfall = null;
                break;
            case AssetsPane.Findings:
                Tier0SummaryText = "";
                SelectedFinding = null;
                Findings.Clear();
                FindingsRefusal = null;
                NothingWasFound = false;
                _findingsFrom = null;
                break;
            case AssetsPane.Laps:
                LapsComputers.Clear();
                LapsCounts.Clear();
                _lapsNext = null;
                SelectedLapsComputer = null;
                LapsRefusal = null;
                LapsTotal = 0;
                LapsShortfall = null;
                AnnounceLaps();
                break;
        }
    }
}
