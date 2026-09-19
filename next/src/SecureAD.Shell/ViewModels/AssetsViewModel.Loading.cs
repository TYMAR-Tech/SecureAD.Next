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
        ListingScope? Scope, int Page, FindingsQuery? Findings);

    private readonly Dictionary<AssetsPane, (ListingQuestion Question, Func<bool> IsCurrent)> _pages = [];

    private ListingQuestion Question() => new(Pane, BundlePath!,
        Pane == AssetsPane.Rules ? null : Selected?.DistinguishedName,
        Pane is AssetsPane.Objects or AssetsPane.Laps ? Scope : null,
        Pane == AssetsPane.Objects ? PageNumber : 1,
        Pane == AssetsPane.Findings ? FindingsAsked() : null);

    private void LoadVisible()
    {
        if (!_resetting) ReadCompletion = LoadVisibleAsync();
    }

    private async Task LoadVisibleAsync()
    {
        if (!_active || _resetting || !HasLooked || _captureIsRunning || BundlePath is null || HasOpenObject)
            return;

        var question = Question();
        ClearListing(question.Pane);
        if (question.Pane is AssetsPane.Objects or AssetsPane.Laps && question.Container is null)
        {
            CancelRead();
            Announce();
            return;
        }

        switch (question.Pane)
        {
            case AssetsPane.Objects:
                await ReadViewAsync(question.Bundle,
                    reader => reader.ListObjects(question.Bundle, question.Container!, question.Scope!.Value, question.Page),
                    (page, current) =>
                    {
                        foreach (var row in page.Objects) Objects.Add(new ListedObjectViewModel(row));
                        Total = page.Total;
                        Shortfall = page.ObjectsAreComplete ? null : page.Shortfall;
                        RememberPage(question, current);
                    }, saved: false);
                break;
            case AssetsPane.Laps:
                await ReadViewAsync(question.Bundle,
                    reader => reader.ListLapsComputers(question.Bundle, question.Container!, question.Scope!.Value, 1),
                    (page, current) =>
                    {
                        foreach (var row in page.Computers) LapsComputers.Add(new LapsComputerViewModel(row));
                        foreach (var state in Enum.GetValues<LapsManagement>())
                            LapsCounts.Add(new LapsCountViewModel(state, page.CountOf(state)));
                        LapsTotal = page.Total;
                        LapsShortfall = page.ComputersAreComplete ? null : page.Shortfall;
                        RememberPage(question, current);
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
                            return Result<(FindingsPage Page, FindingsFilterValues? Filters)>.Failure(choices.Error);
                        filters = choices.Value;
                    }
                    var page = reader.ReadFindings(question.Bundle, question.Findings!);
                    return page.IsSuccess
                        ? Result<(FindingsPage Page, FindingsFilterValues? Filters)>.Success((page.Value, filters))
                        : Result<(FindingsPage Page, FindingsFilterValues? Filters)>.Failure(page.Error);
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
                    RememberPage(question, current);
                }, saved: true);
                break;
            case AssetsPane.Rules:
                await ReadViewAsync(question.Bundle, reader => reader.ReadRuleExecutions(question.Bundle),
                    (read, current) =>
                    {
                        var executions = read.Executions.ToDictionary(row => row.RuleId, StringComparer.OrdinalIgnoreCase);
                        foreach (var rule in RuleCatalogue.All)
                            RuleRows.Add(new RuleRowViewModel(rule.Definition.Id, rule.Definition,
                                executions.GetValueOrDefault(rule.Definition.Id)));
                        var shipped = RuleCatalogue.All.Select(rule => rule.Definition.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
                        foreach (var execution in executions.Values.Where(row => !shipped.Contains(row.RuleId)))
                            RuleRows.Add(new RuleRowViewModel(execution.RuleId, null, execution));
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
            if (revision != _revision || pending.IsCancellationRequested || !_active) return;
            IsLoading = false;
            if (!result.Answer.IsSuccess)
                RefuseView(result.Answer.Error.Description, tree);
            else if (!result.Current())
                RefuseView(SavedPathText.Get("GenerationChanged"), tree);
            else
                apply(result.Answer.Value, result.Current);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _revision && !pending.IsCancellationRequested && _active)
                RefuseView(error.Message, tree);
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
        else if (Pane == AssetsPane.Rules) RulesRefusal = ViewRefusal;
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
        Opened?.Suspend();
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
            case AssetsPane.Objects:
                Objects.Clear();
                Total = 0;
                Shortfall = null;
                break;
            case AssetsPane.Findings:
                SelectedFinding = null;
                Findings.Clear();
                FindingsRefusal = null;
                NothingWasFound = false;
                _findingsFrom = null;
                break;
            case AssetsPane.Laps:
                LapsComputers.Clear();
                LapsCounts.Clear();
                LapsRefusal = null;
                LapsTotal = 0;
                LapsShortfall = null;
                break;
            case AssetsPane.Rules:
                RuleRows.Clear();
                RulesRefusal = null;
                break;
        }
    }
}
