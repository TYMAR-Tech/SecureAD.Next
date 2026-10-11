using System.Collections.ObjectModel;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using SecureAD.Judgement;
using SecureAD.Shell.Services;

namespace SecureAD.Shell.ViewModels;

/// <summary>Saved whole-run rule outcomes, independent of directory navigation.</summary>
internal sealed partial class RulesViewModel(IAssetSource assets) : ObservableObject
{
    private CancellationTokenSource? _pending;
    private long _revision;
    [ObservableProperty] private string? _bundlePath;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private Notice? _rulesRefusal;
    [ObservableProperty] private bool _hasResults;
    [ObservableProperty] private RuleRowViewModel? _selectedRule;
    [ObservableProperty] private string _ruleSearchText = "";
    [ObservableProperty] private string _ruleAssessmentFilter = "All";
    [ObservableProperty] private string _ruleSeverityFilter = "All";
    public ObservableCollection<RuleRowViewModel> RuleRows { get; } = [];
    public ObservableCollection<RuleRowViewModel> VisibleRuleRows { get; } = [];
    public ObservableCollection<string> RuleSeverityChoices { get; } = ["All"];
    public IReadOnlyList<string> RuleAssessmentChoices { get; } =
        ["All", "Completed", "Incomplete", "Failed", "Not run"];
    public Task ReadCompletion { get; private set; } = Task.CompletedTask;
    public bool HasNoRun => BundlePath is null;
    public bool HasRulesRefusal => RulesRefusal is not null;

    public void Show(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        Suspend();
        BundlePath = path;
        RulesRefusal = null;
        assets.SelectRun(path);
        IsLoading = true;
        var pending = new CancellationTokenSource();
        _pending = pending;
        ReadCompletion = LoadAsync(path, pending, _revision);
        Announce();
    }

    private async Task LoadAsync(string path, CancellationTokenSource pending, long revision)
    {
        using var navigation = NavigationDiagnostics.Begin(path, "read saved Rules");
        try
        {
            var result = await assets.ReadAsync(path, (reader, token) =>
            {
                token.ThrowIfCancellationRequested();
                var answer = reader.ReadRuleExecutions(path);
                token.ThrowIfCancellationRequested();
                return (Answer: answer, Current: reader.CaptureReadValidity());
            }, pending.Token);
            if (revision != _revision || pending.IsCancellationRequested)
            {
                navigation.Complete("cancelled", null);
                return;
            }
            if (!result.Answer.IsSuccess)
            {
                RulesRefusal = new(NavigationText.Get("Refused"), result.Answer.Error.Description);
                navigation.Complete("refused", result.Answer.Error.Code);
                return;
            }
            if (!result.Current())
                throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var executions = result.Answer.Value.Executions.ToDictionary(row => row.RuleId, StringComparer.OrdinalIgnoreCase);
            foreach (var rule in RuleCatalogue.All)
                RuleRows.Add(new(rule.Definition.Id, rule.Definition, executions.GetValueOrDefault(rule.Definition.Id)));
            var shipped = RuleCatalogue.All.Select(rule => rule.Definition.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var execution in executions.Values.Where(row => !shipped.Contains(row.RuleId)))
                RuleRows.Add(new(execution.RuleId, null, execution));
            RefreshSeverityChoices();
            ApplyRuleFilters();
            HasResults = true;
            navigation.Complete("success", null);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested)
        {
            navigation.Complete("cancelled", null);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (revision == _revision && !pending.IsCancellationRequested)
            {
                RuleRows.Clear();
                VisibleRuleRows.Clear();
                SelectedRule = null;
                RulesRefusal = new(NavigationText.Get("Refused"), error.Message);
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
            }
            pending.Dispose();
        }
    }

    public void Suspend()
    {
        _revision++;
        var pending = _pending;
        _pending = null;
        pending?.Cancel();
        IsLoading = false;
        HasResults = false;
        SelectedRule = null;
        RuleRows.Clear();
        VisibleRuleRows.Clear();
        RuleSeverityChoices.Clear();
        RuleSeverityChoices.Add("All");
        RuleSearchText = "";
        RuleAssessmentFilter = "All";
        RuleSeverityFilter = "All";
    }

    public void Clear()
    {
        Suspend();
        BundlePath = null;
        RulesRefusal = null;
        Announce();
    }

    private void Announce()
    {
        OnPropertyChanged(nameof(HasNoRun));
        OnPropertyChanged(nameof(HasRulesRefusal));
    }

    partial void OnRuleSearchTextChanged(string value) => ApplyRuleFilters();
    partial void OnRuleAssessmentFilterChanged(string value) => ApplyRuleFilters();
    partial void OnRuleSeverityFilterChanged(string value) => ApplyRuleFilters();

    private void ApplyRuleFilters()
    {
        var selected = SelectedRule;
        VisibleRuleRows.Clear();
        foreach (var row in RuleRows.Where(MatchesRuleFilters))
            VisibleRuleRows.Add(row);
        SelectedRule = selected is not null && VisibleRuleRows.Contains(selected)
            ? selected : VisibleRuleRows.FirstOrDefault();
    }

    private bool MatchesRuleFilters(RuleRowViewModel row)
    {
        var search = RuleSearchText.Trim();
        return (search.Length == 0 || row.Rule.Contains(search, StringComparison.OrdinalIgnoreCase)
                || row.Name.Contains(search, StringComparison.OrdinalIgnoreCase)
                || row.Category.Contains(search, StringComparison.OrdinalIgnoreCase))
            && (RuleAssessmentFilter == "All" || row.Assessment == RuleAssessmentFilter)
            && (RuleSeverityFilter == "All" || row.Severity == RuleSeverityFilter);
    }

    private void RefreshSeverityChoices()
    {
        while (RuleSeverityChoices.Count > 1)
            RuleSeverityChoices.RemoveAt(RuleSeverityChoices.Count - 1);
        if (RuleSeverityChoices.Count == 0)
            RuleSeverityChoices.Add("All");
        foreach (var severity in RuleRows.Select(row => row.Severity).Where(value => value.Length != 0)
                     .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase))
            RuleSeverityChoices.Add(severity);
        RuleSeverityFilter = "All";
        OnPropertyChanged(nameof(RuleSeverityFilter));
    }
}
