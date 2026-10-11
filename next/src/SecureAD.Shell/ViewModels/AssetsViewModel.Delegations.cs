using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty] private string _delegationPrincipalSearch = "";
    [ObservableProperty] private DelegationPrincipalChoice? _selectedDelegationPrincipal;
    [ObservableProperty] private DelegationPermissionChoice _delegationPermissionFilter = new(DelegationPermission.All, DelegationText.Get("All"));
    [ObservableProperty] private bool _includeInheritedDelegations;
    [ObservableProperty] private bool _includeGroupHeldPermissions = true;
    [ObservableProperty] private DelegationRowViewModel? _selectedDelegation;
    [ObservableProperty] private string _delegationPrincipalStatus = DelegationText.Get("PrincipalPrompt");
    [ObservableProperty] private string _delegationStatus = DelegationText.Get("Prompt");
    [ObservableProperty] private string _delegationCoverage = "";
    [ObservableProperty] private bool _isDelegationSearchEditing = true;
    [ObservableProperty] private string _delegationResultSearch = "";

    private DelegationPrincipalMark? _principalNext;
    private DelegationPageMark? _delegationAfter;
    private DelegationPageMark? _delegationNext;
    private readonly Stack<DelegationPageMark?> _delegationBack = new();
    private bool _delegationHasAnswer;

    public ObservableCollection<DelegationPrincipalChoice> DelegationPrincipals { get; } = [];
    public ObservableCollection<DelegationRowViewModel> Delegations { get; } = [];
    public IReadOnlyList<DelegationPermissionChoice> DelegationPermissions { get; } =
        Enum.GetValues<DelegationPermission>().Select(value => new DelegationPermissionChoice(value, DelegationText.Get(value.ToString()))).ToArray();
    public bool ShowsDelegations => Pane == AssetsPane.Delegations;
    public bool ShowsDelegationsListing => ShowsDelegations && ShowsListing;
    public bool ShowsDirectoryTree => !ShowsTier0 && !ShowsDelegations;
    public bool HasDelegationAnswer => _delegationHasAnswer && !IsLoading && !HasViewRefusal;
    public bool HasDelegationSelection => HasDelegationAnswer && SelectedDelegation is not null;
    public bool DelegationControlsAreEnabled => _active && HasTree && !IsLoading;
    public string DelegationBoundary => DelegationText.Get(IncludeGroupHeldPermissions ? "GroupBoundary" : "Boundary");
    public bool ShowsDelegationSearchEditor => IsDelegationSearchEditing || !HasDelegationAnswer;
    public bool ShowsDelegationSearchSummary => HasDelegationAnswer && !IsDelegationSearchEditing;
    public string DelegationSearchSummary => SelectedDelegationPrincipal is not { } principal ? ""
        : DelegationText.Format("SearchSummary", principal.Principal.Name,
            principal.Principal.DomainFqdn ?? DelegationText.Get("Unresolved"),
            DelegationPermissionFilter.Name,
            DelegationText.Get(IncludeGroupHeldPermissions ? "GroupHeldIncluded" : "DirectOnly"),
            DelegationText.Get(IncludeInheritedDelegations ? "InheritedIncluded" : "ExplicitOnly"));
    public IReadOnlyList<DelegationRowViewModel> VisibleDelegations
    {
        get
        {
            var search = DelegationResultSearch.Trim();
            return search.Length == 0 ? [.. Delegations] : Delegations.Where(row =>
                row.RecordedOn.Contains(search, StringComparison.OrdinalIgnoreCase)
                || row.Domain.Contains(search, StringComparison.OrdinalIgnoreCase)
                || row.PermissionHeldBy.Contains(search, StringComparison.OrdinalIgnoreCase)
                || row.Permission.Contains(search, StringComparison.OrdinalIgnoreCase)
                || row.AppliesTo.Contains(search, StringComparison.OrdinalIgnoreCase)).ToArray();
        }
    }

    private bool CanSearchPrincipals() => CanUseDelegations() && !string.IsNullOrWhiteSpace(DelegationPrincipalSearch);
    private bool CanUseDelegations() => _active && HasTree && ShowsDelegationsListing && BundlePath is not null && !IsLoading;
    private bool CanSearchDelegations() => CanUseDelegations() && SelectedDelegationPrincipal is not null;
    private bool CanNextPrincipals() => CanSearchPrincipals() && _principalNext is not null;
    private bool CanNextDelegations() => CanSearchDelegations() && HasDelegationAnswer && _delegationNext is not null;
    private bool CanPreviousDelegations() => CanSearchDelegations() && HasDelegationAnswer && _delegationBack.Count != 0;
    private bool CanCancelDelegationSearch() => ShowsDelegationsListing && IsLoading;

    [RelayCommand(CanExecute = nameof(CanSearchPrincipals))]
    private Task FindDelegationPrincipalAsync() => StartPrincipalSearch(null);

    [RelayCommand(CanExecute = nameof(CanNextPrincipals))]
    private Task NextDelegationPrincipalsAsync() => StartPrincipalSearch(_principalNext);

    private Task StartPrincipalSearch(DelegationPrincipalMark? after)
    {
        var bundle = BundlePath!;
        var search = DelegationPrincipalSearch.Trim();
        SelectedDelegationPrincipal = null;
        DelegationPrincipals.Clear();
        ClearDelegationAnswer();
        _principalNext = null;
        DelegationPrincipalStatus = "";
        return ReadCompletion = ReadViewAsync(bundle, reader => reader.FindDelegationPrincipals(bundle, search, after),
            (page, _) =>
            {
                foreach (var principal in page.Principals) DelegationPrincipals.Add(new(principal));
                _principalNext = page.Next;
                if (after is null && page.Next is null && DelegationPrincipals.Count == 1)
                {
                    var resetting = _resetting;
                    _resetting = true;
                    try { SelectedDelegationPrincipal = DelegationPrincipals[0]; }
                    finally { _resetting = resetting; }
                }
                DelegationPrincipalStatus = page.Principals.Count == 0 ? DelegationText.Get("PrincipalNone")
                    : DelegationText.Format("PrincipalCount", page.Principals.Count, page.Next is null ? "" : DelegationText.Get("More"));
                if (!page.CaptureWasComplete) DelegationPrincipalStatus += " " + DelegationText.Get("CaptureShort");
            }, saved: false);
    }

    [RelayCommand(CanExecute = nameof(CanSearchDelegations))]
    private Task FindDelegationsAsync()
    {
        _delegationBack.Clear();
        return ReadCompletion = ReadDelegationPageAsync(null, 0);
    }

    [RelayCommand(CanExecute = nameof(CanNextDelegations))]
    private Task NextDelegationsAsync() => ReadCompletion = ReadDelegationPageAsync(_delegationNext, 1);

    [RelayCommand(CanExecute = nameof(CanPreviousDelegations))]
    private Task PreviousDelegationsAsync() => ReadCompletion = ReadDelegationPageAsync(_delegationBack.Peek(), -1);

    private Task ReadDelegationPageAsync(DelegationPageMark? after, int direction)
    {
        var bundle = BundlePath!;
        var query = new DelegationQuery(SelectedDelegationPrincipal!.Principal, DelegationPermissionFilter.Value, IncludeInheritedDelegations)
        { IncludeGroupHeldPermissions = IncludeGroupHeldPermissions };
        _delegationHasAnswer = false;
        SelectedDelegation = null;
        Delegations.Clear();
        DelegationStatus = "";
        DelegationCoverage = "";
        _pages.Remove(AssetsPane.Delegations);
        return ReadViewAsync(bundle, reader =>
        {
            var page = reader.ReadDelegations(bundle, query, after);
            if (!page.IsSuccess) return Result<(DelegationPage Page, PermissionVocabulary Vocabulary)>.Failure(page.Error);
            if (query.IncludeGroupHeldPermissions != (page.Value.Membership is not null))
                return Result<(DelegationPage Page, PermissionVocabulary Vocabulary)>.Failure(AuditError.Create(ErrorCategory.Shell,
                    "DelegationMembershipModeMismatch", ErrorSeverity.Failed, DelegationText.Get("MembershipModeMismatch"), bundle));
            var schema = reader.ReadSchemaGuids(bundle);
            return schema.IsSuccess
                ? Result<(DelegationPage Page, PermissionVocabulary Vocabulary)>.Success((page.Value, new PermissionVocabulary(schema.Value)))
                : Result<(DelegationPage Page, PermissionVocabulary Vocabulary)>.Failure(schema.Error);
        }, (answer, current) =>
        {
            if (direction > 0) _delegationBack.Push(_delegationAfter);
            else if (direction < 0) _delegationBack.Pop();
            _delegationAfter = after;
            _delegationNext = answer.Page.Next;
            var membership = answer.Page.Membership is { } graph ? new DelegationMembershipPresentation(graph) : null;
            foreach (var entry in answer.Page.Entries) Delegations.Add(new(entry, answer.Vocabulary, membership));
            DelegationResultSearch = "";
            OnPropertyChanged(nameof(VisibleDelegations));
            _delegationHasAnswer = true;
            IsDelegationSearchEditing = false;
            DelegationStatus = answer.Page.Entries.Count == 0 ? DelegationText.Get(query.IncludeGroupHeldPermissions ? "NoGroupMatch" : "NoMatch")
                : DelegationText.Format("Page", _delegationBack.Count + 1, answer.Page.Entries.Count,
                    answer.Page.Next is null ? "" : DelegationText.Get("More"));
            var coverage = answer.Page.Coverage;
            DelegationCoverage = DelegationText.Format("Coverage", coverage.UnreadableDescriptors,
                coverage.UnattemptedDescriptors, coverage.IncompleteDescriptors, coverage.DescriptorErrors);
            if (!coverage.DeclaredScopeWasRead) DelegationCoverage += "\n" + DelegationText.Get("CaptureShort");
            if (coverage.ExcludedObjectClasses.Count != 0)
                DelegationCoverage += "\n" + DelegationText.Format("ExcludedClasses", string.Join(", ", coverage.ExcludedObjectClasses));
            if (query.Principal.DomainFqdn is null && SecureAD.Kernel.Security.Sid.IsBuiltinDomain(query.Principal.Sid))
                DelegationCoverage += "\n" + DelegationText.Get("DomainSid");
            if (answer.Page.Membership is { Warnings.Count: > 0 } limited)
                DelegationCoverage += "\n" + DelegationText.Format("MembershipWarnings", string.Join("\n", limited.Warnings));
            RememberPage(Question(), current);
        }, saved: false);
    }

    [RelayCommand(CanExecute = nameof(CanCancelDelegationSearch))]
    private void CancelDelegationSearch()
    {
        CancelRead();
        ClearDelegationAnswer();
        DelegationStatus = DelegationText.Get("Cancelled");
        DelegationPrincipalStatus = DelegationText.Get("Cancelled");
        Announce();
    }

    [RelayCommand]
    private void EditDelegationSearch() => IsDelegationSearchEditing = true;

    [RelayCommand(CanExecute = nameof(HasDelegationSelection))]
    private void OpenDelegationDetails()
    {
        if (!_pages.TryGetValue(AssetsPane.Delegations, out var page) || !page.IsCurrent())
        {
            ClearDelegationAnswer();
            RefuseView(SavedPathText.Get("GenerationChanged"));
            Announce();
            return;
        }
        Open(SelectedDelegation!.RecordedOn, ObjectSectionCatalog.Permissions);
    }

    partial void OnDelegationPrincipalSearchChanged(string value)
    {
        if (_resetting) return;
        CancelRead();
        DelegationPrincipals.Clear();
        SelectedDelegationPrincipal = null;
        _principalNext = null;
        DelegationPrincipalStatus = DelegationText.Get("PrincipalPrompt");
        ClearDelegationAnswer();
        Announce();
    }

    partial void OnSelectedDelegationPrincipalChanged(DelegationPrincipalChoice? value) => DelegationQuestionChanged();
    partial void OnDelegationPermissionFilterChanged(DelegationPermissionChoice value) => DelegationQuestionChanged();
    partial void OnIncludeInheritedDelegationsChanged(bool value) => DelegationQuestionChanged();
    partial void OnIncludeGroupHeldPermissionsChanged(bool value)
    {
        OnPropertyChanged(nameof(DelegationBoundary));
        DelegationQuestionChanged();
    }
    partial void OnSelectedDelegationChanged(DelegationRowViewModel? value) => AnnounceDelegations();
    partial void OnIsDelegationSearchEditingChanged(bool value) => AnnounceDelegations();
    partial void OnDelegationResultSearchChanged(string value)
    {
        OnPropertyChanged(nameof(VisibleDelegations));
        if (SelectedDelegation is not null && !VisibleDelegations.Contains(SelectedDelegation))
            SelectedDelegation = VisibleDelegations.FirstOrDefault();
    }

    private void DelegationQuestionChanged()
    {
        if (_resetting) return;
        CancelRead();
        ViewRefusal = null;
        ClearDelegationAnswer();
        IsDelegationSearchEditing = true;
        Announce();
    }

    private void ClearDelegationAnswer()
    {
        _delegationHasAnswer = false;
        _delegationAfter = _delegationNext = null;
        _delegationBack.Clear();
        SelectedDelegation = null;
        Delegations.Clear();
        DelegationResultSearch = "";
        DelegationStatus = DelegationText.Get("Prompt");
        DelegationCoverage = "";
        _pages.Remove(AssetsPane.Delegations);
    }

    private void ClearDelegationSearch()
    {
        var resetting = _resetting;
        _resetting = true;
        SelectedDelegationPrincipal = null;
        DelegationPrincipals.Clear();
        _principalNext = null;
        DelegationPrincipalStatus = DelegationText.Get("PrincipalPrompt");
        ClearDelegationAnswer();
        IsDelegationSearchEditing = true;
        _resetting = resetting;
    }

    private void AnnounceDelegations()
    {
        OnPropertyChanged(nameof(ShowsDelegations));
        OnPropertyChanged(nameof(ShowsDelegationsListing));
        OnPropertyChanged(nameof(ShowsDirectoryTree));
        OnPropertyChanged(nameof(HasDelegationAnswer));
        OnPropertyChanged(nameof(HasDelegationSelection));
        OnPropertyChanged(nameof(DelegationControlsAreEnabled));
        OnPropertyChanged(nameof(ShowsDelegationSearchEditor));
        OnPropertyChanged(nameof(ShowsDelegationSearchSummary));
        OnPropertyChanged(nameof(DelegationSearchSummary));
        FindDelegationPrincipalCommand.NotifyCanExecuteChanged();
        NextDelegationPrincipalsCommand.NotifyCanExecuteChanged();
        FindDelegationsCommand.NotifyCanExecuteChanged();
        NextDelegationsCommand.NotifyCanExecuteChanged();
        PreviousDelegationsCommand.NotifyCanExecuteChanged();
        CancelDelegationSearchCommand.NotifyCanExecuteChanged();
        OpenDelegationDetailsCommand.NotifyCanExecuteChanged();
        EditDelegationSearchCommand.NotifyCanExecuteChanged();
    }
}
