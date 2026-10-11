using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Shell.ViewModels;

internal sealed record GroupFilterChoice<T>(string Label, T Value);

internal sealed class GroupRowViewModel(GroupInventoryRow value)
{
    internal GroupInventoryRow Value { get; } = value;
    public string Name => value.Name;
    public string DistinguishedName => value.DistinguishedName;
    public string AccountName => value.AccountName ?? "Not recorded";
    public string Domain => value.DomainFqdn ?? "Not recorded";
    public string Scope => (value.GroupType & 15) switch { 2 => "Global", 4 or 5 => "Domain local", 8 => "Universal", _ => "Not recorded" };
    public string Kind => value.GroupType is null ? "Type not recorded" : (value.GroupType & 2147483648) != 0 ? "Security" : "Distribution";
    public int DirectMembers => value.DirectMembers;
    public string KnownTotal => value.MembershipTotal.KnownMembers.ToString("N0");
    public string Cycle => value.HasCycle switch { true => "SEC-052", false => "None recorded", _ => "Not assessed" };
    public bool HasCycle => value.HasCycle == true;
    public string MembershipData => value.MembershipTotal.Limitations == GroupMembershipLimitations.None
        ? "Recorded values" : "Incomplete membership evidence";
    public string MembershipDetail => $"{MembershipData}. Unresolved references: {value.MembershipTotal.UnresolvedReferences:N0}; "
        + $"unreadable references: {value.MembershipTotal.UnreadableReferences:N0}.";
    public string Description => value.Description ?? "No description was recorded.";
}

internal sealed partial class AssetsViewModel
{
    public ObservableCollection<GroupRowViewModel> Groups { get; } = [];
    [ObservableProperty] private GroupRowViewModel? _selectedGroup;
    [ObservableProperty] private string _groupSearchText = "";
    [ObservableProperty] private GroupInventoryScope _groupScope;
    [ObservableProperty] private GroupInventoryKind _groupKind;
    [ObservableProperty] private bool _groupsOnlyCycles;
    [ObservableProperty] private bool _groupsWholeCapture;
    [ObservableProperty] private int _groupTotal;
    [ObservableProperty] private string? _groupQualification;
    private string _groupSearch = "";
    private GroupInventorySort _groupSort;
    private GroupInventoryMark? _groupAfter;
    private GroupInventoryMark? _groupNext;
    private readonly Stack<GroupInventoryMark?> _groupBack = [];
    private readonly Stack<string> _groupObjectBack = [];

    public bool ShowsGroups => Pane == AssetsPane.Groups;
    public bool ShowsGroupsListing => ShowsGroups && ShowsListing && HasListingResult;
    public bool ShowsGroupsSurface => _active && ShowsGroups && ShowsListing && HasTree;
    public bool ShowsOtherViewLoading => IsLoading && !ShowsGroups && !ShowsTier0;
    public bool HasOtherViewRefusal => HasViewRefusal && !ShowsGroups && !ShowsTier0;
    public bool HasSelectedGroup => SelectedGroup is not null;
    public bool HasGroupQualification => !string.IsNullOrWhiteSpace(GroupQualification);
    public string GroupLocation => GroupsWholeCapture ? "Groups in the captured forest"
        : Selected is null ? "Choose a directory location" : "Groups in " + Selected.DistinguishedName;
    public string GroupPageDescription => $"{GroupTotal:N0} matching groups - page {_groupBack.Count + 1}";
    public string GroupCountExplanation => "Direct counts are distinct values recorded in the group's member attribute, not a guarantee of complete membership. "
        + "Known total counts distinct captured objects reached through member links, including nested groups, once each; the starting group is excluded. "
        + "Unresolved references are not included. Primary-group relationships remain separate. Recorded values do not guarantee complete membership. Membership is not permission proof.";
    public IReadOnlyList<GroupFilterChoice<GroupInventoryScope>> GroupScopeChoices { get; } =
        [new("All scopes", GroupInventoryScope.All), new("Global", GroupInventoryScope.Global),
            new("Universal", GroupInventoryScope.Universal), new("Domain local", GroupInventoryScope.DomainLocal)];
    public IReadOnlyList<GroupFilterChoice<GroupInventoryKind>> GroupKindChoices { get; } =
        [new("All types", GroupInventoryKind.All), new("Security", GroupInventoryKind.Security), new("Distribution", GroupInventoryKind.Distribution)];

    private GroupInventoryQuery GroupQuestion() => new(GroupsWholeCapture ? null : Selected?.DistinguishedName,
        GroupsWholeCapture ? ListingScope.Subtree : Scope, _groupSearch, GroupScope, GroupKind, GroupsOnlyCycles, _groupSort);

    private async Task LoadGroupsAsync(ListingQuestion question)
    {
        if (!GroupsWholeCapture && Selected is null) { CancelRead(); Announce(); return; }
        var selected = SelectedGroup?.DistinguishedName;
        await ReadViewAsync(question.Bundle, reader => reader.ReadGroups(question.Bundle, question.Groups!, _groupAfter),
            (page, current) =>
            {
                foreach (var group in page.Groups) Groups.Add(new(group));
                GroupTotal = page.Total;
                _groupNext = page.Next;
                GroupQualification = string.Join(" ", new[] { page.Coverage.Shortfall, page.CycleQualification }.Where(value => !string.IsNullOrWhiteSpace(value)));
                SelectedGroup = Groups.FirstOrDefault(group => group.DistinguishedName == selected) ?? Groups.FirstOrDefault();
                RememberPage(question, current);
            }, saved: true);
    }

    private bool CanUseGroups() => _active && ShowsGroups && HasTree && !IsLoading;
    private bool CanOpenGroup(GroupRowViewModel? row) => CanUseGroups()
        && (row ?? SelectedGroup) is { } selected && Groups.Contains(selected);
    private bool CanNextGroupPage() => CanUseGroups() && HasListingResult && _groupNext is not null;
    private bool CanPreviousGroupPage() => CanUseGroups() && _groupBack.Count != 0;

    [RelayCommand(CanExecute = nameof(CanUseGroups))]
    private void SearchGroups() { _groupSearch = GroupSearchText.Trim(); ChangeGroupQuestion(); }

    [RelayCommand(CanExecute = nameof(CanUseGroups))]
    private void ClearGroupFilters()
    {
        _resetting = true;
        GroupSearchText = _groupSearch = "";
        GroupScope = GroupInventoryScope.All;
        GroupKind = GroupInventoryKind.All;
        GroupsOnlyCycles = false;
        _resetting = false;
        ChangeGroupQuestion();
    }

    [RelayCommand(CanExecute = nameof(CanUseGroups))]
    private void SortGroupName() { _groupSort = _groupSort == GroupInventorySort.Name ? GroupInventorySort.NameDescending : GroupInventorySort.Name; ChangeGroupQuestion(); }
    [RelayCommand(CanExecute = nameof(CanUseGroups))]
    private void SortGroupDirect() { _groupSort = _groupSort == GroupInventorySort.DirectDescending ? GroupInventorySort.Direct : GroupInventorySort.DirectDescending; ChangeGroupQuestion(); }

    [RelayCommand(CanExecute = nameof(CanOpenGroup))]
    private void OpenGroup(GroupRowViewModel? row)
    {
        _groupObjectBack.Clear();
        Open((row ?? SelectedGroup ?? throw new InvalidOperationException("No current group is selected.")).DistinguishedName, ObjectSectionCatalog.Membership);
    }

    [RelayCommand(CanExecute = nameof(CanOpenGroup))]
    private void OpenGroupFindings(GroupRowViewModel? row)
    {
        _groupObjectBack.Clear();
        Open((row ?? SelectedGroup ?? throw new InvalidOperationException("No current group is selected.")).DistinguishedName, ObjectSectionCatalog.Findings);
    }

    private void OpenGroupMember(string dn)
    {
        if (Opened is null) return;
        _groupObjectBack.Push(Opened.DistinguishedName);
        Open(dn, ObjectSectionCatalog.Membership);
    }

    [RelayCommand(CanExecute = nameof(CanNextGroupPage))]
    private void NextGroupPage() { _groupBack.Push(_groupAfter); _groupAfter = _groupNext; LoadVisible(); }
    [RelayCommand(CanExecute = nameof(CanPreviousGroupPage))]
    private void PreviousGroupPage() { _groupAfter = _groupBack.Pop(); LoadVisible(); }

    [RelayCommand(CanExecute = nameof(CanUseGroups))]
    private void BrowseAllGroups()
    {
        _resetting = true;
        foreach (var node in Roots.SelectMany(root => root.ThisAndBelow())) node.IsSelected = false;
        Selected = null;
        Scope = ListingScope.Subtree;
        _resetting = false;
        GroupsWholeCapture = true;
        ChangeGroupQuestion();
    }

    private void ChangeGroupQuestion()
    {
        if (_resetting) return;
        ResetGroupPaging();
        if (ShowsGroups && _active) LoadVisible();
        AnnounceGroups();
    }

    private void ResetGroupPaging() { _groupAfter = _groupNext = null; _groupBack.Clear(); }
    private void ClearGroups()
    {
        Groups.Clear();
        SelectedGroup = null;
        _groupObjectBack.Clear();
        ResetGroupPaging();
        _groupsWholeCapture = false;
        GroupSearchText = _groupSearch = "";
        GroupScope = GroupInventoryScope.All;
        GroupKind = GroupInventoryKind.All;
        GroupsOnlyCycles = false;
        GroupQualification = null;
        GroupTotal = 0;
    }
    private void UseSelectedGroupLocation()
    {
        _groupObjectBack.Clear();
        if (ShowsGroups) { _groupsWholeCapture = false; OnPropertyChanged(nameof(GroupsWholeCapture)); }
        ResetGroupPaging();
    }
    partial void OnGroupScopeChanged(GroupInventoryScope value) => ChangeGroupQuestion();
    partial void OnGroupKindChanged(GroupInventoryKind value) => ChangeGroupQuestion();
    partial void OnGroupsOnlyCyclesChanged(bool value) => ChangeGroupQuestion();
    partial void OnSelectedGroupChanged(GroupRowViewModel? value) => AnnounceGroups();
    partial void OnGroupQualificationChanged(string? value) => OnPropertyChanged(nameof(HasGroupQualification));

    private void AnnounceGroups()
    {
        OnPropertyChanged(nameof(ShowsGroups));
        OnPropertyChanged(nameof(ShowsGroupsListing));
        OnPropertyChanged(nameof(ShowsGroupsSurface));
        OnPropertyChanged(nameof(ShowsOtherViewLoading));
        OnPropertyChanged(nameof(HasOtherViewRefusal));
        OnPropertyChanged(nameof(HasSelectedGroup));
        OnPropertyChanged(nameof(GroupLocation));
        OnPropertyChanged(nameof(CanChangeBrowsingScope));
        OnPropertyChanged(nameof(GroupPageDescription));
        SearchGroupsCommand.NotifyCanExecuteChanged();
        ClearGroupFiltersCommand.NotifyCanExecuteChanged();
        SortGroupNameCommand.NotifyCanExecuteChanged();
        SortGroupDirectCommand.NotifyCanExecuteChanged();
        OpenGroupCommand.NotifyCanExecuteChanged();
        OpenGroupFindingsCommand.NotifyCanExecuteChanged();
        NextGroupPageCommand.NotifyCanExecuteChanged();
        PreviousGroupPageCommand.NotifyCanExecuteChanged();
        BrowseAllGroupsCommand.NotifyCanExecuteChanged();
    }
}
