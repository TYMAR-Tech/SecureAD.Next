using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class ControlEdgesSectionViewModel
{
    private Func<ControlEdgeRowViewModel, CancellationToken, Task<Result<MemberAttributionDetail>>>? _readMembers;
    private Func<bool, long, CancellationToken, Task<Result<MemberPermissionPage>>>? _readThroughMembership;
    private CancellationTokenSource? _memberPending;
    private CancellationTokenSource? _membershipPending;
    private long _memberPermissionAfter;
    private Func<bool> _memberCurrent = () => false;
    /// <summary>The selected permission's membership support read.</summary>
    public Task MemberReadCompletion { get; private set; } = Task.CompletedTask;
    /// <summary>The current reverse-membership page read.</summary>
    public Task MembershipReadCompletion { get; private set; } = Task.CompletedTask;
    public MemberAttributionPanelViewModel MemberPanel { get; } = new();
    public string ThroughMembershipHeading => MemberAttributionPanelViewModel.Text("ReverseHeading");
    [ObservableProperty] private string _throughMembershipCoverage = MemberAttributionPanelViewModel.Text("SelectPermission");
    [ObservableProperty] private IReadOnlyList<MemberPermissionRowViewModel> _throughMembership = [];
    [ObservableProperty] private bool _hasMoreThroughMembership;

    /// <summary>Binds protected membership reads without preparing hidden support.</summary>
    public void ConfigureMemberAttributionAsync(
        Func<ControlEdgeRowViewModel, CancellationToken, Task<Result<MemberAttributionDetail>>> readMembers,
        Func<bool, long, CancellationToken, Task<Result<MemberPermissionPage>>>? readThroughMembership,
        Func<bool> isCurrent)
    {
        ArgumentNullException.ThrowIfNull(isCurrent);
        _memberCurrent = isCurrent;
        _readMembers = readMembers;
        _readThroughMembership = readThroughMembership;
        OnSelectedEdgeChanged(SelectedEdge);
        if (_generation is not null) FirstMembershipPermissionPage();
    }

    partial void OnSelectedEdgeChanged(ControlEdgeRowViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelectedEdge));
        OnPropertyChanged(nameof(HasNoSelectedEdge));
        var pending = _memberPending;
        _memberPending = null;
        pending?.Cancel();
        MemberPanel.Clear();
        if (_active && value is not null && _readMembers is not null)
            MemberReadCompletion = LoadMembersAsync(value);
    }

    private async Task LoadMembersAsync(ControlEdgeRowViewModel row)
    {
        if (_readMembers is null) return;
        var pending = new CancellationTokenSource();
        _memberPending = pending;
        var generation = _generation;
        MemberPanel.ShowLoading();
        try
        {
            var result = await _readMembers(row, pending.Token);
            if (ReferenceEquals(_memberPending, pending) && !pending.IsCancellationRequested)
                MemberPanel.Show(result, generation, _memberCurrent);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (ReferenceEquals(_memberPending, pending) && !pending.IsCancellationRequested)
                MemberPanel.ShowRefusal(error.Message);
        }
        finally
        {
            if (ReferenceEquals(_memberPending, pending)) _memberPending = null;
            pending.Dispose();
        }
    }

    private void CancelMemberReads()
    {
        var member = _memberPending;
        var membership = _membershipPending;
        _memberPending = _membershipPending = null;
        member?.Cancel();
        membership?.Cancel();
        MemberPanel.Clear();
    }

    [RelayCommand]
    private void FirstMembershipPermissionPage()
    {
        _memberPermissionAfter = 0;
        LoadMembershipPermissions();
    }

    [RelayCommand]
    private void NextMembershipPermissionPage()
    {
        if (HasMoreThroughMembership) LoadMembershipPermissions();
    }

    private void LoadMembershipPermissions()
    {
        if (_active) MembershipReadCompletion = LoadMembershipPermissionsAsync();
    }

    private async Task LoadMembershipPermissionsAsync()
    {
        var previous = _membershipPending;
        _membershipPending = null;
        previous?.Cancel();
        ThroughMembership = [];
        HasMoreThroughMembership = false;
        if (_readThroughMembership is null) return;
        var pending = new CancellationTokenSource();
        _membershipPending = pending;
        var generation = _generation;
        ThroughMembershipCoverage = NavigationText.Get("SavedLoading");
        try
        {
            var result = await _readThroughMembership(IncludeExpected, _memberPermissionAfter, pending.Token);
            if (!ReferenceEquals(_membershipPending, pending) || pending.IsCancellationRequested) return;
            ApplyMembershipPermissions(result, generation);
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (ReferenceEquals(_membershipPending, pending) && !pending.IsCancellationRequested)
                ThroughMembershipCoverage = NavigationText.Get("Refused") + " " + error.Message;
        }
        finally
        {
            if (ReferenceEquals(_membershipPending, pending)) _membershipPending = null;
            pending.Dispose();
        }
    }

    private void ApplyMembershipPermissions(Result<MemberPermissionPage> result, Guid? generation)
    {
        if (!result.IsSuccess || generation is null || result.Value.GenerationId != generation)
        {
            ThroughMembershipCoverage = MemberAttributionPanelViewModel.Text("InvalidEvidence");
            return;
        }
        var page = result.Value;
        ThroughMembershipCoverage = MemberAttributionPanelViewModel.Text(!page.WasRun ? "NotRun" : page.IsComplete ? "ReverseComplete" : "ReversePartial");
        if (page.WasRun) ThroughMembershipCoverage += " " + MemberAttributionPanelViewModel.Text(IncludeExpected ? "ReverseExpectedShown" : "ReverseExpectedHidden", page.ExpectedCount);
        ThroughMembership = page.Permissions.Select(permission => new MemberPermissionRowViewModel(permission)).ToArray();
        HasMoreThroughMembership = page.HasMore;
        _memberPermissionAfter = page.LastId;
    }

internal sealed class MemberPermissionRowViewModel(MemberPermissionReference value)
{
    public string HolderSid => value.HolderSid + (value.HolderScope is { } scope ? " [" + scope + "]" : "");
    public string Target => value.Target;
    public string Capability => MemberAttributionPanelViewModel.Text("SourcePermission",
        value.Capability == "HasFullControl" ? ControlEdgeRowViewModel.Text("FullControlLabel")
            : Enum.TryParse<ControlCapability>(value.Capability, out var capability) ? ControlEdgeRowViewModel.CapabilityText(capability) : value.Capability,
        value.PermissionState, ControlEdgeRowViewModel.Text(value.IncludedInFullControl ? "FullControlIncluded" : value.IsCounted ? "CountedOnce" : "NotCounted"));
    public string Membership => MemberAttributionPanelViewModel.Text("Membership" + value.Membership);
    public string ResourceApplicability => MemberAttributionPanelViewModel.Text(value.ResourceApplicability switch
    {
        MemberAttributionState.Established => "Applicable",
        MemberAttributionState.NotEstablished => "NotApplicable",
        _ => "UnknownApplicability",
    }, value.Reason);
}
}
