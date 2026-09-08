using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class ControlEdgesSectionViewModel
{
    private Func<ControlEdgeRowViewModel, Result<MemberAttributionDetail>>? _readMembers;
    private Func<bool, long, Result<MemberPermissionPage>>? _readThroughMembership;
    private long _memberPermissionAfter;
    public MemberAttributionPanelViewModel MemberPanel { get; } = new();
    public string ThroughMembershipHeading => MemberAttributionPanelViewModel.Text("ReverseHeading");
    [ObservableProperty] private string _throughMembershipCoverage = MemberAttributionPanelViewModel.Text("SelectPermission");
    [ObservableProperty] private IReadOnlyList<MemberPermissionRowViewModel> _throughMembership = [];
    [ObservableProperty] private bool _hasMoreThroughMembership;

    public void ConfigureMemberAttribution(Func<ControlEdgeRowViewModel, Result<MemberAttributionDetail>> readMembers,
        Func<bool, long, Result<MemberPermissionPage>>? readThroughMembership)
    {
        _readMembers = readMembers;
        _readThroughMembership = readThroughMembership;
        OnSelectedEdgeChanged(SelectedEdge);
        FirstMembershipPermissionPage();
    }

    partial void OnSelectedEdgeChanged(ControlEdgeRowViewModel? value)
    {
        MemberPanel.Clear();
        if (value is not null && _readMembers is not null) MemberPanel.Show(_readMembers(value), _generation);
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
        ThroughMembership = [];
        HasMoreThroughMembership = false;
        if (_readThroughMembership is null) return;
        var result = _readThroughMembership(IncludeExpected, _memberPermissionAfter);
        if (!result.IsSuccess || _generation is null || result.Value.GenerationId != _generation)
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
