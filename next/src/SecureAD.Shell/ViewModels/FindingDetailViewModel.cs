using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed record FindingDetailContent(FindingListItem Saved, string? Completeness, string? Membership)
{
    internal SavedAccountSetting? AccountSetting { get; init; }
    internal SavedDelegationConfiguration? DelegationConfiguration { get; init; }
    internal SavedAttributeWritePermission? AttributeWritePermission { get; init; }

    internal static FindingDetailContent FromSaved(FindingListItem saved)
    {
        var row = new FindingRowViewModel(saved);
        return new(saved, saved.Membership is null ? null : row.MembershipCompleteness,
            saved.Membership is null ? null : row.MembershipDetails);
    }
}

internal sealed class CapturedAccountSettingViewModel(SavedAccountSetting setting)
{
    public string Setting => setting.SettingName + ": Enabled";
    public string AccountState => setting.AccountControl.IsDisabled ? "Disabled" : "Enabled";
    public bool HasControllerRoleNote => setting.Delegation?.IsComputer == true;
    public string ControllerRoleNote => "Domain-controller role is not independently verified by this saved finding.";
    public bool HasControllerDisagreement => setting.Delegation is
        { IsComputer: true, ControllerSignals: { SignalsDisagree: true } };
    public string ControllerDisagreement => "Captured controller indicators disagree. Verify the actual role before changing delegation.";
}

internal sealed partial class FindingDetailViewModel : ObservableObject
{
    private readonly FindingRowViewModel _selected;
    private readonly Func<bool, CancellationToken, Task<Result<FindingDetailContent>>> _read;
    private readonly Func<bool> _current;
    private readonly Func<DelegationConfigurationMark?, CancellationToken, Task<Result<SavedDelegationConfiguration>>>? _readDelegation;
    private readonly Func<AttributeWritePermissionMark?, CancellationToken, Task<Result<SavedAttributeWritePermission>>>? _readWritePermission;
    private CancellationTokenSource? _pending;
    private bool _active = true;

    internal FindingDetailViewModel(FindingRowViewModel selected,
        Func<bool, CancellationToken, Task<Result<FindingDetailContent>>> read, Func<bool> current,
        Func<DelegationConfigurationMark?, CancellationToken, Task<Result<SavedDelegationConfiguration>>>? readDelegation = null,
        Func<AttributeWritePermissionMark?, CancellationToken, Task<Result<SavedAttributeWritePermission>>>? readWritePermission = null)
    {
        (_selected, _read, _current, _readDelegation) = (selected, read, current, readDelegation);
        _readWritePermission = readWritePermission;
        ReadCompletion = LoadAsync(false);
    }

    public string Title => _selected.Target + " - Finding details | SecureAD";
    public string LoadingText => NavigationText.Get("SavedLoading");
    public FindingRowViewModel? Finding { get; private set; }
    public bool HasFinding => Finding is not null;
    public CapturedAccountSettingViewModel? CapturedSetting { get; private set; }
    public bool HasCapturedSetting => CapturedSetting is not null;
    public DelegationConfigurationViewModel? DelegationConfiguration { get; private set; }
    public bool HasDelegationConfiguration => DelegationConfiguration is not null;
    public AttributeWritePermissionViewModel? AttributeWritePermission { get; private set; }
    public bool HasAttributeWritePermission => AttributeWritePermission is not null;
    public bool ShowsStandardIdentity => HasFinding && !HasDelegationConfiguration && !HasAttributeWritePermission;
    public bool ShowsSavedDescription => HasFinding && !HasCapturedSetting && !HasDelegationConfiguration && !HasAttributeWritePermission;
    public bool IsLoading { get; private set; }
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public bool IsLoadingMembership { get; private set; }
    public string? MembershipRefusal { get; private set; }
    public bool HasMembershipRefusal => MembershipRefusal is not null;
    public string? MembershipCompleteness { get; private set; }
    public string? MembershipDetails { get; private set; }
    public bool HasMembershipDetails => MembershipDetails is not null;
    public Task ReadCompletion { get; private set; }

    private bool CanLoadMembership() => _active && !IsLoading && !IsLoadingMembership
        && Finding?.HasMembershipEvidence == true && !HasMembershipDetails;

    [RelayCommand(CanExecute = nameof(CanLoadMembership))]
    private void LoadMembership()
    {
        if (CanLoadMembership()) ReadCompletion = LoadAsync(true);
    }

    internal bool CheckCurrent()
    {
        if (_active && _current()) return true;
        Refusal = SavedPathText.Get("GenerationChanged");
        Finding = null;
        CapturedSetting = null;
        DelegationConfiguration?.Suspend();
        DelegationConfiguration = null;
        AttributeWritePermission?.Suspend();
        AttributeWritePermission = null;
        MembershipCompleteness = MembershipDetails = null;
        Announce();
        return false;
    }

    private async Task LoadAsync(bool membership)
    {
        _pending?.Cancel();
        using var pending = new CancellationTokenSource();
        _pending = pending;
        IsLoading = !membership;
        IsLoadingMembership = membership;
        if (membership) MembershipRefusal = null;
        else Refusal = null;
        Announce();
        try
        {
            if (!_active || !_current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var answer = await _read(membership, pending.Token);
            if (!_active || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending)) return;
            if (!_current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            var content = answer.Value;
            if ((content.Saved with { Membership = null }) != (_selected.Saved with { Membership = null }))
                throw new InvalidDataException("The saved explanation does not match the selected finding.");
            if (membership)
            {
                if (content.Saved.Membership is null || content.Completeness is null || content.Membership is null)
                    throw new InvalidDataException("The selected finding's saved membership support is unavailable.");
                MembershipCompleteness = content.Completeness;
                MembershipDetails = content.Membership;
            }
            else
            {
                if (content.Saved.Membership is not null || content.Membership is not null || content.Completeness is not null)
                    throw new InvalidDataException("The finding explanation unexpectedly loaded membership support.");
                if (SavedAccountSetting.SupportsRule(content.Saved.RuleId))
                {
                    if (content.AccountSetting is not { } setting
                        || setting.Reference != content.Saved.Reference || setting.RuleId != content.Saved.RuleId
                        || setting.ObjectGuid != content.Saved.ObjectGuid
                        || setting.Subject != content.Saved.Subject || setting.DistinguishedName != content.Saved.DistinguishedName
                        || !setting.HasReportedSetting || !setting.HasExpectedContext)
                        throw new InvalidDataException("The saved account setting does not match the selected finding.");
                    CapturedSetting = new(setting);
                }
                else if (content.AccountSetting is not null)
                    throw new InvalidDataException("The selected finding has unrelated account setting data.");
                if (content.Saved.RuleId is "SEC-012" or "SEC-013")
                {
                    if (content.DelegationConfiguration is not { Context: not null } delegation || _readDelegation is null
                        || !delegation.Context.Matches(content.Saved) || !delegation.IsExpectedPage(0))
                        throw new InvalidDataException(content.Saved.RuleId == "SEC-013"
                            ? SavedDelegationConfiguration.ResourceInvalidDetails : SavedDelegationConfiguration.ConstrainedInvalidDetails);
                    DelegationConfiguration = new(content.Saved.PrincipalName, delegation, _readDelegation, CheckCurrent);
                }
                else if (content.DelegationConfiguration is not null)
                    throw new InvalidDataException("The selected finding has unrelated delegation configuration data.");
                if (SavedAttributeWritePermission.SupportsRule(content.Saved.RuleId))
                {
                    if (content.AttributeWritePermission is not { Context: not null } permission || _readWritePermission is null
                        || !permission.Context.Matches(content.Saved) || !permission.IsExpectedPage(-1))
                        throw new InvalidDataException(SavedAttributeWritePermission.InvalidDetailsForRule(content.Saved.RuleId));
                    AttributeWritePermission = new(permission, _readWritePermission, CheckCurrent);
                }
                else if (content.AttributeWritePermission is not null)
                    throw new InvalidDataException("The selected finding has unrelated saved write-permission data.");
                Finding = new(content.Saved, _current);
            }
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (_active && !pending.IsCancellationRequested && ReferenceEquals(_pending, pending))
            {
                if (!_current())
                {
                    Refusal = SavedPathText.Get("GenerationChanged");
                    Finding = null;
                    CapturedSetting = null;
                    DelegationConfiguration?.Suspend();
                    DelegationConfiguration = null;
                    AttributeWritePermission?.Suspend();
                    AttributeWritePermission = null;
                    MembershipCompleteness = MembershipDetails = null;
                }
                else if (membership) MembershipRefusal = error.Message;
                else Refusal = error.Message;
            }
        }
        finally
        {
            if (ReferenceEquals(_pending, pending))
            {
                _pending = null;
                IsLoading = IsLoadingMembership = false;
                Announce();
            }
        }
    }

    internal void Suspend()
    {
        _active = false;
        _pending?.Cancel();
        Finding = null;
        CapturedSetting = null;
        DelegationConfiguration?.Suspend();
        DelegationConfiguration = null;
        AttributeWritePermission?.Suspend();
        AttributeWritePermission = null;
        MembershipCompleteness = MembershipDetails = null;
        Announce();
    }

    private void Announce()
    {
        OnPropertyChanged(nameof(Finding));
        OnPropertyChanged(nameof(HasFinding));
        OnPropertyChanged(nameof(CapturedSetting));
        OnPropertyChanged(nameof(HasCapturedSetting));
        OnPropertyChanged(nameof(DelegationConfiguration));
        OnPropertyChanged(nameof(HasDelegationConfiguration));
        OnPropertyChanged(nameof(AttributeWritePermission));
        OnPropertyChanged(nameof(HasAttributeWritePermission));
        OnPropertyChanged(nameof(ShowsStandardIdentity));
        OnPropertyChanged(nameof(ShowsSavedDescription));
        OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Refusal));
        OnPropertyChanged(nameof(HasRefusal));
        OnPropertyChanged(nameof(IsLoadingMembership));
        OnPropertyChanged(nameof(MembershipRefusal));
        OnPropertyChanged(nameof(HasMembershipRefusal));
        OnPropertyChanged(nameof(MembershipCompleteness));
        OnPropertyChanged(nameof(MembershipDetails));
        OnPropertyChanged(nameof(HasMembershipDetails));
        LoadMembershipCommand.NotifyCanExecuteChanged();
    }
}
