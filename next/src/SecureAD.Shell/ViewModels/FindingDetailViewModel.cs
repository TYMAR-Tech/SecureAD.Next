using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed record FindingDetailContent(FindingListItem Saved)
{
    internal SavedAccountSetting? AccountSetting { get; init; }
    internal SavedDelegationConfiguration? DelegationConfiguration { get; init; }
    internal SavedAttributeWritePermission? AttributeWritePermission { get; init; }
    internal SavedGmsaPasswordReaders? GmsaPasswordReaders { get; init; }
    internal SavedGpoDirectoryPermission? GpoDirectoryPermission { get; init; }
    internal Func<GpoDirectoryPermissionMark?, CancellationToken, Task<Result<SavedGpoDirectoryPermission>>>? ReadGpoDirectoryPermission { get; init; }
    internal Func<GmsaPasswordReaderMark?, CancellationToken, Task<Result<SavedGmsaPasswordReaders>>>? ReadGmsaPasswordReaders { get; init; }
    internal SavedDuplicateSpn? DuplicateSpn { get; init; }
    internal SavedSidHistory? SidHistory { get; init; }
    internal SavedProtectionMarker? ProtectionMarker { get; init; }
    internal SavedOwnershipAssessment? OwnershipAssessment { get; init; }
    internal SavedReplicationPermission? ReplicationPermission { get; init; }
    internal SavedServiceRegistrations? ServiceRegistration { get; init; }
    internal SavedGroupReview? GroupReview { get; init; }
    internal SavedCircularMembershipLoop? CircularMembership { get; init; }
    internal SavedBroadMembershipPage<SavedBroadIdentity>? BroadMembership { get; init; }
    internal SavedBroadMembershipPage<AdministrativeMembershipLimitation>? BroadMembershipLimitations { get; init; }
    internal SavedServiceAccountDetails? ServiceAccount { get; init; }
    internal SavedPermissionControl? PermissionControl { get; init; }

    internal static FindingDetailContent FromSaved(FindingListItem saved) => new(saved);
}

internal sealed class CapturedAccountSettingViewModel(SavedAccountSetting setting)
{
    public string Setting => setting.SettingName + ": Enabled";
    public string AccountState => setting.AccountControl.IsDisabled ? "Disabled" : "Enabled";
    public bool HasControllerRoleNote => setting.Delegation?.IsComputer == true;
    public string ControllerRoleNote => "Domain-controller role is not independently verified by this saved finding.";
    public bool HasControllerDisagreement => setting.Delegation is { } context
        && (context.ControllerSignals.SignalsDisagree
            || (!context.IsComputer && setting.AccountControl.HasDomainControllerFlag));
    public string ControllerDisagreement => "Captured controller indicators disagree. Verify the actual role before changing delegation.";
}

internal sealed partial class FindingDetailViewModel : ObservableObject
{
    private readonly FindingRowViewModel _selected;
    private readonly Func<CancellationToken, Task<Result<FindingDetailContent>>> _read;
    private readonly Func<bool> _current;
    private readonly Func<DelegationConfigurationMark?, CancellationToken, Task<Result<SavedDelegationConfiguration>>>? _readDelegation;
    private readonly Func<AttributeWritePermissionMark?, CancellationToken, Task<Result<SavedAttributeWritePermission>>>? _readWritePermission;
    private readonly Func<DuplicateSpnMark?, CancellationToken, Task<Result<SavedDuplicateSpn>>>? _readDuplicateSpn;
    private readonly Func<SidHistoryMark?, CancellationToken, Task<Result<SavedSidHistory>>>? _readSidHistory;
    private readonly Func<ReplicationPermissionMark?, CancellationToken, Task<Result<SavedReplicationPermission>>>? _readReplication;
    private readonly ServiceRegistrationReads? _serviceReads;
    private readonly Func<GroupReviewReferenceMark?, CancellationToken, Task<Result<SavedGroupReferences>>>? _readGroupReferences;
    private readonly CircularMembershipReads? _circularReads;
    private readonly BroadMembershipReads? _broadReads;
    private readonly ServiceAccountReads? _serviceAccountReads;
    private readonly Func<PermissionControlMark?, CancellationToken, Task<Result<SavedPermissionControlChain>>>? _readPermissionControl;
    private CancellationTokenSource? _pending;
    private bool _active = true;

    internal FindingDetailViewModel(FindingRowViewModel selected,
        Func<CancellationToken, Task<Result<FindingDetailContent>>> read, Func<bool> current,
        Func<DelegationConfigurationMark?, CancellationToken, Task<Result<SavedDelegationConfiguration>>>? readDelegation,
        Func<AttributeWritePermissionMark?, CancellationToken, Task<Result<SavedAttributeWritePermission>>>? readWritePermission,
        Func<DuplicateSpnMark?, CancellationToken, Task<Result<SavedDuplicateSpn>>>? readDuplicateSpn,
        Func<SidHistoryMark?, CancellationToken, Task<Result<SavedSidHistory>>>? readSidHistory,
        Func<ReplicationPermissionMark?, CancellationToken, Task<Result<SavedReplicationPermission>>>? readReplication,
        ServiceRegistrationReads? serviceReads,
        Func<GroupReviewReferenceMark?, CancellationToken, Task<Result<SavedGroupReferences>>>? readGroupReferences,
        CircularMembershipReads? circularReads,
        BroadMembershipReads? broadReads,
        ServiceAccountReads? serviceAccountReads,
        Func<PermissionControlMark?, CancellationToken, Task<Result<SavedPermissionControlChain>>>? readPermissionControl)
    {
        (_selected, _read, _current, _readDelegation) = (selected, read, current, readDelegation);
        _readWritePermission = readWritePermission;
        _readDuplicateSpn = readDuplicateSpn;
        _readSidHistory = readSidHistory;
        _readReplication = readReplication;
        _serviceReads = serviceReads;
        _readGroupReferences = readGroupReferences;
        _circularReads = circularReads;
        _broadReads = broadReads;
        _serviceAccountReads = serviceAccountReads;
        _readPermissionControl = readPermissionControl;
        ReadCompletion = LoadAsync();
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
    public GmsaPasswordReadersViewModel? GmsaPasswordReaders { get; private set; }
    public bool HasGmsaPasswordReaders => GmsaPasswordReaders is not null;
    public GpoDirectoryPermissionViewModel? GpoDirectoryPermission { get; private set; }
    public bool HasGpoDirectoryPermission => GpoDirectoryPermission is not null;
    public DuplicateSpnViewModel? DuplicateSpn { get; private set; }
    public bool HasDuplicateSpn => DuplicateSpn is not null;
    public SidHistoryViewModel? SidHistory { get; private set; }
    public bool HasSidHistory => SidHistory is not null;
    public ProtectionMarkerViewModel? ProtectionMarker { get; private set; }
    public bool HasProtectionMarker => ProtectionMarker is not null;
    public OwnershipAssessmentViewModel? OwnershipAssessment { get; private set; }
    public bool HasOwnershipAssessment => OwnershipAssessment is not null;
    public ReplicationPermissionViewModel? ReplicationPermission { get; private set; }
    public bool HasReplicationPermission => ReplicationPermission is not null;
    public ServiceRegistrationViewModel? ServiceRegistration { get; private set; }
    public bool HasServiceRegistration => ServiceRegistration is not null;
    public GroupReviewViewModel? GroupReview { get; private set; }
    public bool HasGroupReview => GroupReview is not null;
    public CircularMembershipViewModel? CircularMembership { get; private set; }
    public bool HasCircularMembership => CircularMembership is not null;
    public BroadMembershipViewModel? BroadMembership { get; private set; }
    public bool HasBroadMembership => BroadMembership is not null;
    public ServiceAccountViewModel? ServiceAccount { get; private set; }
    public bool HasServiceAccount => ServiceAccount is not null;
    public PermissionControlViewModel? PermissionControl { get; private set; }
    public bool HasPermissionControl => PermissionControl is not null;
    public bool ShowsStandardPresentation => !HasPermissionControl;
    public bool ShowsStandardIdentity => HasFinding && !HasDelegationConfiguration && !HasAttributeWritePermission && !HasGmsaPasswordReaders && !HasGpoDirectoryPermission && !HasDuplicateSpn && !HasSidHistory && !HasProtectionMarker && !HasOwnershipAssessment && !HasReplicationPermission && !HasServiceRegistration && !HasGroupReview && !HasCircularMembership && !HasBroadMembership && !HasServiceAccount && !HasPermissionControl;
    public bool ShowsSavedDescription => HasFinding && !HasCapturedSetting && !HasDelegationConfiguration && !HasAttributeWritePermission && !HasGmsaPasswordReaders && !HasGpoDirectoryPermission && !HasDuplicateSpn && !HasSidHistory && !HasProtectionMarker && !HasOwnershipAssessment && !HasReplicationPermission && !HasServiceRegistration && !HasGroupReview && !HasCircularMembership && !HasBroadMembership && !HasServiceAccount && !HasPermissionControl;
    public bool IsLoading { get; private set; }
    public string? Refusal { get; private set; }
    public bool HasRefusal => Refusal is not null;
    public Task ReadCompletion { get; private set; }

    internal bool CheckCurrent()
    {
        if (_active && _current()) return true;
        Refusal = SavedPathText.Get("GenerationChanged");
        GpoDirectoryPermission?.Suspend();
        GpoDirectoryPermission = null;
        GmsaPasswordReaders?.Suspend();
        GmsaPasswordReaders = null;
        Finding = null;
        CapturedSetting = null;
        DelegationConfiguration?.Suspend();
        DelegationConfiguration = null;
        AttributeWritePermission?.Suspend();
        AttributeWritePermission = null;
        DuplicateSpn?.Suspend();
        DuplicateSpn = null;
        SidHistory?.Suspend();
        SidHistory = null;
        ProtectionMarker = null;
        OwnershipAssessment = null;
        ReplicationPermission?.Suspend();
        ReplicationPermission = null;
        ServiceRegistration?.Suspend();
        ServiceRegistration = null;
        GroupReview?.Suspend(); GroupReview = null;
        CircularMembership?.Suspend(); CircularMembership = null;
        BroadMembership?.Suspend(); BroadMembership = null;
        ServiceAccount?.Suspend(); ServiceAccount = null;
        PermissionControl?.Suspend(); PermissionControl = null;
        Announce();
        return false;
    }

    private async Task LoadAsync()
    {
        _pending?.Cancel();
        using var pending = new CancellationTokenSource();
        _pending = pending;
        IsLoading = true;
        Refusal = null;
        Announce();
        try
        {
            if (!_active || !_current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            var answer = await _read(pending.Token);
            if (!_active || pending.IsCancellationRequested || !ReferenceEquals(_pending, pending)) return;
            if (!_current()) throw new InvalidOperationException(SavedPathText.Get("GenerationChanged"));
            if (!answer.IsSuccess) throw new InvalidDataException(answer.Error.Description);
            var content = answer.Value;
            if ((content.Saved with { Membership = null }) != (_selected.Saved with { Membership = null }))
                throw new InvalidDataException("The saved explanation does not match the selected finding.");
            {
                if (content.Saved.Membership is not null)
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
                if (content.Saved.RuleId == "SEC-102")
                {
                    if (content.GmsaPasswordReaders is not { Context: not null } readers || content.ReadGmsaPasswordReaders is not { } readGmsa
                        || !readers.Context.Matches(content.Saved) || !readers.IsExpectedPage(-1))
                        throw new InvalidDataException(SavedGmsaPasswordReaders.InvalidDetails);
                    GmsaPasswordReaders = new(readers, readGmsa, CheckCurrent);
                }
                else if (content.GmsaPasswordReaders is not null)
                    throw new InvalidDataException(SavedGmsaPasswordReaders.InvalidDetails);
                if (SavedGpoDirectoryPermission.SupportsRule(content.Saved.RuleId))
                {
                    if (content.GpoDirectoryPermission is not { Context: not null } gpo || content.ReadGpoDirectoryPermission is not { } readGpo
                        || !gpo.Context.Matches(content.Saved) || !gpo.IsExpectedPage(-1))
                        throw new InvalidDataException(SavedGpoDirectoryPermission.InvalidDetails);
                    GpoDirectoryPermission = new(gpo, readGpo, CheckCurrent);
                }
                else if (content.GpoDirectoryPermission is not null)
                    throw new InvalidDataException(SavedGpoDirectoryPermission.InvalidDetails);
                if (content.Saved.RuleId == "SEC-026")
                {
                    if (content.DuplicateSpn is not { Context: not null } duplicate || _readDuplicateSpn is null
                        || !duplicate.Context.Matches(content.Saved) || !duplicate.IsExpectedPage(null))
                        throw new InvalidDataException(SavedDuplicateSpn.InvalidDetails);
                    DuplicateSpn = new(duplicate, _readDuplicateSpn, CheckCurrent);
                }
                else if (content.DuplicateSpn is not null)
                    throw new InvalidDataException(SavedDuplicateSpn.InvalidDetails);
                if (content.Saved.RuleId == "SEC-027")
                {
                    if (content.SidHistory is not { Context: not null } history || _readSidHistory is null
                        || !history.Context.Matches(content.Saved) || !history.IsExpectedPage(null))
                        throw new InvalidDataException(SavedSidHistory.InvalidDetails);
                    SidHistory = new(history, _readSidHistory, CheckCurrent);
                }
                else if (content.SidHistory is not null)
                    throw new InvalidDataException(SavedSidHistory.InvalidDetails);
                if (content.Saved.RuleId == "SEC-030")
                {
                    if (content.ProtectionMarker is not { } marker || !marker.Matches(content.Saved))
                        throw new InvalidDataException(SavedProtectionMarker.InvalidDetails);
                    ProtectionMarker = new(marker);
                }
                else if (content.ProtectionMarker is not null)
                    throw new InvalidDataException(SavedProtectionMarker.InvalidDetails);
                if (content.Saved.RuleId is "SEC-031" or "SEC-032")
                {
                    if (content.OwnershipAssessment is not { } ownership || !ownership.Matches(content.Saved))
                        throw new InvalidDataException(SavedOwnershipAssessment.InvalidDetails);
                    OwnershipAssessment = new(ownership);
                }
                else if (content.OwnershipAssessment is not null)
                    throw new InvalidDataException(SavedOwnershipAssessment.InvalidDetails);
                if (content.Saved.RuleId == "SEC-060")
                {
                    if (content.PermissionControl is not { } control || _readPermissionControl is null || !control.Matches(content.Saved))
                        throw new InvalidDataException(SavedPermissionControl.InvalidDetails);
                    PermissionControl = new(control, _readPermissionControl, CheckCurrent);
                }
                else if (content.PermissionControl is not null) throw new InvalidDataException(SavedPermissionControl.InvalidDetails);
                if (content.Saved.RuleId == "SEC-002")
                {
                    if (content.ReplicationPermission is not { Context: not null } replication || _readReplication is null
                        || !replication.Context.Matches(content.Saved) || !replication.IsExpectedPage(-1))
                        throw new InvalidDataException(SavedReplicationPermission.InvalidDetails);
                    ReplicationPermission = new(replication, _readReplication, CheckCurrent);
                }
                else if (content.ReplicationPermission is not null)
                    throw new InvalidDataException(SavedReplicationPermission.InvalidDetails);
                if (content.Saved.RuleId == "SEC-021")
                {
                    if (content.ServiceRegistration is not { Context: not null } service || _serviceReads is null
                        || !service.Context.Matches(content.Saved) || !ServiceRegistrationViewModel.ValidNames(service, service.Context, null))
                        throw new InvalidDataException(SavedServiceRegistrations.InvalidDetails);
                    ServiceRegistration = new(service, _serviceReads, CheckCurrent);
                }
                else if (content.ServiceRegistration is not null) throw new InvalidDataException(SavedServiceRegistrations.InvalidDetails);
                if (content.Saved.RuleId is "SEC-050" or "SEC-051")
                {
                    if (content.GroupReview is not { } review || _readGroupReferences is null || !review.Matches(content.Saved))
                        throw new InvalidDataException(SavedGroupReview.InvalidDetails(content.Saved.RuleId));
                    GroupReview = new(review, _readGroupReferences, CheckCurrent);
                }
                else if (content.GroupReview is not null) throw new InvalidDataException("The selected finding has unrelated membership-review details.");
                if (content.Saved.RuleId is "SEC-061" or "SEC-062")
                {
                    if (content.BroadMembership is not { Context: not null } broad || _broadReads is null
                        || !broad.Context.Matches(content.Saved) || !broad.IsExpectedPage(null)
                        || (broad.Context.LimitationCount > 0) != (content.BroadMembershipLimitations is not null)
                        || content.BroadMembershipLimitations is { } limits && (limits.Context != broad.Context || !limits.IsExpectedPage(null)))
                        throw new InvalidDataException(SavedBroadMembershipContext.InvalidDetails);
                    BroadMembership = new(broad, content.BroadMembershipLimitations, _broadReads, CheckCurrent);
                }
                else if (content.BroadMembership is not null || content.BroadMembershipLimitations is not null)
                    throw new InvalidDataException(SavedBroadMembershipContext.InvalidDetails);
                if (content.Saved.RuleId is "SEC-100" or "SEC-101")
                {
                    if (content.ServiceAccount is not { } serviceAccount || _serviceAccountReads is null
                        || !serviceAccount.Matches(content.Saved))
                        throw new InvalidDataException(SavedServiceAccountContext.InvalidDetails);
                    ServiceAccount = new(serviceAccount, _serviceAccountReads, CheckCurrent);
                }
                else if (content.ServiceAccount is not null)
                    throw new InvalidDataException(SavedServiceAccountContext.InvalidDetails);
                if (content.Saved.RuleId == "SEC-052")
                {
                    if (content.CircularMembership is not { Context: not null } circular || _circularReads is null
                        || !circular.Context.Matches(content.Saved) || !circular.IsExpectedPage(null))
                        throw new InvalidDataException(SavedCircularMembershipContext.InvalidDetails);
                    CircularMembership = new(circular, _circularReads, CheckCurrent);
                    Finding = new(content.Saved with { CircularInventoryComplete = circular.Context.InventoryComplete,
                        EvidenceIsComplete = circular.Context.InventoryComplete }, _current);
                }
                else
                {
                    if (content.CircularMembership is not null) throw new InvalidDataException("The selected finding has unrelated circular-membership details.");
                    Finding = new(content.Saved, _current);
                }
            }
        }
        catch (OperationCanceledException) when (pending.IsCancellationRequested) { }
        catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException
            or InvalidOperationException or ArgumentException or Microsoft.Data.Sqlite.SqliteException)
        {
            if (_active && !pending.IsCancellationRequested && ReferenceEquals(_pending, pending))
            {
                GpoDirectoryPermission?.Suspend();
                GpoDirectoryPermission = null;
                GmsaPasswordReaders?.Suspend();
                GmsaPasswordReaders = null;
                if (!_current())
                {
                    Refusal = SavedPathText.Get("GenerationChanged");
                    Finding = null;
                    CapturedSetting = null;
                    DelegationConfiguration?.Suspend();
                    DelegationConfiguration = null;
                    AttributeWritePermission?.Suspend();
                    AttributeWritePermission = null;
                    GmsaPasswordReaders?.Suspend();
                    GmsaPasswordReaders = null;
                    DuplicateSpn?.Suspend();
                    DuplicateSpn = null;
                    SidHistory?.Suspend();
                    SidHistory = null;
                    ProtectionMarker = null;
                    OwnershipAssessment = null;
                    ReplicationPermission?.Suspend();
                    ReplicationPermission = null;
                    ServiceRegistration?.Suspend();
                    ServiceRegistration = null;
                    GroupReview?.Suspend(); GroupReview = null;
                    CircularMembership?.Suspend(); CircularMembership = null;
                    BroadMembership?.Suspend(); BroadMembership = null;
                    ServiceAccount?.Suspend(); ServiceAccount = null;
                    PermissionControl?.Suspend(); PermissionControl = null;
                }
                else Refusal = error.Message;
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
        }
    }

    internal void Suspend()
    {
        _active = false;
        GpoDirectoryPermission?.Suspend();
        GpoDirectoryPermission = null;
        _pending?.Cancel();
        Finding = null;
        CapturedSetting = null;
        GmsaPasswordReaders?.Suspend();
        GmsaPasswordReaders = null;
        DelegationConfiguration?.Suspend();
        DelegationConfiguration = null;
        AttributeWritePermission?.Suspend();
        AttributeWritePermission = null;
        DuplicateSpn?.Suspend();
        DuplicateSpn = null;
        SidHistory?.Suspend();
        SidHistory = null;
        ProtectionMarker = null;
        OwnershipAssessment = null;
        ReplicationPermission?.Suspend();
        ReplicationPermission = null;
        ServiceRegistration?.Suspend();
        ServiceRegistration = null;
        GroupReview?.Suspend(); GroupReview = null;
        CircularMembership?.Suspend(); CircularMembership = null;
        BroadMembership?.Suspend(); BroadMembership = null;
        ServiceAccount?.Suspend(); ServiceAccount = null;
        PermissionControl?.Suspend(); PermissionControl = null;
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
        OnPropertyChanged(nameof(GmsaPasswordReaders));
        OnPropertyChanged(nameof(HasGmsaPasswordReaders));
        OnPropertyChanged(nameof(GpoDirectoryPermission));
        OnPropertyChanged(nameof(HasGpoDirectoryPermission));
        OnPropertyChanged(nameof(DuplicateSpn));
        OnPropertyChanged(nameof(HasDuplicateSpn));
        OnPropertyChanged(nameof(SidHistory));
        OnPropertyChanged(nameof(HasSidHistory));
        OnPropertyChanged(nameof(ProtectionMarker));
        OnPropertyChanged(nameof(HasProtectionMarker));
        OnPropertyChanged(nameof(OwnershipAssessment));
        OnPropertyChanged(nameof(HasOwnershipAssessment));
        OnPropertyChanged(nameof(ReplicationPermission));
        OnPropertyChanged(nameof(HasReplicationPermission));
        OnPropertyChanged(nameof(ShowsStandardIdentity));
        OnPropertyChanged(nameof(ShowsSavedDescription));
        OnPropertyChanged(nameof(IsLoading));
        OnPropertyChanged(nameof(Refusal));
        OnPropertyChanged(nameof(HasRefusal));
        OnPropertyChanged(nameof(ServiceRegistration));
        OnPropertyChanged(nameof(HasServiceRegistration));
        OnPropertyChanged(nameof(GroupReview)); OnPropertyChanged(nameof(HasGroupReview));
        OnPropertyChanged(nameof(CircularMembership)); OnPropertyChanged(nameof(HasCircularMembership));
        OnPropertyChanged(nameof(BroadMembership)); OnPropertyChanged(nameof(HasBroadMembership));
        OnPropertyChanged(nameof(ServiceAccount)); OnPropertyChanged(nameof(HasServiceAccount));
        OnPropertyChanged(nameof(PermissionControl)); OnPropertyChanged(nameof(HasPermissionControl));
        OnPropertyChanged(nameof(ShowsStandardPresentation));
    }
}
