using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Kernel;

namespace SecureAD.Shell.ViewModels;

internal sealed partial class AssetsViewModel
{
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasFindingPresentation))]
    private FindingDetailViewModel? _findingDetails;

    public bool HasFindingPresentation => FindingDetails is not null;

    [RelayCommand]
    public void OpenFinding(FindingRowViewModel? finding)
    {
        if (finding is null || BundlePath is not { } bundle || _captureIsRunning) return;
        FindingDetails?.Suspend();
        FindingDetails = new(finding, token =>
            ReadBoundAsync(bundle, finding.IsCurrent, reader =>
            {
                if (finding.Saved.Reference is not { } reference)
                    return Result<FindingDetailContent>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed,
                        "The selected finding has no saved identity.", bundle));
                var answer = reader.ReadSelectedFinding(bundle, reference, false);
                if (!answer.IsSuccess) return Result<FindingDetailContent>.Failure(answer.Error);
                var content = FindingDetailContent.FromSaved(answer.Value);
                if (SavedAccountSetting.SupportsRule(answer.Value.RuleId))
                {
                    var setting = reader.ReadAccountSetting(bundle, reference);
                    if (!setting.IsSuccess) return Result<FindingDetailContent>.Failure(setting.Error);
                    content = content with { AccountSetting = setting.Value };
                }
                if (answer.Value.RuleId is "SEC-012" or "SEC-013")
                {
                    var delegation = answer.Value.RuleId == "SEC-013"
                        ? reader.ReadResourceDelegation(bundle, reference, null)
                        : reader.ReadConstrainedDelegation(bundle, reference, null);
                    if (!delegation.IsSuccess) return Result<FindingDetailContent>.Failure(delegation.Error);
                    content = content with { DelegationConfiguration = delegation.Value };
                }
                if (SavedAttributeWritePermission.SupportsRule(answer.Value.RuleId))
                {
                    var permission = reader.ReadAttributeWritePermission(bundle, reference, null);
                    if (!permission.IsSuccess) return Result<FindingDetailContent>.Failure(permission.Error);
                    content = content with { AttributeWritePermission = permission.Value };
                }
                if (answer.Value.RuleId == "SEC-026")
                {
                    var duplicate = reader.ReadDuplicateSpn(bundle, reference, null);
                    if (!duplicate.IsSuccess) return Result<FindingDetailContent>.Failure(duplicate.Error);
                    content = content with { DuplicateSpn = duplicate.Value };
                }
                if (answer.Value.RuleId == "SEC-027")
                {
                    var history = reader.ReadSidHistory(bundle, reference, null);
                    if (!history.IsSuccess) return Result<FindingDetailContent>.Failure(history.Error);
                    content = content with { SidHistory = history.Value };
                }
                if (answer.Value.RuleId == "SEC-030")
                {
                    var marker = reader.ReadProtectionMarker(bundle, reference);
                    if (!marker.IsSuccess) return Result<FindingDetailContent>.Failure(marker.Error);
                    content = content with { ProtectionMarker = marker.Value };
                }
                if (answer.Value.RuleId is "SEC-031" or "SEC-032")
                {
                    var ownership = reader.ReadOwnershipAssessment(bundle, reference);
                    if (!ownership.IsSuccess) return Result<FindingDetailContent>.Failure(ownership.Error);
                    content = content with { OwnershipAssessment = ownership.Value };
                }
                if (answer.Value.RuleId == "SEC-060")
                {
                    var control = reader.ReadPermissionControl(bundle, reference);
                    if (!control.IsSuccess) return Result<FindingDetailContent>.Failure(control.Error);
                    content = content with { PermissionControl = control.Value };
                }
                if (answer.Value.RuleId == "SEC-002")
                {
                    var replication = reader.ReadReplicationPermission(bundle, reference, null);
                    if (!replication.IsSuccess) return Result<FindingDetailContent>.Failure(replication.Error);
                    content = content with { ReplicationPermission = replication.Value };
                }
                if (answer.Value.RuleId == "SEC-021")
                {
                    var service = reader.ReadServiceRegistrations(bundle, reference, null);
                    if (!service.IsSuccess) return Result<FindingDetailContent>.Failure(service.Error);
                    content = content with { ServiceRegistration = service.Value };
                }
                if (answer.Value.RuleId is "SEC-050" or "SEC-051")
                {
                    var review = reader.ReadGroupReview(bundle, reference);
                    if (!review.IsSuccess) return Result<FindingDetailContent>.Failure(review.Error);
                    content = content with { GroupReview = review.Value };
                }
                if (answer.Value.RuleId == "SEC-052")
                {
                    var circular = reader.ReadCircularMembershipLoop(bundle, reference, null);
                    if (!circular.IsSuccess) return Result<FindingDetailContent>.Failure(circular.Error);
                    content = content with { CircularMembership = circular.Value };
                }
                if (answer.Value.RuleId is "SEC-061" or "SEC-062")
                {
                    var broad = reader.ReadBroadMembershipSources(bundle, reference, null);
                    if (!broad.IsSuccess) return Result<FindingDetailContent>.Failure(broad.Error);
                    content = content with { BroadMembership = broad.Value };
                    if (broad.Value.Context.LimitationCount > 0)
                    {
                        var limitations = reader.ReadBroadMembershipLimitations(bundle, reference, null);
                        if (!limitations.IsSuccess) return Result<FindingDetailContent>.Failure(limitations.Error);
                        content = content with { BroadMembershipLimitations = limitations.Value };
                    }
                }
                if (answer.Value.RuleId is "SEC-100" or "SEC-101")
                {
                    var serviceAccount = reader.ReadServiceAccount(bundle, reference);
                    if (!serviceAccount.IsSuccess) return Result<FindingDetailContent>.Failure(serviceAccount.Error);
                    content = content with { ServiceAccount = serviceAccount.Value };
                }
                return Result<FindingDetailContent>.Success(content);
            }, token, "read selected finding"),
            finding.IsCurrent,
            (after, token) => ReadBoundAsync(bundle, finding.IsCurrent, reader =>
                finding.Saved.Reference is { } reference
                    ? finding.Saved.RuleId == "SEC-013"
                        ? reader.ReadResourceDelegation(bundle, reference, after)
                        : reader.ReadConstrainedDelegation(bundle, reference, after)
                    : Result<SavedDelegationConfiguration>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed,
                        "The selected finding has no saved identity.", bundle)),
                token, "read selected delegation services"),
            (after, token) => ReadBoundAsync(bundle, finding.IsCurrent, reader =>
                finding.Saved.Reference is { } reference
                    ? reader.ReadAttributeWritePermission(bundle, reference, after)
                    : Result<SavedAttributeWritePermission>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed, "The selected finding has no saved identity.", bundle)),
                token, "read selected write-permission entries"),
            (position, token) => ReadBoundAsync(bundle, finding.IsCurrent, reader =>
                finding.Saved.Reference is { } reference
                    ? reader.ReadDuplicateSpn(bundle, reference, position)
                    : Result<SavedDuplicateSpn>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed, "The selected finding has no saved identity.", bundle)),
                token, "read selected duplicate service names"),
            (after, token) => ReadBoundAsync(bundle, finding.IsCurrent, reader =>
                finding.Saved.Reference is { } reference
                    ? reader.ReadSidHistory(bundle, reference, after)
                    : Result<SavedSidHistory>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed, "The selected finding has no saved identity.", bundle)),
                token, "read selected SID-history values"),
            (after, token) => ReadBoundAsync(bundle, finding.IsCurrent, reader =>
                finding.Saved.Reference is { } reference
                    ? reader.ReadReplicationPermission(bundle, reference, after)
                    : Result<SavedReplicationPermission>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed, "The selected finding has no saved identity.", bundle)),
                token, "read selected replication-permission entries"),
            new ServiceRegistrationReads(
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadServiceRegistrations(bundle, finding.Saved.Reference!.Value, after), token, "read selected service names"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadInitialMemberships(bundle, finding.Saved.Reference!.Value, after), token, "read selected initial memberships"),
                (group, after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadMembershipRoutes(bundle, finding.Saved.Reference!.Value, group, after), token, "read selected membership routes"),
                (group, route, after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadMembershipSteps(bundle, finding.Saved.Reference!.Value, group, route, after), token, "read selected membership steps")),
            (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                reader => reader.ReadGroupReviewReferences(bundle, finding.Saved.Reference!.Value, after), token, "read saved direct references"),
            new CircularMembershipReads(
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadCircularMembershipLoop(bundle, finding.Saved.Reference!.Value, after), token, "read saved circular loop"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadCircularMembershipGroups(bundle, finding.Saved.Reference!.Value, after), token, "read saved circular groups"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadCircularMembershipLinks(bundle, finding.Saved.Reference!.Value, after), token, "read recorded circular membership links"),
                (group, member, after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadCircularMembershipWitnesses(bundle, finding.Saved.Reference!.Value, group, member, after), token, "read selected circular membership values"),
                OpenCircularGroup, ReviewCircularMembership),
            new BroadMembershipReads(
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadBroadMembershipSources(bundle, finding.Saved.Reference!.Value, after), token, "read saved broad identities"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadBroadMembershipLinks(bundle, finding.Saved.Reference!.Value, after), token, "read saved broad membership links"),
                (link, after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadBroadMembershipValues(bundle, finding.Saved.Reference!.Value, link, after), token, "read saved broad membership values"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadBroadMembershipLimitations(bundle, finding.Saved.Reference!.Value, after), token, "read saved broad membership limitations")),
            new ServiceAccountReads(
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadServiceAccountNames(bundle, finding.Saved.Reference!.Value, after), token, "read captured service-account names"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadServiceAccountEntryMemberships(bundle, finding.Saved.Reference!.Value, after), token, "read service-account entry memberships"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadServiceAccountLinks(bundle, finding.Saved.Reference!.Value, after), token, "read saved service-account links"),
                (link, after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadServiceAccountValues(bundle, finding.Saved.Reference!.Value, link, after), token, "read saved service-account values"),
                (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                    reader => reader.ReadServiceAccountLimitations(bundle, finding.Saved.Reference!.Value, after), token, "read saved service-account limitations")),
            (after, token) => ReadBoundAsync(bundle, finding.IsCurrent,
                reader => reader.ReadPermissionControlChain(bundle, finding.Saved.Reference!.Value, after), token, "read saved permission-control chain"));
    }

    [RelayCommand]
    public void CloseFindingDetails()
    {
        FindingDetails?.Suspend();
        FindingDetails = null;
    }

    [RelayCommand]
    private void OpenAffectedObject()
    {
        if (FindingDetails is not { } details || !details.CheckCurrent() || details.Finding is not { } finding) return;
        if (Opened is { } opened && opened.ObjectGuid == finding.Saved.ObjectGuid
            && opened.DistinguishedName.Equals(finding.DistinguishedName, StringComparison.OrdinalIgnoreCase))
            AnnounceObjectPresentation();
        else
            Open(finding.DistinguishedName, ObjectSectionCatalog.Overview, finding.Saved.ObjectGuid);
    }

    private void OpenCircularGroup(CircularMembershipGroup group)
    {
        if (FindingDetails is not { } details || !details.CheckCurrent() || details.CircularMembership is not { } circular
            || !circular.ContainsGroup(group)) return;
        Open(group.DistinguishedName, ObjectSectionCatalog.Overview, group.ObjectGuid);
    }

    private void ReviewCircularMembership(SavedCircularMembershipLink link)
    {
        if (FindingDetails is not { } details || !details.CheckCurrent() || details.CircularMembership is not { } circular
            || !circular.ContainsLoopLink(link)) return;
        Open(link.ContainingGroup.DistinguishedName, ObjectSectionCatalog.Membership, link.ContainingGroup.ObjectGuid);
    }
}
