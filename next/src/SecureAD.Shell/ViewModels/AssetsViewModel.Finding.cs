using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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
        FindingDetails = new(finding, (membership, token) =>
            ReadBoundAsync(bundle, finding.IsCurrent, reader =>
            {
                if (finding.Saved.Reference is not { } reference)
                    return Result<FindingDetailContent>.Failure(AuditError.Create(ErrorCategory.Shell,
                        "FindingIdentityUnavailable", ErrorSeverity.Failed,
                        "The selected finding has no saved identity.", bundle));
                var answer = reader.ReadSelectedFinding(bundle, reference, membership);
                if (!answer.IsSuccess) return Result<FindingDetailContent>.Failure(answer.Error);
                // Formatting requested chains belongs to the read worker, never a hidden WPF binding.
                var content = FindingDetailContent.FromSaved(answer.Value);
                if (!membership && SavedAccountSetting.SupportsRule(answer.Value.RuleId))
                {
                    var setting = reader.ReadAccountSetting(bundle, reference);
                    if (!setting.IsSuccess) return Result<FindingDetailContent>.Failure(setting.Error);
                    content = content with { AccountSetting = setting.Value };
                }
                if (!membership && answer.Value.RuleId is "SEC-012" or "SEC-013")
                {
                    var delegation = answer.Value.RuleId == "SEC-013"
                        ? reader.ReadResourceDelegation(bundle, reference, null)
                        : reader.ReadConstrainedDelegation(bundle, reference, null);
                    if (!delegation.IsSuccess) return Result<FindingDetailContent>.Failure(delegation.Error);
                    content = content with { DelegationConfiguration = delegation.Value };
                }
                if (!membership && SavedAttributeWritePermission.SupportsRule(answer.Value.RuleId))
                {
                    var permission = reader.ReadAttributeWritePermission(bundle, reference, null);
                    if (!permission.IsSuccess) return Result<FindingDetailContent>.Failure(permission.Error);
                    content = content with { AttributeWritePermission = permission.Value };
                }
                if (!membership && answer.Value.RuleId == "SEC-026")
                {
                    var duplicate = reader.ReadDuplicateSpn(bundle, reference, null);
                    if (!duplicate.IsSuccess) return Result<FindingDetailContent>.Failure(duplicate.Error);
                    content = content with { DuplicateSpn = duplicate.Value };
                }
                if (!membership && answer.Value.RuleId == "SEC-027")
                {
                    var history = reader.ReadSidHistory(bundle, reference, null);
                    if (!history.IsSuccess) return Result<FindingDetailContent>.Failure(history.Error);
                    content = content with { SidHistory = history.Value };
                }
                if (!membership && answer.Value.RuleId == "SEC-030")
                {
                    var marker = reader.ReadProtectionMarker(bundle, reference);
                    if (!marker.IsSuccess) return Result<FindingDetailContent>.Failure(marker.Error);
                    content = content with { ProtectionMarker = marker.Value };
                }
                return Result<FindingDetailContent>.Success(content);
            }, token, membership ? "read selected finding membership" : "read selected finding"),
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
                token, "read selected SID-history values"));
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
}
