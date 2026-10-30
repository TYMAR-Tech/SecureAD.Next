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
                return Result<FindingDetailContent>.Success(content);
            }, token, membership ? "read selected finding membership" : "read selected finding"),
            finding.IsCurrent);
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
