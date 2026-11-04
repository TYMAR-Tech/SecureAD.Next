using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads the exact saved SEC-030 assessment identity without replaying its protection inputs.</summary>
    public Result<SavedProtectionMarker> ReadProtectionMarker(FindingReference reference)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedProtectionMarker>.Failure(selected.Error);
        if (selected.Value.RuleId != "SEC-030")
            return Result<SavedProtectionMarker>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged",
                ErrorSeverity.Failed, SavedProtectionMarker.InvalidDetails, BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT sid FROM finding_admincount_without_protection WHERE finding_id=$id";
        command.Parameters.AddWithValue("$id", reference.FindingId);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string sid) throw new InvalidDataException(SavedProtectionMarker.InvalidDetails);
        var finding = selected.Value;
        var marker = new SavedProtectionMarker(reference, finding.Subject,
            new(finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass),
            finding.PrincipalName, sid, finding.Coverage);
        if (!marker.Matches(finding)) throw new InvalidDataException(SavedProtectionMarker.InvalidDetails);
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedProtectionMarker>.Success(marker);
    }
}
