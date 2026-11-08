using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads one current saved ownership header without rights, membership or protection replay.</summary>
    public Result<SavedOwnershipAssessment> ReadOwnershipAssessment(FindingReference reference)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedOwnershipAssessment>.Failure(selected.Error);
        if (selected.Value.RuleId is not ("SEC-031" or "SEC-032"))
            return Result<SavedOwnershipAssessment>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged",
                ErrorSeverity.Failed, SavedOwnershipAssessment.InvalidDetails, BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT owner_sid,owner_name,standing,object_class,membership_was_complete
            FROM finding_object_ownership WHERE finding_id=$id
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string sid || row.GetValue(2) is not string standingText
            || !Enum.TryParse<ObjectOwnerStanding>(standingText, out var standing) || !Enum.IsDefined(standing)
            || row.GetValue(3) is not string kind || row.GetValue(4) is not long complete || complete is not (0 or 1))
            throw new InvalidDataException(SavedOwnershipAssessment.InvalidDetails);
        var finding = selected.Value;
        var assessment = new SavedOwnershipAssessment(reference, finding.RuleId, finding.Subject,
            new(finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, kind), finding.PrincipalName,
            sid, row.IsDBNull(1) ? null : row.GetString(1), standing, complete == 1, finding.Coverage);
        if (!assessment.Matches(finding)) throw new InvalidDataException(SavedOwnershipAssessment.InvalidDetails);
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedOwnershipAssessment>.Success(assessment);
    }
}
