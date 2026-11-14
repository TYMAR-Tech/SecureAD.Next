using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    public Result<SavedDuplicateSpn> ReadDuplicateSpn(FindingReference reference, DuplicateSpnMark? position)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedDuplicateSpn>.Failure(selected.Error);
        if (selected.Value.RuleId != "SEC-026" || position is { } mark
            && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
                || mark.SubjectGuid != selected.Value.ObjectGuid || mark.SpnIndex < 0 || mark.Offset < 0
                || mark.Offset % SavedDuplicateSpn.PageSize != 0 || !Enum.IsDefined(mark.Kind)))
            return Result<SavedDuplicateSpn>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged",
                ErrorSeverity.Failed, SavedDuplicateSpn.InvalidDetails, BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,typeof(proof),fingerprint FROM finding_duplicate_spn WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetString(0) != Description.GenerationId.ToString("D")
                || row.GetString(1) != "text" || row.GetValue(2) is not byte[] { Length: 32 })
                throw new InvalidDataException(SavedDuplicateSpn.InvalidDetails);
        }
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_duplicate_spn", "proof", reference.FindingId, readOnly: true);
        var page = DuplicateSpnProjection.Read(proof, selected.Value, Description, position, _readCancellation);
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedDuplicateSpn>.Success(page);
    }
}
