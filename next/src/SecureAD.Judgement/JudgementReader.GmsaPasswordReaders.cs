using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads one selected gMSA finding's saved context and holder page without loading or replaying its proof.</summary>
    public Result<SavedGmsaPasswordReaders> ReadGmsaPasswordReaders(FindingReference reference, GmsaPasswordReaderMark? after)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedGmsaPasswordReaders>.Failure(selected.Error);
        if (selected.Value.RuleId != "SEC-102" || after is { } mark
            && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
                || mark.ObjectGuid != selected.Value.ObjectGuid || mark.Ordinal < 0))
            return Result<SavedGmsaPasswordReaders>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed, SavedGmsaPasswordReaders.InvalidDetails, BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        GmsaPasswordReaderContext context;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,context FROM finding_gmsa_reader WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetString(0) != Description.GenerationId.ToString("D")) throw GmsaPasswordReaderStorage.Invalid();
            context = JsonSerializer.Deserialize<GmsaPasswordReaderContext>(row.GetString(1), ProofSerialization.Options)
                ?? throw GmsaPasswordReaderStorage.Invalid();
            if (!context.Matches(selected.Value)) throw GmsaPasswordReaderStorage.Invalid();
        }
        var holders = new List<SavedGmsaPasswordReaderHolder>();
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                SELECT ordinal,sid,scope,name,direct,grant_count,inherited,null_dacl,membership_complete
                FROM finding_gmsa_reader_holder WHERE finding_id=$id AND ordinal>$after ORDER BY ordinal LIMIT $limit
                """;
            command.Parameters.AddWithValue("$id", reference.FindingId);
            command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
            command.Parameters.AddWithValue("$limit", SavedGmsaPasswordReaders.PageSize + 1);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                holders.Add(new(row.GetInt32(0), row.GetString(1), row.IsDBNull(2) ? null : row.GetString(2),
                    row.IsDBNull(3) ? null : row.GetString(3), Bit(4), row.GetInt32(5), Bit(6), Bit(7), Bit(8)));
            }
            bool Bit(int column) => row.GetInt64(column) switch { 0 => false, 1 => true, _ => throw GmsaPasswordReaderStorage.Invalid() };
        }
        GmsaPasswordReaderMark? next = null;
        if (holders.Count > SavedGmsaPasswordReaders.PageSize)
        {
            holders.RemoveAt(SavedGmsaPasswordReaders.PageSize);
            next = new(reference.GenerationId, reference.FindingId, context.ObjectGuid, holders[^1].Ordinal);
        }
        var page = new SavedGmsaPasswordReaders(context, holders, next);
        if (!page.IsExpectedPage(after?.Ordinal ?? -1)) throw GmsaPasswordReaderStorage.Invalid();
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedGmsaPasswordReaders>.Success(page);
    }
}
