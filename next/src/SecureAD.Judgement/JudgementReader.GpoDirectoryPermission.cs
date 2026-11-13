using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads prepared GPO-directory facts and one selected original-entry page without schema or authorization replay.</summary>
    public Result<SavedGpoDirectoryPermission> ReadGpoDirectoryPermission(FindingReference reference, GpoDirectoryPermissionMark? after)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedGpoDirectoryPermission>.Failure(selected.Error);
        if (!SavedGpoDirectoryPermission.SupportsRule(selected.Value.RuleId) || after is { } mark
            && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
                || mark.TargetGuid != selected.Value.ObjectGuid || mark.Ordinal < 0))
            return Result<SavedGpoDirectoryPermission>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed, SavedGpoDirectoryPermission.InvalidDetails, BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        GpoDirectoryPermissionContext context;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,context FROM finding_gpo_directory WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetString(0) != Description.GenerationId.ToString("D")) throw GpoDirectoryPermissionRules.Invalid();
            context = JsonSerializer.Deserialize<GpoDirectoryPermissionContext>(row.GetString(1), ProofSerialization.Options)
                ?? throw GpoDirectoryPermissionRules.Invalid();
            if (!context.Matches(selected.Value)) throw GpoDirectoryPermissionRules.Invalid();
        }
        var entries = new List<SavedGpoDirectoryEntry>();
        using (var count = _connection.CreateCommand())
        {
            count.CommandText = "SELECT COUNT(*) FROM finding_gpo_directory_entry WHERE finding_id=$id AND selected=1";
            count.Parameters.AddWithValue("$id", reference.FindingId);
            if ((long)count.ExecuteScalar()! != context.EntryCount) throw GpoDirectoryPermissionRules.Invalid();
        }
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                SELECT ordinal,display FROM finding_gpo_directory_entry
                WHERE finding_id=$id AND selected=1 AND ordinal>$after ORDER BY ordinal LIMIT $limit
                """;
            command.Parameters.AddWithValue("$id", reference.FindingId);
            command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
            command.Parameters.AddWithValue("$limit", SavedGpoDirectoryPermission.PageSize + 1);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                var entry = JsonSerializer.Deserialize<SavedGpoDirectoryEntry>(row.GetString(1), ProofSerialization.Options)
                    ?? throw GpoDirectoryPermissionRules.Invalid();
                if (entry.Ordinal != row.GetInt32(0)) throw GpoDirectoryPermissionRules.Invalid();
                entries.Add(entry);
            }
        }
        GpoDirectoryPermissionMark? next = null;
        if (entries.Count > SavedGpoDirectoryPermission.PageSize)
        {
            entries.RemoveAt(SavedGpoDirectoryPermission.PageSize);
            next = new(reference.GenerationId, reference.FindingId, selected.Value.ObjectGuid, entries[^1].Ordinal);
        }
        var page = new SavedGpoDirectoryPermission(context, entries, next);
        if (!page.IsExpectedPage(after?.Ordinal ?? -1)
            || after is null && entries.Count != Math.Min(context.EntryCount, SavedGpoDirectoryPermission.PageSize))
            throw GpoDirectoryPermissionRules.Invalid();
        return Result<SavedGpoDirectoryPermission>.Success(page);
    }
}
