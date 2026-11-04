using SecureAD.Kernel;
using SecureAD.Kernel.Security;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads selected saved SID rows using the same catalogue interpretation as existing readback.</summary>
    public Result<SavedSidHistory> ReadSidHistory(FindingReference reference, SidHistoryMark? after = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedSidHistory>.Failure(selected.Error);
        if (selected.Value.RuleId != "SEC-027" || after is { } mark
            && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
                || mark.ObjectGuid != selected.Value.ObjectGuid || mark.Ordinal < -1 || !Enum.IsDefined(mark.Kind)))
            return Result<SavedSidHistory>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged",
                ErrorSeverity.Failed, SavedSidHistory.InvalidDetails, BundleDirectory));
        OpenPart(SecureAD.Evidence.StoreSegmentRole.PermissionProof);
        string? objectSid;
        int unreadable;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT object_sid,unreadable_values FROM finding_privileged_sid_history WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetValue(1) is not long count || count is < 0 or > int.MaxValue) throw Invalid();
            objectSid = row.IsDBNull(0) ? null : row.GetString(0);
            unreadable = (int)count;
        }
        var finding = selected.Value;
        var context = new SidHistoryContext(reference, finding.Subject,
            new(finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass),
            finding.PrincipalName, objectSid, unreadable, finding.Coverage);
        if (!context.Matches(finding)) throw Invalid();
        var kind = after?.Kind ?? SidHistoryPageKind.Flagged;
        var values = new List<SavedHistoryValue>();
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                SELECT ordinal,sid FROM finding_privileged_sid_history_value
                WHERE finding_id=$id AND ordinal>$after ORDER BY ordinal
                """;
            command.Parameters.AddWithValue("$id", reference.FindingId);
            command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || ordinal is < 0 or > int.MaxValue || row.GetValue(1) is not string sid
                    || Sid.ToBytes(sid) is null) throw Invalid();
                var name = PrivilegedSidCatalogue.PrivilegedName(sid);
                if ((name is not null) != (kind == SidHistoryPageKind.Flagged)) continue;
                values.Add(new((int)ordinal, sid, name));
                if (values.Count > SavedSidHistory.PageSize) break;
            }
        }
        SidHistoryMark? next = null;
        if (values.Count > SavedSidHistory.PageSize)
        {
            values.RemoveAt(SavedSidHistory.PageSize);
            next = new(reference.GenerationId, reference.FindingId, finding.ObjectGuid, kind, values[^1].Ordinal);
        }
        var page = new SavedSidHistory(context, kind, values.ToArray(), next);
        if (!page.IsExpectedPage(after)) throw Invalid();
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedSidHistory>.Success(page);
        static InvalidDataException Invalid() => new(SavedSidHistory.InvalidDetails);
    }
}
