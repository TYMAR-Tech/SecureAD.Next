using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads saved attribute-write context and one original permission-entry page without permission or schema replay.</summary>
    public Result<SavedAttributeWritePermission> ReadAttributeWritePermission(FindingReference reference, AttributeWritePermissionMark? after)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedAttributeWritePermission>.Failure(selected.Error);
        var invalidDetails = SavedAttributeWritePermission.InvalidDetailsForRule(selected.Value.RuleId);
        if (after is { } mark && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
            || mark.TargetGuid != selected.Value.ObjectGuid || mark.Ordinal < 0))
            return Result<SavedAttributeWritePermission>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed, invalidDetails, BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,typeof(proof),fingerprint FROM finding_attribute_write WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetString(0) != Description.GenerationId.ToString("D") || row.GetString(1) != "text"
                || row.GetValue(2) is not byte[] { Length: 32 }) throw Invalid();
        }
        long total;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT COUNT(*) FROM finding_attribute_write_entry WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            total = (long)command.ExecuteScalar()!;
        }
        var entries = new List<SavedWriteEntrySource>();
        using (var command = _connection.CreateCommand())
        {
            // The protected published file already binds each original link to its shared value.
            // Meaning payloads are deliberately not selected or revalidated for this display page.
            command.CommandText = """
                SELECT r.ordinal,r.entry_id,r.fingerprint,p.generation,p.ace_type,p.sid,p.mask,p.object_type,
                       p.inherited,p.has_object_type,p.inheritance_flags,p.propagation_flags,p.has_inherited_object_type,
                       p.inherited_object_type,length(p.application_data)
                FROM finding_attribute_write_entry r LEFT JOIN permission_entry p ON p.id=r.entry_id
                WHERE r.finding_id=$id AND r.ordinal>$after ORDER BY r.ordinal LIMIT $limit
                """;
            command.Parameters.AddWithValue("$id", reference.FindingId);
            command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
            command.Parameters.AddWithValue("$limit", SavedAttributeWritePermission.PageSize + 1);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || ordinal is < 0 or > int.MaxValue
                    || row.GetValue(1) is not long entryId || entryId <= 0 || row.GetValue(2) is not byte[] { Length: 32 }
                    || row.IsDBNull(3) || row.GetString(3) != Description.GenerationId.ToString("D")
                    || row.GetString(4) is not ("AccessAllowed" or "AccessAllowedObject" or "AccessDenied" or "AccessDeniedObject")
                    || row.GetValue(6) is not long mask || mask is < int.MinValue or > uint.MaxValue || (mask & 0x20) == 0
                    || row.GetValue(10) is not long inheritance || inheritance is < 0 or > 255
                    || row.GetValue(11) is not long propagation || propagation is < 0 or > 255 || (propagation & 0x08) != 0
                    || row.GetValue(14) is not long dataLength || dataLength != 0) throw Invalid();
                var inherited = Bit(8);
                var objectType = row.IsDBNull(7) ? null : row.GetString(7);
                var hasObjectType = Bit(9);
                var hasInheritedType = Bit(12);
                if (hasObjectType != (objectType is not null)
                    || hasInheritedType != !row.IsDBNull(13)) throw Invalid();
                entries.Add(new((int)ordinal, row.GetString(4).Contains("Denied", StringComparison.Ordinal),
                    row.GetString(5), objectType, hasObjectType, inherited));
            }
            bool Bit(int column) => row.GetValue(column) is long value && value is 0 or 1
                ? value == 1 : throw Invalid();
        }
        AttributeWritePermissionMark? next = null;
        if (entries.Count > SavedAttributeWritePermission.PageSize)
        {
            entries.RemoveAt(SavedAttributeWritePermission.PageSize);
            next = new(Description.GenerationId, reference.FindingId, selected.Value.ObjectGuid, entries[^1].Ordinal);
        }
        _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        if (_findingDerivationSeal is null) throw Invalid();
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_attribute_write", "proof", reference.FindingId, readOnly: true);
        var page = AttributeWritePermissionProjection.Read(proof, selected.Value, Description, _findingDerivationSeal,
            entries, total, after, next, _readCancellation);
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedAttributeWritePermission>.Success(page);
        InvalidDataException Invalid() => new(invalidDetails);
    }
}
