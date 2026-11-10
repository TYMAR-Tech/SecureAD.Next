using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

/// <summary>A continuation for one exact finding in one saved judgement generation.</summary>
public sealed record LapsReadSupportMark(FindingReference Reference, int AfterOrdinal);

/// <summary>Requested supporting exposures, with independently saved whole-finding counts.</summary>
public sealed record SavedLapsReadSupports(FindingReference Reference, LapsReadSummary Assessment,
    IReadOnlyList<LapsReadExposure> Exposures, LapsReadSupportMark? Next);

public sealed partial class JudgementReader
{
    /// <summary>Reads at most fifty requested supports without loading another page or replaying analysis.</summary>
    public Result<SavedLapsReadSupports> ReadLapsReadSupports(FindingReference reference, LapsReadSupportMark? after = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        if (reference.GenerationId != Description.GenerationId || reference.FindingId <= 0
            || after is not null && (after.Reference != reference || after.AfterOrdinal < 0))
            return Result<SavedLapsReadSupports>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed,
                "The LAPS permission continuation does not belong to this saved finding.", BundleDirectory));
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedLapsReadSupports>.Failure(selected.Error);
        if (selected.Value.RuleId != "SEC-090" || selected.Value.RuleVersion != LapsPasswordReadAccess.RuleVersion)
            return Result<SavedLapsReadSupports>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "UnsupportedFindingVersion", ErrorSeverity.Failed,
                "This saved finding does not support the corrected LAPS permission assessment.", BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        LapsReadSummary summary;
        string broad;
        using (var header = _connection.CreateCommand())
        {
            header.CommandText = """
                SELECT assessment_json,exposure_count,established_count,assessment_complete,broad_principal_sid
                FROM finding_laps_password_reader WHERE finding_id=$id
                """;
            header.Parameters.AddWithValue("$id", reference.FindingId);
            using var read = header.ExecuteReader();
            if (!read.Read()) throw LapsReadFindingStorage.Invalid();
            summary = LapsReadFindingStorage.ReadSummary(read.GetString(0), read.GetInt64(1), read.GetInt64(2), read.GetInt64(3));
            broad = read.GetString(4);
        }
        if (after is not null && after.AfterOrdinal >= summary.ExposureCount)
            return Result<SavedLapsReadSupports>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed,
                "The LAPS permission continuation is outside the saved exposure count.", BundleDirectory));
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT ordinal,generation_id,trustee_sid,attribute,state,payload FROM finding_laps_password_reader_support
            WHERE finding_id=$id AND ordinal>$after ORDER BY ordinal LIMIT 51
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        command.Parameters.AddWithValue("$after", after?.AfterOrdinal ?? -1);
        var values = new List<LapsReadExposure>();
        var originals = new Dictionary<(string Attribute, int Ordinal), LapsReadEntryEvidence>();
        var ordinal = (after?.AfterOrdinal ?? -1) + 1;
        LapsReadSupportMark? next = null;
        using var rows = command.ExecuteReader();
        while (rows.Read())
        {
            _readCancellation.ThrowIfCancellationRequested();
            if (rows.GetInt32(0) != ordinal || ordinal >= summary.ExposureCount) throw LapsReadFindingStorage.Invalid();
            if (values.Count == 50)
            {
                next = new(reference, ordinal - 1);
                break;
            }
            if (!Guid.TryParse(rows.GetString(1), out var generation) || generation != reference.GenerationId)
                throw LapsReadFindingStorage.Invalid();
            var value = JsonSerializer.Deserialize<LapsReadExposure>(rows.GetString(5), ProofSerialization.Options)
                ?? throw LapsReadFindingStorage.Invalid();
            if (value.Entries is not null || value.EntryOrdinals is null) throw LapsReadFindingStorage.Invalid();
            var entries = new List<LapsReadEntryEvidence>();
            foreach (var referenceOrdinal in value.EntryOrdinals)
            {
                _readCancellation.ThrowIfCancellationRequested();
                var key = (value.Attribute, referenceOrdinal);
                if (!originals.TryGetValue(key, out var original))
                {
                    using var originalQuery = _connection.CreateCommand();
                    originalQuery.CommandText = """
                        SELECT payload FROM finding_laps_password_reader_entry
                        WHERE finding_id=$id AND attribute=$attribute AND ordinal=$ordinal
                        """;
                    originalQuery.Parameters.AddWithValue("$id", reference.FindingId);
                    originalQuery.Parameters.AddWithValue("$attribute", value.Attribute);
                    originalQuery.Parameters.AddWithValue("$ordinal", referenceOrdinal);
                    var payload = originalQuery.ExecuteScalar() as string ?? throw LapsReadFindingStorage.Invalid();
                    original = JsonSerializer.Deserialize<LapsReadEntryEvidence>(payload, ProofSerialization.Options)
                        ?? throw LapsReadFindingStorage.Invalid();
                    if (original.Entry is null || original.Entry.Ordinal != referenceOrdinal) throw LapsReadFindingStorage.Invalid();
                    originals.Add(key, original);
                }
                entries.Add(original);
            }
            value = value with { Entries = entries };
            LapsReadFindingStorage.ValidateExposure(value, selected.Value.DistinguishedName, selected.Value.ObjectGuid, broad);
            if (value.TrusteeSid != rows.GetString(2) || value.Attribute != rows.GetString(3)
                || value.State.ToString() != rows.GetString(4)) throw LapsReadFindingStorage.Invalid();
            values.Add(value);
            ordinal++;
        }
        if (next is null && ordinal != summary.ExposureCount) throw LapsReadFindingStorage.Invalid();
        return Result<SavedLapsReadSupports>.Success(new(reference, summary, values, next));
    }
}
