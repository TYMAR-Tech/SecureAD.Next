using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Storage;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads saved display values, this page's membership support and selected completeness headers, never full proof.</summary>
    public Result<FindingListPage> ReadListPage(FindingsQuery query)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        _readCancellation.ThrowIfCancellationRequested();
        if (query.After is { } mark && mark.GenerationId != Description.GenerationId)
            return Result<FindingListPage>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "JudgementGenerationChanged", ErrorSeverity.Failed,
                "The findings continuation belongs to a different saved judgement.", BundleDirectory));
        var page = ReadPageRows(query, """
            f.finding_id,f.rule_id,f.subject_kind,f.subject_key,f.object_guid,f.severity,
            f.distinguished_name,f.detail,f.coverage,f.domain_fqdn,f.object_class,f.principal_name,
            r.rule_version,f.list_kind,f.evidence_complete,f.protection_catalogue_version,
            f.direct_protection_entry_id,f.direct_protection_name
            """, "JOIN rule_execution r ON r.rule_id=f.rule_id",
            row => (Id: row.GetInt64(0), Item: ReadListItem(row)));
        if (!page.IsSuccess)
            return Result<FindingListPage>.Failure(page.Error);
        var findings = new List<FindingListItem>(page.Value.Rows.Count);
        foreach (var (id, item) in page.Value.Rows)
        {
            var complete = ReadListCompleteness(id, item);
            findings.Add(complete == item.EvidenceIsComplete ? item : item with { EvidenceIsComplete = complete });
        }
        return Result<FindingListPage>.Success(new(findings, page.Value.Next, page.Value.RulesRan));
    }

    private bool ReadListCompleteness(long findingId, FindingListItem item)
    {
        _readCancellation.ThrowIfCancellationRequested();
        // Existing same-format summaries defaulted these families to complete. Their original
        // scalar headers remain authoritative; no values, membership paths or proof JSON are read.
        var sql = item.RuleId switch
        {
            "SEC-027" => """
                SELECT CASE WHEN typeof(unreadable_values)='integer' AND unreadable_values>=0
                    THEN unreadable_values=0 END
                FROM finding_privileged_sid_history WHERE finding_id=$id
                """,
            "SEC-031" or "SEC-032" => """
                SELECT membership_was_complete FROM finding_object_ownership WHERE finding_id=$id
                """,
            "SEC-060" => """
                SELECT expansion_was_complete FROM finding_object_takeover WHERE finding_id=$id
                """,
            "SEC-090" => """
                SELECT expansion_was_complete FROM finding_laps_password_reader WHERE finding_id=$id
                """,
            "SEC-093" => """
                SELECT CASE WHEN typeof(expansion_was_complete)='integer' AND expansion_was_complete IN (0,1)
                    THEN expansion_was_complete AND decryptor_sid IS NOT NULL END
                FROM finding_laps_decryptor WHERE finding_id=$id
                """,
            _ => null,
        };
        if (sql is null) return item.EvidenceIsComplete;
        OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$id", findingId);
        var saved = command.ExecuteScalar();
        if (saved is not long complete || complete is not (0 or 1))
            throw new InvalidDataException($"Saved finding {findingId} ({item.RuleId}) has no valid completeness header.");
        return complete == 1;
    }

    private FindingListItem ReadListItem(SqliteDataReader row)
    {
        var kind = Enum.Parse<FindingListKind>(row.GetString(13));
        var complete = row.GetInt64(14);
        if (!Enum.IsDefined(kind) || complete is not (0 or 1))
            throw new InvalidDataException("A saved finding has invalid display values.");
        FindingMembershipDisplay? membership = null;
        if (kind == FindingListKind.Membership)
        {
            var subject = row.GetInt64(0).ToString(CultureInfo.InvariantCulture);
            var routes = MembershipRouteStorage.Read(_connection, subject);
            if (!routes.TryGetValue(subject, out var summary) || summary.IsComplete != (complete == 1))
                throw new InvalidDataException("A saved finding has no matching membership completeness record.");
            membership = new(row.IsDBNull(15) ? null : row.GetInt32(15),
                row.IsDBNull(16) ? null : row.GetInt32(16), row.IsDBNull(17) ? null : row.GetString(17), summary);
        }
        else if (!row.IsDBNull(15) || !row.IsDBNull(16) || !row.IsDBNull(17)
            || kind == FindingListKind.Tier0Routes && row.GetString(1) != UnexpectedTier0Route.RuleId)
            throw new InvalidDataException("A saved finding has contradictory display values.");
        var severity = Enum.Parse<Severity>(row.GetString(5));
        var coverage = Enum.Parse<EvidenceCompleteness>(row.GetString(8));
        var subjectKind = Enum.Parse<FindingSubjectKind>(row.GetString(2));
        if (!Enum.IsDefined(severity) || !Enum.IsDefined(coverage) || !Enum.IsDefined(subjectKind))
            throw new InvalidDataException("A saved finding has an unsupported classification.");
        _readCancellation.ThrowIfCancellationRequested();
        return new(row.GetString(1), row.GetInt32(12), severity, new(subjectKind, row.GetString(3)),
            Guid.Parse(row.GetString(4)), row.GetString(6), row.GetString(9), row.GetString(10), row.GetString(7),
            coverage, row.GetString(11), kind, complete == 1, membership);
    }
}
