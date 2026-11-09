using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;
using SecureAD.Storage;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    private const string ListColumnPrefix = """
        f.finding_id,f.rule_id,f.subject_kind,f.subject_key,f.object_guid,f.severity,
        f.distinguished_name,
        """;
    private const string ListColumnSuffix = """
        f.coverage,f.domain_fqdn,f.object_class,f.principal_name,
        r.rule_version,f.list_kind,f.evidence_complete,f.protection_catalogue_version,
        f.direct_protection_entry_id,f.direct_protection_name
        """;
    private const string ListColumns = ListColumnPrefix
        + "CASE WHEN f.rule_id IN ('SEC-002','SEC-012','SEC-013','SEC-014','SEC-021','SEC-024','SEC-025','SEC-026','SEC-027','SEC-030','SEC-031','SEC-032','SEC-050','SEC-051','SEC-052','SEC-061','SEC-062','SEC-100','SEC-101') THEN NULL ELSE f.detail END AS detail,"
        + ListColumnSuffix;
    private const string FindingHeaderColumns = ListColumnPrefix + "NULL AS detail," + ListColumnSuffix;

    /// <summary>Reads saved display values and scalar completeness headers, without membership routes or full proof.</summary>
    public Result<FindingListPage> ReadListPage(FindingsQuery query)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(query);
        _readCancellation.ThrowIfCancellationRequested();
        if (query.After is { } mark && mark.GenerationId != Description.GenerationId)
            return Result<FindingListPage>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "JudgementGenerationChanged", ErrorSeverity.Failed,
                "The findings continuation belongs to a different saved judgement.", BundleDirectory));
        var page = ReadPageRows(query, ListColumns, "JOIN rule_execution r ON r.rule_id=f.rule_id",
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

    /// <summary>Reads one saved explanation; membership support is read only when explicitly requested.</summary>
    public Result<FindingListItem> ReadSelectedFinding(FindingReference reference, bool includeMembership = false) =>
        ReadSelectedFindingCore(reference, includeMembership, null);

    private Result<FindingListItem> ReadSelectedFindingCore(FindingReference reference, bool includeMembership, string? statement)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        if (reference.GenerationId != Description.GenerationId || reference.FindingId <= 0)
            return Result<FindingListItem>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed,
                "The selected finding does not belong to this saved judgement.", BundleDirectory));
        using var command = _connection.CreateCommand();
        command.CommandText = $"""
            SELECT {(statement is null ? ListColumns : FindingHeaderColumns)} FROM finding f
            JOIN rule_execution r ON r.rule_id=f.rule_id WHERE f.finding_id=$id
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        FindingListItem item;
        using (var row = command.ExecuteReader())
        {
            if (!row.Read())
                return Result<FindingListItem>.Failure(AuditError.Create(ErrorCategory.Evidence,
                    "FindingNotFound", ErrorSeverity.Failed,
                    "The selected saved finding is unavailable.", BundleDirectory));
            item = ReadListItem(row, includeMembership, statement);
        }
        return Result<FindingListItem>.Success(item with
        {
            EvidenceIsComplete = ReadListCompleteness(reference.FindingId, item),
        });
    }

    /// <summary>Reads one supported account option's original flags without reconstructing other finding proof.</summary>
    public Result<SavedAccountSetting> ReadAccountSetting(FindingReference reference)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        if (reference.GenerationId != Description.GenerationId || reference.FindingId <= 0)
            return Result<SavedAccountSetting>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed,
                "The selected finding does not belong to this saved judgement.", BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT f.finding_id,f.rule_id,f.object_guid,f.subject_kind,f.subject_key,
                f.distinguished_name,
                CASE WHEN f.rule_id IN ('SEC-010','SEC-011')
                    THEN d.user_account_control ELSE p.user_account_control END,
                d.is_computer,d.server_trust_account_bit,
                d.primary_group_is_domain_controller,d.under_domain_controllers_ou
            FROM finding f
            LEFT JOIN finding_user_account_control p ON p.finding_id=f.finding_id
            LEFT JOIN finding_unconstrained_delegation d ON d.finding_id=f.finding_id
            WHERE f.finding_id=$id
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        using var row = command.ExecuteReader();
        const string invalidSetting = "The selected finding's saved account setting is missing, invalid or inconsistent.";
        if (!row.Read() || !SavedAccountSetting.SupportsRule(row.GetString(1))
            || !Guid.TryParse(row.GetString(2), out var objectGuid)
            || !Enum.TryParse<FindingSubjectKind>(row.GetString(3), out var subjectKind) || !Enum.IsDefined(subjectKind)
            || row.GetValue(6) is not long control || control < 0 || control > uint.MaxValue)
            throw new InvalidDataException(invalidSetting);
        var setting = new SavedAccountSetting(new(Description.GenerationId, row.GetInt64(0)),
            row.GetString(1), objectGuid, new(subjectKind, row.GetString(4)), row.GetString(5), new((uint)control));
        if (SavedAccountSetting.UsesDelegationHeader(setting.RuleId))
            setting = setting with
            {
                Delegation = new(ReadBit(7), new(ReadBit(8), ReadBit(9), ReadBit(10))),
            };
        if (!setting.HasReportedSetting || !setting.HasExpectedContext) throw new InvalidDataException(invalidSetting);
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedAccountSetting>.Success(setting);

        bool ReadBit(int column) => row.GetValue(column) is long value && value is 0 or 1
            ? value == 1 : throw new InvalidDataException(invalidSetting);
    }

    private bool ReadListCompleteness(long findingId, FindingListItem item)
    {
        _readCancellation.ThrowIfCancellationRequested();
        // Existing same-format summaries defaulted these families to complete. Their original
        // scalar headers remain authoritative; no values, membership paths or proof JSON are read.
        var membership = item.Kind == FindingListKind.Membership;
        var sql = membership ? """
            SELECT CASE WHEN typeof(incomplete_reasons)='integer' AND incomplete_reasons>=0
                THEN incomplete_reasons=0 END
            FROM membership_route_summary WHERE subject_id=CAST($id AS TEXT)
            """ : item.RuleId switch
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
        if (!membership) OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddWithValue("$id", findingId);
        var saved = command.ExecuteScalar();
        if (saved is not long complete || complete is not (0 or 1))
            throw new InvalidDataException($"Saved finding {findingId} ({item.RuleId}) has no valid completeness header.");
        if (membership && (complete == 1) != item.EvidenceIsComplete)
            throw new InvalidDataException("A saved finding has contradictory membership completeness.");
        return complete == 1;
    }

    private FindingListItem ReadListItem(SqliteDataReader row, bool includeMembership = false, string? statement = null)
    {
        var kind = Enum.Parse<FindingListKind>(row.GetString(13));
        var complete = row.GetInt64(14);
        if (!Enum.IsDefined(kind) || complete is not (0 or 1))
            throw new InvalidDataException("A saved finding has invalid display values.");
        FindingMembershipDisplay? membership = null;
        if (kind == FindingListKind.Membership)
        {
            if (includeMembership)
            {
                var subject = row.GetInt64(0).ToString(CultureInfo.InvariantCulture);
                var routes = MembershipRouteStorage.Read(_connection, subject);
                if (!routes.TryGetValue(subject, out var summary) || summary.IsComplete != (complete == 1))
                    throw new InvalidDataException("A saved finding has no matching membership completeness record.");
                membership = new(row.IsDBNull(15) ? null : row.GetInt32(15),
                    row.IsDBNull(16) ? null : row.GetInt32(16), row.IsDBNull(17) ? null : row.GetString(17), summary);
            }
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
        var ruleId = row.GetString(1);
        // Structured windows read selected saved facts instead of complete delegation/permission prose.
        var detail = statement ?? (ruleId switch
        {
            "SEC-002" => SavedReplicationPermission.Statement,
            "SEC-021" => ServiceRegistrationPresentation.Why,
            "SEC-050" or "SEC-051" => SavedGroupReview.Statement(ruleId),
            "SEC-052" => CircularGroupMembership.Explanation,
            "SEC-061" => BroadPreWindows2000Membership.Explanation,
            "SEC-062" => BroadAdministrativeGroupMembership.Explanation,
            "SEC-012" => SavedDelegationConfiguration.ConstrainedStatement,
            "SEC-013" => SavedDelegationConfiguration.ResourceStatement,
            "SEC-014" or "SEC-024" or "SEC-025" => SavedAttributeWritePermission.ScopeNoteForRule(ruleId),
            "SEC-026" => SavedDuplicateSpn.Statement,
            "SEC-027" => SavedSidHistory.Statement,
            "SEC-030" => SavedProtectionMarker.Statement,
            "SEC-031" or "SEC-032" => SavedOwnershipAssessment.ScopeNote,
            "SEC-100" or "SEC-101" => SavedServiceAccountContext.Statement(ruleId),
            _ => row.GetString(7),
        });
        return new(ruleId, row.GetInt32(12), severity, new(subjectKind, row.GetString(3)),
            Guid.Parse(row.GetString(4)), row.GetString(6), row.GetString(9), row.GetString(10), detail,
            coverage, row.GetString(11), kind, complete == 1, membership)
        {
            Reference = new(Description.GenerationId, row.GetInt64(0)),
        };
    }
}
