using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    public Result<SavedPermissionControl> ReadPermissionControl(FindingReference reference)
    {
        var selected = ReadSelectedFindingCore(reference, false, "");
        if (!selected.IsSuccess) return Result<SavedPermissionControl>.Failure(selected.Error);
        if (selected.Value.RuleId != "SEC-060")
            return Result<SavedPermissionControl>.Failure(AuditError.Create(ErrorCategory.Evidence, "FindingSelectionChanged",
                ErrorSeverity.Failed, SavedPermissionControl.InvalidDetails, BundleDirectory));
        var current = selected.Value.RuleVersion == BroadPrincipalCanTakeOverObject.RuleVersion;
        if (selected.Value.RuleVersion != 2 && !current)
            return Result<SavedPermissionControl>.Failure(AuditError.Create(ErrorCategory.Evidence, "UnsupportedFindingVersion",
                ErrorSeverity.Failed, "This calculation version has no approved finding-detail presentation.", BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        using var command = _connection.CreateCommand();
        var chainColumns = current ? "NULL,NULL,NULL" : """
                (SELECT COUNT(*) FROM finding_object_takeover_path p WHERE p.finding_id=t.finding_id),
                (SELECT sid FROM finding_object_takeover_path p WHERE p.finding_id=t.finding_id ORDER BY ordinal LIMIT 1),
                (SELECT sid FROM finding_object_takeover_path p WHERE p.finding_id=t.finding_id ORDER BY ordinal DESC LIMIT 1)
            """;
        command.CommandText = $"""
            SELECT trustee_sid,trustee_name,broad_principal_sid,broad_principal_name,takeover_right,
                inherited_from,expansion_was_complete,{chainColumns}
            FROM finding_object_takeover t WHERE finding_id=$id
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string holder || row.GetValue(2) is not string broad
            || row.GetValue(4) is not string rightText || !Enum.TryParse<ObjectTakeoverRight>(rightText, out var right)
            || !Enum.IsDefined(right) || row.GetValue(6) is not long complete || complete is not (0 or 1)
            || !row.IsDBNull(5) && (row.GetValue(5) is not string marker || string.IsNullOrWhiteSpace(marker))) throw PermissionControlInvalid();
        var finding = selected.Value;
        SavedPermissionControlAssessment? display = null;
        long count;
        if (current)
        {
            display = PermissionControlCalculationStorage.ReadDisplay(_connection, reference.FindingId);
            _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
            if (display.EvidenceSeal != Description.EvidenceSeal
                || display.DerivationGenerationId != Description.DerivationGenerationId
                || display.DerivationSeal != _findingDerivationSeal || !row.IsDBNull(5)) throw PermissionControlInvalid();
            count = display.ChainCount;
        }
        else
        {
            if (row.GetValue(7) is not long savedCount || savedCount < 1 || row.GetValue(8) is not string first || first != holder
                || row.GetValue(9) is not string last || last != broad) throw PermissionControlInvalid();
            count = savedCount;
        }
        var assessment = new SavedPermissionControl(reference, finding.Subject,
            new(finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn, finding.ObjectClass),
            finding.PrincipalName, holder, row.IsDBNull(1) ? null : row.GetString(1),
            broad, row.IsDBNull(3) ? null : row.GetString(3), right, display?.SupportingEntryIsInherited ?? !row.IsDBNull(5),
            complete == 1, finding.Coverage, count)
        {
            RuleVersion = finding.RuleVersion,
            Assessment = display,
        };
        if (!assessment.Matches(finding)) throw PermissionControlInvalid();
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedPermissionControl>.Success(assessment);
    }

    public Result<SavedPermissionControlChain> ReadPermissionControlChain(FindingReference reference, PermissionControlMark? after = null)
    {
        var selected = ReadPermissionControl(reference);
        if (!selected.IsSuccess) return Result<SavedPermissionControlChain>.Failure(selected.Error);
        var context = selected.Value;
        if (after is { } mark && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
            || mark.ObjectGuid != context.Object.ObjectGuid || mark.Ordinal < 0 || mark.Ordinal >= context.ChainCount - 1
            || mark.Ordinal % SavedPermissionControl.PageSize != SavedPermissionControl.PageSize - 1)) throw PermissionControlInvalid();
        using var command = _connection.CreateCommand();
        command.CommandText = """
            SELECT ordinal,sid,name FROM finding_object_takeover_path
            WHERE finding_id=$id AND ordinal>$after ORDER BY ordinal LIMIT 50
            """;
        command.Parameters.AddWithValue("$id", reference.FindingId);
        command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
        var steps = new List<SavedPermissionControlStep>();
        using (var row = command.ExecuteReader())
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || row.GetValue(1) is not string sid) throw PermissionControlInvalid();
                steps.Add(new(ordinal, sid, row.IsDBNull(2) ? null : row.GetString(2)));
            }
        var start = after is { } previous ? previous.Ordinal + 1 : 0;
        if (steps.Count != Math.Min(SavedPermissionControl.PageSize, context.ChainCount - start)) throw PermissionControlInvalid();
        PermissionControlMark? next = start + steps.Count < context.ChainCount
            ? new(reference.GenerationId, reference.FindingId, context.Object.ObjectGuid, steps[^1].Ordinal) : null;
        var page = new SavedPermissionControlChain(context, steps, next);
        if (!page.IsExpectedPage(after)) throw PermissionControlInvalid();
        return Result<SavedPermissionControlChain>.Success(page);
    }

    private static InvalidDataException PermissionControlInvalid() => new(SavedPermissionControl.InvalidDetails);
}
