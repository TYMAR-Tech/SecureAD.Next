using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed record SavedPermissionControlCalculation(FindingReference Reference, PermissionControlCalculation Calculation);

public sealed partial class JudgementReader
{
    public Result<SavedPermissionControlCalculation> ReadPermissionControlCalculation(FindingReference reference)
    {
        var selected = ReadSelectedFindingCore(reference, false, "");
        if (!selected.IsSuccess) return Result<SavedPermissionControlCalculation>.Failure(selected.Error);
        var finding = selected.Value;
        if (finding.RuleId != "SEC-060" || finding.RuleVersion != BroadPrincipalCanTakeOverObject.RuleVersion)
            return Result<SavedPermissionControlCalculation>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "UnsupportedFindingVersion", ErrorSeverity.Failed, "This finding has no supported permission calculation.", BundleDirectory));
        OpenPart(StoreSegmentRole.PermissionProof);
        var value = PermissionControlCalculationStorage.Read(_connection, reference.FindingId);
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT trustee_sid,broad_principal_sid,takeover_right FROM finding_object_takeover WHERE finding_id=$id";
        command.Parameters.AddWithValue("$id", reference.FindingId);
        using var row = command.ExecuteReader();
        if (!row.Read() || row.GetValue(0) is not string holder || row.GetValue(1) is not string broad
            || row.GetValue(2) is not string right || !Enum.TryParse<ObjectTakeoverRight>(right, out var reported))
            throw PermissionControlCalculationStorage.Invalid();
        PermissionControlCalculationStorage.Validate(value, Description.GenerationId, Description.EvidenceSeal,
            Description.DerivationGenerationId, finding.ObjectGuid, finding.DistinguishedName, finding.DomainFqdn,
            holder, broad, reported);
        _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        if (value.DerivationSeal != _findingDerivationSeal) throw PermissionControlCalculationStorage.Invalid();
        if (finding.Subject.Key != BroadPrincipalCanTakeOverObject.SubjectKeyFor(value.BroadSid))
            throw PermissionControlCalculationStorage.Invalid();
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedPermissionControlCalculation>.Success(new(reference, value));
    }
}
