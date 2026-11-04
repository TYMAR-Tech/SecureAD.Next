using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads selected saved SEC-012 context and one original service page without analysis replay.</summary>
    public Result<SavedDelegationConfiguration> ReadConstrainedDelegation(FindingReference reference, DelegationConfigurationMark? after = null)
        => ReadDelegationConfiguration(reference, after, DelegationConfigurationKind.Constrained);

    /// <summary>Reads selected saved SEC-013 context and configured holders, without descriptor or authorization replay.</summary>
    public Result<SavedDelegationConfiguration> ReadResourceDelegation(FindingReference reference, DelegationConfigurationMark? after = null)
        => ReadDelegationConfiguration(reference, after, DelegationConfigurationKind.ResourceBased);

    private Result<SavedDelegationConfiguration> ReadDelegationConfiguration(FindingReference reference,
        DelegationConfigurationMark? after, DelegationConfigurationKind kind)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var invalidDetails = SavedDelegationConfiguration.InvalidDetailsFor(kind);
        if (reference.GenerationId != Description.GenerationId || reference.FindingId <= 0
            || after is { } mark && (mark.GenerationId != reference.GenerationId || mark.FindingId != reference.FindingId
                || mark.ResourceGuid == Guid.Empty || mark.Offset <= 0 || mark.Offset > long.MaxValue - SavedDelegationConfiguration.PageSize
                || mark.Offset % SavedDelegationConfiguration.PageSize != 0))
            return Result<SavedDelegationConfiguration>.Failure(AuditError.Create(ErrorCategory.Evidence,
                "FindingSelectionChanged", ErrorSeverity.Failed,
                kind == DelegationConfigurationKind.Constrained
                    ? "The selected finding or service continuation does not belong to this saved judgement."
                    : "The selected finding or delegation continuation does not belong to this saved judgement.", BundleDirectory));
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedDelegationConfiguration>.Failure(selected.Error);
        if (selected.Value.RuleId != (kind == DelegationConfigurationKind.Constrained ? "SEC-012" : "SEC-013"))
            throw new InvalidDataException(invalidDetails);
        OpenPart(StoreSegmentRole.PermissionProof);
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                SELECT generation,typeof(proof),fingerprint,account_source_hash,resource_source_hash
                FROM finding_delegation_configuration WHERE finding_id=$id
                """;
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetString(0) != Description.GenerationId.ToString("D") || row.GetString(1) != "text"
                || row.GetValue(2) is not byte[] { Length: 32 } || row.GetValue(3) is not byte[] { Length: 32 }
                || row.GetValue(4) is not byte[] { Length: 32 }) throw new InvalidDataException(invalidDetails);
        }
        _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        if (_findingDerivationSeal is null) throw new InvalidDataException(invalidDetails);
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_delegation_configuration", "proof", reference.FindingId, readOnly: true);
        var page = DelegationConfigurationProjection.Read(proof, selected.Value, Description, _findingDerivationSeal, after, _readCancellation);
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedDelegationConfiguration>.Success(page);
    }

}
