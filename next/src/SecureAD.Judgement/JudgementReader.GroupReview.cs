using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    public Result<SavedGroupReview> ReadGroupReview(FindingReference reference)
    {
        var read = ReadGroupReviewCore(reference, false, null);
        return read.IsSuccess ? Result<SavedGroupReview>.Success(read.Value.Context) : Result<SavedGroupReview>.Failure(read.Error);
    }
    public Result<SavedGroupReferences> ReadGroupReviewReferences(FindingReference reference, GroupReviewReferenceMark? after = null) =>
        ReadGroupReviewCore(reference, true, after);

    private Result<SavedGroupReferences> ReadGroupReviewCore(FindingReference reference, bool references, GroupReviewReferenceMark? after)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedGroupReferences>.Failure(selected.Error);
        var finding = selected.Value; var invalid = SavedGroupReview.InvalidDetails(finding.RuleId);
        if (finding.RuleId is not ("SEC-050" or "SEC-051")) throw new InvalidDataException(invalid);
        OpenPart(StoreSegmentRole.PermissionProof);
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT generation,typeof(proof),fingerprint FROM finding_membership_review WHERE finding_id=$id";
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetString(0) != reference.GenerationId.ToString("D") || row.GetString(1) != "text"
                || row.GetValue(2) is not byte[] { Length: 32 }) throw new InvalidDataException(invalid);
        }
        _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        if (_findingDerivationSeal is null) throw new InvalidDataException(invalid);
        using var proof = new SqliteBlob(_connection, JudgementStoreLayout.Schema(_connection, StoreSegmentRole.PermissionProof),
            "finding_membership_review", "proof", reference.FindingId, readOnly: true);
        var read = GroupReviewProjection.Read(proof, finding, Description, _findingDerivationSeal, references, after, _readCancellation);
        if (read.Context.IsSizeReview)
        {
            using var command = _connection.CreateCommand();
            command.CommandText = """
                SELECT g.object_guid,g.direct_members,g.known_total,g.unresolved_members,g.unreadable_members,g.membership_limitations
                FROM group_inventory g JOIN group_inventory_product p ON p.id=1
                WHERE g.distinguished_name=$dn AND p.generation=$generation AND p.completed=1
                """;
            command.Parameters.AddWithValue("$dn", read.Context.Affected.Identity.DistinguishedName);
            command.Parameters.AddWithValue("$generation", reference.GenerationId.ToString("D"));
            using var row = command.ExecuteReader(); var context = read.Context;
            if (!row.Read() || row.GetString(0) != context.Affected.Identity.ObjectGuid.ToString("D")
                || row.GetInt32(1) != context.DirectCount || row.GetInt32(2) != context.KnownTotal
                || row.GetInt32(3) != context.UnresolvedReferences || row.GetInt32(4) != context.UnreadableReferences
                || row.GetInt32(5) != (int)context.TotalLimitations || row.Read()) throw new InvalidDataException(invalid);
        }
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedGroupReferences>.Success(read);
    }
}
