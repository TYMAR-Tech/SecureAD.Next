using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Kernel;

namespace SecureAD.Judgement;

public sealed partial class JudgementReader
{
    /// <summary>Reads one saved replication header and one page of original entries, without routes or access replay.</summary>
    public Result<SavedReplicationPermission> ReadReplicationPermission(FindingReference reference, ReplicationPermissionMark? after)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _readCancellation.ThrowIfCancellationRequested();
        var selected = ReadSelectedFinding(reference);
        if (!selected.IsSuccess) return Result<SavedReplicationPermission>.Failure(selected.Error);
        var finding = selected.Value;
        if (finding.RuleId != "SEC-002" || after is { } offered && (offered.GenerationId != reference.GenerationId
            || offered.FindingId != reference.FindingId || offered.RootGuid != finding.ObjectGuid || offered.EdgeId <= 0 || offered.Ordinal < 0))
            throw Invalid();
        OpenPart(StoreSegmentRole.PermissionProof);
        ReplicationPermissionEvidence metadata;
        ControlEdge edge;
        long count;
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = """
                SELECT r.edge_id,r.generation AS finding_generation,r.proof,r.fingerprint,r.source_hash,
                       e.*,o.descriptor_outcome,p.engine_version,p.completed
                FROM finding_replication_permission r JOIN control_edge e ON e.id=r.edge_id
                JOIN control_object o ON o.target=e.target COLLATE NOCASE AND o.target=e.target COLLATE BINARY
                JOIN control_product p ON p.id=1 WHERE r.finding_id=$id
                """;
            command.Parameters.AddWithValue("$id", reference.FindingId);
            using var row = command.ExecuteReader();
            if (!row.Read() || Text("finding_generation") != reference.GenerationId.ToString("D")
                || row.GetValue(row.GetOrdinal("fingerprint")) is not byte[] { Length: 32 }
                || row.GetValue(row.GetOrdinal("source_hash")) is not byte[] { Length: 32 }
                || Number("engine_version") != ControlEdgeStorage.EngineVersion || Number("completed") != 1
                || Number("precondition_count") != 6 || Number("counted") != 1 || Number("uncertainty") != 0
                || Number("ace_count") is < 0 or > int.MaxValue) throw Invalid();
            try { metadata = JsonSerializer.Deserialize<ReplicationPermissionEvidence>(Text("proof")!, ProofSerialization.Options) ?? throw Invalid(); }
            catch (JsonException error) { throw new InvalidDataException(SavedReplicationPermission.InvalidDetails, error); }
            if (metadata.Entries is not { Count: 0 }) throw Invalid();
            try { ReplicationPermissionFindingStorage.Validate(metadata); }
            catch (InvalidDataException error) { throw new InvalidDataException(SavedReplicationPermission.InvalidDetails, error); }
            if (Text("edge_class") != nameof(ControlEdgeClass.ReplicationControl)) throw Invalid();
            edge = new(Number("edge_id"), GuidValue("target_guid"), Text("target")!, Text("target_class"),
                Text("holder_sid")!, Text("holder_name"), Text("holder_scope"), Value<ControlCapability>("capability"),
                Value<ControlEvaluationState>("evaluation"), (ControlUncertainty)Number("uncertainty"),
                Value<ControlExpectedness>("expectedness"), Value<ControlExpectednessReason>("expectedness_reason"),
                checked((int)Number("catalogue_version")), GuidValue("generation") ?? throw Invalid(),
                GuidValue("derivation_generation"), true, [], [], MembershipRouteSummary.NotDerived)
                { DescriptorOutcome = Text("descriptor_outcome")! };
            count = Number("ace_count");
            string? Text(string name) => row.IsDBNull(row.GetOrdinal(name)) ? null : row.GetString(row.GetOrdinal(name));
            long Number(string name) => row.GetValue(row.GetOrdinal(name)) is long number ? number : throw Invalid();
            Guid? GuidValue(string name) => Text(name) is not { } text ? null : Guid.TryParse(text, out var guid) ? guid : throw Invalid();
            T Value<T>(string name) where T : struct, Enum =>
                Enum.TryParse<T>(Text(name), out var value) && Enum.IsDefined(value) ? value : throw Invalid();
        }
        var checks = new List<ControlPrecondition>();
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT name,state,evidence FROM control_precondition WHERE edge_id=$id ORDER BY ordinal";
            command.Parameters.AddWithValue("$id", edge.Id);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (checks.Count == 6 || !Enum.TryParse<ControlEvaluationState>(row.GetString(1), out var state)
                    || !Enum.IsDefined(state)) throw Invalid();
                checks.Add(new(row.GetString(0), state, row.GetString(2)));
            }
        }
        edge = edge with { Preconditions = checks };
        var names = new[] { ReplicationControlDeriver.Changes, ReplicationControlDeriver.All, ReplicationControlDeriver.Filtered,
            "NamingContextRoot", "NamingContextKind", "HolderDomainControllerAsset" };
        if (checks.Count != 6 || names.Any(name => checks.Count(check => check.Name == name) != 1)) throw Invalid();
        _findingDerivationSeal ??= FindingInputBinding.DerivationSeal(BundleDirectory, Description.DerivationGenerationId);
        if (_findingDerivationSeal is null || metadata.GenerationId != Description.GenerationId
            || metadata.EvidenceSeal != Description.EvidenceSeal || metadata.DerivationGenerationId != Description.DerivationGenerationId
            || metadata.DerivationSeal != _findingDerivationSeal) throw Invalid();
        try { ReplicationPermissionFindingStorage.RequireSource(metadata, edge); }
        catch (InvalidDataException error) { throw new InvalidDataException(SavedReplicationPermission.InvalidDetails, error); }
        using (var command = _connection.CreateCommand())
        {
            command.CommandText = "SELECT COUNT(*) FROM control_ace WHERE edge_id=$id";
            command.Parameters.AddWithValue("$id", edge.Id);
            if (command.ExecuteScalar() is not long actual || actual != count) throw Invalid();
        }
        var context = new ReplicationPermissionContext(reference, finding.Subject,
            new(metadata.RootGuid, metadata.NamingContextRoot, metadata.DomainFqdn, metadata.RootClass), edge.Id,
            metadata.HolderSid, metadata.HolderScope, metadata.HolderName, metadata.ExpectednessReason,
            metadata.DescriptorOutcome == "GrantsEveryoneEverything", metadata.Limitations.Contains("CaptureIncomplete"),
            metadata.Limitations.Any(value => value != "CaptureIncomplete"), metadata.IsComplete, count);
        if (!context.Matches(finding) || after is { } position && position.EdgeId != edge.Id) throw Invalid();
        long entriesBefore = 0;
        if (after is { } prior)
        {
            using var command = _connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*),MAX(ordinal) FROM control_ace WHERE edge_id=$id AND ordinal<=$ordinal";
            command.Parameters.AddWithValue("$id", edge.Id);
            command.Parameters.AddWithValue("$ordinal", prior.Ordinal);
            using var row = command.ExecuteReader();
            if (!row.Read() || row.GetValue(0) is not long before || row.IsDBNull(1) || row.GetInt64(1) != prior.Ordinal) throw Invalid();
            entriesBefore = before;
        }
        var entries = new List<SavedReplicationPermissionEntry>();
        using (var command = _connection.CreateCommand())
        {
            // Protected published links are the original source; interpretation payloads and routes are not display inputs.
            command.CommandText = """
                SELECT a.ordinal,a.fingerprint,p.generation,p.ace_type,p.sid,p.name,p.object_type,p.has_object_type,
                       p.inherited,p.inheritance_flags,p.propagation_flags,p.has_inherited_object_type,p.inherited_object_type
                FROM control_ace a LEFT JOIN permission_entry p ON p.id=a.entry_id
                WHERE a.edge_id=$id AND a.ordinal>$after ORDER BY a.ordinal LIMIT $limit
                """;
            command.Parameters.AddWithValue("$id", edge.Id);
            command.Parameters.AddWithValue("$after", after?.Ordinal ?? -1);
            command.Parameters.AddWithValue("$limit", SavedReplicationPermission.PageSize + 1);
            using var row = command.ExecuteReader();
            while (row.Read())
            {
                _readCancellation.ThrowIfCancellationRequested();
                if (row.GetValue(0) is not long ordinal || ordinal is < 0 or > int.MaxValue
                    || row.GetValue(1) is not byte[] { Length: 32 } || row.IsDBNull(2)
                    || row.GetString(2) != Description.GenerationId.ToString("D") || row.IsDBNull(3) || row.IsDBNull(4)
                    || row.GetValue(9) is not long inheritance || inheritance is < 0 or > 255
                    || row.GetValue(10) is not long propagation || propagation is < 0 or > 255 || (propagation & 0x08) != 0)
                    throw Invalid();
                var hasType = Bit(7);
                var objectType = row.IsDBNull(6) ? null : row.GetString(6);
                if (hasType != (objectType is not null) || objectType is not null && !Guid.TryParse(objectType, out _)
                    || Bit(11) != !row.IsDBNull(12)) throw Invalid();
                var type = row.GetString(3) switch
                {
                    "AccessAllowed" or "AccessAllowedObject" => "Allow",
                    "AccessDenied" or "AccessDeniedObject" => "Deny",
                    _ => "Other saved entry (not re-evaluated here)",
                };
                var scope = !hasType ? "All extended rights"
                    : checks.Where(check => names.Take(3).Contains(check.Name))
                        .FirstOrDefault(check => string.Equals(check.EvidenceSource, objectType, StringComparison.OrdinalIgnoreCase))?.Name switch
                    {
                        ReplicationControlDeriver.Changes => "Replicating Directory Changes",
                        ReplicationControlDeriver.All => "Replicating Directory Changes All",
                        ReplicationControlDeriver.Filtered => "Replicating Directory Changes In Filtered Set",
                        _ => "Other saved scope (not re-evaluated here)",
                    };
                entries.Add(new((int)ordinal, type, row.GetString(4), row.IsDBNull(5) ? null : row.GetString(5), scope, Bit(8)));
            }
            bool Bit(int column) => row.GetValue(column) is long value && value is 0 or 1 ? value == 1 : throw Invalid();
        }
        ReplicationPermissionMark? next = null;
        if (entries.Count > SavedReplicationPermission.PageSize)
        {
            entries.RemoveAt(SavedReplicationPermission.PageSize);
            next = new(reference.GenerationId, reference.FindingId, finding.ObjectGuid, edge.Id, entries[^1].Ordinal);
        }
        var page = new SavedReplicationPermission(context, entries, next, entriesBefore);
        if (!page.IsExpectedPage(after?.Ordinal ?? -1)) throw Invalid();
        _readCancellation.ThrowIfCancellationRequested();
        return Result<SavedReplicationPermission>.Success(page);
        static InvalidDataException Invalid() => new(SavedReplicationPermission.InvalidDetails);
    }
}
