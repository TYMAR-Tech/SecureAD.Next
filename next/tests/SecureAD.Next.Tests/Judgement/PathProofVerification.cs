using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

// Resealed alterations test production proof correctness offline, not a tamper claim made by browsing.
internal static class PathProofVerification
{
    internal static void EnableJsonReads(SqliteConnection connection) =>
        connection.CreateFunction("path_json", (long id) => Json(connection, id));

    internal static string Json(SqliteConnection connection, long id)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT data FROM path_proof_chunk WHERE proof_id=$id ORDER BY ordinal";
        command.Parameters.AddWithValue("$id", id);
        using var read = command.ExecuteReader();
        using var bytes = new MemoryStream();
        while (read.Read()) bytes.Write((byte[])read.GetValue(0));
        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    internal static void ReplaceJson(SqliteConnection connection, long id, string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM path_proof_chunk WHERE proof_id=$id";
        command.Parameters.AddWithValue("$id", id);
        command.ExecuteNonQuery();
        command.CommandText = "INSERT INTO path_proof_chunk VALUES ($id,$ordinal,$data)";
        command.Parameters.Add("$ordinal", SqliteType.Integer);
        command.Parameters.Add("$data", SqliteType.Blob);
        var chunks = 0;
        for (var offset = 0; offset < bytes.Length; offset += PathProofStorage.ChunkSize)
        {
            command.Parameters["$ordinal"].Value = chunks++;
            command.Parameters["$data"].Value = bytes.AsSpan(offset, Math.Min(PathProofStorage.ChunkSize, bytes.Length - offset)).ToArray();
            command.ExecuteNonQuery();
        }
        command.Parameters.Clear();
        command.CommandText = "UPDATE path_proof SET byte_length=$length,chunk_count=$chunks WHERE id=$id";
        command.Parameters.AddWithValue("$length", bytes.Length);
        command.Parameters.AddWithValue("$chunks", chunks);
        command.Parameters.AddWithValue("$id", id);
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("The proof manifest was not replaced.");
    }

    internal static void AlterJson(SqliteConnection connection, string table, string expression,
        string condition = "", string column = "proof")
    {
        EnableJsonReads(connection);
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT rowid,{column} FROM {table} {condition}";
        var rows = new List<(long Row, long Proof)>();
        using (var read = command.ExecuteReader())
            while (read.Read()) rows.Add((read.GetInt64(0), read.GetInt64(1)));
        if (rows.Count == 0) throw new InvalidOperationException("The mutation did not select a saved proof.");
        foreach (var row in rows)
        {
            command.Parameters.Clear();
            command.CommandText = "SELECT " + expression;
            command.Parameters.AddWithValue("$json", Json(connection, row.Proof));
            var json = (string)command.ExecuteScalar()!;
            ReplaceJson(connection, row.Proof, json);
            if (column != "proof") continue;
            command.Parameters.Clear();
            command.CommandText = $"UPDATE {table} SET fingerprint=$hash WHERE rowid=$row";
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
            command.Parameters.AddWithValue("$row", row.Row);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("The proof fingerprint was not replaced.");
        }
    }

    internal static void ChangeJson(string directory, string table, string path, string sqlValue, string condition = "") =>
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var record = Regex.Match(path, @"^\$\.Selection\.(Candidates|Sources|Limitations)\[(\d+)\](.*)$");
            if (table != "tier0_path_calculation" || !record.Success)
            {
                if (table == "tier0_path_calculation" && path == "$.Selection.Candidates" && sqlValue == "json('[]')")
                {
                    using var clear = connection.CreateCommand();
                    clear.CommandText = "DELETE FROM path_calculation_record WHERE kind='Candidates'";
                    clear.ExecuteNonQuery();
                    sqlValue = "json('" + JsonSerializer.Serialize(new PathCalculationStorage.RecordSet(0,
                        Tier0PathCalculation.Fingerprint(Array.Empty<PathProofStorage.Reference>())), ProofSerialization.Options) + "')";
                }
                AlterJson(connection, table, $"json_set($json,'{path}',{sqlValue})", condition);
                if (table == "tier0_path_calculation") RebindRequesterProofs(connection);
                return;
            }
            var kind = record.Groups[1].Value;
            var ordinal = int.Parse(record.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT proof,hex(fingerprint) FROM path_calculation_record WHERE kind=$kind AND ordinal=$ordinal";
            command.Parameters.AddWithValue("$kind", kind);
            command.Parameters.AddWithValue("$ordinal", ordinal);
            long id;
            string fingerprint;
            using (var read = command.ExecuteReader())
            {
                if (!read.Read()) throw new InvalidOperationException("No selection record to mutate.");
                id = read.GetInt64(0);
                fingerprint = read.GetString(1);
            }
            var description = Description(connection);
            var shared = new PathSharedProofStorage(connection, description, CancellationToken.None);
            var logical = kind switch
            {
                "Candidates" => JsonSerializer.Serialize(shared.Read<PathRequesterCandidate>(id, fingerprint), ProofSerialization.Options),
                "Sources" => JsonSerializer.Serialize(shared.Read<PathRequesterSelectionSource>(id, fingerprint), ProofSerialization.Options),
                _ => JsonSerializer.Serialize(shared.Read<PathRequesterSelectionLimitation>(id, fingerprint), ProofSerialization.Options),
            };
            var changed = Change(connection, logical, "$" + record.Groups[3].Value, sqlValue);
            using var transaction = connection.BeginTransaction();
            using var statements = new PreparedStatements(connection);
            using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
            var writer = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
            var saved = kind switch
            {
                "Candidates" => writer.Write(JsonSerializer.Deserialize<PathRequesterCandidate>(changed, ProofSerialization.Options)),
                "Sources" => writer.Write(JsonSerializer.Deserialize<PathRequesterSelectionSource>(changed, ProofSerialization.Options)),
                _ => writer.Write(JsonSerializer.Deserialize<PathRequesterSelectionLimitation>(changed, ProofSerialization.Options)),
            };
            command.Parameters.Clear();
            command.CommandText = "UPDATE path_calculation_record SET proof=$proof,fingerprint=$hash WHERE kind=$kind AND ordinal=$ordinal";
            command.Transaction = transaction;
            command.Parameters.AddWithValue("$proof", saved.Id);
            command.Parameters.AddWithValue("$hash", saved.Fingerprint);
            command.Parameters.AddWithValue("$kind", kind);
            command.Parameters.AddWithValue("$ordinal", ordinal);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Selection mutation did not replace a record.");
            transaction.Commit();
            command.Transaction = null;
            command.Parameters.Clear();
            command.CommandText = "SELECT proof,fingerprint FROM path_calculation_record WHERE kind=$kind ORDER BY ordinal";
            command.Parameters.AddWithValue("$kind", kind);
            var references = new List<PathProofStorage.Reference>();
            using (var read = command.ExecuteReader())
                while (read.Read()) references.Add(new(read.GetInt64(0), (byte[])read.GetValue(1)));
            var digest = Tier0PathCalculation.Fingerprint(references);
            AlterJson(connection, "tier0_path_calculation", $"json_set($json,'$.Selection.{kind}.Fingerprint','{digest}')");
            RebindRequesterProofs(connection);
        });

    internal static PathInputs ReadInputs(JudgementReader reader)
    {
        using var connection = Open(reader);
        var inputs = PathInputStorage.Read(connection, reader.Description, out var ownership, CancellationToken.None);
        using var sources = ControlProofVerification.OpenSources(reader);
        if (inputs.Availability == PathInputAvailability.Recorded)
            PathInputStorage.ValidateSources(connection, reader.Description, sources, ownership, inputs, CancellationToken.None);
        else
            OwnershipAuditValidation.Validate(connection, reader.Description, sources,
                new OwnershipAuditStorage.Snapshot(connection, reader.Description, CancellationToken.None));
        return inputs;
    }

    internal static Tier0PathResult ReadPath(JudgementReader reader, string subjectDn)
    {
        Verify(reader);
        return reader.ReadTier0Path(subjectDn);
    }

    internal static PathRequesterCoverage ReadCoverage(JudgementReader reader)
    {
        Verify(reader);
        return reader.ReadPathRequesterCoverage();
    }

    private static void Verify(JudgementReader reader)
    {
        var inputs = ReadInputs(reader);
        using var connection = Open(reader);
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT proof,fingerprint FROM tier0_path_calculation WHERE id=1";
        PathCalculationStorage.Manifest? header;
        using (var read = query.ExecuteReader()) header = read.Read()
            ? Decode<PathCalculationStorage.Manifest>(Json(connection, read.GetInt64(0)), (byte[])read.GetValue(1)) : null;
        query.CommandText = "SELECT target,outcome,proof,fingerprint FROM tier0_path_node ORDER BY target";
        var saved = new List<Tier0PathNode>();
        using (var read = query.ExecuteReader()) while (read.Read())
        {
            var node = Decode<Tier0PathNode>(Json(connection, read.GetInt64(2)), (byte[])read.GetValue(3));
            if (node.Subject.DistinguishedName != read.GetString(0) || node.Reachability.ToString() != read.GetString(1))
                throw Tier0PathStorage.InvalidProof();
            saved.Add(node);
        }
        if (header is null)
        {
            if (inputs.Availability == PathInputAvailability.Recorded || saved.Count != 0) throw Tier0PathStorage.InvalidProof();
            return;
        }
        if (header.Version != Tier0PathCalculation.Version || header.Generation != reader.Description.GenerationId
            || header.InputFingerprint != Tier0PathCalculation.Fingerprint(inputs) || header.NodeCount != saved.Count)
            throw Tier0PathStorage.InvalidProof();
        var proofs = PathRequesterRiskStorage.ReadProofs(connection, reader.Description, CancellationToken.None);
        if (proofs.Requesters.Count != header.RequesterCount || proofs.OwnAccounts.Count != header.OwnAccountCount
            || proofs.MembershipDacls.Count != header.MembershipDaclCount
            || Tier0PathCalculation.Fingerprint(PathCalculationStorage.SourceReferences(connection, CancellationToken.None)) != header.ProofFingerprint)
            throw Tier0PathStorage.InvalidProof();
        using var sources = ControlProofVerification.OpenSources(reader);
        var bundle = sources.Bundle;
        var contexts = sources.ReadNamingContexts().Value;
        var identities = OwnershipAuditStorage.Targets(connection).Select(row => row.Identity)
            .ToDictionary(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<Tier0PathNode> nodes = inputs.Availability == PathInputAvailability.Recorded
            ? Tier0PathCalculation.Calculate(inputs, identities.Values.ToArray(),
                TerminalPermissions(connection, reader.Description), bundle.ReadObjectAttributes, contexts, CancellationToken.None, null)
            : [];
        if (PathCalculationStorage.ReadSelection(connection, reader.Description, header, CancellationToken.None) is { } selection)
        {
            var expected = new RequesterSelectionReference(bundle.ReadObjectAttributes, bundle.ReadPermissions, inputs,
                nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), contexts, CancellationToken.None)
                .Select() with { Version = PathRequesterSelector.Version };
            Equal(selection, expected);
        }
        var requesters = TargetPermissionReference.Create(connection, reader.Description, sources, identities, inputs,
            proofs.Requesters.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None, obtainedMembership: null,
            RequesterMembershipContext.Create(sources, identities, inputs, CancellationToken.None), currentSourceFingerprints: true);
        Equal(proofs.Requesters, requesters);
        nodes = nodes.Select(node => node with { RequesterRoute = RequesterRouteReference.Requester(node, requesters) }).ToArray();
        var ownAccounts = MembershipPrerequisiteReference.OwnAccounts(connection, reader.Description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            proofs.OwnAccounts.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None, currentSourceFingerprints: true);
        Equal(proofs.OwnAccounts, ownAccounts);
        nodes = nodes.Select(node => node with { OwnAccountRoute = RequesterRouteReference.OwnAccount(node, ownAccounts, requesters) }).ToArray();
        var membershipDacls = MembershipPrerequisiteReference.Combined(connection, reader.Description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            proofs.MembershipDacls.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None,
            RequesterMembershipContext.Create(sources, identities, inputs, CancellationToken.None), currentSourceFingerprints: true);
        Equal(proofs.MembershipDacls, membershipDacls);
        nodes = nodes.Select(node => node with { MembershipDaclRoute = RequesterRouteReference.MembershipDacl(node, membershipDacls, requesters, ownAccounts) }).ToArray();
        Equal(saved, nodes);
        reader.ReadPathRequesterCoverage();
    }

    internal static void AlterRequesterProof(string directory, string address, string sqlValue) =>
        SelfMembershipCoverageTests.Mutate(directory, connection =>
        {
            var match = Regex.Match(address, @"^\$\.(Requesters|OwnAccounts|MembershipDacls)\[(\d+)\](\..+)$");
            if (!match.Success) throw new ArgumentException("A proof mutation must identify its family, ordinal and member.", nameof(address));
            var family = match.Groups[1].Value switch
            {
                "Requesters" => PathRequesterFamily.RequesterDacl,
                "OwnAccounts" => PathRequesterFamily.OwnAccountMembership,
                _ => PathRequesterFamily.MembershipDacl,
            };
            var ordinal = int.Parse(match.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture);
            using var command = connection.CreateCommand();
            EnableJsonReads(connection);
            command.CommandText = """
                SELECT id,source_proof,hex(source_fingerprint) FROM path_requester_risk
                WHERE json_extract(path_json(proof),'$.Family')=$family ORDER BY id LIMIT 1 OFFSET $ordinal
                """;
            command.Parameters.AddWithValue("$family", family.ToString());
            command.Parameters.AddWithValue("$ordinal", ordinal);
            long row;
            long source;
            string fingerprint;
            using (var read = command.ExecuteReader())
            {
                if (!read.Read()) throw new InvalidOperationException("No requester proof to mutate.");
                row = read.GetInt64(0);
                source = read.GetInt64(1);
                fingerprint = read.GetString(2);
            }
            var description = Description(connection);
            var shared = new PathSharedProofStorage(connection, description, CancellationToken.None);
            var logical = family switch
            {
                PathRequesterFamily.RequesterDacl => JsonSerializer.Serialize(shared.Read<SavedRequesterDaclProof>(source, fingerprint), ProofSerialization.Options),
                PathRequesterFamily.OwnAccountMembership => JsonSerializer.Serialize(shared.Read<SavedOwnAccountMembershipProof>(source, fingerprint), ProofSerialization.Options),
                _ => JsonSerializer.Serialize(shared.Read<SavedMembershipDaclProof>(source, fingerprint), ProofSerialization.Options),
            };
            var changed = Change(connection, logical, "$" + match.Groups[3].Value, sqlValue);
            using (var transaction = connection.BeginTransaction())
            using (var statements = new PreparedStatements(connection))
            using (var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None))
            {
                var writer = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
                var saved = family switch
                {
                    PathRequesterFamily.RequesterDacl => writer.Write(JsonSerializer.Deserialize<SavedRequesterDaclProof>(changed, ProofSerialization.Options)),
                    PathRequesterFamily.OwnAccountMembership => writer.Write(JsonSerializer.Deserialize<SavedOwnAccountMembershipProof>(changed, ProofSerialization.Options)),
                    _ => writer.Write(JsonSerializer.Deserialize<SavedMembershipDaclProof>(changed, ProofSerialization.Options)),
                };
                command.Transaction = transaction;
                command.Parameters.Clear();
                command.CommandText = "UPDATE path_requester_risk SET source_proof=$source,source_fingerprint=$hash WHERE id=$id";
                command.Parameters.AddWithValue("$source", saved.Id);
                command.Parameters.AddWithValue("$hash", saved.Fingerprint);
                command.Parameters.AddWithValue("$id", row);
                if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("Requester mutation did not replace a proof.");
                transaction.Commit();
            }
            RebindRequesterProofs(connection);
        });

    internal static void RebindRequesterProofs(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,proof,source_fingerprint FROM path_requester_risk ORDER BY id";
        var rows = new List<(long Id, JsonObject Risk, string Fingerprint)>();
        using (var read = command.ExecuteReader())
            while (read.Read()) rows.Add((read.GetInt64(0), JsonNode.Parse(Json(connection, read.GetInt64(1)))!.AsObject(),
                Convert.ToHexString((byte[])read.GetValue(2))));
        command.Parameters.Clear();
        command.CommandText = "SELECT proof FROM tier0_path_calculation WHERE id=1";
        var header = JsonNode.Parse(Json(connection, (long)command.ExecuteScalar()!))!.AsObject();
        header["ProofFingerprint"] = Tier0PathCalculation.Fingerprint(PathCalculationStorage.SourceReferences(connection, CancellationToken.None));
        var headerJson = header.ToJsonString(ProofSerialization.Options);
        var calculation = Convert.ToHexString(OwnershipAuditStorage.Hash(headerJson));
        Update("tier0_path_calculation", 1, headerJson);
        foreach (var row in rows)
        {
            row.Risk["SourceProofFingerprint"] = row.Fingerprint;
            row.Risk["CalculationFingerprint"] = calculation;
            Update("path_requester_risk", row.Id, row.Risk.ToJsonString(ProofSerialization.Options));
        }
        command.Parameters.Clear();
        command.CommandText = "SELECT proof FROM path_risk_product WHERE id=1";
        var coverage = JsonNode.Parse((string)command.ExecuteScalar()!)!.AsObject();
        coverage["CalculationFingerprint"] = calculation;
        Update("path_risk_product", 1, coverage.ToJsonString(ProofSerialization.Options));

        void Update(string table, long id, string json)
        {
            command.Parameters.Clear();
            if (table != "path_risk_product")
            {
                command.CommandText = $"SELECT proof FROM {table} WHERE id=$id";
                command.Parameters.AddWithValue("$id", id);
                ReplaceJson(connection, (long)command.ExecuteScalar()!, json);
                command.Parameters.Clear();
                command.CommandText = $"UPDATE {table} SET fingerprint=$hash WHERE id=$id";
            }
            else
            {
                command.CommandText = $"UPDATE {table} SET proof=$proof,fingerprint=$hash WHERE id=$id";
                command.Parameters.AddWithValue("$proof", json);
            }
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
            command.Parameters.AddWithValue("$id", id);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("A proof binding was not updated.");
        }
    }

    internal static string SourceFingerprint<T>(SqliteConnection connection, JudgementDescription description,
        PathRequesterFamily family, T expected)
    {
        EnableJsonReads(connection);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT source_proof,source_fingerprint FROM path_requester_risk
            WHERE json_extract(path_json(proof),'$.Family')=$family ORDER BY id
            """;
        command.Parameters.AddWithValue("$family", family.ToString());
        using var read = command.ExecuteReader();
        if (!read.Read()) throw new InvalidOperationException("No source proof for this family.");
        var id = read.GetInt64(0);
        var hash = Convert.ToHexString(OwnershipAuditStorage.Hash(Json(connection, id)));
        if (hash != Convert.ToHexString((byte[])read.GetValue(1))) throw Tier0PathStorage.InvalidProof();
        Equal(expected, new PathSharedProofStorage(connection, description, CancellationToken.None).Read<T>(id, hash));
        return hash;
    }

    internal static string ExpandedSourceJson(SqliteConnection connection, JudgementDescription description,
        PathRequesterFamily family, long id, string fingerprint)
    {
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None);
        return family switch
        {
            PathRequesterFamily.RequesterDacl => JsonSerializer.Serialize(shared.Read<SavedRequesterDaclProof>(id, fingerprint), ProofSerialization.Options),
            PathRequesterFamily.OwnAccountMembership => JsonSerializer.Serialize(shared.Read<SavedOwnAccountMembershipProof>(id, fingerprint), ProofSerialization.Options),
            _ => JsonSerializer.Serialize(shared.Read<SavedMembershipDaclProof>(id, fingerprint), ProofSerialization.Options),
        };
    }

    private static string Change(SqliteConnection connection, string json, string path, string sqlValue)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT json_set($json,$path,{sqlValue})";
        command.Parameters.AddWithValue("$json", json);
        command.Parameters.AddWithValue("$path", path);
        return (string)command.ExecuteScalar()!;
    }

    private static JudgementDescription Description(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT evidence_seal,judgement_generation_id,derivation_generation_id FROM judgement";
        using var read = command.ExecuteReader();
        if (!read.Read()) throw new InvalidOperationException("No judgement description.");
        return new(read.GetString(0), Guid.Parse(read.GetString(1)), read.IsDBNull(2) ? null : Guid.Parse(read.GetString(2)),
            JudgementRunState.CompletedDegraded, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
    }

    private static IEnumerable<ControlEdge> TerminalPermissions(SqliteConnection connection, JudgementDescription description)
    {
        using var query = connection.CreateCommand();
        query.CommandText = "SELECT e.id FROM control_edge e JOIN path_anchor a ON a.target=e.target COLLATE NOCASE WHERE e.capability IN ('CanWriteDacl','IsOwnerAndCanRewriteDacl')";
        var ids = new List<long>();
        using (var read = query.ExecuteReader()) while (read.Read()) ids.Add(read.GetInt64(0));
        return ids.Select(id => ControlEdgeStorage.ReadEdge(connection, description, id))
            .OrderBy(edge => edge.Target, StringComparer.OrdinalIgnoreCase).ThenBy(edge => edge.Capability).ThenBy(edge => edge.Id);
    }

    private static T Decode<T>(string json, byte[] fingerprint)
    {
        if (!OwnershipAuditStorage.Hash(json).AsSpan().SequenceEqual(fingerprint)) throw Tier0PathStorage.InvalidProof();
        try { return JsonSerializer.Deserialize<T>(json, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof(); }
        catch (JsonException) { throw Tier0PathStorage.InvalidProof(); }
    }

    private static void Equal<T>(T actual, T expected)
    {
        if (Tier0PathCalculation.Fingerprint(actual) != Tier0PathCalculation.Fingerprint(expected)) throw Tier0PathStorage.InvalidProof();
    }

    private static SqliteConnection Open(JudgementReader reader)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }
}
