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
    private sealed record Header(int Version, Guid Generation, string InputFingerprint, int NodeCount,
        int RequesterCount, int OwnAccountCount, int MembershipDaclCount, string ProofFingerprint,
        bool OfflineSelection, PathRequesterSelection? Selection);

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
        Header? header;
        using (var read = query.ExecuteReader()) header = read.Read() ? Decode<Header>(read.GetString(0), (byte[])read.GetValue(1)) : null;
        query.CommandText = "SELECT target,outcome,proof,fingerprint FROM tier0_path_node ORDER BY target";
        var saved = new List<Tier0PathNode>();
        using (var read = query.ExecuteReader()) while (read.Read())
        {
            var node = Decode<Tier0PathNode>(read.GetString(2), (byte[])read.GetValue(3));
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
            || Tier0PathCalculation.Fingerprint(proofs) != header.ProofFingerprint) throw Tier0PathStorage.InvalidProof();
        using var sources = ControlProofVerification.OpenSources(reader);
        var bundle = sources.Bundle;
        var contexts = sources.ReadNamingContexts().Value;
        var identities = OwnershipAuditStorage.Targets(connection).Select(row => row.Identity)
            .ToDictionary(value => value.DistinguishedName, StringComparer.OrdinalIgnoreCase);
        IReadOnlyList<Tier0PathNode> nodes = inputs.Availability == PathInputAvailability.Recorded
            ? Tier0PathCalculation.Calculate(inputs, identities.Values.ToArray(),
                TerminalPermissions(connection, reader.Description), bundle.ReadObjectAttributes, contexts, CancellationToken.None)
            : [];
        if (header.Selection is { } selection)
        {
            var expected = new RequesterSelectionReference(bundle.ReadObjectAttributes, bundle.ReadPermissions, inputs,
                nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), contexts, CancellationToken.None)
                .Select() with { Version = PathRequesterSelector.Version };
            Equal(selection, expected);
        }
        var requesters = RequesterDaclProofs.Create(connection, reader.Description, sources, identities, inputs,
            proofs.Requesters.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None, obtainedMembership: null,
            RequesterMembershipContext.Create(sources, identities, inputs, CancellationToken.None));
        Equal(proofs.Requesters, requesters);
        nodes = nodes.Select(node => node with { RequesterRoute = RequesterRouteReference.Requester(node, requesters) }).ToArray();
        var ownAccounts = OwnAccountMembershipProofs.Create(connection, reader.Description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            proofs.OwnAccounts.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None);
        Equal(proofs.OwnAccounts, ownAccounts);
        nodes = nodes.Select(node => node with { OwnAccountRoute = RequesterRouteReference.OwnAccount(node, ownAccounts, requesters) }).ToArray();
        var membershipDacls = MembershipDaclProofs.Create(connection, reader.Description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            proofs.MembershipDacls.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None,
            RequesterMembershipContext.Create(sources, identities, inputs, CancellationToken.None));
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
            using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE path_requester_risk SET source_proof=json_set(source_proof,$path,
                """ + sqlValue + """
                ) WHERE id=(SELECT id FROM path_requester_risk
                WHERE json_extract(proof,'$.Family')=$family ORDER BY id LIMIT 1 OFFSET $ordinal)
                """;
            command.Parameters.AddWithValue("$path", "$" + match.Groups[3].Value);
            command.Parameters.AddWithValue("$family", family.ToString());
            command.Parameters.AddWithValue("$ordinal", int.Parse(match.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture));
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("The intended source-proof mutation changed no question.");
            RebindRequesterProofs(connection);
        });

    internal static void RebindRequesterProofs(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,proof,source_proof FROM path_requester_risk ORDER BY id";
        var rows = new List<(long Id, JsonObject Risk, string Source)>();
        using (var read = command.ExecuteReader())
            while (read.Read()) rows.Add((read.GetInt64(0), JsonNode.Parse(read.GetString(1))!.AsObject(), read.GetString(2)));
        var direct = new List<SavedRequesterDaclProof>();
        var own = new List<SavedOwnAccountMembershipProof>();
        var combined = new List<SavedMembershipDaclProof>();
        foreach (var row in rows)
        {
            var family = Enum.Parse<PathRequesterFamily>(row.Risk["Family"]!.GetValue<string>());
            if (family == PathRequesterFamily.RequesterDacl)
                direct.Add(JsonSerializer.Deserialize<SavedRequesterDaclProof>(row.Source, ProofSerialization.Options)!);
            else if (family == PathRequesterFamily.OwnAccountMembership)
                own.Add(JsonSerializer.Deserialize<SavedOwnAccountMembershipProof>(row.Source, ProofSerialization.Options)!);
            else
                combined.Add(JsonSerializer.Deserialize<SavedMembershipDaclProof>(row.Source, ProofSerialization.Options)!);
        }
        command.Parameters.Clear();
        command.CommandText = "SELECT proof FROM tier0_path_calculation WHERE id=1";
        var header = JsonNode.Parse((string)command.ExecuteScalar()!)!.AsObject();
        header["ProofFingerprint"] = Tier0PathCalculation.Fingerprint(new PathRequesterProofs(direct, own, combined));
        var headerJson = header.ToJsonString(ProofSerialization.Options);
        var calculation = Convert.ToHexString(OwnershipAuditStorage.Hash(headerJson));
        Update("tier0_path_calculation", 1, headerJson);
        foreach (var row in rows)
        {
            row.Risk["SourceProofFingerprint"] = Convert.ToHexString(OwnershipAuditStorage.Hash(row.Source));
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
            command.CommandText = $"UPDATE {table} SET proof=$proof,fingerprint=$hash WHERE id=$id";
            command.Parameters.AddWithValue("$proof", json);
            command.Parameters.AddWithValue("$hash", OwnershipAuditStorage.Hash(json));
            command.Parameters.AddWithValue("$id", id);
            if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("A proof binding was not updated.");
        }
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
        return JsonSerializer.Deserialize<T>(json, ProofSerialization.Options) ?? throw Tier0PathStorage.InvalidProof();
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
