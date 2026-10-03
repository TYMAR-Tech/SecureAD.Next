using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;

namespace SecureAD.Next.Tests.Judgement;

// Resealed alterations test production proof correctness offline, not a tamper claim made by browsing.
internal static class PathProofVerification
{
    private sealed record Header(int Version, Guid Generation, string InputFingerprint, int NodeCount,
        IReadOnlyList<SavedRequesterDaclProof> Requesters, IReadOnlyList<SavedOwnAccountMembershipProof> OwnAccounts,
        IReadOnlyList<SavedMembershipDaclProof> MembershipDacls, bool OfflineSelection, PathRequesterSelection? Selection);

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
            var expected = new PathRequesterSelector(bundle, inputs,
                nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), contexts, CancellationToken.None).Select();
            Equal(selection, expected);
        }
        var requesters = RequesterDaclProofs.Create(connection, reader.Description, sources, identities, inputs,
            header.Requesters.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None, obtainedMembership: null);
        Equal(header.Requesters, requesters);
        nodes = nodes.Select(node => node with { RequesterRoute = RequesterDaclProofs.Best(node, requesters) }).ToArray();
        var ownAccounts = OwnAccountMembershipProofs.Create(connection, reader.Description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            header.OwnAccounts.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None);
        Equal(header.OwnAccounts, ownAccounts);
        nodes = nodes.Select(node => node with { OwnAccountRoute = OwnAccountMembershipProofs.Best(node, ownAccounts, requesters) }).ToArray();
        var membershipDacls = MembershipDaclProofs.Create(connection, reader.Description, sources, identities, inputs,
            nodes.ToDictionary(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase),
            header.MembershipDacls.Select(proof => proof.Assessment.Request).ToArray(), CancellationToken.None);
        Equal(header.MembershipDacls, membershipDacls);
        nodes = nodes.Select(node => node with { MembershipDaclRoute = MembershipDaclProofs.Best(node, membershipDacls, requesters, ownAccounts) }).ToArray();
        Equal(saved, nodes);
        reader.ReadPathRequesterCoverage();
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
