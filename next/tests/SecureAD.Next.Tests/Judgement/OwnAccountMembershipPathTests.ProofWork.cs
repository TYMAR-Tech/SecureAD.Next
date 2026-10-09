using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnAccountMembershipPathTests
{
    [Fact]
    public void NormalRequesterProofsUseThePreparedOriginalFingerprintIndex()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        var request = new RequesterDaclRequest(UserDn, CoreDn);
        var expected = Assert.Single(TargetPermissionReference.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, [request], CancellationToken.None, null, fixture.Memberships, currentSourceFingerprints: true));
        Assert.Equal(ControlEvaluationState.Established, expected.Assessment.Authorization);

        var actual = Assert.Single(RequesterBatchEvaluation.Create(fixture.Connection, fixture.Description, fixture.Sources,
            fixture.Identities, fixture.Inputs, [new(request, null)], CancellationToken.None, fixture.Memberships));

        Assert.Equal(JsonSerializer.Serialize(expected, ProofSerialization.Options), JsonSerializer.Serialize(actual, ProofSerialization.Options));
    }

    [Fact]
    public void PathNodesReuseOneWriterCommandAndKeepEverySavedNode()
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions", 4);
        ClearProofRows(fixture.Connection);
        using var statements = new PreparedStatements(fixture.Connection);

        Tier0PathStorage.Write(fixture.Connection, fixture.Description, fixture.Sources, [], [], CancellationToken.None,
            [], false, _ => { }, null, statements);

        var commands = Assert.IsType<Dictionary<string, SqliteCommand>>(typeof(PreparedStatements)
            .GetField("_commands", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(statements));
        var command = Assert.Single(commands.Values.Where(value => value.CommandText.StartsWith("INSERT INTO tier0_path_node ", StringComparison.Ordinal)));
        Assert.Equal(4, command.Parameters.Count);
        using var readNodes = fixture.Connection.CreateCommand();
        readNodes.CommandText = "SELECT proof,fingerprint FROM tier0_path_node ORDER BY target COLLATE NOCASE";
        using var read = readNodes.ExecuteReader();
        var nodes = new List<Tier0PathNode>();
        while (read.Read())
            nodes.Add(PathProofStorage.Read<Tier0PathNode>(fixture.Connection, read.GetInt64(0),
                Convert.ToHexString((byte[])read.GetValue(1)), CancellationToken.None));
        Assert.Equal(fixture.Nodes.Count, nodes.Count);
        Assert.Equal(JsonSerializer.Serialize(fixture.Nodes.Values.OrderBy(node => node.Subject.DistinguishedName, StringComparer.OrdinalIgnoreCase), ProofSerialization.Options),
            JsonSerializer.Serialize(nodes, ProofSerialization.Options));
        Assert.Equal(nodes[^1].Subject.DistinguishedName, command.Parameters["$target"].Value);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void InterruptedNodeWritesRollbackEveryNewProofRow(bool cancel)
    {
        using var fixture = PrerequisiteFixtureFor("both-permissions");
        ClearProofRows(fixture.Connection);
        using var stopping = new CancellationTokenSource();
        using var statements = new PreparedStatements(fixture.Connection);
        using var command = fixture.Connection.CreateCommand();
        command.CommandText = "SELECT (SELECT COUNT(*) FROM path_proof)+(SELECT COUNT(*) FROM path_proof_chunk)";
        var existing = Assert.IsType<long>(command.ExecuteScalar());
        var written = 0;
        fixture.Connection.CreateFunction("interrupt_node", () => { written++; stopping.Cancel(); return 1; });
        command.CommandText = cancel
            ? "CREATE TRIGGER interrupt_node_write AFTER INSERT ON tier0_path_node BEGIN SELECT interrupt_node(); END"
            : "CREATE TRIGGER ignore_node_write BEFORE INSERT ON tier0_path_node BEGIN SELECT RAISE(IGNORE); END";
        command.ExecuteNonQuery();

        var error = Record.Exception(() => Tier0PathStorage.Write(fixture.Connection, fixture.Description, fixture.Sources,
            [], [], stopping.Token, [], false, _ => { }, null, statements));

        if (cancel)
        {
            Assert.IsType<OperationCanceledException>(error);
            Assert.Equal(1, written);
        }
        else Assert.IsType<InvalidDataException>(error);
        command.CommandText = "SELECT (SELECT COUNT(*) FROM path_proof)+(SELECT COUNT(*) FROM path_proof_chunk)";
        Assert.Equal(existing, command.ExecuteScalar());
        command.CommandText = "SELECT (SELECT COUNT(*) FROM tier0_path_node)+(SELECT COUNT(*) FROM tier0_path_calculation)";
        Assert.Equal(0L, command.ExecuteScalar());
        Assert.Equal(fixture.Description.GenerationId,
            AnalysisStoreLifecycle.Resolve(fixture.Reader.BundleDirectory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    private static void ClearProofRows(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM tier0_best_route; DELETE FROM tier0_distance; DELETE FROM tier0_distance_product; DELETE FROM path_requester_risk; DELETE FROM path_risk_product; DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation";
        command.ExecuteNonQuery();
    }
}
