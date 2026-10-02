using System.Reflection;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SQLitePCL;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PostPassLookupTests
{
    private const string IdentityQuery = "SELECT distinguished_name,object_id FROM captured_object";

    [Fact]
    public void AdmissionPreparesOnceAndOwnershipReusesRowIdentities()
    {
        using var fixture = new AdmissionFixture(observeSeed: true);
        using var trace = new Statements(EvidenceConnection(fixture.Bundle));
        Assert.Equal(2, fixture.Admit());
        Assert.Single(trace.Sql.Where(sql => sql == IdentityQuery));
        Assert.Equal(2, trace.Sql.Count(IsAttributeRowRead));
        fixture.Assess();
        Assert.Single(trace.Sql.Where(sql => sql == IdentityQuery));
        Assert.Equal(3, trace.Sql.Count(IsAttributeRowRead));
        Assert.DoesNotContain(trace.Sql, sql => sql.Contains("WHERE o.distinguished_name =", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void NoAdmittedWorkDoesNotPrepareIdentityMap(bool missingInput)
    {
        using var fixture = new AdmissionFixture(observeSeed: false);
        using var trace = new Statements(EvidenceConnection(fixture.Bundle));
        Assert.Equal(0, fixture.Admit(missingInput));
        Assert.DoesNotContain(IdentityQuery, trace.Sql);
        Assert.DoesNotContain(trace.Sql, IsAttributeRowRead);
    }

    [Fact]
    public void StoredEdgeReadsSeekTheParentAndRetainSupportingPermission()
    {
        using var fixture = new EdgeFixture();
        using var trace = new Statements(fixture.Connection);
        var edge = ControlEdgeStorage.ReadEdge(fixture.Connection, fixture.Description, fixture.Id);
        var exact = ControlEdgeStorage.ReadExact(fixture.Connection, fixture.Description, edge.Target, fixture.Id);
        Assert.Equal(JsonSerializer.Serialize(edge), JsonSerializer.Serialize(exact));
        Assert.Equal(ControlCapability.CanSetOwner, edge.Capability);
        var permission = Assert.Single(edge.Evidence);
        Assert.Equal((7, 0x80000, ControlEdgeDeriverTests.Holder), (permission.Ordinal, permission.AccessMask, permission.Trustee.Sid));
        var statements = trace.Sql.Where(sql => sql.StartsWith("SELECT control_edge.*,", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, statements.Length);
        foreach (var sql in statements)
        {
            using var command = fixture.Connection.CreateCommand();
            command.CommandText = "EXPLAIN QUERY PLAN " + sql;
            command.Parameters.AddWithValue("$id", fixture.Id);
            using var read = command.ExecuteReader();
            var plan = new List<string>();
            while (read.Read()) plan.Add(read.GetString(3));
            Assert.Contains(plan, detail => detail.StartsWith("SEARCH control_object USING INDEX", StringComparison.Ordinal));
            Assert.DoesNotContain(plan, detail => detail.StartsWith("SCAN control_object", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void IndexedParentLookupStillRefusesDifferentStoredTargetSpelling()
    {
        using var fixture = new EdgeFixture();
        Execute(fixture.Connection, "UPDATE control_object SET target=upper(target) WHERE target='OU=Test,DC=contoso,DC=com'");
        Assert.Throws<InvalidOperationException>(() => ControlEdgeStorage.ReadEdge(fixture.Connection, fixture.Description, fixture.Id));
    }

    // Descriptor reads use the same alias and predicate; only the captured-object query reads attributes.
    private static bool IsAttributeRowRead(string sql) =>
        sql.StartsWith("SELECT o.object_id, o.distinguished_name,", StringComparison.Ordinal)
        && sql.Contains(" FROM captured_object AS o ", StringComparison.Ordinal)
        && sql.Contains("WHERE o.object_id =", StringComparison.Ordinal);

    // Observe the reader's real connection without adding a production diagnostic surface.
    private static SqliteConnection EvidenceConnection(BundleReader reader) => Assert.IsType<SqliteConnection>(
        typeof(BundleReader).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(reader));

    private sealed class Statements : IDisposable
    {
        private readonly SqliteConnection connection;
        private readonly strdelegate_trace callback;
        internal List<string> Sql { get; } = [];

        internal Statements(SqliteConnection connection)
        {
            this.connection = connection;
            callback = (_, sql) => Sql.Add(sql);
            raw.sqlite3_trace(connection.Handle!, callback, null!);
            Execute(connection, "SELECT 73");
            Assert.Contains("SELECT 73", Sql);
        }

        public void Dispose()
        {
            raw.sqlite3_trace(connection.Handle!, (strdelegate_trace)null!, null!);
            GC.KeepAlive(callback);
        }
    }

    private sealed class AdmissionFixture : IDisposable
    {
        internal BundleReader Bundle { get; }
        private readonly JudgementWriter writer;
        private readonly CapturedMembershipInput input;
        private readonly Tier0InputBinding binding;
        private readonly Tier0DiscoveryScheduler discovery;
        private readonly JudgingContext context;
        private readonly JudgementDescription description;
        private readonly int objects;

        internal AdmissionFixture(bool observeSeed)
        {
            var directory = SelfMembershipDiscoveryTests.Bundle(rootDescriptor: $"O:SYG:SYD:(A;;WO;;;{UserSid})");
            Derive(directory);
            var opened = BundleReader.Open(directory);
            Assert.True(opened.IsSuccess, opened.Error?.Description);
            Bundle = opened.Value;
            var derived = DerivationReader.Open(directory);
            Assert.True(derived.IsSuccess, derived.Error?.Description);
            using var derivation = derived.Value;
            input = derivation.ReadMembershipInput();
            var contexts = Bundle.ReadNamingContexts();
            Assert.True(contexts.IsSuccess, contexts.Error?.Description);
            var subjects = Bundle.StreamObjects().Objects.ToArray();
            objects = subjects.Length;
            var byName = subjects.ToDictionary(subject => subject.DistinguishedName, StringComparer.OrdinalIgnoreCase);
            var seal = JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(BundleLayout.SealPath(directory)))!;
            binding = OwnershipAuditRun.Binding(directory, seal.Hash, input.DerivationGenerationId, "contoso.com", contexts.Value);
            context = JudgingContext.At(Started) with
            {
                ForestFqdn = "contoso.com", NamingContexts = contexts.Value,
                SchemaGuids = Bundle.ReadSchemaGuids(), ControlPrincipals = dn => byName.GetValueOrDefault(dn),
            };
            writer = JudgementWriter.Create(directory, seal.Hash, input.DerivationGenerationId, Started, Started);
            description = new(seal.Hash, writer.GenerationId, input.DerivationGenerationId, JudgementRunState.Running, Started, Started, default);
            writer.StartControlEdges(true, true);
            writer.StartAutomaticOwnership(description, OwnershipAuditRun.OwnerRightsHash(context.OwnerImplicitRights));
            writer.StartPathInputs(description, true);
            discovery = new(binding, true, dn => byName.GetValueOrDefault(dn), subject => OwnershipAuditRun.Target(subject, contexts.Value), CancellationToken.None);
            foreach (var subject in subjects)
            {
                writer.WriteControlEdges(ControlEdgeDeriver.Derive(subject, null, context, writer.GenerationId, input.DerivationGenerationId, ControlEdgeDeriverTests.DomainSid),
                    OwnershipAuditRun.Target(subject, contexts.Value));
                if (observeSeed || subject.DistinguishedName == UserDn)
                    discovery.Observe(subject, Bundle.ReadPermissions(subject.DistinguishedName));
            }
            writer.FlushObjects();
        }

        internal int Admit(bool missingInput = false) => writer.AdmitDiscoveredScope(Bundle, description, missingInput ? null : input,
            binding, discovery, context, ControlEdgeDeriverTests.DomainSid, input.DerivationGenerationId, CancellationToken.None, status: null);

        internal void Assess() => writer.AssessAutomaticOwnership(Bundle, description, input, binding, context,
            ControlEdgeDeriverTests.DomainSid, objects, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, scopeAlreadyPlanned: true);

        public void Dispose()
        {
            writer.Dispose();
            Bundle.Dispose();
        }
    }

    private sealed class EdgeFixture : IDisposable
    {
        internal SqliteConnection Connection { get; }
        internal JudgementDescription Description { get; }
        internal long Id { get; }
        private readonly JudgementWriter writer;

        internal EdgeFixture()
        {
            var directory = TempDirectories.Create("post-pass-edge-lookup");
            var seal = new string('A', 64);
            File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, seal)));
            writer = JudgementWriter.Create(directory, seal, null, Started, Started);
            writer.StartControlEdges(true);
            var evaluation = ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(ControlEdgeDeriverTests.Ace(7, ControlEdgeDeriverTests.Holder, 0x80000)));
            writer.WriteControlEdges(evaluation with { Edges = evaluation.Edges.Select(edge => edge with { GenerationId = writer.GenerationId }).ToArray() }, null);
            writer.FlushObjects();
            writer.CompleteControlEdges();
            Connection = new SqliteConnection("Data Source=" + BundleLayout.JudgementPartialPath(directory) + ";Pooling=False");
            Connection.Open();
            Execute(Connection, "PRAGMA foreign_keys=ON");
            Execute(Connection, "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<512) INSERT INTO control_object SELECT 'CN=Filler'||x||',DC=contoso,DC=com',NULL,NULL,'DescriptorNotRead',0,0 FROM n");
            using var command = Connection.CreateCommand();
            command.CommandText = "SELECT id FROM control_edge WHERE capability='CanSetOwner'";
            Id = (long)command.ExecuteScalar()!;
            Description = new(seal, writer.GenerationId, null, JudgementRunState.Running, Started, Started, default);
        }

        public void Dispose()
        {
            Connection.Dispose();
            writer.Dispose();
        }
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
