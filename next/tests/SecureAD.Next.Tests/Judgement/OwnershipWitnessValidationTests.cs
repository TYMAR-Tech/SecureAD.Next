using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SQLitePCL;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class OwnershipWitnessValidationTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void EachResourceIsReadOnceEvenWhenWitnessesAreInterleaved(bool interleaved)
    {
        using var fixture = new Fixture();
        if (interleaved) fixture.Interleave();
        using var trace = new DescriptorReads(fixture.Sources.Bundle.Connection);

        var result = fixture.Validate();

        Assert.True(result.Count > 4);
        Assert.Equal(4, trace.Count);
    }

    [Fact]
    public void GroupingPreservesEveryRelationInItsStoredOrder()
    {
        using var fixture = new Fixture();
        fixture.Interleave();
        var expected = PathInputStorage.Read(fixture.Database, fixture.Description).AdmissionRelationships;

        var actual = fixture.Validate();

        Assert.Equal(expected.Count, actual.Count);
        Assert.Equal(Tier0PathCalculation.Fingerprint(expected), Tier0PathCalculation.Fingerprint(actual));
    }

    [Fact]
    public void DifferentDomainsNeverReuseAnotherResourcesPermissionReading()
    {
        using var fixture = new Fixture();
        fixture.Interleave();

        var actual = fixture.Validate();

        foreach (var domain in Enumerable.Range(0, 2))
        {
            var target = OwnershipWitnessFixture.TargetDn(domain);
            var owner = Assert.Single(actual.Where(relation => relation.Affected.DistinguishedName == target
                && relation.Witness?.IsOwner == true));
            Assert.Equal(OwnershipWitnessFixture.UserSid(domain, 0), owner.Witness!.TrusteeSid);
        }
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("ordinal")]
    [InlineData("trustee")]
    [InlineData("resource")]
    public void ReusedPermissionReadingsStillRefuseEveryInvalidWitness(string changed)
    {
        using var fixture = new Fixture();
        fixture.Corrupt(changed);

        Assert.Throws<InvalidOperationException>(() => fixture.Validate());
    }

    [Fact]
    public void CancellationWinsBeforeTheNextCachedWitnessIsChecked()
    {
        using var fixture = new Fixture();
        fixture.Corrupt("ordinal");
        using var cancellation = new CancellationTokenSource();
        using var trace = new DescriptorReads(fixture.Sources.Bundle.Connection, cancellation.Cancel);

        Assert.Throws<OperationCanceledException>(() => fixture.Validate(cancellation.Token));
        Assert.Equal(1, trace.Count);
    }

    [Fact]
    public void CapturedAndStoredEdgeWitnessesShareTheSameResourcePreparation()
    {
        using var fixture = new Fixture();
        foreach (var domain in Enumerable.Range(0, 2))
        {
            using var command = fixture.Database.CreateCommand();
            command.CommandText = """
                UPDATE ownership_relation SET
                    edge_id=(SELECT id FROM control_edge WHERE target=$target AND holder_sid=$sid AND capability='CanWriteDacl'),
                    witness_target=NULL,witness_ordinal=NULL,witness_trustee=NULL,witness_is_owner=0,witness_capability=NULL
                WHERE witness_target=$target AND witness_ordinal=0 AND witness_is_owner=0
                """;
            command.Parameters.AddWithValue("$target", OwnershipWitnessFixture.TargetDn(domain));
            command.Parameters.AddWithValue("$sid", OwnershipWitnessFixture.UserSid(domain, 0));
            Assert.Equal(1, command.ExecuteNonQuery());
        }
        fixture.Interleave();
        var expected = PathInputStorage.Read(fixture.Database, fixture.Description).AdmissionRelationships;
        using var trace = new DescriptorReads(fixture.Sources.Bundle.Connection);

        var actual = fixture.Validate();

        Assert.Equal(2, actual.Count(relation => relation.ControlEdgeId is not null));
        Assert.Equal(Tier0PathCalculation.Fingerprint(expected), Tier0PathCalculation.Fingerprint(actual));
        Assert.Equal(4, trace.Count);
    }

    private sealed class Fixture : IDisposable
    {
        internal JudgingInputs Sources { get; }
        internal SqliteConnection Database { get; }
        internal JudgementDescription Description { get; }

        internal Fixture()
        {
            var directory = Path.Combine(Path.GetTempPath(), "witness-" + Guid.NewGuid().ToString("N"));
            OwnershipWitnessFixture.Capture(directory, repeated: true, domains: 2);
            OwnershipWitnessFixture.Derive(directory, CancellationToken.None);
            // Stop after ownership is saved, before the validator being tested can run.
            // A broken validator must fail the test, not its fixture construction.
            using var cancellation = new CancellationTokenSource();
            Guid? generation = null;
            Assert.Throws<OperationCanceledException>(() => JudgingRun.JudgeAudit(directory, RuleCatalogue.All, PathRequesterPolicy.Disabled,
                OwnershipWitnessFixture.When, OwnershipWitnessFixture.When, new Watching(progress =>
                {
                    if (progress.RequesterPhase != PathRequesterWorkPhase.PreparingPaths) return;
                    generation = progress.JudgementGenerationId;
                    cancellation.Cancel();
                }), RunLog.Discarded, cancellation.Token, selfMembershipDiscoveryBudget: null));
            Assert.True(cancellation.IsCancellationRequested);
            Assert.NotNull(generation);
            var database = Path.Combine(directory, "witness-verification.db");
            File.Copy(AnalysisStoreLifecycle.StagingPath(directory, AnalysisStoreKind.Judgement), database);
            Database = new(new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString());
            Database.Open();
            var sources = JudgingInputs.Open(directory, CancellationToken.None);
            Assert.True(sources.IsSuccess, sources.Error?.Description);
            Sources = sources.Value;
            var derivation = Sources.OpenDerivation();
            Assert.True(derivation.IsSuccess, derivation.Error?.Description);
            Description = new(Sources.EvidenceSeal, generation.Value, Sources.Facts.Description.GenerationId,
                JudgementRunState.Failed, OwnershipWitnessFixture.When, OwnershipWitnessFixture.When, OwnershipWitnessFixture.When);
        }

        private sealed class Watching(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
        {
            public void Report(JudgingRun.JudgingProgress value) => report(value);
        }

        internal IReadOnlyList<Tier0RelevanceRelation> Validate(CancellationToken cancellationToken = default)
        {
            var snapshot = new OwnershipAuditStorage.Snapshot(Database, Description, CancellationToken.None);
            return OwnershipAuditValidation.Validate(Database, Description, Sources, snapshot, cancellationToken).Relations;
        }

        internal void Interleave()
        {
            using var command = Database.CreateCommand();
            command.CommandText = "SELECT id FROM ownership_relation ORDER BY COALESCE(witness_ordinal,-1),affected_target DESC,id DESC";
            var ids = new List<long>();
            using (var reader = command.ExecuteReader()) while (reader.Read()) ids.Add(reader.GetInt64(0));
            command.CommandText = "UPDATE ownership_relation SET id=-id";
            Assert.Equal(ids.Count, command.ExecuteNonQuery());
            command.CommandText = "UPDATE ownership_relation SET id=$new WHERE id=$old";
            command.Parameters.Add("$new", SqliteType.Integer);
            command.Parameters.Add("$old", SqliteType.Integer);
            for (var index = 0; index < ids.Count; index++)
            {
                command.Parameters["$new"].Value = index + 1;
                command.Parameters["$old"].Value = -ids[index];
                Assert.Equal(1, command.ExecuteNonQuery());
            }
        }

        internal void Corrupt(string changed)
        {
            using var command = Database.CreateCommand();
            var assignment = changed switch
            {
                "owner" or "trustee" => "witness_trustee='S-1-5-18'",
                "ordinal" => "witness_ordinal=2147483647",
                "resource" => "witness_target='DC=d1,DC=witness,DC=invalid'",
                _ => throw new ArgumentOutOfRangeException(nameof(changed)),
            };
            command.CommandText = $"""
                UPDATE ownership_relation SET {assignment}
                WHERE id=(SELECT id FROM ownership_relation WHERE witness_target=$target
                    AND witness_is_owner=$owner ORDER BY id LIMIT 1 OFFSET $skip)
                """;
            command.Parameters.AddWithValue("$target", OwnershipWitnessFixture.TargetDn(0));
            command.Parameters.AddWithValue("$owner", changed == "owner" ? 1 : 0);
            command.Parameters.AddWithValue("$skip", changed == "owner" ? 0 : 1);
            Assert.Equal(1, command.ExecuteNonQuery());
        }

        public void Dispose()
        {
            Sources.Dispose();
            Database.Dispose();
        }
    }

    private sealed class DescriptorReads : IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly strdelegate_trace _callback;
        internal int Count { get; private set; }

        internal DescriptorReads(SqliteConnection connection, Action? onRead = null)
        {
            _connection = connection;
            var sentinel = false;
            _callback = (_, sql) =>
            {
                if (sql == "SELECT 971") sentinel = true;
                if (!sql.Contains("FROM object_security_descriptor AS o", StringComparison.Ordinal)) return;
                Count++;
                onRead?.Invoke();
            };
            raw.sqlite3_trace(connection.Handle!, _callback, null!);
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT 971";
            command.ExecuteScalar();
            Assert.True(sentinel, "The descriptor-read trace must observe its own sentinel.");
        }

        public void Dispose()
        {
            raw.sqlite3_trace(_connection.Handle!, (strdelegate_trace)null!, null!);
            GC.KeepAlive(_callback);
        }
    }
}
