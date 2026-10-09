using System.Text.Json;
using System.Runtime.CompilerServices;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class PathSharedProofStorageTests
{
    private sealed record Value(int Occurrence, Tier0Target Target, IReadOnlyList<ObjectAttributes> Schema,
        IReadOnlyList<Tier0Evidence> Witnesses);

    [Fact]
    public void SharedPathComponentsKeepExactLargeValuesAndEveryOccurrence()
    {
        using var connection = Database();
        var description = Description();
        var value = Sample(new string('x', 196_625) + "\u00e9\u6f22\\\"\r\n");
        var expected = JsonSerializer.Serialize(value, ProofSerialization.Options);
        var references = new List<PathProofStorage.Reference>();
        using (var transaction = connection.BeginTransaction())
        using (var statements = new PreparedStatements(connection))
        using (var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None))
        {
            var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
            for (var i = 0; i < 100; i++) references.Add(shared.Write(value with { Occurrence = i }));
            transaction.Commit();
        }
        Assert.Equal(100, references.Select(reference => reference.Id).Distinct().Count());
        Assert.Equal(1L, Count(connection, "SELECT COUNT(*) FROM path_shared_proof WHERE kind='SchemaEvidence'"));
        Assert.Equal(2L, Count(connection, "SELECT COUNT(*) FROM path_shared_proof WHERE kind='SourceWitness'"));
        Assert.True(Count(connection, "SELECT SUM(byte_length) FROM path_proof") < expected.Length * 4L);
        var reader = new PathSharedProofStorage(connection, description, CancellationToken.None);
        for (var i = 0; i < references.Count; i++)
        {
            var restored = reader.Read<Value>(references[i].Id, Convert.ToHexString(references[i].Fingerprint));
            Assert.Equal(expected, JsonSerializer.Serialize(restored with { Occurrence = 0 }, ProofSerialization.Options));
            Assert.Equal(i, restored.Occurrence);
            Assert.Equal(new[] { 7, 3, 7 }, restored.Witnesses.Select(witness => witness.Ordinal));
        }
        PathProofStorage.RequirePublishable(connection, CancellationToken.None);
        PathSharedProofStorage.RequirePublishable(connection, description);
    }

    [Fact]
    public void SharedPathLookupCollisionsDoNotMergeDifferentValues()
    {
        using var connection = Database();
        var description = Description();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements,
            _ => new byte[32]);
        var values = new[] { "Case", "case", " Case ", "", "Case" }.Select(Sample).ToArray();
        var saved = values.Select(shared.Write).ToArray();
        Assert.Equal(4L, Count(connection, "SELECT COUNT(*) FROM path_shared_proof WHERE kind='SchemaEvidence'"));
        for (var i = 0; i < values.Length; i++)
            Assert.Equal(JsonSerializer.Serialize(values[i], ProofSerialization.Options),
                JsonSerializer.Serialize(shared.Read<Value>(saved[i].Id, Convert.ToHexString(saved[i].Fingerprint)), ProofSerialization.Options));
    }

    [Fact]
    public void SharedPathStorageDoesNotTrustMutableCollectionIdentity()
    {
        using var connection = Database();
        var description = Description();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
        var schema = Sample("before").Schema.ToArray();
        var value = Sample("ignored") with { Schema = schema };
        var first = shared.Write(value);
        schema[0] = schema[0] with { DistinguishedName = "after" };
        var second = shared.Write(value);
        Assert.Equal(2L, Count(connection, "SELECT COUNT(*) FROM path_shared_proof WHERE kind='SchemaEvidence'"));
        Assert.Equal("before", shared.Read<Value>(first.Id, Convert.ToHexString(first.Fingerprint)).Schema[0].DistinguishedName);
        Assert.Equal("after", shared.Read<Value>(second.Id, Convert.ToHexString(second.Fingerprint)).Schema[0].DistinguishedName);
    }

    [Fact]
    public void SharedPathPreparationVisitsEachChildOnceWithinOneProofWrite()
    {
        using var connection = Database();
        using var trace = new JudgingInputReuseTests.Statements(connection);
        var value = Sample("schema");
        Write(connection, Description(), value with { Witnesses = Enumerable.Repeat(value.Witnesses[0], 100).ToArray() });
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM path_shared_proof WHERE kind='Identity'", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM path_shared_proof WHERE kind='SourceWitness'", StringComparison.Ordinal)));
    }

    [Fact]
    public void SharedPathImmutableComponentsArePreparedOnceAcrossProofWrites()
    {
        using var connection = Database();
        var description = Description();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
        var sample = Sample("schema");
        var immutable = sample with { Schema = new JudgingInputs.AttributeSnapshot(sample.Schema) };
        using var trace = new JudgingInputReuseTests.Statements(connection);

        for (var index = 0; index < 20; index++) shared.Write(immutable with { Occurrence = index });

        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM path_shared_proof WHERE kind='SchemaEvidence'", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM path_shared_proof WHERE kind='Identity'", StringComparison.Ordinal)));
        Assert.Equal(2, trace.Sql.Count(sql => sql.Contains("FROM path_shared_proof WHERE kind='SourceWitness'", StringComparison.Ordinal)));
    }

    [Fact]
    public void SharedPathAttributeSnapshotDetachesBinaryValuesBeforeReuse()
    {
        using var connection = Database();
        var description = Description();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
        byte[] original = [1, 2, 3];
        var source = Sample("schema");
        var schema = source.Schema.Select(value => value with
        {
            Attributes = [new ObjectAttribute("schemaIDGUID", SecureAD.Kernel.Capture.AttributeCardinality.SingleValued,
                [new AttributeValue(0, null, original)])],
        }).ToArray();
        var value = source with { Schema = new JudgingInputs.AttributeSnapshot(schema) };
        original[0] = 9;
        value.Schema[0].Attributes[0].Values[0].Bytes![1] = 9;

        var saved = shared.Write(value);
        var restored = shared.Read<Value>(saved.Id, Convert.ToHexString(saved.Fingerprint));

        Assert.Equal(new byte[] { 1, 2, 3 }, restored.Schema[0].Attributes[0].Values[0].Bytes);
    }

    [Fact]
    public void SharedPathImmutableReuseDoesNotRetainCompletedProofInputs()
    {
        using var connection = Database();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, Description(), CancellationToken.None, proofs, transaction, statements);
        var weak = WriteTemporarySnapshot(shared);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.False(weak.IsAlive);
        GC.KeepAlive(shared);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference WriteTemporarySnapshot(PathSharedProofStorage shared)
    {
        var sample = Sample("temporary");
        var snapshot = new JudgingInputs.AttributeSnapshot(sample.Schema);
        shared.Write(sample with { Schema = snapshot });
        return new(snapshot);
    }

    [Fact]
    public void SharedPathSelectionWitnessPreparationRetainsEveryOrderedUse()
    {
        using var connection = Database();
        var description = Description();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
        using var trace = new JudgingInputReuseTests.Statements(connection);
        var witness = new PathRequesterSelectionWitness("CN=Target,DC=example", 7, 0x40000, "CN=Holder,DC=example", null);
        var first = shared.PrepareSelectionWitness(witness);
        var second = shared.PrepareSelectionWitness(witness with { PermissionOrdinal = 3 });
        PathProofStorage.Reference[] uses = [first, second, first];
        var saved = new List<PathProofStorage.Reference>();
        for (var index = 0; index < 12; index++)
        {
            saved.Add(shared.WriteSelectionCandidate(new(index + 1, PathRequesterFamily.RequesterDacl,
                $"CN=User{index},DC=example", witness.ResourceDn, null, null), new string('a', 64), uses));
        }
        var preparationCount = trace.Sql.Count(sql => sql.Contains("FROM path_shared_proof WHERE kind='SelectionWitness'", StringComparison.Ordinal));

        Assert.Equal(2, preparationCount);
        for (var index = 0; index < saved.Count; index++)
        {
            var restored = shared.Read<PathRequesterCandidate>(saved[index].Id, Convert.ToHexString(saved[index].Fingerprint));
            Assert.Equal($"CN=User{index},DC=example", restored.RequesterDn);
            Assert.Equal(new[] { 7, 3, 7 }, restored.Witnesses.Select(value => value.PermissionOrdinal));
        }
    }

    [Fact]
    public void SharedPathReadReusesValidatedComponentsOnlyWithinThatRead()
    {
        using var connection = Database();
        var description = Description();
        var value = Sample("schema");
        var saved = Write(connection, description, value with { Witnesses = Enumerable.Repeat(value.Witnesses[0], 100).ToArray() });
        var reader = new PathSharedProofStorage(connection, description, CancellationToken.None);
        using var trace = new JudgingInputReuseTests.Statements(connection);
        var actual = reader.Read<Value>(saved.Id, Convert.ToHexString(saved.Fingerprint));
        Assert.Equal(100, actual.Witnesses.Count);
        Assert.Equal(3, trace.Sql.Count(sql => sql.Contains("FROM path_shared_proof WHERE proof=", StringComparison.Ordinal)));
        Execute(connection, "UPDATE path_shared_proof SET evidence_seal='changed' WHERE kind='Identity'");
        Assert.Throws<InvalidDataException>(() => reader.Read<Value>(saved.Id, Convert.ToHexString(saved.Fingerprint)));
    }

    [Fact]
    public void SharedPathPageScopeSharesComponentsButNeverSurvivesThePage()
    {
        using var connection = Database();
        var description = Description();
        var first = Write(connection, description, Sample("schema"));
        var second = Write(connection, description, Sample("schema") with { Occurrence = 1 });
        var reader = new PathSharedProofStorage(connection, description, CancellationToken.None);
        using var trace = new JudgingInputReuseTests.Statements(connection);
        using (reader.BeginRead())
        {
            reader.Read<Value>(first.Id, Convert.ToHexString(first.Fingerprint));
            reader.Read<Value>(second.Id, Convert.ToHexString(second.Fingerprint));
            Assert.Equal(4, trace.Sql.Count(sql => sql.Contains("FROM path_shared_proof WHERE proof=", StringComparison.Ordinal)));
        }
        Execute(connection, "UPDATE path_shared_proof SET evidence_seal='changed' WHERE kind='Identity'");
        Assert.Throws<InvalidDataException>(() => reader.Read<Value>(first.Id, Convert.ToHexString(first.Fingerprint)));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("derivation")]
    [InlineData("evidence")]
    public void SharedPathComponentsCannotBeReadUnderAnotherGeneration(string changed)
    {
        using var connection = Database();
        var description = Description();
        var saved = Write(connection, description, Sample("schema"));
        var other = changed switch
        {
            "generation" => description with { GenerationId = Guid.NewGuid() },
            "derivation" => description with { DerivationGenerationId = Guid.NewGuid() },
            _ => description with { EvidenceSeal = new string('b', 64) },
        };
        var reader = new PathSharedProofStorage(connection, other, CancellationToken.None);
        Assert.Throws<InvalidDataException>(() => reader.Read<Value>(saved.Id, Convert.ToHexString(saved.Fingerprint)));
    }

    [Theory]
    [InlineData("UPDATE path_shared_proof SET kind='SchemaEvidence' WHERE kind='Identity'")]
    [InlineData("UPDATE path_shared_proof SET resource='wrong resource' WHERE kind='Identity'")]
    [InlineData("UPDATE path_shared_proof SET fingerprint=zeroblob(32) WHERE kind='Identity'")]
    [InlineData("DELETE FROM path_shared_proof WHERE kind='Identity'")]
    [InlineData("DELETE FROM path_proof_chunk WHERE proof_id=(SELECT proof FROM path_shared_proof WHERE kind='Identity' LIMIT 1)")]
    public void SharedPathReadRefusesBrokenTypedReferences(string sql)
    {
        using var connection = Database();
        var description = Description();
        var saved = Write(connection, description, Sample("schema"));
        Execute(connection, sql);
        var reader = new PathSharedProofStorage(connection, description, CancellationToken.None);
        Assert.Throws<InvalidDataException>(() => reader.Read<Value>(saved.Id, Convert.ToHexString(saved.Fingerprint)));
    }

    [Fact]
    public void SharedPathWritingCancellationRollsBackComponentsAndParents()
    {
        using var connection = Database();
        using var stopping = new CancellationTokenSource();
        connection.CreateFunction("stop_shared", () => { stopping.Cancel(); return 1; });
        Execute(connection, "CREATE TRIGGER cancel_shared AFTER INSERT ON path_shared_proof BEGIN SELECT stop_shared(); END");
        using (var transaction = connection.BeginTransaction())
        using (var statements = new PreparedStatements(connection))
        using (var proofs = new PathProofStorage.Writer(connection, transaction, stopping.Token))
        {
            var shared = new PathSharedProofStorage(connection, Description(), stopping.Token, proofs, transaction, statements);
            Assert.Throws<OperationCanceledException>(() => shared.Write(Sample("schema")));
            transaction.Rollback();
        }
        Assert.Equal(0L, Count(connection, "SELECT (SELECT COUNT(*) FROM path_shared_proof)+(SELECT COUNT(*) FROM path_proof)+(SELECT COUNT(*) FROM path_proof_chunk)"));
    }

    [Fact]
    public void SharedPathWriterCannotReuseRolledBackComponentIdentities()
    {
        using var connection = Database();
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, Description(), CancellationToken.None, proofs, transaction, statements);
        shared.Write(Sample("schema"));
        transaction.Rollback();
        Assert.ThrowsAny<InvalidOperationException>(() => shared.Write(Sample("schema")));
        Assert.Equal(0L, Count(connection, "SELECT COUNT(*) FROM path_shared_proof"));
    }

    [Fact]
    public void SharedPathSelectedReadDoesNotLoadUnrelatedProofs()
    {
        using var connection = Database();
        var description = Description();
        var first = Write(connection, description, Sample("selected"));
        var other = Write(connection, description, Sample("unrelated") with
        {
            Target = Sample("unused").Target with { DistinguishedName = "CN=Other,DC=example,DC=test" },
        });
        Execute(connection, $"DELETE FROM path_proof_chunk WHERE proof_id={other.Id}");
        var reader = new PathSharedProofStorage(connection, description, CancellationToken.None);
        Assert.Equal("selected", reader.Read<Value>(first.Id, Convert.ToHexString(first.Fingerprint)).Schema[0].DistinguishedName);
        Assert.Throws<InvalidDataException>(() => reader.Read<Value>(other.Id, Convert.ToHexString(other.Fingerprint)));
    }

    [Fact]
    public void SharedPathPermissionReferencesKeepResourceOrderAndDuplicates()
    {
        using var connection = Database();
        var description = Description();
        var firstTarget = Sample("schema").Target;
        var secondTarget = firstTarget with { ObjectGuid = Guid.NewGuid(), DistinguishedName = "CN=Other,DC=example,DC=test" };
        var entry = FullControlEvaluatorTests.Allow(7);
        var deny = entry with { Ordinal = 3, AceType = "AccessDenied" };
        var trustee = new RequesterTrusteeEvidence(entry.Trustee.Sid, RequesterTrusteeState.Unknown,
            RequesterTrusteeReason.MembershipNotEstablished, null, null, null, null, null, null);
        SavedRequesterDaclProof Proof(Tier0Target target) => new(new(new(firstTarget.DistinguishedName, target.DistinguishedName),
            description.GenerationId, description.DerivationGenerationId, description.EvidenceSeal, firstTarget, target,
            ControlEvaluationState.Unknown, [RequesterDaclIssue.DescriptorIncomplete],
            [new(entry, ControlEvaluationState.Unknown, trustee), new(deny, ControlEvaluationState.Unknown, trustee),
                new(entry, ControlEvaluationState.Unknown, trustee)], [], []), new string('f', 64));
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var shared = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements);
        var first = shared.Write(Proof(firstTarget));
        var second = shared.Write(Proof(secondTarget));
        Assert.Equal(2L, Count(connection, "SELECT COUNT(*) FROM permission_entry"));
        foreach (var (reference, target) in new[] { (first, firstTarget), (second, secondTarget) })
        {
            var restored = shared.Read<SavedRequesterDaclProof>(reference.Id, Convert.ToHexString(reference.Fingerprint));
            Assert.Equal(JsonSerializer.Serialize(Proof(target), ProofSerialization.Options), JsonSerializer.Serialize(restored, ProofSerialization.Options));
            Assert.Equal(new[] { 7, 3, 7 }, restored.Assessment.Evidence.Select(value => value.Entry.Ordinal));
        }
        Execute(connection, "UPDATE path_shared_proof SET resource='CN=Wrong,DC=example,DC=test' WHERE kind='RequesterDacl'");
        Assert.Throws<InvalidOperationException>(() => shared.Read<SavedRequesterDaclProof>(first.Id, Convert.ToHexString(first.Fingerprint)));
    }

    private static PathProofStorage.Reference Write(SqliteConnection connection, JudgementDescription description, Value value)
    {
        using var transaction = connection.BeginTransaction();
        using var statements = new PreparedStatements(connection);
        using var proofs = new PathProofStorage.Writer(connection, transaction, CancellationToken.None);
        var result = new PathSharedProofStorage(connection, description, CancellationToken.None, proofs, transaction, statements).Write(value);
        transaction.Commit();
        return result;
    }

    private static Value Sample(string schema)
    {
        var target = new Tier0Target(Guid.Parse("f32e4916-e292-458f-aebd-b2134dff4b0f"), "CN=Group,DC=example,DC=test",
            "DC=example,DC=test", "example.test", "S-1-5-21-1-2-3-512", null);
        var witness = new Tier0Evidence(target, "member", 7, "CN=User,DC=example,DC=test");
        return new(0, target, [new(schema, target.ObjectGuid, DateTimeOffset.UnixEpoch, default, [], null)],
            [witness, witness with { Ordinal = 3 }, witness]);
    }

    private static JudgementDescription Description() => new(new string('a', 64), Guid.NewGuid(), Guid.NewGuid(),
        JudgementRunState.CompletedDegraded, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);

    private static SqliteConnection Database()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        SharedPermissionStorage.CreateTables(connection);
        PathProofStorage.CreateTables(connection);
        PathSharedProofStorage.CreateTables(connection);
        return connection;
    }

    private static long Count(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (long)command.ExecuteScalar()!;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
}
