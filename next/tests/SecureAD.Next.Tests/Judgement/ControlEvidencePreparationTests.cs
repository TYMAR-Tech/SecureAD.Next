using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ControlEvidencePreparationTests
{
    [Fact]
    public void ManyHolderAnswersPrepareEachOccurrenceAndTheCommonSourceOnce()
    {
        using var counts = new Counts();
        var evaluation = Evaluation(128);
        Guid generation = default;
        var directory = Store(writer =>
        {
            generation = writer.GenerationId;
            var prepared = ControlEvidencePreparation.Create(Bind(evaluation, generation), generation, null);
            writer.WritePreparedControlEdges(prepared, null);
        });
        Assert.Equal((128L, 1L, 1L), (counts.For("control.permission_preparations", generation),
            counts.For("control.sequence_preparations", generation), counts.For("control.route_preparations", generation)));
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description, SqliteOpenMode.ReadOnly);
        Assert.Equal((128L, 256L, 128L, 256L), (Count(connection, "full_control_assessment"), Count(connection, "control_edge"),
            Count(connection, "full_control_source_entry"), Count(connection, "full_control_support")));
        Assert.Equal(128L, reader.ReadControlEdges(evaluation.Target, null, null, true, 0).UnknownCount);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    [InlineData(9)]
    public void PreparationIsResourceLocalRatherThanAssumingForestWideSharing(int resources)
    {
        using var counts = new Counts();
        Guid generation = default;
        var directory = Store(writer =>
        {
            generation = writer.GenerationId;
            for (var index = 0; index < resources; index++)
            {
                var subject = ControlEdgeDeriverTests.Subject with
                {
                    DistinguishedName = $"OU=Target,DC=domain{index},DC=example",
                    DomainFqdn = $"domain{index}.example",
                    ObjectGuid = Guid.NewGuid(),
                };
                var permissions = ControlEdgeDeriverTests.Permissions(subject.DistinguishedName,
                    ControlEdgeDeriverTests.Ace(0, ControlEdgeDeriverTests.Holder, FullControlEvaluatorTests.FullMask));
                var evaluation = ControlEdgeDeriver.Derive(subject, permissions,
                    JudgingContext.At(DateTimeOffset.UnixEpoch) with { ForestFqdn = "example" },
                    generation, null, _ => "S-1-5-21-1-2-3");
                writer.WritePreparedControlEdges(ControlEvidencePreparation.Create(evaluation, generation, null), null);
            }
        });
        Assert.Equal(((long)resources, (long)resources, (long)resources),
            (counts.For("control.permission_preparations", generation), counts.For("control.sequence_preparations", generation),
             counts.For("control.route_preparations", generation)));
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description);
        Assert.Equal((long)resources, Count(connection, "full_control_source"));
    }

    [Fact]
    public void PreparedAnswersOwnPermissionBytesAndAllMutableFullControlCollections()
    {
        var original = FullControlEvaluatorTests.Allow(0) with { ApplicationData = [1, 2, 3] };
        var entries = new[] { original };
        var evaluation = FullControlStorageTests.Evaluation(entries);
        var classes = evaluation.FullControlAssessments[0].Source.Classes.ToList();
        var domains = evaluation.FullControlAssessments[0].Source.AuthorityDomainSids.ToDictionary(pair => pair.Key, pair => pair.Value);
        var grants = evaluation.FullControlAssessments[0].Rights[0].GrantOrdinals.ToList();
        evaluation = evaluation with
        {
            FullControlAssessments = [evaluation.FullControlAssessments[0] with
            {
                Source = evaluation.FullControlAssessments[0].Source with { Classes = classes, AuthorityDomainSids = domains },
                Rights = evaluation.FullControlAssessments[0].Rights.Select((right, index) =>
                    index == 0 ? right with { GrantOrdinals = grants } : right).ToArray(),
            }],
        };
        string? expectedSource = null;
        string? expectedRights = null;
        var directory = Store(writer =>
        {
            var bound = Bind(evaluation, writer.GenerationId);
            expectedSource = JsonSerializer.Serialize(bound.FullControlAssessments[0].Source);
            expectedRights = JsonSerializer.Serialize(bound.FullControlAssessments[0].Rights);
            var prepared = ControlEvidencePreparation.Create(bound, writer.GenerationId, null);
            original.ApplicationData[0] = 99;
            entries[0] = FullControlEvaluatorTests.Deny(0, FullControlEvaluatorTests.FullMask);
            classes[0] = "computer";
            domains["unrelated.example"] = "S-1-5-21-9-9-9";
            grants.Clear();
            writer.WritePreparedControlEdges(prepared, null);
        });
        using var reader = FullControlStorageTests.Open(directory);
        var answer = Assert.Single(reader.ReadControlEdges(evaluation.Target, null, null, true, 0).FullControlAssessments);
        Assert.Equal(expectedSource, JsonSerializer.Serialize(answer.Source));
        Assert.Equal(expectedRights, JsonSerializer.Serialize(answer.Rights));
    }

    [Fact]
    public void PreparedMembershipProofOwnsEveryNestedRouteCollection()
    {
        var principal = new MembershipRoutePrincipal(ControlEdgeDeriverTests.Holder, null, "CN=Holder,DC=contoso,DC=com");
        var root = new MembershipRoutePrincipal("S-1-5-21-1-2-3-512", null, "CN=Domain Admins,DC=contoso,DC=com");
        var steps = new List<MembershipRouteStep> { new(principal, false), new(root, true) };
        var routes = new List<MembershipRoute> { new(512, "Domain Admins", MembershipRouteAuthorization.SecurityEnabled, false, steps) };
        var groups = new List<InitialMembershipRoutes> { new(root, routes, MembershipRouteIncompleteReason.None) };
        var summary = new MembershipRouteSummary(groups, MembershipRouteIncompleteReason.None);
        var evaluation = Evaluation(1) with { FullControlAssessments = [] };
        evaluation = evaluation with { Edges = evaluation.Edges.Select(edge => edge with { MembershipRoutes = summary }).ToArray() };
        var expected = JsonSerializer.Serialize(summary);
        var directory = Store(writer =>
        {
            var prepared = ControlEvidencePreparation.Create(Bind(evaluation, writer.GenerationId), writer.GenerationId, null);
            steps.Clear();
            routes.Clear();
            groups.Clear();
            writer.WritePreparedControlEdges(prepared, null);
        });
        using var reader = FullControlStorageTests.Open(directory);
        var page = reader.ReadControlEdges(evaluation.Target, null, null, true, 0);
        Assert.All(page.Edges, edge => Assert.Equal(expected, JsonSerializer.Serialize(edge.MembershipRoutes)));
    }

    [Fact]
    public void ASecondFullControlSourceCannotSubstituteDifferentOrderedEvidence()
    {
        var original = Evaluation(2);
        var evaluation = original with
        {
            Edges = [],
            FullControlAssessments = original.FullControlAssessments.Select(value => value with { SupportingCapabilities = [] }).ToArray(),
        };
        var source = evaluation.FullControlAssessments[1].Source;
        var altered = source.Entries.Select(entry => entry.Ordinal == 0
            ? entry with { Trustee = entry.Trustee with { Meaning = "A different captured explanation." } } : entry).ToArray();
        evaluation = evaluation with
        {
            FullControlAssessments = [evaluation.FullControlAssessments[0],
                evaluation.FullControlAssessments[1] with { Source = source with { Entries = altered } }],
        };
        Assert.Throws<InvalidOperationException>(() => ControlEvidencePreparation.Create(evaluation, Guid.Empty, null));
    }

    [Fact]
    public void EqualButSeparatelyOwnedSourceCollectionsRemainValid()
    {
        var evaluation = Evaluation(2);
        evaluation = evaluation with
        {
            FullControlAssessments = evaluation.FullControlAssessments.Select(value => value with
            {
                Source = value.Source with { Entries = value.Source.Entries.Select(entry => entry with { ApplicationData = entry.ApplicationData.ToArray() }).ToArray() },
            }).ToArray(),
        };
        using var reader = FullControlStorageTests.Open(FullControlStorageTests.Store([evaluation]));
        var page = reader.ReadControlEdges(evaluation.Target, null, null, true, 0);
        Assert.Equal((2, 4), (page.FullControlAssessments.Count, page.FullControlSupports.Count));
    }

    [Theory]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("derivation")]
    public void PreparationRefusesMixedResourceAndGenerationBindings(string changed)
    {
        var evaluation = Evaluation(1) with { FullControlAssessments = [] };
        evaluation = evaluation with { Edges = evaluation.Edges.Select(edge => changed switch
        {
            "target" => edge with { Target = "OU=Other,DC=contoso,DC=com" },
            "generation" => edge with { GenerationId = Guid.NewGuid() },
            _ => edge with { DerivationGenerationId = Guid.NewGuid() },
        }).ToArray() };
        Assert.Throws<InvalidOperationException>(() => ControlEvidencePreparation.Create(evaluation, Guid.Empty, null));
    }

    [Fact]
    public void APreparedAnswerCannotEnterAnotherWriterGeneration()
    {
        var directory = Partial(out var writer);
        using (writer)
        {
            writer.StartControlEdges(true);
            var prepared = ControlEvidencePreparation.Create(Evaluation(1), Guid.Empty, null);
            Assert.Throws<InvalidOperationException>(() => writer.WritePreparedControlEdges(prepared, null));
            using var connection = PartialDatabase(directory);
            Assert.Equal(0L, Count(connection, "control_object"));
        }
    }

    [Fact]
    public void RejectedPreparationRollsBackTheEarlierObjectInItsWriterBatch()
    {
        var directory = Partial(out var writer);
        using (writer)
        {
            writer.StartControlEdges(true);
            writer.WriteControlEdges(Bind(Evaluation(1), writer.GenerationId), null);
            var invalid = Bind(Evaluation(1), writer.GenerationId);
            invalid = invalid with { FullControlAssessments = [invalid.FullControlAssessments[0] with
            {
                EvaluationState = ControlEvaluationState.NotEstablished,
            }] };
            Assert.Throws<InvalidOperationException>(() => writer.WriteControlEdges(invalid, null));
            writer.FlushObjects();
            using var connection = PartialDatabase(directory);
            Assert.Equal((0L, 0L, 0L), (Count(connection, "control_object"), Count(connection, "permission_entry"), Count(connection, "shared_proof_value")));
        }
    }

    [Fact]
    public void OwnershipCandidatesDecodeSharedValuesOnceWithoutDroppingTheirOccurrences()
    {
        var directory = FullControlStorageTests.Store([Evaluation(128)]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description);
        using var counts = new Counts();
        var candidates = ControlEdgeStorage.ReadOwnerCandidates(connection, reader.Description, ControlEdgeDeriverTests.Subject.DistinguishedName);
        Assert.Equal((128, 16384), (candidates.Count, candidates.Sum(candidate => candidate.Evidence.Count)));
        Assert.Equal((128L, 1L), (counts.For("control.permission_reads", reader.Description.GenerationId),
            counts.For("control.route_reads", reader.Description.GenerationId)));
        Assert.All(candidates, candidate => Assert.Equal(Enumerable.Range(0, 128), candidate.Evidence.Select(entry => entry.Ordinal)));
    }

    [Theory]
    [InlineData("target")]
    [InlineData("generation")]
    [InlineData("derivation")]
    public void OwnershipReadReferencesCannotBeRebound(string changed)
    {
        var directory = FullControlStorageTests.Store([Evaluation(1)]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description);
        var original = Assert.Single(ControlEdgeStorage.ReadOwnerCandidates(connection, reader.Description, ControlEdgeDeriverTests.Subject.DistinguishedName));
        using var scope = new ControlEvidenceReadScope(connection, reader.Description, original.Target);
        var other = changed switch
        {
            "target" => original with { Target = "OU=Other,DC=contoso,DC=com" },
            "generation" => original with { GenerationId = Guid.NewGuid() },
            _ => original with { DerivationGenerationId = Guid.NewGuid() },
        };
        Assert.Throws<InvalidOperationException>(() => scope.RequireFor(connection, other));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OwnershipReadScopeRefusesChangedDatabaseRatherThanReusingStaleEvidence(bool anotherConnection)
    {
        var directory = FullControlStorageTests.Store([Evaluation(1)]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description);
        var original = Assert.Single(ControlEdgeStorage.ReadOwnerCandidates(connection, reader.Description, ControlEdgeDeriverTests.Subject.DistinguishedName));
        using var scope = new ControlEvidenceReadScope(connection, reader.Description, original.Target);
        using var other = anotherConnection ? Database(directory, reader.Description) : null;
        Execute(other ?? connection, "UPDATE control_product SET capture_complete=0");
        Assert.Throws<InvalidOperationException>(() => scope.RequireFor(connection, original));
    }

    [Fact]
    public void OwnershipReadScopeRefusesDisposedAndOtherConnectionUse()
    {
        var directory = FullControlStorageTests.Store([Evaluation(1)]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description);
        using var other = Database(directory, reader.Description);
        var original = Assert.Single(ControlEdgeStorage.ReadOwnerCandidates(connection, reader.Description, ControlEdgeDeriverTests.Subject.DistinguishedName));
        var scope = new ControlEvidenceReadScope(connection, reader.Description, original.Target);
        Assert.Throws<InvalidOperationException>(() => scope.RequireFor(other, original));
        scope.Dispose();
        Assert.Throws<InvalidOperationException>(() => scope.RequireFor(connection, original));
    }

    [Fact]
    public void ReusedOwnershipReferencesStillRefuseAnAlteredOccurrenceFingerprint()
    {
        var directory = FullControlStorageTests.Store([Evaluation(2)]);
        using var reader = FullControlStorageTests.Open(directory);
        using var connection = Database(directory, reader.Description);
        Execute(connection, """
            UPDATE control_ace SET fingerprint=zeroblob(32) WHERE edge_id=(
                SELECT MAX(id) FROM control_edge WHERE capability='CanSetOwner') AND ordinal=0
            """);
        Assert.Throws<InvalidOperationException>(() => ControlEdgeStorage.ReadOwnerCandidates(connection, reader.Description, ControlEdgeDeriverTests.Subject.DistinguishedName));
    }

    [Fact]
    public void PreparedResourcesRetainNoCallerCollectionsAndWritersRetainNoPreparedBodies()
    {
        var directory = Partial(out var writer);
        using (writer)
        {
            writer.StartControlEdges(true);
            var (source, prepared) = PrepareAndWrite(writer);
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            Assert.False(source.IsAlive);
            Assert.False(prepared.IsAlive);
            writer.CompleteControlEdges();
            writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (WeakReference Source, WeakReference Prepared) PrepareAndWrite(JudgementWriter writer)
    {
        var (source, prepared) = PrepareDetached(writer.GenerationId);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        Assert.False(source.IsAlive);
        GC.KeepAlive(prepared);
        writer.WritePreparedControlEdges(prepared, null);
        return (source, new(prepared));
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static (WeakReference Source, ControlEvidencePreparation Prepared) PrepareDetached(Guid generation)
    {
        var evaluation = Bind(Evaluation(2), generation);
        return (new(evaluation.FullControlAssessments[0].Source.Entries),
            ControlEvidencePreparation.Create(evaluation, generation, null));
    }

    internal static ControlObjectEvaluation Evaluation(int holders)
    {
        var entries = Enumerable.Range(0, holders).Select(index =>
            ControlEdgeDeriverTests.Ace(index, $"S-1-5-21-1-2-3-{1200 + index}", FullControlEvaluatorTests.FullMask)).ToArray();
        return ControlEdgeDeriverTests.Derive(ControlEdgeDeriverTests.Permissions(entries));
    }

    private static ControlObjectEvaluation Bind(ControlObjectEvaluation value, Guid generation) => value with
    {
        Edges = value.Edges.Select(edge => edge with { GenerationId = generation }).ToArray(),
        FullControlAssessments = value.FullControlAssessments.Select(assessment => assessment with { GenerationId = generation }).ToArray(),
    };

    private static string Partial(out JudgementWriter writer)
    {
        var directory = TempDirectories.Create("prepared-control");
        var seal = new string('a', 64);
        File.WriteAllText(BundleLayout.SealPath(directory), JsonSerializer.Serialize(new BundleSealContents(BundleSealing.Algorithm, seal)));
        writer = JudgementWriter.Create(directory, seal, null, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch);
        return directory;
    }

    private static string Store(Action<JudgementWriter> write)
    {
        var directory = Partial(out var writer);
        using (writer)
        {
            writer.StartControlEdges(true);
            write(writer);
            writer.CompleteControlEdges();
            writer.Complete(DateTimeOffset.UnixEpoch.AddMinutes(1));
        }
        return directory;
    }

    private static SqliteConnection PartialDatabase(string directory) => Connect(TestSealing.PendingJudgementPath(directory), staged: true);
    private static SqliteConnection Database(string directory, JudgementDescription description,
        SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate) =>
        Connect(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, description.GenerationId), mode);
    private static SqliteConnection Connect(string path, SqliteOpenMode mode = SqliteOpenMode.ReadWriteCreate, bool staged = false)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false, Mode = mode }.ToString());
        connection.Open();
        var directory = Path.GetDirectoryName(path)!;
        TestSealing.AttachJudgementParts(connection, directory, staged ? Guid.Empty
            : AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId, staged);
        return connection;
    }

    private static long Count(SqliteConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM " + table;
        return (long)command.ExecuteScalar()!;
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    internal sealed class Counts : IDisposable
    {
        private readonly ConcurrentDictionary<(string Instrument, string Generation), long> _values = [];
        private readonly MeterListener _listener = new();

        internal Counts()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == ControlEvidencePreparation.MeterName) listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                foreach (var tag in tags)
                    if (tag.Key == "generation" && tag.Value is string generation)
                        _values.AddOrUpdate((instrument.Name, generation), value, (_, current) => current + value);
            });
            _listener.Start();
        }

        internal long For(string instrument, Guid generation) => _values.GetValueOrDefault((instrument, generation.ToString("D")));
        public void Dispose() => _listener.Dispose();
    }
}
