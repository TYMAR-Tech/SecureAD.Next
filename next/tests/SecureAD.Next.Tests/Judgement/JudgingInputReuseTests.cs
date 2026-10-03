using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SQLitePCL;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class JudgingInputReuseTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ProductionJudgingVerifiesEachSourceOnce(bool scheduledRules)
    {
        var directory = Ready();
        using var counts = new Verifications(directory);
        Run(directory, scheduledRules ? RuleCatalogue.All : []);
        Assert.Equal((1L, 1L, 1L), (counts.Evidence, counts.Derivation, counts.Formats));
    }

    [Fact]
    public void MembershipLoadingIsOncePerOwnedSource()
    {
        var directory = Ready();
        using var sources = Sources(directory);
        var derived = sources.OpenDerivation();
        Assert.True(derived.IsSuccess);
        using var trace = new Statements(Connection(derived.Value));
        var first = sources.ReadMembershipInput();
        var second = sources.ReadMembershipInput();
        Assert.Same(first, second);
        Assert.NotEmpty(first.Objects);
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM membership_input_source ORDER BY ordinal", StringComparison.Ordinal)));
        Assert.Same(sources.Facts, sources.Facts);
    }

    [Fact]
    public void StoredDerivationProductsAreValidatedBeforeReuse()
    {
        var directory = Ready();
        var path = SourceFile(directory, "derivation");
        using (var database = OpenDatabase(path))
        {
            Assert.True(Scalar(database, "SELECT COUNT(*) FROM membership_route_summary") > 0);
            Execute(database, "DELETE FROM membership_route_summary");
            Execute(database, "PRAGMA wal_checkpoint(TRUNCATE)");
        }
        BundleSealing.Seal(path, SourceFile(directory, "derivation-seal"));
        using var sources = JudgingInputs.Open(directory, CancellationToken.None).Value;
        var opened = sources.OpenDerivation();
        Assert.False(opened.IsSuccess);
        Assert.Equal("Evidence.DerivationUnreadable", opened.Error?.Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MembershipReuseStillRequiresItsStoredFingerprintAndOrdinals(bool ordinal)
    {
        var directory = Ready();
        var path = SourceFile(directory, "derivation");
        using (var database = OpenDatabase(path))
        {
            Execute(database, ordinal
                ? "UPDATE membership_input_source SET ordinal=ordinal+1000"
                : "UPDATE membership_input_manifest SET source_hash=printf('%064d',0)");
            Execute(database, "PRAGMA wal_checkpoint(TRUNCATE)");
        }
        BundleSealing.Seal(path, SourceFile(directory, "derivation-seal"));
        using var sources = Sources(directory);
        Assert.Throws<InvalidOperationException>(() => sources.ReadMembershipInput());
    }

    [Fact]
    public void BinaryMembershipValuesCannotChangeLaterReads()
    {
        using var sources = Sources(Ready());
        var input = sources.ReadMembershipInput();
        var subject = input.Objects.Single(item => item.DistinguishedName == UserDn);
        var expected = subject.Find("objectSid")!.OnlyValue!.Bytes!.ToArray();
        subject.Find("objectSid")!.OnlyValue!.Bytes![0] ^= 0xff;
        Assert.Equal(expected, sources.ReadMembershipInput().Objects.Single(item => item.DistinguishedName == UserDn)
            .Find("objectSid")!.OnlyValue!.Bytes);
    }

    [Theory]
    [InlineData("objects")]
    [InlineData("attributes")]
    [InlineData("values")]
    public void MembershipCollectionsCannotBeReplaced(string collection)
    {
        using var sources = Sources(Ready());
        var input = sources.ReadMembershipInput();
        var subject = input.Objects.Single(item => item.DistinguishedName == UserDn);
        switch (collection)
        {
            case "objects":
                Assert.Throws<NotSupportedException>(() => ((IList<ObjectAttributes>)input.Objects)[0] = subject);
                break;
            case "attributes":
                Assert.Throws<NotSupportedException>(() => ((IList<ObjectAttribute>)subject.Attributes)[0] = subject.Attributes[0]);
                break;
            default:
                Assert.False(subject.Find("objectClass")!.Values is IList<AttributeValue>);
                break;
        }
    }

    [Theory]
    [InlineData("evidence")]
    [InlineData("derivation")]
    public void ReusedSourcesRefuseADifferentBinding(string changed)
    {
        using var sources = Sources(Ready());
        var description = Description(sources);
        sources.RequireFor(description);
        Assert.Throws<InvalidOperationException>(() => sources.RequireFor(changed == "evidence"
            ? description with { EvidenceSeal = new string('0', 64) }
            : description with { DerivationGenerationId = Guid.NewGuid() }));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AClosedOrCancelledScopeCannotReturnCachedMembership(bool cancel)
    {
        using var stopping = new CancellationTokenSource();
        using var sources = Sources(Ready(), stopping.Token);
        sources.ReadMembershipInput();
        Assert.True(sources.ReadNamingContexts().IsSuccess);
        if (cancel)
        {
            stopping.Cancel();
            Assert.Throws<OperationCanceledException>(() => sources.ReadMembershipInput());
            Assert.Throws<OperationCanceledException>(() => sources.ReadNamingContexts());
        }
        else
        {
            sources.Dispose();
            Assert.Throws<ObjectDisposedException>(() => sources.ReadMembershipInput());
            Assert.Throws<ObjectDisposedException>(() => sources.ReadNamingContexts());
        }
    }

    [Fact]
    public void ANewAttemptVerifiesTheSourcesAgain()
    {
        var directory = Ready();
        using var counts = new Verifications(directory);
        Run(directory, []);
        Run(directory, []);
        Assert.Equal((2L, 2L, 2L), (counts.Evidence, counts.Derivation, counts.Formats));
    }

    [Theory]
    [InlineData("evidence")]
    [InlineData("evidence-seal")]
    [InlineData("derivation")]
    [InlineData("derivation-seal")]
    public void SourceFilesStayProtectedThroughPathPreparation(string kind)
    {
        var directory = Ready();
        var path = SourceFile(directory, kind);
        var observed = false;
        Run(directory, [], new Watching(value =>
        {
            if (value.RequesterPhase != PathRequesterWorkPhase.PreparingPaths) return;
            observed = true;
            Assert.Throws<IOException>(() =>
            {
                using var attempted = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            });
        }));
        Assert.True(observed);
    }

    [Theory]
    [InlineData("success")]
    [InlineData("failure")]
    [InlineData("cancel")]
    public void EveryExitReleasesTheSourceFiles(string exit)
    {
        var directory = Ready();
        using var stopping = new CancellationTokenSource();
        var progress = new Watching(value =>
        {
            if (value.RequesterPhase != PathRequesterWorkPhase.PreparingPaths) return;
            if (exit == "failure") throw new InvalidOperationException("injected path failure");
            if (exit == "cancel") stopping.Cancel();
        });
        if (exit == "success") Run(directory, [], progress, stopping.Token);
        else if (exit == "cancel") Assert.Throws<OperationCanceledException>(() => Run(directory, [], progress, stopping.Token));
        else Assert.Throws<InvalidOperationException>(() => Run(directory, [], progress, stopping.Token));
        foreach (var kind in new[] { "evidence", "evidence-seal", "derivation", "derivation-seal" })
        {
            using var released = new FileStream(SourceFile(directory, kind), FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            Assert.True(released.CanWrite);
        }
    }

    [Theory]
    [InlineData(JudgingPhase.WritingFindings)]
    [InlineData(JudgingPhase.PublishingJudgement)]
    public void AChangedSourceSelectionCannotPublish(JudgingPhase phase)
    {
        var directory = Ready();
        Run(directory, []);
        var previous = File.ReadAllBytes(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement));
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation);
        var original = File.ReadAllBytes(manifest);
        Derive(directory);
        var replacement = File.ReadAllBytes(manifest);
        Assert.NotEqual(original, replacement);
        File.WriteAllBytes(manifest, original);
        var changed = false;
        Assert.Throws<InvalidOperationException>(() => Run(directory, [], new Watching(value =>
        {
            if (value.Phase != phase || changed) return;
            changed = true;
            File.WriteAllBytes(manifest, replacement);
        })));
        Assert.True(changed);
        Assert.Equal(previous, File.ReadAllBytes(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement)));
    }

    [Fact]
    public void PublicationProtectionHoldsTheCheckedSelectionUntilReleased()
    {
        var directory = Ready();
        using var sources = Sources(directory);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation);
        using (sources.ProtectPublication(Description(sources)))
        {
            Assert.Throws<IOException>(() =>
            {
                using var attempted = new FileStream(manifest, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete);
            });
        }
        using var released = new FileStream(manifest, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Assert.True(released.CanWrite);
    }

    [Fact]
    public void PathProductionLoadsFinalOwnershipCollectionsOnce()
    {
        using var fixture = new SavedFixture();
        Execute(fixture.Database, "DELETE FROM path_requester_risk; DELETE FROM path_risk_product; DELETE FROM tier0_path_node; DELETE FROM tier0_path_calculation");
        using var trace = new Statements(fixture.Database);
        var phases = new List<PathRequesterWorkPhase>();
        Tier0PathStorage.Write(fixture.Database, fixture.Description, fixture.Sources, [], [], CancellationToken.None, [], false, phases.Add);
        Assert.Contains(PathRequesterWorkPhase.PreparingPaths, phases);
        Assert.Contains(PathRequesterWorkPhase.WritingProofs, phases);
        Assert.Single(trace.Sql.Where(sql => sql.StartsWith("SELECT target,identity_json,fingerprint,", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.StartsWith("SELECT target,routes,classification_fingerprint,", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM ownership_relation ORDER BY id", StringComparison.Ordinal)));
        Assert.Equal(fixture.NodeCount, Scalar(fixture.Database, "SELECT COUNT(*) FROM tier0_path_node"));
    }

    [Fact]
    public void TheSnapshotContainsFinishedAssessmentStates()
    {
        using var fixture = new SavedFixture();
        var snapshot = new OwnershipAuditStorage.Snapshot(fixture.Database, fixture.Description, CancellationToken.None);
        var target = snapshot.ByTarget["DC=contoso,DC=com"];
        Assert.Equal(OwnershipScopeState.Included, target.Selection);
        Assert.True(target.Candidates > 0);
        Assert.Equal(target.Candidates, target.Transitions);
        Assert.Equal(OwnershipAssessmentExecution.CompletedWithLimitations, target.Execution);
        Assert.Same(target, snapshot.Targets.Single(row => row.Identity == target.Identity));
    }

    [Fact]
    public void AnUnfinishedAssessmentCannotSupplyTheFinalSnapshot()
    {
        using var fixture = new SavedFixture();
        Execute(fixture.Database, "UPDATE ownership_audit SET completed=0");
        Assert.Throws<InvalidOperationException>(() =>
            new OwnershipAuditStorage.Snapshot(fixture.Database, fixture.Description, CancellationToken.None));
    }

    [Theory]
    [InlineData("connection")]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    [InlineData("evaluation")]
    public void OwnershipSnapshotsCannotCrossTheirSourceBinding(string changed)
    {
        using var fixture = new SavedFixture();
        using var other = OpenDatabase(fixture.Path);
        var snapshot = new OwnershipAuditStorage.Snapshot(fixture.Database, fixture.Description, CancellationToken.None);
        snapshot.RequireFor(fixture.Database, fixture.Description);
        var description = changed switch
        {
            "generation" => fixture.Description with { GenerationId = Guid.NewGuid() },
            "evidence" => fixture.Description with { EvidenceSeal = new string('0', 64) },
            "derivation" => fixture.Description with { DerivationGenerationId = Guid.NewGuid() },
            "evaluation" => fixture.Description with { EvaluationAsOf = Started.AddDays(1) },
            _ => fixture.Description,
        };
        Assert.Throws<InvalidOperationException>(() => snapshot.RequireFor(changed == "connection" ? other : fixture.Database, description));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void OwnershipSnapshotsRefuseLaterWrites(bool anotherConnection)
    {
        using var fixture = new SavedFixture();
        using var other = OpenDatabase(fixture.Path);
        var snapshot = new OwnershipAuditStorage.Snapshot(fixture.Database, fixture.Description, CancellationToken.None);
        Execute(anotherConnection ? other : fixture.Database, "UPDATE ownership_target SET candidate_count=candidate_count+1");
        Assert.Throws<InvalidOperationException>(() => snapshot.RequireFor(fixture.Database, fixture.Description));
    }

    [Theory]
    [InlineData("owner")]
    [InlineData("seed")]
    [InlineData("uncertainty")]
    public void ReuseStillChecksTheSavedSourceWitnesses(string changed)
    {
        using var fixture = new SavedFixture();
        if (changed == "owner")
        {
            Assert.True(Scalar(fixture.Database, "SELECT COUNT(*) FROM ownership_relation WHERE witness_is_owner=1") > 0);
            Execute(fixture.Database, "UPDATE ownership_relation SET witness_trustee='S-1-5-18' WHERE witness_is_owner=1");
        }
        else if (changed == "seed")
        {
            Execute(fixture.Database, """
                UPDATE ownership_seed SET classification=json_set(classification,'$.Supports[0].Evidence[0].Value','wrong source value')
                WHERE target='DC=contoso,DC=com'
                """);
            Rehash(fixture.Database, "ownership_seed", "classification", "classification_fingerprint");
        }
        else
        {
            Assert.True(Scalar(fixture.Database, "SELECT COUNT(*) FROM path_uncertainty WHERE json_extract(proof,'$.Source.Reason')='DescriptorUnavailable'") > 0);
            Execute(fixture.Database, """
                UPDATE path_uncertainty SET proof=json_set(proof,'$.Source.Reason','NullDacl','$.Cause','BroadPrincipalNotExpanded')
                WHERE json_extract(proof,'$.Source.Reason')='DescriptorUnavailable'
                """);
            Rehash(fixture.Database, "path_uncertainty", "proof", "fingerprint");
        }
        // Structural reading succeeds: only qualification against the original sources may refuse.
        var inputs = PathInputStorage.Read(fixture.Database, fixture.Description, out var ownership, CancellationToken.None);
        Assert.Equal(PathInputAvailability.Recorded, inputs.Availability);
        void Validate() => PathInputStorage.ValidateSources(fixture.Database, fixture.Description, fixture.Sources, ownership, inputs, CancellationToken.None);
        if (changed == "uncertainty") Assert.Throws<InvalidDataException>(Validate);
        else Assert.Throws<InvalidOperationException>(Validate);
    }

    [Fact]
    public void UnavailablePathInputsDoNotLoadAnOwnershipSnapshot()
    {
        var directory = Bundle();
        Run(directory, []);
        using var reader = JudgementReader.Open(directory).Value;
        using var connection = OpenDatabase(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, reader.Description.GenerationId));
        using var trace = new Statements(connection);
        var inputs = PathInputStorage.Read(connection, reader.Description, out var ownership, CancellationToken.None);
        Assert.Equal(PathInputAvailability.RequiredInputsUnavailable, inputs.Availability);
        Assert.Null(ownership);
        Assert.DoesNotContain(trace.Sql, sql => sql.StartsWith("SELECT target,identity_json,", StringComparison.Ordinal));
    }

    private static string Ready()
    {
        var directory = Bundle(targetDescriptor: false, rootDescriptor: $"O:{UserSid}G:SYD:(A;;WO;;;{UserSid})(A;;WD;;;{UserSid})");
        Derive(directory);
        return directory;
    }

    private static void Run(string directory, IReadOnlyList<IRule> rules,
        IProgress<JudgingRun.JudgingProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var result = JudgingRun.JudgeAudit(directory, rules, JudgingRun.ProductionPathRequesterPolicy, Started, Started,
            progress ?? JudgingRun.NobodyIsWatching, RunLog.Discarded, cancellationToken, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgingInputs Sources(string directory, CancellationToken cancellationToken = default)
    {
        var opened = JudgingInputs.Open(directory, cancellationToken);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        var derivation = opened.Value.OpenDerivation();
        Assert.True(derivation.IsSuccess, derivation.Error?.Description);
        return opened.Value;
    }

    private static JudgementDescription Description(JudgingInputs sources) => new(sources.EvidenceSeal, Guid.NewGuid(),
        sources.Facts.Description.GenerationId, JudgementRunState.Running, Started, Started, default);

    private static string SourceFile(string directory, string kind)
    {
        if (kind == "evidence") return BundleLayout.EvidencePath(directory);
        if (kind == "evidence-seal") return BundleLayout.SealPath(directory);
        var generation = AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value;
        return kind == "derivation" ? BundleLayout.AnalysisGenerationDataPath(directory, generation.Kind, generation.GenerationId)
            : BundleLayout.AnalysisGenerationSealPath(directory, generation.Kind, generation.GenerationId);
    }

    private sealed class SavedFixture : IDisposable
    {
        internal JudgingInputs Sources { get; }
        internal JudgementDescription Description { get; }
        internal SqliteConnection Database { get; }
        internal string Path { get; }
        internal long NodeCount { get; }

        internal SavedFixture()
        {
            var directory = Ready();
            Run(directory, []);
            using var reader = JudgementReader.Open(directory).Value;
            Description = reader.Description;
            Path = System.IO.Path.Combine(directory, "ownership-verification.db");
            File.Copy(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement, Description.GenerationId), Path);
            Database = OpenDatabase(Path);
            Sources = JudgingInputReuseTests.Sources(directory);
            NodeCount = Scalar(Database, "SELECT COUNT(*) FROM tier0_path_node");
        }

        public void Dispose()
        {
            Database.Dispose();
            Sources.Dispose();
        }
    }

    private static SqliteConnection OpenDatabase(string path)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    private static SqliteConnection Connection(DerivationReader reader) => Assert.IsType<SqliteConnection>(
        typeof(DerivationReader).GetField("_connection", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(reader));

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long Scalar(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return (long)command.ExecuteScalar()!;
    }

    private static void Rehash(SqliteConnection connection, string table, string value, string hash)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"SELECT rowid,{value} FROM {table}";
        var rows = new List<(long Id, string Json)>();
        using (var read = command.ExecuteReader()) while (read.Read()) rows.Add((read.GetInt64(0), read.GetString(1)));
        foreach (var row in rows)
        {
            command.CommandText = $"UPDATE {table} SET {hash}=$hash WHERE rowid=$id";
            command.Parameters.Clear();
            command.Parameters.AddWithValue("$hash", SHA256.HashData(Encoding.UTF8.GetBytes(row.Json)));
            command.Parameters.AddWithValue("$id", row.Id);
            Assert.Equal(1, command.ExecuteNonQuery());
        }
    }

    private sealed class Watching(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => report(value);
    }

    internal sealed class Statements : IDisposable
    {
        private readonly SqliteConnection _connection;
        private readonly strdelegate_trace _callback;
        internal List<string> Sql { get; } = [];
        internal Statements(SqliteConnection connection)
        {
            _connection = connection;
            _callback = (_, sql) => Sql.Add(sql);
            raw.sqlite3_trace(connection.Handle!, _callback, null!);
            Execute(connection, "SELECT 73");
            Assert.Contains("SELECT 73", Sql);
        }
        public void Dispose()
        {
            raw.sqlite3_trace(_connection.Handle!, (strdelegate_trace)null!, null!);
            GC.KeepAlive(_callback);
        }
    }

    internal sealed class Verifications : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new();
        internal Verifications(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name is "store.verifications" or "evidence.format_checks")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                foreach (var tag in tags)
                {
                    if (tag.Value is not string file || !file.StartsWith(directory, StringComparison.OrdinalIgnoreCase)) continue;
                    var kind = instrument.Name == "evidence.format_checks" ? "format"
                        : System.IO.Path.GetFileName(file).StartsWith("evidence.", StringComparison.Ordinal) ? "evidence"
                        : System.IO.Path.GetFileName(file).StartsWith("derivation.", StringComparison.Ordinal) ? "derivation" : "judgement";
                    _counts.AddOrUpdate(kind, value, (_, count) => count + value);
                }
            });
            _listener.Start();
        }
        internal long Evidence => _counts.GetValueOrDefault("evidence");
        internal long Derivation => _counts.GetValueOrDefault("derivation");
        internal long Formats => _counts.GetValueOrDefault("format");
        public void Dispose() => _listener.Dispose();
    }
}
