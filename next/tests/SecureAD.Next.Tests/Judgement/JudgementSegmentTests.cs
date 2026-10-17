using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Judgement;
using SecureAD.Shell.Services;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class JudgementSegmentTests
{
    private const string Target = "CN=Service target,DC=contoso,DC=com";
    private const string Descriptor = "O:SYG:SYD:(A;;WP;;;S-1-5-21-1-2-3-1200)(A;;WP;;;S-1-5-21-1-2-3-1200)";
    private static readonly DateTimeOffset When = DateTimeOffset.UnixEpoch;

    [Fact]
    public void EveryPayloadTableHasOneOwnerAndFindingsContainsNoGlobalProofOrInventory()
    {
        var directory = Published();
        var root = Root(directory);
        Assert.Equal(BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement), root.Segments.Select(segment => segment.Role));
        var tables = new Dictionary<string, StoreSegmentRole>(StringComparer.Ordinal);
        foreach (var segment in root.Segments)
        {
            var path = Path.Combine(directory, segment.FileName);
            Assert.Equal(root.GenerationId, segment.GenerationId);
            Assert.Equal(JudgementSchema.Version, segment.SchemaVersion);
            Assert.Equal(new FileInfo(path).Length, segment.ByteLength);
            Assert.Equal(BundleSealing.HashFile(path), segment.Hash);
            Assert.Equal(segment.Hash, BundleSealing.ReadSeal(path + ".seal")!.Hash);
            using var connection = Database(path);
            using var query = connection.CreateCommand();
            query.CommandText = "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'judgement_part'";
            using var rows = query.ExecuteReader();
            while (rows.Read()) Assert.True(tables.TryAdd(rows.GetString(0), segment.Role), rows.GetString(0));
        }
        Assert.Equal(StoreSegmentRole.Judgement, tables["finding"]);
        Assert.Equal(StoreSegmentRole.Judgement, tables["group_inventory"]);
        Assert.Equal(StoreSegmentRole.Judgement, tables["group_inventory_product"]);
        Assert.Equal(StoreSegmentRole.Judgement, tables["tier0_distance"]);
        Assert.Equal(StoreSegmentRole.Judgement, tables["tier0_distance_product"]);
        Assert.Equal(StoreSegmentRole.PermissionProof, tables["finding_attribute_write_entry"]);
        Assert.Equal(StoreSegmentRole.PermissionProof, tables["permission_entry"]);
        Assert.Equal(StoreSegmentRole.PermissionProof, tables["shared_proof_value"]);
        Assert.Equal(StoreSegmentRole.PathProof, tables["path_proof_chunk"]);
        Assert.Equal(StoreSegmentRole.PathProof, tables["path_shared_proof"]);
        Assert.Equal(StoreSegmentRole.PathProof, tables["tier0_best_route"]);
        Assert.Equal(StoreSegmentRole.JudgementFacts, tables["permission_classification_entry"]);
    }

    [Fact]
    public void TypedFindingsVerifyOnlyTheirSharedPermissionPartAndKeepEveryOriginalOccurrence()
    {
        var directory = Published();
        var root = Root(directory);
        using var counts = new Verifications(directory);
        using var source = new BundleAssetSource();
        var page = source.ReadFindings(directory, FindingsQuery.About(Target));
        Assert.True(page.IsSuccess, page.Error?.Description);
        Assert.Equal(3, page.Value.Findings.Count);
        foreach (var finding in page.Value.Findings)
        {
            var proof = Assert.IsType<AttributeWritePermissionEvidence>(finding.Evidence);
            Assert.Equal(new[] { 0, 1 }, proof.Entries.Select(entry => entry.Ordinal));
            Assert.Equal(root.GenerationId, proof.GenerationId);
            Assert.Equal(root.EvidenceSeal, proof.EvidenceSeal);
            Assert.Equal(finding.ObjectGuid, proof.Target.ObjectGuid);
            Assert.Equal(Target, proof.Target.DistinguishedName);
            Assert.Equal(proof.Entries[0] with { Ordinal = 1 }, proof.Entries[1]);
        }
        var first = JsonSerializer.Serialize(page.Value);
        Assert.Equal(first, JsonSerializer.Serialize(source.ReadFindings(directory, FindingsQuery.About(Target)).Value));
        Assert.True(source.ReadFindingsFilterValues(directory).IsSuccess);
        Assert.True(source.ReadRuleExecutions(directory).IsSuccess);
        Assert.Equal((1L, 1L, 0L, 0L, 0L, 0L), counts.Snapshot());
        Assert.True(source.CaptureReadValidity()());
        source.CloseRun();
        source.SelectRun(directory);
        Assert.True(source.ReadFindings(directory, FindingsQuery.About(Target)).IsSuccess);
        Assert.Equal((2L, 2L, 0L, 0L, 0L, 0L), counts.Snapshot());
        using var database = Database(Path.Combine(directory, root.Segment(StoreSegmentRole.PermissionProof).FileName));
        using var query = database.CreateCommand();
        query.CommandText = "SELECT COUNT(*) FROM permission_entry";
        Assert.Equal(1L, query.ExecuteScalar());
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("schema")]
    [InlineData("role")]
    [InlineData("generation")]
    [InlineData("evidence")]
    [InlineData("derivation")]
    public void AnUnverifiedOrContradictorySharedPartNeverReturnsAFindingsPage(string defect)
    {
        var directory = Published();
        var root = Root(directory);
        var path = Path.Combine(directory, root.Segment(StoreSegmentRole.PermissionProof).FileName);
        using (var connection = Database(path, writable: true))
        {
            using var edit = connection.CreateCommand();
            edit.CommandText = defect switch
            {
                "bytes" => "UPDATE control_object SET is_complete=1-is_complete",
                "schema" => "UPDATE judgement_part SET schema_version=999",
                "role" => "UPDATE judgement_part SET role='PathProof'",
                "generation" => "UPDATE judgement_part SET generation='11111111-2222-3333-4444-555555555555'",
                "evidence" => "UPDATE judgement_part SET evidence_seal='foreign evidence'",
                "derivation" => "UPDATE judgement_part SET derivation_generation=NULL",
                _ => throw new ArgumentOutOfRangeException(nameof(defect)),
            };
            Assert.True(edit.ExecuteNonQuery() > 0);
            edit.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            edit.ExecuteNonQuery();
        }
        if (defect != "bytes") TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        using var source = new BundleAssetSource();
        var read = source.ReadFindings(directory, FindingsQuery.About(Target));
        Assert.False(read.IsSuccess);
        Assert.NotNull(read.Error);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("missing-seal")]
    [InlineData("name")]
    [InlineData("role")]
    [InlineData("generation")]
    [InlineData("schema")]
    [InlineData("length")]
    [InlineData("hash")]
    [InlineData("root")]
    public void AChangedRootOrSelectedDeclarationNeverReturnsAFindingsPage(string defect)
    {
        var directory = Published();
        var root = Root(directory);
        var part = root.Segment(StoreSegmentRole.PermissionProof);
        var path = Path.Combine(directory, part.FileName);
        if (defect == "missing") File.Delete(path);
        else if (defect == "missing-seal") File.Delete(path + ".seal");
        else
        {
            if (defect == "name")
            {
                File.Copy(path, Path.Combine(directory, "foreign-proof.db"));
                File.Copy(path + ".seal", Path.Combine(directory, "foreign-proof.db.seal"));
            }
            root = root with { Segments = root.Segments.Select(segment => segment.Role != part.Role ? segment : defect switch
            {
                "name" => segment with { FileName = "foreign-proof.db" },
                "role" => segment with { Role = StoreSegmentRole.PathProof },
                "generation" => segment with { GenerationId = Guid.NewGuid() },
                "schema" => segment with { SchemaVersion = 999 },
                "length" => segment with { ByteLength = segment.ByteLength + 1 },
                "hash" => segment with { Hash = new string('0', 64) },
                _ => segment,
            }).ToArray() };
            File.WriteAllText(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement),
                JsonSerializer.Serialize(root with { Hash = defect == "root" ? new string('0', 64) : root.ComputeHash() }));
        }
        using var source = new BundleAssetSource();
        var read = source.ReadFindings(directory, FindingsQuery.About(Target));
        Assert.False(read.IsSuccess);
        Assert.NotNull(read.Error);
    }

    [Fact]
    public void VerifiedSharedBytesAndTheirSealStayProtectedUntilTheSelectedRunCloses()
    {
        var directory = Published();
        var path = Path.Combine(directory, Root(directory).Segment(StoreSegmentRole.PermissionProof).FileName);
        using var source = new BundleAssetSource();
        Assert.True(source.ReadFindings(directory, FindingsQuery.About(Target)).IsSuccess);
        Assert.Throws<IOException>(() => File.AppendAllText(path, "changed"));
        Assert.Throws<IOException>(() => File.AppendAllText(path + ".seal", "changed"));
        source.CloseRun();
        File.AppendAllText(path, "changed");
        var reopened = source.ReadFindings(directory, FindingsQuery.About(Target));
        Assert.False(reopened.IsSuccess);
    }

    [Fact]
    public void RelatedProofReadbackNeverIncorporatesUnsealedWalBytes()
    {
        var directory = Published();
        var path = Path.Combine(directory, Root(directory).Segment(StoreSegmentRole.PermissionProof).FileName);
        var clone = Path.Combine(directory, "wal-source.db");
        File.Copy(path, clone);
        using var writer = Database(clone, writable: true);
        using var edit = writer.CreateCommand();
        edit.CommandText = "PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE)";
        edit.ExecuteNonQuery();
        edit.CommandText = "UPDATE permission_entry SET mask=mask+1";
        Assert.Equal(1, edit.ExecuteNonQuery());
        File.Copy(clone + "-wal", path + "-wal");
        using var source = new BundleAssetSource();
        var read = source.ReadFindings(directory, FindingsQuery.About(Target));
        Assert.True(read.IsSuccess, read.Error?.Description);
        Assert.All(read.Value.Findings, finding => Assert.All(
            Assert.IsType<AttributeWritePermissionEvidence>(finding.Evidence).Entries, entry => Assert.Equal(0x20, entry.AccessMask)));
    }

    [Fact]
    public void CompleteVerificationChecksUnselectedPartsWithoutMakingFindingsReadThem()
    {
        var directory = Published();
        var root = Root(directory);
        File.AppendAllText(Path.Combine(directory, root.Segment(StoreSegmentRole.JudgementFacts).FileName), "changed");
        using var source = new BundleAssetSource();
        Assert.True(source.ReadFindings(directory, FindingsQuery.About(Target)).IsSuccess);
        Assert.Equal(SealState.Mismatch, BundleSealing.VerifyJudgement(directory).State);
    }

    [Theory]
    [InlineData(StoreSegmentRole.Judgement)]
    [InlineData(StoreSegmentRole.PermissionProof)]
    [InlineData(StoreSegmentRole.PathProof)]
    [InlineData(StoreSegmentRole.JudgementFacts)]
    public void FailureSealingAnyPartPreservesTheExactPreviousCompletedResult(StoreSegmentRole role)
    {
        var directory = Published();
        var root = Root(directory);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var previous = File.ReadAllBytes(manifest);
        var hashes = root.Segments.Select(segment => BundleSealing.HashFile(Path.Combine(directory, segment.FileName))).ToArray();
        using var writer = JudgementWriter.Create(directory, root.EvidenceSeal, Derivation(directory), When, When);
        var generation = new AnalysisStoreGeneration(AnalysisStoreKind.Judgement, writer.GenerationId);
        Directory.CreateDirectory(BundleLayout.AnalysisSegmentDataPath(directory, generation, role) + ".seal");
        Assert.Throws<UnauthorizedAccessException>(() => writer.Complete(When));
        Assert.Equal(previous, File.ReadAllBytes(manifest));
        Assert.Equal(hashes, root.Segments.Select(segment => BundleSealing.HashFile(Path.Combine(directory, segment.FileName))));
        Assert.Equal(root.GenerationId, Root(directory).GenerationId);
        Assert.True(AnalysisStoreLifecycle.HasUnpublishedChanges(directory, AnalysisStoreKind.Judgement));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(3, reader.ReadPage(FindingsQuery.About(Target)).Value.Findings.Count);
    }

    [Fact]
    public void FinalCancellationAfterEveryPartIsSealedPreservesThePreviousRoot()
    {
        var directory = Published();
        var root = Root(directory);
        var manifest = AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement);
        var previous = File.ReadAllBytes(manifest);
        using var stopping = new CancellationTokenSource();
        var sealedParts = 0;
        var log = new JudgingStatusTests.StatusLog(line =>
        {
            if (line.Message == "file sealing" && line.Value("artifact") == AnalysisStoreKind.Judgement.ToString()
                && ++sealedParts == 4) stopping.Cancel();
        });
        using var writer = JudgementWriter.Create(directory, root.EvidenceSeal, Derivation(directory), When, When);
        Assert.Throws<OperationCanceledException>(() => writer.Complete(When, stopping.Token, null, log));
        Assert.Equal(4, sealedParts);
        Assert.Equal(previous, File.ReadAllBytes(manifest));
        Assert.Equal(root.GenerationId, Root(directory).GenerationId);
        foreach (var role in BundleLayout.JudgementParts.Prepend(StoreSegmentRole.Judgement))
        {
            var path = BundleLayout.AnalysisSegmentDataPath(directory, new(AnalysisStoreKind.Judgement, writer.GenerationId), role);
            Assert.True(File.Exists(path + ".seal"));
        }
    }

    [Fact]
    public void CrossProductForeignKeysStillRejectAnOrphanOriginalOccurrence()
    {
        var directory = TempDirectories.Create("segment-reference");
        using var connection = Database(Path.Combine(directory, "staging.db"), writable: true, create: true);
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA foreign_keys=ON";
        pragma.ExecuteNonQuery();
        JudgementStoreLayout.Create(connection, directory, Guid.NewGuid(), new string('a', 64), null);
        JudgementSchema.CreateTables(connection);
        pragma.CommandText = "PRAGMA temp_store=FILE";
        pragma.ExecuteNonQuery();
        using var insert = connection.CreateCommand();
        using (var transaction = connection.BeginTransaction())
        {
            using var statements = new PreparedStatements(connection);
            var payload = SavedTextPayloadStorage.Classifications.Write(connection, transaction, statements, "{}");
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO permission_classification_descriptor VALUES(1,$payload,1,zeroblob(32))";
            insert.Parameters.AddWithValue("$payload", payload);
            Assert.Equal(1, insert.ExecuteNonQuery());
            transaction.Commit();
        }
        insert.Transaction = null;
        insert.Parameters.Clear();
        insert.CommandText = "INSERT INTO permission_classification_entry VALUES(1,0,999)";
        Assert.Throws<SqliteException>(() => insert.ExecuteNonQuery());
        insert.CommandText = "SELECT COUNT(*) FROM permission_classification_entry";
        Assert.Equal(0L, insert.ExecuteScalar());
    }

    private static string Published() => AttributeWriteRuleTests.Published(Descriptor);
    private static StoreRootManifest Root(string directory) => AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
    private static Guid Derivation(string directory) => AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Derivation).Value.GenerationId;
    private static SqliteConnection Database(string path, bool writable = false, bool create = false)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path, Pooling = false,
            Mode = create ? SqliteOpenMode.ReadWriteCreate : writable ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadOnly,
        }.ToString());
        connection.Open();
        return connection;
    }

    private sealed class Verifications : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new();
        internal Verifications(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name == "store.verifications") listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                foreach (var tag in tags)
                {
                    if (tag.Value is not string path || !path.StartsWith(directory, StringComparison.OrdinalIgnoreCase)) continue;
                    var name = Path.GetFileName(path);
                    var key = name.Contains(".permission-proof.", StringComparison.Ordinal) ? "permission"
                        : name.Contains(".path-proof.", StringComparison.Ordinal) ? "path"
                        : name.Contains(".facts.", StringComparison.Ordinal) ? "facts"
                        : name.Split('.')[0];
                    _counts.AddOrUpdate(key, value, (_, count) => count + value);
                }
            });
            _listener.Start();
        }
        internal (long Findings, long Permission, long Path, long Facts, long Evidence, long Derivation) Snapshot() =>
            (_counts.GetValueOrDefault("judgement"), _counts.GetValueOrDefault("permission"), _counts.GetValueOrDefault("path"),
                _counts.GetValueOrDefault("facts"), _counts.GetValueOrDefault("evidence"), _counts.GetValueOrDefault("derivation"));
        public void Dispose() => _listener.Dispose();
    }
}
