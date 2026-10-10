using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace SecureAD.JudgementDiagnostic;

internal static partial class Program
{
    private const int SchemaVersion = 2;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public static int Main(string[] args)
    {
        try
        {
            DiagnosticSqlite.Initialize();
            if (args is ["--self-test"])
            {
                SelfTest();
                Console.WriteLine("Judgement diagnostic self-test passed.");
                return 0;
            }

            var options = Options.Parse(args);
            var report = Inspect(options.RunDirectory);
            WriteReport(options.OutputPath, report);
            Console.WriteLine($"Wrote aggregate read-only report to {options.OutputPath}");
            if (!report.MeasurementsComplete)
                Console.Error.WriteLine("Measurements are incomplete or do not reconcile; return the report with its explicit discrepancies.");
            return report.MeasurementsComplete ? 0 : 2;
        }
        catch (DiagnosticException error)
        {
            Console.Error.WriteLine(error.Message);
            return 2;
        }
        catch (SqliteException error)
        {
            Console.Error.WriteLine($"SQLite refused the diagnostic: code {error.SqliteErrorCode}, extended code {error.SqliteExtendedErrorCode}. No successful report was produced.");
            return 1;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(
                args is ["--self-test"]
                    ? error.ToString()
                    : $"Diagnostic failed: {error.GetType().Name}");
            return 1;
        }
    }

    private static DiagnosticReport Inspect(string runDirectory)
    {
        var run = Path.GetFullPath(runDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (!Directory.Exists(run))
            throw new DiagnosticException("The run directory does not exist.");
        if (File.Exists(Path.Combine(run, "judgement.write.lock")))
            throw new DiagnosticException("SecureAD still holds the Judgement write lock. Close SecureAD before running this diagnostic.");

        var database = Path.Combine(run, "judgement.db.partial");
        if (!File.Exists(database))
            throw new DiagnosticException("The run does not contain judgement.db.partial.");

        using var guards = SourceGuards.Acquire(database);
        var sourceBefore = SourceFiles(database);
        var report = new DiagnosticReport
        {
            SchemaVersion = SchemaVersion,
            CollectedUtc = DateTimeOffset.UtcNow,
            Safety = new SafetyReport(),
            SourceFilesBefore = sourceBefore,
        };

        using (var connection = OpenReadOnly(database))
        {
            report.Database = ReadDatabaseFacts(connection);
            report.SchemaObjects = ReadSchema(connection);
            report.PageUse = ReadPageUse(connection);
            report.PageUse.Account(report.Database);
            report.TableRows = ReadRowCounts(connection, report.SchemaObjects);
            report.Proofs = ReadProofs(connection, report.SchemaObjects);
        }

        report.SourceFilesAfter = SourceFiles(database);
        report.SourceMetadataUnchanged = sourceBefore.SequenceEqual(report.SourceFilesAfter);
        if (!report.SourceMetadataUnchanged)
            throw new DiagnosticException("A source file's length or timestamp changed while the read-only diagnostic was running.");
        return report;
    }

    private static SqliteConnection OpenReadOnly(string database)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = database,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
            DefaultTimeout = 5,
        }.ToString());
        connection.Open();
        Execute(connection, "PRAGMA query_only=ON");
        Execute(connection, "PRAGMA temp_store=MEMORY");
        Execute(connection, "PRAGMA cache_size=-8192");
        Execute(connection, "PRAGMA mmap_size=0");
        Execute(connection, "PRAGMA trusted_schema=OFF");
        if (ScalarLong(connection, "PRAGMA query_only") != 1)
        {
            connection.Dispose();
            throw new DiagnosticException("SQLite did not confirm query-only mode.");
        }
        return connection;
    }

    private static DatabaseFacts ReadDatabaseFacts(SqliteConnection connection) => new()
    {
        SqliteVersion = ScalarText(connection, "SELECT sqlite_version()"),
        SqliteSourceId = ScalarText(connection, "SELECT sqlite_source_id()"),
        NativeLibrarySha256 = DiagnosticSqlite.LibrarySha256,
        AutoVacuum = ScalarLong(connection, "PRAGMA auto_vacuum"),
        ConnectionMode = new SqliteConnectionStringBuilder(connection.ConnectionString).Mode.ToString(),
        PageSize = ScalarLong(connection, "PRAGMA page_size"),
        PageCount = ScalarLong(connection, "PRAGMA page_count"),
        FreePageCount = ScalarLong(connection, "PRAGMA freelist_count"),
        JournalMode = ScalarText(connection, "PRAGMA journal_mode"),
        QueryOnly = ScalarLong(connection, "PRAGMA query_only") == 1,
        TempStore = ScalarLong(connection, "PRAGMA temp_store") == 2 ? "memory" : "unexpected",
    };

    private static List<SchemaObject> ReadSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT name, type, COALESCE(tbl_name, ''), rootpage
            FROM sqlite_schema
            WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_stat%'
            ORDER BY type, name
            """;
        using var reader = command.ExecuteReader();
        var values = new List<SchemaObject>();
        while (reader.Read())
        {
            values.Add(new SchemaObject
            {
                Name = reader.GetString(0),
                Kind = reader.GetString(1),
                Table = reader.GetString(2),
                RootPage = reader.GetInt64(3),
            });
        }
        return values;
    }

    private static PageUseReport ReadPageUse(SqliteConnection connection)
    {
        Console.WriteLine("Reading aggregate table/index page use...");
            using var command = connection.CreateCommand();
            command.CommandTimeout = 0;
            command.CommandText = """
                SELECT name, pageno, pgsize, payload, unused, mx_payload
                FROM dbstat WHERE aggregate=TRUE
                """;
            using var reader = command.ExecuteReader();
            var values = new List<PageUse>();
            while (reader.Read())
            {
                values.Add(new PageUse
                {
                    Name = reader.GetString(0),
                    Pages = reader.GetInt64(1),
                    Bytes = reader.GetInt64(2),
                    PayloadBytes = reader.GetInt64(3),
                    UnusedBytes = reader.GetInt64(4),
                    LargestCellPayloadBytes = reader.GetInt64(5),
                });
            }
            values.Sort((left, right) => right.Bytes.CompareTo(left.Bytes));
            return new PageUseReport { Status = "available", Objects = values };
    }

    private static List<TableRows> ReadRowCounts(
        SqliteConnection connection,
        IReadOnlyList<SchemaObject> schema)
    {
        var tables = schema
            .Where(value => value.Kind == "table" && !value.Name.StartsWith("sqlite_", StringComparison.Ordinal))
            .Select(value => value.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();
        var values = new List<TableRows>(tables.Length);
        foreach (var table in tables)
        {
            Console.WriteLine($"Counting rows: {table}");
            try
            {
                using var command = connection.CreateCommand();
                command.CommandTimeout = 0;
                command.CommandText = $"SELECT COUNT(*) FROM {Quote(table)}";
                values.Add(new TableRows
                {
                    Name = table,
                    Status = "counted",
                    Rows = Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture),
                });
            }
            catch (SqliteException error)
            {
                values.Add(new TableRows
                {
                    Name = table,
                    Status = $"unavailable:sqlite-{error.SqliteErrorCode}",
                });
            }
        }
        values.Sort((left, right) => Nullable.Compare(right.Rows, left.Rows));
        return values;
    }

    private static string Quote(string identifier) =>
        "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    private static List<SourceFile> SourceFiles(string database)
    {
        var paths = new[] { database, database + "-wal", database + "-shm" };
        return paths.Select(path =>
        {
            var file = new FileInfo(path);
            file.Refresh();
            return new SourceFile
            {
                Name = Path.GetFileName(path),
                Exists = file.Exists,
                Length = file.Exists ? file.Length : null,
                LastWriteUtc = file.Exists ? file.LastWriteTimeUtc : null,
            };
        }).ToList();
    }

    private static void WriteReport(string outputPath, DiagnosticReport report)
    {
        var output = Path.GetFullPath(outputPath);
        var parent = Path.GetDirectoryName(output)
            ?? throw new DiagnosticException("The output path has no parent directory.");
        if (!Directory.Exists(parent))
            throw new DiagnosticException("The output directory does not exist.");
        File.WriteAllText(output, JsonSerializer.Serialize(report, Json) + Environment.NewLine);
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static long ScalarLong(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string ScalarText(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToString(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture) ?? "unavailable";
    }

    private static void SelfTest()
    {
        var scratch = Path.Combine(Path.GetTempPath(), "securead-judgement-diagnostic-" + Guid.NewGuid().ToString("N"));
        var run = Path.Combine(scratch, "synthetic-run");
        var snapshot = Path.Combine(scratch, "snapshot");
        var output = Path.Combine(scratch, "report.json");
        Directory.CreateDirectory(run);
        Directory.CreateDirectory(snapshot);
        var database = Path.Combine(run, "judgement.db.partial");
        try
        {
            using (var connection = new SqliteConnection($"Data Source={database};Pooling=False"))
            {
                connection.Open();
                Execute(connection, "PRAGMA journal_mode=WAL");
                Execute(connection, "PRAGMA wal_autocheckpoint=0");
                Execute(connection, "CREATE TABLE large_product(id INTEGER PRIMARY KEY, secret TEXT NOT NULL)");
                Execute(connection, "CREATE INDEX ix_large_product_secret ON large_product(secret)");
                using var transaction = connection.BeginTransaction();
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = "INSERT INTO large_product(secret) VALUES ($secret)";
                var parameter = command.Parameters.Add("$secret", SqliteType.Text);
                for (var index = 0; index < 1_000; index++)
                {
                    parameter.Value = "CUSTOMER-SECRET-" + index;
                    command.ExecuteNonQuery();
                }
                transaction.Commit();

                Execute(connection, """
                    CREATE TABLE path_proof(id INTEGER PRIMARY KEY,byte_length INTEGER NOT NULL,chunk_count INTEGER NOT NULL);
                    CREATE TABLE path_proof_chunk(proof_id INTEGER REFERENCES path_proof(id),ordinal INTEGER,data BLOB,
                        PRIMARY KEY(proof_id,ordinal));
                    CREATE TABLE proof_consumer(proof INTEGER REFERENCES path_proof(id));
                    INSERT INTO path_proof VALUES(1,100,1),(2,100000,2);
                    INSERT INTO path_proof_chunk VALUES(1,0,zeroblob(100)),(2,0,zeroblob(65536)),(2,1,zeroblob(34464));
                    INSERT INTO proof_consumer VALUES(1),(2),(2),(999);
                    """);
                foreach (var path in new[] { database, database + "-wal", database + "-shm" })
                    CopyShared(path, Path.Combine(snapshot, Path.GetFileName(path)));
            }

            foreach (var path in Directory.EnumerateFiles(run))
                File.Delete(path);
            foreach (var path in Directory.EnumerateFiles(snapshot))
                File.Copy(path, Path.Combine(run, Path.GetFileName(path)));

            var before = SourceHashes(database);
            using (var guards = SourceGuards.Acquire(database))
            {
                foreach (var path in new[] { database, database + "-wal", database + "-shm" })
                {
                    var denied = false;
                    try { using var write = new FileStream(path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite); }
                    catch (IOException) { denied = true; }
                    Require(denied, "the operating system did not deny source writes");
                }
            }
            var report = Inspect(run);
            WriteReport(output, report);
            var after = SourceHashes(database);
            var json = File.ReadAllText(output);

            Require(before.SequenceEqual(after), "a database or sidecar changed");
            Require(report.Safety.ConnectionMode == "ReadOnly", "read-only mode was not declared");
            Require(report.Safety.OperatingSystemDeniesSourceWrites, "operating-system write denial was not declared");
            Require(!report.Safety.CheckpointRequested, "a checkpoint was requested");
            Require(!report.Safety.DatabaseCopied, "a production database copy was requested");
            Require(!report.Safety.DatabaseHashed, "a production database hash was requested");
            Require(!report.Safety.CustomerValuesSelected, "customer values were selected");
            Require(report.Database.QueryOnly, "query-only mode was not confirmed");
            Require(report.Database.ConnectionMode == "ReadOnly", "the SQLite connection was not opened in read-only mode");
            Require(report.Database.TempStore == "memory", "temporary storage was not held in memory");
            Require(report.SourceMetadataUnchanged, "source metadata changed");
            Require(report.SourceFilesBefore.All(value => !Path.IsPathRooted(value.Name)), "a source path was exported");
            Require(report.TableRows.Single(value => value.Name == "large_product").Rows == 1_000, "row count was not reported");
            Require(report.PageUse.Status == "available" && report.PageUse.Objects.Count >= 5, "real page accounting is unavailable");
            Require(report.PageUse.Reconciled && report.PageUse.UnattributedBytes == 0, "page totals do not reconcile");
            Require(report.PageUse.LogicalDatabaseBytes == report.Database.PageSize * report.Database.PageCount,
                "logical size does not match SQLite pages");
            Require(report.PageUse.Objects.Sum(value => value.Bytes) == report.PageUse.LogicalDatabaseBytes,
                "measured table/index bytes do not cover the database");
            Require(report.PageUse.Objects.Single(value => value.Name == "ix_large_product_secret").Bytes > 0,
                "index size is missing");
            var discrepancy = new PageUseReport { Objects = [new PageUse { Bytes = 4096 }] };
            discrepancy.Account(new DatabaseFacts { PageSize = 4096, PageCount = 3, FreePageCount = 1 });
            Require(!discrepancy.Reconciled && discrepancy.UnattributedBytes == 4096 && discrepancy.FreelistBytes == 4096,
                "unattributed pages were hidden");
            Require(report.PageUse.Objects.Single(value => value.Name == "path_proof_chunk").PayloadBytes >= 100100,
                "overflow payload was not measured");
            Require(report.Proofs.StoredProofs is { Rows: 2, Bytes: 100100, LargestProofBytes: 100000, Chunks: 3 },
                "stored proof aggregates are wrong");
            Require(report.Proofs.LengthsAgree && report.Proofs.StoredChunkBytes == 100100,
                "chunk lengths do not match proof lengths");
            var references = report.Proofs.References.Single(value => value.Table == "proof_consumer");
            Require(references is { Rows: 4, MatchedProofs: 3, Bytes: 200100, UnmatchedReferences: 1 }
                && references.AverageProofBytes == 66700, "proof references were lost or incorrectly deduplicated");
            Require(!json.Contains("CUSTOMER-SECRET", StringComparison.Ordinal), "a stored value escaped into the report");
            Require(!json.Contains(run, StringComparison.OrdinalIgnoreCase), "the run path escaped into the report");
            Require(new FileInfo(output).Length < 1_000_000, "the report was not compact");
            var refusedInsideOutput = false;
            try
            {
                _ = Options.Parse(
                    ["--run-directory", run, "--output", Path.Combine(run, "unsafe.json")]);
            }
            catch (DiagnosticException)
            {
                refusedInsideOutput = true;
            }
            Require(refusedInsideOutput, "an output inside the run directory was accepted");
            File.Delete(database + "-shm");
            var refusedMissingSidecar = false;
            try { _ = Inspect(run); }
            catch (DiagnosticException) { refusedMissingSidecar = true; }
            Require(refusedMissingSidecar && !File.Exists(database + "-shm"), "missing sidecar was created or accepted");
        }
        finally
        {
            Directory.Delete(scratch, recursive: true);
        }
    }

    private static List<string> SourceHashes(string database) =>
        new[] { database, database + "-wal", database + "-shm" }
            .Select(Hash)
            .ToList();

    private static void CopyShared(string source, string destination)
    {
        using var input = new FileStream(
            source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        input.CopyTo(output);
    }

    private static string Hash(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void Require(bool condition, string description)
    {
        if (!condition)
            throw new DiagnosticException("Self-test failed: " + description);
    }

    private sealed class DiagnosticException(string message) : Exception(message);

    private sealed record Options(string RunDirectory, string OutputPath)
    {
        internal static Options Parse(string[] args)
        {
            string? run = null;
            string? output = null;
            for (var index = 0; index < args.Length; index++)
            {
                if (args[index] == "--run-directory" && index + 1 < args.Length)
                    run = args[++index];
                else if (args[index] == "--output" && index + 1 < args.Length)
                    output = args[++index];
                else
                    throw Usage();
            }
            if (string.IsNullOrWhiteSpace(run) || string.IsNullOrWhiteSpace(output))
                throw Usage();

            var fullRun = Path.GetFullPath(run).TrimEnd(Path.DirectorySeparatorChar);
            var fullOutput = Path.GetFullPath(output);
            if (fullOutput.Equals(fullRun, StringComparison.OrdinalIgnoreCase)
                || fullOutput.StartsWith(fullRun + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new DiagnosticException("The output must be outside the failed run directory.");
            if (!Path.GetExtension(fullOutput).Equals(".json", StringComparison.OrdinalIgnoreCase))
                throw new DiagnosticException("The output path must end in .json.");
            return new(fullRun, fullOutput);
        }

        private static DiagnosticException Usage() => new(
            "Usage: SecureAD.JudgementDiagnostic.exe --run-directory <failed-run> --output <report.json>");
    }

    private sealed class DiagnosticReport
    {
        public int SchemaVersion { get; init; }
        public DateTimeOffset CollectedUtc { get; init; }
        public SafetyReport Safety { get; init; } = new();
        public DatabaseFacts Database { get; set; } = new();
        public List<SourceFile> SourceFilesBefore { get; init; } = [];
        public List<SourceFile> SourceFilesAfter { get; set; } = [];
        public bool SourceMetadataUnchanged { get; set; }
        public List<SchemaObject> SchemaObjects { get; set; } = [];
        public PageUseReport PageUse { get; set; } = new();
        public List<TableRows> TableRows { get; set; } = [];
        public ProofReport Proofs { get; set; } = new();
        public bool MeasurementsComplete => SourceMetadataUnchanged && PageUse.Reconciled
            && TableRows.Count > 0 && TableRows.All(value => value.Status == "counted")
            && Proofs.LengthsAgree && Proofs.References.Count > 0
            && Proofs.References.All(value => value.UnmatchedReferences == 0);
    }

    private sealed class SafetyReport
    {
        public string ConnectionMode { get; init; } = "ReadOnly";
        public bool QueryOnlyRequired { get; init; } = true;
        public string TemporaryStorage { get; init; } = "memory";
        public bool OperatingSystemDeniesSourceWrites { get; init; } = true;
        public bool CheckpointRequested { get; init; }
        public bool DatabaseCopied { get; init; }
        public bool DatabaseHashed { get; init; }
        public bool CustomerValuesSelected { get; init; }
        public bool SourcePathsExcluded { get; init; } = true;
    }

    private sealed class DatabaseFacts
    {
        public string SqliteVersion { get; init; } = "";
        public string SqliteSourceId { get; init; } = "";
        public string NativeLibrarySha256 { get; init; } = "";
        public long AutoVacuum { get; init; }
        public string ConnectionMode { get; init; } = "";
        public long PageSize { get; init; }
        public long PageCount { get; init; }
        public long FreePageCount { get; init; }
        public string JournalMode { get; init; } = "";
        public bool QueryOnly { get; init; }
        public string TempStore { get; init; } = "";
    }

    private sealed class SourceFile : IEquatable<SourceFile>
    {
        public string Name { get; init; } = "";
        public bool Exists { get; init; }
        public long? Length { get; init; }
        public DateTime? LastWriteUtc { get; init; }

        public bool Equals(SourceFile? other) =>
            other is not null
            && Name == other.Name
            && Exists == other.Exists
            && Length == other.Length
            && LastWriteUtc == other.LastWriteUtc;

        public override bool Equals(object? obj) => Equals(obj as SourceFile);
        public override int GetHashCode() => HashCode.Combine(Name, Exists, Length, LastWriteUtc);
    }

    private sealed class SchemaObject
    {
        public string Name { get; init; } = "";
        public string Kind { get; init; } = "";
        public string Table { get; init; } = "";
        public long RootPage { get; init; }
    }

    private sealed class PageUseReport
    {
        public string Status { get; init; } = "";
        public List<PageUse> Objects { get; init; } = [];
        public long LogicalDatabaseBytes { get; private set; }
        public long TableAndIndexBytes { get; private set; }
        public long FreelistBytes { get; private set; }
        public long UnattributedBytes { get; private set; }
        public bool Reconciled { get; private set; }
        public string AccountingNote { get; } = "Includes sqlite_schema and overflow pages; excludes WAL history. Nonzero unattributed bytes remain unexplained, including possible pointer-map or locking pages.";

        internal void Account(DatabaseFacts database)
        {
            LogicalDatabaseBytes = checked(database.PageCount * database.PageSize);
            TableAndIndexBytes = Objects.Sum(value => value.Bytes);
            FreelistBytes = checked(database.FreePageCount * database.PageSize);
            UnattributedBytes = checked(LogicalDatabaseBytes - TableAndIndexBytes - FreelistBytes);
            Reconciled = UnattributedBytes == 0 && Objects.Count > 0;
            if (UnattributedBytes < 0)
                throw new DiagnosticException("Page accounting exceeds the logical database size.");
        }
    }

    private sealed class PageUse
    {
        public string Name { get; init; } = "";
        public long Pages { get; init; }
        public long Bytes { get; init; }
        public long PayloadBytes { get; init; }
        public long UnusedBytes { get; init; }
        public long LargestCellPayloadBytes { get; init; }
    }

    private sealed class TableRows
    {
        public string Name { get; init; } = "";
        public string Status { get; init; } = "";
        public long? Rows { get; init; }
    }

    private sealed class SourceGuards : IDisposable
    {
        private readonly List<FileStream> _streams;

        private SourceGuards(List<FileStream> streams) => _streams = streams;

        internal static SourceGuards Acquire(string database)
        {
            var paths = new[] { database, database + "-wal", database + "-shm" };
            if (paths.Any(path => !File.Exists(path)))
                throw new DiagnosticException(
                    "The database, WAL and SHM must all exist. The diagnostic refuses to let SQLite create a missing sidecar.");

            var streams = new List<FileStream>(paths.Length);
            try
            {
                foreach (var path in paths)
                    streams.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
                return new SourceGuards(streams);
            }
            catch
            {
                foreach (var stream in streams)
                    stream.Dispose();
                throw new DiagnosticException(
                    "The database or a sidecar could not be protected with an operating-system deny-write handle.");
            }
        }

        public void Dispose()
        {
            foreach (var stream in _streams)
                stream.Dispose();
        }
    }
}
