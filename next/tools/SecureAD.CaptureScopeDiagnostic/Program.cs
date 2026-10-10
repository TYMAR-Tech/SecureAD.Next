using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Kernel.Capture;

namespace SecureAD.CaptureScopeDiagnostic;

internal static class Program
{
    internal const int ExcludedObjectsFound = 2;
    internal const int ClassCountsIncomplete = 3;

    public static int Main(string[] args)
    {
        try
        {
            if (args is ["--help"] or [])
            {
                Console.WriteLine(
                    """
                    SecureAD saved-capture Enatel check (Windows x64)

                    SecureAD.CaptureScopeDiagnostic.exe --run "D:\Saved runs\completed-run" --output "D:\run-summary-enatel.txt"

                    Use a completed, sealed capture, not the currently running audit.
                    The input is opened read-only and its existing seal is verified.
                    This forensic checker reads Evidence formats 14, 15 and 16; it does not migrate them.
                    No directory connection, recapture, rejudging or input-file change occurs.
                    The output must be a new file outside the saved-run directory.
                    Only aggregate counts, class names and capture/tool fingerprints are exported.

                    Exit 0: no recorded-exclusion violation, storage-class gap or account-class scope gap was found.
                    Exit 2: excluded objects or a prior default storage/account class-scope gap was found.
                    Exit 3: some captured objects lack class information; read the qualified summary.
                    Exit 1: the check could not complete; no successful summary was produced.

                    --self-test runs synthetic offline correctness checks, not a production audit.
                    """);
                return 0;
            }
            if (args is ["--self-test"])
            {
                SelfTests.Run();
                return 0;
            }
            if (args is ["--self-test", var test])
            {
                SelfTests.Run(test);
                return 0;
            }

            var options = Options.Parse(args);
            ValidateOutput(options.RunDirectory, options.OutputPath);
            Console.Error.WriteLine("Verifying the completed capture's existing seal. This reads the evidence file; nothing is changed.");
            var report = Inspect(options.RunDirectory);
            WriteReport(options.RunDirectory, options.OutputPath, report);
            Console.WriteLine("Wrote the counts-only summary. Return that summary, not the capture.");
            if (report.ExitCode == ExcludedObjectsFound)
                Console.Error.WriteLine("Excluded objects or a prior default storage/account class-scope gap were found. Read the summary; this is not a passing exclusion check.");
            if (report.ExitCode == ClassCountsIncomplete)
                Console.Error.WriteLine("Some objects lack class information. Absence of excluded objects cannot be established for them.");
            return report.ExitCode;
        }
        catch (DiagnosticException error)
        {
            Console.Error.WriteLine("Check refused: " + error.Message);
            return 1;
        }
        catch (SqliteException error)
        {
            Console.Error.WriteLine($"Check failed: SQLite {error.SqliteErrorCode}/{error.SqliteExtendedErrorCode}. {error.Message}");
            return 1;
        }
        catch (IOException error)
        {
            Console.Error.WriteLine("Check failed while accessing local files: " + error.Message);
            return 1;
        }
        catch (UnauthorizedAccessException error)
        {
            Console.Error.WriteLine("Check refused by local file permissions: " + error.Message);
            return 1;
        }
        catch (JsonException error)
        {
            Console.Error.WriteLine("Check failed while reading the seal: " + error.Message);
            return 1;
        }
    }

    internal static Report Inspect(string runDirectory)
    {
        var run = Path.GetFullPath(runDirectory);
        if (!Directory.Exists(run))
            throw new DiagnosticException("The saved-run directory does not exist.");
        if (File.Exists(BundleLayout.PartialPath(run)) || File.Exists(Path.Combine(run, "judgement.write.lock")))
            throw new DiagnosticException("This run is unfinished or being judged. Choose an already-completed run and leave the current audit alone.");

        var database = BundleLayout.EvidencePath(run);
        var sealPath = BundleLayout.SealPath(run);
        RequireNoJournal(database);
        using var dataGuard = File.Open(database, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sealGuard = File.Open(sealPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        RequireNoJournal(database);
        var verified = BundleSealing.Verify(run);
        if (!verified.MayBeOpened)
            throw new DiagnosticException($"Evidence seal refused {verified.State}: {verified.Detail}");
        var seal = JsonSerializer.Deserialize<BundleSealContents>(File.ReadAllText(sealPath))
            ?? throw new DiagnosticException("The verified seal has no contents.");
        using var connection = OpenReadOnly(database);
        using var transaction = connection.BeginTransaction(deferred: true);
        var capture = ReadCaptureDescription(connection, transaction);

        var total = Count(connection, transaction, "SELECT COUNT(*) FROM captured_object");
        var unattributed = Count(connection, transaction,
            """
            SELECT COUNT(*) FROM captured_object o
            LEFT JOIN partition_coverage p ON p.coverage_id=o.coverage_id
            WHERE p.coverage_id IS NULL
            """);
        var orphanClasses = Count(connection, transaction,
            """
            SELECT COUNT(*) FROM objectclass_value v
            LEFT JOIN captured_object o ON o.object_id=v.object_id
            WHERE o.object_id IS NULL
            """);
        if (unattributed != 0 || orphanClasses != 0)
            throw new DiagnosticException("Objects or class values have broken source references; counts would be misleading.");
        var missingClasses = Count(connection, transaction,
            """
            SELECT COUNT(*) FROM captured_object o
            WHERE NOT EXISTS (
                SELECT 1 FROM objectclass_value v
                WHERE v.object_id=o.object_id AND length(trim(v.value))>0)
            """);
        var partitions = ReadPartitions(connection, transaction);
        if (partitions.Sum(partition => partition.Objects) != total)
            throw new DiagnosticException("Partition totals do not reconcile with the captured-object total.");
        var classes = ReadClasses(connection, transaction, capture.ExcludedObjectClasses);
        var instances = Count(connection, transaction,
            """
            SELECT COUNT(*) FROM captured_object o
            WHERE EXISTS (
                SELECT 1 FROM objectclass_value v
                WHERE v.object_id=o.object_id AND v.value LIKE 'enatel%')
            """);
        var excludedInstances = Count(connection, transaction,
            """
            SELECT COUNT(*) FROM captured_object o
            WHERE EXISTS (
                SELECT 1 FROM objectclass_value v
                JOIN capture_object_class_exclusion e ON e.class_name=v.value COLLATE NOCASE
                WHERE v.object_id=o.object_id AND v.value LIKE 'enatel%')
            """);
        var definitions = ReadDefinitions(connection, transaction);
        transaction.Commit();
        RequireNoJournal(database);
        var assembly = typeof(Program).Assembly;
        return new Report(
            DateTimeOffset.UtcNow, capture, seal.Hash, dataGuard.Length,
            assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                ?? throw new DiagnosticException("The diagnostic has no build identity."),
            assembly.ManifestModule.ModuleVersionId,
            total, missingClasses, instances, excludedInstances, partitions, classes, definitions);
    }

    internal static SqliteConnection OpenReadOnly(string database)
    {
        // immutable avoids creating SQLite sidecars; Inspect holds non-writable file guards.
        var uri = new Uri(Path.GetFullPath(database)).AbsoluteUri + "?immutable=1";
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = uri, Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA query_only=ON";
            command.ExecuteNonQuery();
            return connection;
        }
        catch
        {
            connection.Dispose();
            throw;
        }
    }

    private static void RequireNoJournal(string database)
    {
        foreach (var suffix in new[] { "-wal", "-shm", "-journal" })
            if (File.Exists(database + suffix))
                throw new DiagnosticException("The evidence has a SQLite sidecar. Use a completed, closed capture; no sidecar is ignored or deleted.");
    }

    private static long Count(SqliteConnection connection, SqliteTransaction transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command.ExecuteScalar() is long count && count >= 0
            ? count : throw new DiagnosticException("A required count did not return a nonnegative integer.");
    }

    private static BundleDescription ReadCaptureDescription(SqliteConnection connection, SqliteTransaction transaction)
    {
        // This forensic tool reads the known table layout and each recorded scope, not a product legacy reader.
        if (Count(connection, transaction, "SELECT COUNT(*) FROM bundle") != 1)
            throw new DiagnosticException("The evidence must contain exactly one capture description.");
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT schema_version, captured_attribute_catalog_version, schema_guid_catalog_version,
                   security_descriptor_parser_version, forest_fqdn, capture_started_utc, capture_completed_utc,
                   coverage_id, every_declared_unit_recorded_as_read, continuation_reconciliation_outcome
            FROM bundle
            """;
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw new DiagnosticException("The capture description is missing.");
        var version = reader.GetInt32(0);
        if (version is not (14 or 15 or 16))
            throw new DiagnosticException($"SchemaVersionUnsupported: this forensic check reads Evidence 14, 15 and 16, not {version}.");
        if (!DateTimeOffset.TryParseExact(reader.GetString(5), "O", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var started)
            || !DateTimeOffset.TryParseExact(reader.GetString(6), "O", CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var completed) || completed < started
            || string.IsNullOrWhiteSpace(reader.GetString(7))
            || reader.GetInt64(8) is not (0 or 1)
            || !Enum.TryParse<ContinuationReconciliationOutcome>(reader.GetString(9), out var reconciliation)
            || !Enum.IsDefined(reconciliation))
            throw new DiagnosticException("The capture description has invalid provenance or coverage fields.");

        using var scopeCommand = connection.CreateCommand();
        scopeCommand.Transaction = transaction;
        scopeCommand.CommandText = "SELECT class_name FROM capture_object_class_exclusion ORDER BY class_name COLLATE NOCASE";
        using var scopeReader = scopeCommand.ExecuteReader();
        var exclusions = new List<string>();
        while (scopeReader.Read()) exclusions.Add(scopeReader.GetString(0));
        var recorded = exclusions.ToHashSet(StringComparer.OrdinalIgnoreCase);
        string[] expectedDefault = version switch
        {
            14 => ["dnsNode", "dnsZone", "enatelSSOAccountParameter", "enatelUserManagedAuth", "enatelSSOStorageV3"],
            15 => ["dnsNode", "dnsZone", "enatelSSOAccountParameter", "enatelUserManagedAuth", "enatelSSOStorage"],
            16 => ["dnsNode", "dnsZone", "enatelSSOAccountParameter", "enatelUserManagedAuth", "enatelSSOStorage", "enatelSSOAccount"],
            _ => throw new DiagnosticException("Unsupported capture format."),
        };
        if (!recorded.SetEquals(expectedDefault) && !recorded.SetEquals(["dnsNode", "dnsZone"]))
            throw new DiagnosticException("InvalidScope: the recorded exclusions do not match this evidence format.");
        return new(version, reader.GetInt32(1), reader.GetInt32(2), reader.GetInt32(3), reader.GetString(4),
            started, completed, reader.GetString(7), reader.GetInt64(8) != 0, reconciliation, exclusions.AsReadOnly());
    }

    private static List<PartitionCount> ReadPartitions(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT p.naming_context_kind, COUNT(*)
            FROM captured_object o JOIN partition_coverage p ON p.coverage_id=o.coverage_id
            GROUP BY p.naming_context_kind ORDER BY p.naming_context_kind
            """;
        using var reader = command.ExecuteReader();
        var result = new List<PartitionCount>();
        while (reader.Read())
        {
            var kind = reader.GetString(0);
            if (!Enum.TryParse<NamingContextKind>(kind, out var parsed) || !Enum.IsDefined(parsed))
                throw new DiagnosticException("An object has an unsupported partition kind.");
            result.Add(new(kind, reader.GetInt64(1)));
        }
        return result;
    }

    private static List<ClassCount> ReadClasses(SqliteConnection connection, SqliteTransaction transaction,
        IReadOnlyList<string> excluded)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText =
            """
            SELECT v.value COLLATE NOCASE, p.naming_context_kind, COUNT(DISTINCT o.object_id)
            FROM objectclass_value v
            JOIN captured_object o ON o.object_id=v.object_id
            JOIN partition_coverage p ON p.coverage_id=o.coverage_id
            WHERE v.value LIKE 'enatel%'
            GROUP BY v.value COLLATE NOCASE, p.naming_context_kind
            ORDER BY v.value COLLATE NOCASE, p.naming_context_kind
            """;
        using var reader = command.ExecuteReader();
        var result = new List<ClassCount>();
        while (reader.Read())
        {
            var name = reader.GetString(0);
            result.Add(new(name, reader.GetString(1), reader.GetInt64(2),
                excluded.Contains(name, StringComparer.OrdinalIgnoreCase)));
        }
        return result;
    }

    private static List<DefinitionCount> ReadDefinitions(SqliteConnection connection, SqliteTransaction transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var displayName = BundleSchema.ColumnNameFor("lDAPDisplayName");
        command.CommandText =
            $"""
            SELECT o.{displayName} COLLATE NOCASE, v.value COLLATE NOCASE, COUNT(DISTINCT o.object_id)
            FROM captured_object o
            JOIN objectclass_value v ON v.object_id=o.object_id
            WHERE o.{displayName} LIKE 'enatel%' AND v.value COLLATE NOCASE IN ('classSchema','attributeSchema')
            GROUP BY o.{displayName} COLLATE NOCASE, v.value COLLATE NOCASE
            ORDER BY o.{displayName} COLLATE NOCASE, v.value COLLATE NOCASE
            """;
        using var reader = command.ExecuteReader();
        var result = new List<DefinitionCount>();
        while (reader.Read())
            result.Add(new(reader.GetString(0), reader.GetString(1), reader.GetInt64(2)));
        return result;
    }

    internal static void ValidateOutput(string runDirectory, string outputPath)
    {
        var run = Path.TrimEndingDirectorySeparator(Path.GetFullPath(runDirectory));
        var output = Path.GetFullPath(outputPath);
        if (output.Equals(run, StringComparison.OrdinalIgnoreCase)
            || output.StartsWith(run + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new DiagnosticException("The output must be outside the saved-run directory.");
        if (File.Exists(output) || Directory.Exists(output))
            throw new DiagnosticException("The output already exists and will not be overwritten. Choose a new summary filename.");
        var parent = Path.GetDirectoryName(output);
        if (parent is null || !Directory.Exists(parent))
            throw new DiagnosticException("The output's parent directory must already exist.");
    }

    internal static void WriteReport(string runDirectory, string outputPath, Report report)
    {
        ValidateOutput(runDirectory, outputPath);
        using var stream = new FileStream(outputPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.Write(report.Text());
    }

    internal sealed record PartitionCount(string Kind, long Objects);
    internal sealed record ClassCount(string Class, string PartitionKind, long Objects, bool RecordedExcluded);
    internal sealed record DefinitionCount(string LdapDisplayName, string DefinitionKind, long Objects);

    internal sealed record Report(
        DateTimeOffset CheckedUtc, BundleDescription Capture, string EvidenceSha256, long EvidenceBytes,
        string ToolVersion, Guid ToolMvid, long TotalObjects, long MissingClasses, long EnatelInstances,
        long ExcludedEnatelInstances, IReadOnlyList<PartitionCount> Partitions,
        IReadOnlyList<ClassCount> Classes, IReadOnlyList<DefinitionCount> Definitions)
    {
        internal long StorageClassInstances => Classes
            .Where(value => value.Class.Equals("enatelSSOStorage", StringComparison.OrdinalIgnoreCase))
            .Sum(value => value.Objects);
        // Quest KB 4256730 identifies enatelSSOStorage as the class; V3 was only the child CN.
        internal long StorageClassExclusionGap =>
            Capture.ExcludedObjectClasses.Contains("enatelSSOStorageV3", StringComparer.OrdinalIgnoreCase)
                && !Capture.ExcludedObjectClasses.Contains("enatelSSOStorage", StringComparer.OrdinalIgnoreCase)
                ? StorageClassInstances : 0;
        internal long AccountClassInstances => Classes
            .Where(value => value.Class.Equals("enatelSSOAccount", StringComparison.OrdinalIgnoreCase))
            .Sum(value => value.Objects);
        internal long AccountClassScopeGap =>
            !Capture.ExcludedObjectClasses.Contains("enatelSSOAccount", StringComparer.OrdinalIgnoreCase)
                && (Capture.ExcludedObjectClasses.Contains("enatelSSOStorage", StringComparer.OrdinalIgnoreCase)
                    || Capture.ExcludedObjectClasses.Contains("enatelSSOStorageV3", StringComparer.OrdinalIgnoreCase))
                ? AccountClassInstances : 0;
        internal int ExitCode => ExcludedEnatelInstances > 0 || StorageClassExclusionGap > 0 || AccountClassScopeGap > 0 ? ExcludedObjectsFound
            : MissingClasses > 0 ? ClassCountsIncomplete : 0;

        internal string Text()
        {
            var text = new StringBuilder();
            text.AppendLine("SecureAD saved-capture Enatel scope summary");
            text.AppendLine("No directory access, recapture, rejudging or input-file change. Counts refer only to this saved capture.");
            text.AppendLine("No object names, distinguished names, forest/domain/controller names, attribute payloads or permissions are exported.");
            text.AppendLine($"Diagnostic version: {ToolVersion}");
            text.AppendLine($"Diagnostic assembly MVID: {ToolMvid:D}");
            text.AppendLine($"Checked UTC: {CheckedUtc:O}");
            text.AppendLine($"Capture started UTC: {Capture.CaptureStartedUtc:O}");
            text.AppendLine($"Capture completed UTC: {Capture.CaptureCompletedUtc:O}");
            text.AppendLine($"Evidence schema: {Capture.SchemaVersion}");
            text.AppendLine($"Evidence verified SHA-256: {EvidenceSha256}");
            text.AppendLine($"Evidence bytes: {EvidenceBytes.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Coverage fingerprint: {Capture.CoverageId}");
            text.AppendLine($"Every declared partition recorded Read: {Capture.EveryDeclaredUnitRecordedAsRead}");
            text.AppendLine();
            text.AppendLine("Recorded object-class exclusions (intent recorded by capture, not proof that the filter worked):");
            foreach (var value in Capture.ExcludedObjectClasses)
                text.AppendLine("  " + JsonSerializer.Serialize(value));
            text.AppendLine();
            text.AppendLine($"Captured objects: {TotalObjects.ToString(CultureInfo.InvariantCulture)}");
            foreach (var value in Partitions)
                text.AppendLine($"  {value.Kind}: {value.Objects.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Objects with no usable objectClass values: {MissingClasses.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Distinct objects with an Enatel objectClass: {EnatelInstances.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Distinct objects with a recorded-excluded Enatel objectClass: {ExcludedEnatelInstances.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Vendor-documented enatelSSOStorage instances: {StorageClassInstances.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Storage instances missed by the recorded V3-name exclusion: {StorageClassExclusionGap.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"enatelSSOAccount instances: {AccountClassInstances.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine($"Account instances outside the now-approved default metadata exclusions: {AccountClassScopeGap.ToString(CultureInfo.InvariantCulture)}");
            text.AppendLine("Vendor anchor: Quest KB 4256730 queries objectClass=enatelSSOStorage for V2/V3-named storage containers.");
            text.AppendLine("https://support.quest.com/kb/4256730/how-to-calculate-the-number-of-esso-user-licenses-used");
            text.AppendLine();
            text.AppendLine("Named Enatel metadata classes (all objectClass values checked, not only the most specific):");
            foreach (var name in CapturedAttributeCatalog.EnatelSsoObjectClasses)
            {
                var count = Classes.Where(value => name.Equals(value.Class, StringComparison.OrdinalIgnoreCase)).Sum(value => value.Objects);
                var excluded = Capture.ExcludedObjectClasses.Contains(name, StringComparer.OrdinalIgnoreCase);
                text.AppendLine($"  {JsonSerializer.Serialize(name)}: {count.ToString(CultureInfo.InvariantCulture)}; recorded excluded: {excluded}");
            }
            text.AppendLine();
            text.AppendLine("Every observed Enatel instance class, by partition kind:");
            foreach (var value in Classes)
                text.AppendLine($"  {JsonSerializer.Serialize(value.Class)} | {value.PartitionKind} | {value.Objects.ToString(CultureInfo.InvariantCulture)} | recorded excluded: {value.RecordedExcluded}");
            if (Classes.Count == 0) text.AppendLine("  None observed in stored objectClass values.");
            text.AppendLine("An object may have several Enatel classes; per-class counts must not be summed as unique objects.");
            text.AppendLine();
            text.AppendLine("Enatel schema definitions (names of classes/attributes, not Enatel object instances):");
            foreach (var value in Definitions)
                text.AppendLine($"  {JsonSerializer.Serialize(value.LdapDisplayName)} | {value.DefinitionKind} | {value.Objects.ToString(CultureInfo.InvariantCulture)}");
            if (Definitions.Count == 0) text.AppendLine("  None observed.");
            text.AppendLine();
            if (StorageClassExclusionGap > 0)
                text.AppendLine("RESULT: STORAGE-CLASS EXCLUSION GAP. Documented enatelSSOStorage instances are present despite the recorded V3-name exclusion; that exclusion targeted a container name as a class.");
            else if (AccountClassScopeGap > 0)
                text.AppendLine("RESULT: ACCOUNT-CLASS SCOPE GAP. This earlier default scope captured enatelSSOAccount objects; the now-approved default metadata exclusions include this class.");
            else if (ExcludedEnatelInstances > 0)
                text.AppendLine("RESULT: RECORDED-EXCLUDED ENATEL OBJECTS ARE PRESENT. This capture does not satisfy its recorded Enatel exclusions.");
            else if (MissingClasses > 0)
                text.AppendLine("RESULT: CLASS COUNTS INCOMPLETE. No excluded Enatel instances were identified, but objects lacking classes prevent establishing absence.");
            else
                text.AppendLine("RESULT: No recorded-excluded Enatel objects, storage-class exclusion gap or account-class scope gap were found in this saved capture.");
            if (Classes.Any(value => !value.RecordedExcluded))
                text.AppendLine("ADDITIONAL OBSERVATION: Enatel instance classes outside the recorded exclusions are present; inspect the class table before claiming all Enatel objects were bypassed.");
            text.AppendLine("This is a saved-data check, not proof about an uncaptured object, a live LDAP filter, permission safety or audit performance.");
            text.AppendLine("END OF SUMMARY - diagnostic completed; see RESULT and the exit code.");
            return text.ToString();
        }
    }

    internal sealed record Options(string RunDirectory, string OutputPath)
    {
        internal static Options Parse(string[] args)
        {
            string? run = null;
            string? output = null;
            for (var index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || string.IsNullOrWhiteSpace(args[index + 1]))
                    throw new DiagnosticException("Each option needs a value. Use --help.");
                if (args[index] == "--run" && run is null) run = args[index + 1];
                else if (args[index] == "--output" && output is null) output = args[index + 1];
                else throw new DiagnosticException("Unknown or repeated option. Use --help.");
            }
            if (run is null || output is null)
                throw new DiagnosticException("Both --run and --output are required. Use --help.");
            return new(Path.GetFullPath(run), Path.GetFullPath(output));
        }
    }

    internal sealed class DiagnosticException(string message) : Exception(message) { }
}
