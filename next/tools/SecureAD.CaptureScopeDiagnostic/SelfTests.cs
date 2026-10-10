using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;

namespace SecureAD.CaptureScopeDiagnostic;

internal static class SelfTests
{
    internal static void Run(string? selected = null)
    {
        var cases = new Dictionary<string, Action>(StringComparer.Ordinal)
        {
            ["class-chains"] = () => WithReport(CaptureObjectScope.Default, true, report =>
                Check("class-chains", report.Classes.Single(value => value.Class.Equals("enatelSSOAccountParameter", StringComparison.OrdinalIgnoreCase)).Objects == 1
                    && report.Classes.Single(value => value.Class.Equals("enatelUserManagedAuth", StringComparison.OrdinalIgnoreCase)).Objects == 1)),
            ["unique-counts"] = () => WithReport(CaptureObjectScope.Default, true, report =>
                Check("unique-counts", report.EnatelInstances == 5 && report.ExcludedEnatelInstances == 3 && report.ExitCode == Program.ExcludedObjectsFound)),
            ["additional-classes"] = () => WithReport(CaptureObjectScope.Default, true, report =>
                Check("additional-classes", report.Classes.Where(value => value.Class == "enatelSyntheticOtherClass").Sum(value => value.Objects) == 2
                    && report.Classes.Where(value => value.Class == "enatelSyntheticOtherClass").All(value => !value.RecordedExcluded)
                    && report.Text().Contains("ADDITIONAL OBSERVATION:", StringComparison.Ordinal))),
            ["schema-definitions"] = () => WithReport(CaptureObjectScope.Default, true, report =>
                Check("schema-definitions", report.Definitions.Count == 2 && report.Definitions.Sum(value => value.Objects) == 2 && report.EnatelInstances == 5)),
            ["partition-counts"] = () => WithReport(CaptureObjectScope.Default, true, report =>
                Check("partition-counts", report.TotalObjects == 9 && report.Partitions.Single(value => value.Kind == "Domain").Objects == 6
                    && report.Partitions.Single(value => value.Kind == "Configuration").Objects == 1
                    && report.Partitions.Single(value => value.Kind == "Schema").Objects == 2)),
            ["binding-and-privacy"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true);
                var report = Program.Inspect(fixture.Directory);
                Check("binding-and-privacy", report.EvidenceSha256 == BundleSealing.HashFile(BundleLayout.EvidencePath(fixture.Directory))
                    && report.Capture.CaptureStartedUtc == DateTimeOffset.UnixEpoch
                    && !report.Text().Contains("example.com", StringComparison.Ordinal)
                    && !report.Text().Contains("DC=example", StringComparison.Ordinal)
                    && !report.Text().Contains("CN=object", StringComparison.Ordinal));
            },
            ["unchanged-input"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true);
                var before = Fingerprint(fixture.Directory);
                Program.Inspect(fixture.Directory);
                Check("unchanged-input", before == Fingerprint(fixture.Directory));
            },
            ["read-only-mode"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                using var connection = Program.OpenReadOnly(BundleLayout.EvidencePath(fixture.Directory));
                Check("read-only-mode", new SqliteConnectionStringBuilder(connection.ConnectionString).Mode == SqliteOpenMode.ReadOnly);
            },
            ["writes-refused"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                using var connection = Program.OpenReadOnly(BundleLayout.EvidencePath(fixture.Directory));
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE captured_object SET cn='changed'";
                try
                {
                    command.ExecuteNonQuery();
                    throw new Program.DiagnosticException("Self-test failed: writes-refused");
                }
                catch (SqliteException error) when (error.SqliteErrorCode == 8)
                {
                    Console.WriteLine("PASS writes-refused");
                }
            },
            ["absent-instances"] = () => WithReport(CaptureObjectScope.Default, false, report =>
                Check("absent-instances", report.EnatelInstances == 0 && report.ExcludedEnatelInstances == 0
                    && report.Definitions.Count == 2 && report.ExitCode == 0)),
            ["explicit-inclusion"] = () => WithReport(CaptureObjectScope.WithEnatelSso, true, report =>
                Check("explicit-inclusion", report.EnatelInstances == 5 && report.ExcludedEnatelInstances == 0
                    && report.ExitCode == 0 && report.Classes.All(value => !value.RecordedExcluded))),
            ["missing-classes"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false, missingClasses: true);
                var report = Program.Inspect(fixture.Directory);
                Check("missing-classes", report.MissingClasses == 1 && report.ExitCode == Program.ClassCountsIncomplete
                    && report.Text().Contains("RESULT: CLASS COUNTS INCOMPLETE", StringComparison.Ordinal));
            },
            ["output-outside"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                Refused("output-outside", () => Program.ValidateOutput(fixture.Directory,
                    Path.Combine(fixture.Directory, "summary.txt")), "outside");
            },
            ["output-no-overwrite"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true);
                var report = Program.Inspect(fixture.Directory);
                var output = Path.Combine(fixture.Parent, "summary.txt");
                Program.WriteReport(fixture.Directory, output, report);
                var before = File.ReadAllText(output);
                Refused("output-no-overwrite", () => Program.WriteReport(fixture.Directory, output, report), "already exists");
                Check("output-no-overwrite", before == File.ReadAllText(output));
            },
            ["failing-summary"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true);
                var output = Path.Combine(fixture.Parent, "summary.txt");
                Program.WriteReport(fixture.Directory, output, Program.Inspect(fixture.Directory));
                Check("failing-summary", File.ReadAllText(output).Contains("RESULT: RECORDED-EXCLUDED ENATEL OBJECTS ARE PRESENT", StringComparison.Ordinal));
            },
            ["command-outcomes"] = () =>
            {
                using var present = Fixture.Create(CaptureObjectScope.Default, true);
                var output = Path.Combine(present.Parent, "summary.txt");
                Check("command-outcomes", Program.Main(["--run", present.Directory, "--output", output]) == Program.ExcludedObjectsFound
                    && File.ReadAllText(output).Contains("END OF SUMMARY", StringComparison.Ordinal)
                    && Program.Main(["--run", present.Directory, "--output", output]) == 1);
                using var absent = Fixture.Create(CaptureObjectScope.Default, false);
                Check("command-outcomes", Program.Main(["--run", absent.Directory, "--output", Path.Combine(absent.Parent, "summary.txt")]) == 0);
                using var incomplete = Fixture.Create(CaptureObjectScope.Default, false, missingClasses: true);
                Check("command-outcomes", Program.Main(["--run", incomplete.Directory, "--output", Path.Combine(incomplete.Parent, "summary.txt")]) == Program.ClassCountsIncomplete);
            },
            ["active-run"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                File.WriteAllText(Path.Combine(fixture.Directory, "judgement.write.lock"), "synthetic");
                Refused("active-run", () => Program.Inspect(fixture.Directory), "being judged");
            },
            ["sidecars"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                File.WriteAllBytes(BundleLayout.EvidencePath(fixture.Directory) + "-wal", []);
                Refused("sidecars", () => Program.Inspect(fixture.Directory), "sidecar");
            },
            ["bad-seal"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                File.WriteAllText(BundleLayout.SealPath(fixture.Directory), "{\"Algorithm\":\"SHA-256\",\"Hash\":\"invalid\"}");
                Refused("bad-seal", () => Program.Inspect(fixture.Directory), "refused");
            },
            ["old-format"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("UPDATE bundle SET schema_version=11");
                Refused("old-format", () => Program.Inspect(fixture.Directory), "SchemaVersionUnsupported");
            },
            ["broken-provenance"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("PRAGMA foreign_keys=OFF; UPDATE captured_object SET coverage_id=99999");
                Refused("broken-provenance", () => Program.Inspect(fixture.Directory), "source references");
            },
            ["invalid-options"] = () =>
                Refused("invalid-options", () => Program.Options.Parse(["--run"]), "needs a value"),
            ["option-order"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                Check("option-order", Program.Options.Parse(["--output", Path.Combine(fixture.Parent, "summary.txt"),
                    "--run", fixture.Directory]).RunDirectory == fixture.Directory);
            },
            ["vendor-storage-containers"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true, storageOnly: true);
                var report = Program.Inspect(fixture.Directory);
                Check("vendor-storage-containers", report.StorageClassInstances == 2 && report.ExcludedEnatelInstances == 2
                    && report.StorageClassExclusionGap == 0 && report.ExitCode == Program.ExcludedObjectsFound);
            },
            ["historic-storage-gap"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true, storageOnly: true);
                fixture.UsePriorFormat(14);
                var report = Program.Inspect(fixture.Directory);
                Check("historic-storage-gap", report.Capture.SchemaVersion == 14 && report.StorageClassInstances == 2
                    && report.ExcludedEnatelInstances == 0 && report.StorageClassExclusionGap == 2
                    && report.ExitCode == Program.ExcludedObjectsFound
                    && report.Text().Contains("RESULT: STORAGE-CLASS EXCLUSION GAP", StringComparison.Ordinal));
            },
            ["historic-inclusion"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.WithEnatelSso, true, storageOnly: true);
                fixture.UsePriorFormat(14);
                var report = Program.Inspect(fixture.Directory);
                Check("historic-inclusion", report.StorageClassInstances == 2 && report.StorageClassExclusionGap == 0
                    && report.ExcludedEnatelInstances == 0 && report.ExitCode == 0);
            },
            ["historic-default-empty"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.UsePriorFormat(14);
                Check("historic-default-empty", Program.Inspect(fixture.Directory).ExitCode == 0);
            },
            ["future-format"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("UPDATE bundle SET schema_version=17");
                Refused("future-format", () => Program.Inspect(fixture.Directory), "SchemaVersionUnsupported");
            },
            ["invalid-scope"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("DELETE FROM capture_object_class_exclusion");
                Refused("invalid-scope", () => Program.Inspect(fixture.Directory), "InvalidScope");
            },
            ["old-scope-new-format"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("UPDATE capture_object_class_exclusion SET class_name='enatelSSOStorageV3' WHERE class_name='enatelSSOStorage'");
                Refused("old-scope-new-format", () => Program.Inspect(fixture.Directory), "InvalidScope");
            },
            ["capture-description-cardinality"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("DELETE FROM bundle");
                Refused("capture-description-cardinality", () => Program.Inspect(fixture.Directory), "exactly one");
            },
            ["account-current-default"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true, accountOnly: true);
                var report = Program.Inspect(fixture.Directory);
                Check("account-current-default", report.Capture.SchemaVersion == 16
                    && report.AccountClassInstances == 2 && report.ExcludedEnatelInstances == 2
                    && report.AccountClassScopeGap == 0 && report.ExitCode == Program.ExcludedObjectsFound);
            },
            ["account-prior-storage-scope"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true, accountOnly: true);
                fixture.UsePriorFormat(15);
                var report = Program.Inspect(fixture.Directory);
                var output = Path.Combine(fixture.Parent, "summary.txt");
                Check("account-prior-storage-scope", report.Capture.SchemaVersion == 15
                    && report.AccountClassInstances == 2 && report.ExcludedEnatelInstances == 0
                    && report.StorageClassExclusionGap == 0 && report.AccountClassScopeGap == 2
                    && report.ExitCode == Program.ExcludedObjectsFound
                    && Program.Main(["--run", fixture.Directory, "--output", output]) == Program.ExcludedObjectsFound
                    && File.ReadAllText(output).Contains("RESULT: ACCOUNT-CLASS SCOPE GAP", StringComparison.Ordinal));
            },
            ["account-prior-v3-scope"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true, accountOnly: true);
                fixture.UsePriorFormat(14);
                var report = Program.Inspect(fixture.Directory);
                Check("account-prior-v3-scope", report.Capture.SchemaVersion == 14
                    && report.AccountClassInstances == 2 && report.ExcludedEnatelInstances == 0
                    && report.StorageClassExclusionGap == 0 && report.AccountClassScopeGap == 2
                    && report.ExitCode == Program.ExcludedObjectsFound);
            },
            ["account-current-inclusion"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.WithEnatelSso, true, accountOnly: true);
                var report = Program.Inspect(fixture.Directory);
                Check("account-current-inclusion", report.Capture.SchemaVersion == 16
                    && report.AccountClassInstances == 2 && report.AccountClassScopeGap == 0
                    && report.ExcludedEnatelInstances == 0 && report.ExitCode == 0);
            },
            ["account-prior-inclusion"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.WithEnatelSso, true, accountOnly: true);
                fixture.UsePriorFormat(15);
                var report = Program.Inspect(fixture.Directory);
                Check("account-prior-inclusion", report.Capture.SchemaVersion == 15
                    && report.AccountClassInstances == 2 && report.AccountClassScopeGap == 0
                    && report.ExcludedEnatelInstances == 0 && report.ExitCode == 0);
            },
            ["account-prior-empty"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.UsePriorFormat(15);
                var report = Program.Inspect(fixture.Directory);
                Check("account-prior-empty", report.AccountClassInstances == 0
                    && report.AccountClassScopeGap == 0 && report.ExitCode == 0);
            },
            ["storage-only-scope-new-format"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, false);
                fixture.Alter("DELETE FROM capture_object_class_exclusion WHERE class_name='enatelSSOAccount'");
                Refused("storage-only-scope-new-format", () => Program.Inspect(fixture.Directory), "InvalidScope");
            },
            ["prior-format-storage-count"] = () =>
            {
                using var fixture = Fixture.Create(CaptureObjectScope.Default, true, storageOnly: true);
                fixture.UsePriorFormat(15);
                var report = Program.Inspect(fixture.Directory);
                Check("prior-format-storage-count", report.Capture.SchemaVersion == 15
                    && report.StorageClassInstances == 2 && report.ExcludedEnatelInstances == 2
                    && report.StorageClassExclusionGap == 0 && report.AccountClassScopeGap == 0
                    && report.ExitCode == Program.ExcludedObjectsFound);
            },
        };
        if (selected is not null && !cases.ContainsKey(selected))
            throw new Program.DiagnosticException("Unknown self-test case: " + selected);
        foreach (var test in cases)
            if (selected is null || selected == test.Key)
            {
                Console.WriteLine("RUN " + test.Key);
                test.Value();
            }
        Console.WriteLine("Capture-scope diagnostic self-test passed.");
    }

    private static void WithReport(CaptureObjectScope scope, bool instances, Action<Program.Report> check)
    {
        using var fixture = Fixture.Create(scope, instances);
        check(Program.Inspect(fixture.Directory));
    }
    private static void Check(string name, bool passed)
    {
        if (!passed) throw new Program.DiagnosticException("Self-test failed: " + name);
        Console.WriteLine("PASS " + name);
    }

    private static void Refused(string name, Action action, string expected)
    {
        try { action(); }
        catch (Program.DiagnosticException error) when (error.Message.Contains(expected, StringComparison.Ordinal))
        {
            Console.WriteLine("PASS " + name);
            return;
        }
        throw new Program.DiagnosticException("Self-test failed: " + name);
    }

    private static string Fingerprint(string directory)
    {
        var values = System.IO.Directory.GetFiles(directory).Order(StringComparer.Ordinal)
            .Select(path => Path.GetFileName(path) + ":" + new FileInfo(path).LastWriteTimeUtc.Ticks
                + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))));
        return string.Join("|", values);
    }

    private sealed class Fixture : IDisposable
    {
        private Fixture(string parent) { Parent = parent; Directory = Path.Combine(parent, "run"); }
        internal string Parent { get; }
        internal string Directory { get; }

        internal static Fixture Create(CaptureObjectScope scope, bool instances, bool missingClasses = false,
            bool storageOnly = false, bool accountOnly = false)
        {
            var result = new Fixture(Path.Combine(Path.GetTempPath(), "securead-enatel-check-" + Guid.NewGuid().ToString("N")));
            System.IO.Directory.CreateDirectory(result.Parent);
            using var writer = BundleWriter.Create(result.Directory, DateTimeOffset.UnixEpoch);
            var domain = Coverage(NamingContextKind.Domain, "DC=example,DC=com");
            var configuration = Coverage(NamingContextKind.Configuration, "CN=Configuration,DC=example,DC=com");
            var schema = Coverage(NamingContextKind.Schema, "CN=Schema,CN=Configuration,DC=example,DC=com");
            writer.WriteCoverage(domain);
            writer.WriteCoverage(configuration);
            writer.WriteCoverage(schema);
            var ordinal = 0;
            void Object(PartitionCoverage coverage, string[] classes, string? definition = null, string? storageCn = null,
                string? relativeDn = null)
            {
                var attributes = new List<EvidenceAttribute>
                {
                    new("objectClass", StoredAttributeCompleteness.Complete, classes.Select(EvidenceValue.OfText).ToArray()),
                    new("cn", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("Enatel-labelled ordinary object")]),
                };
                if (definition is not null)
                    attributes.Add(new("lDAPDisplayName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(definition)]));
                var dn = storageCn is null ? $"CN=object-{++ordinal},{coverage.NamingContextDn}"
                    : $"CN={storageCn},CN=user,{coverage.NamingContextDn}";
                if (relativeDn is not null) dn = relativeDn + "," + coverage.NamingContextDn;
                writer.WriteObject(new(coverage, dn,
                    Guid.NewGuid(), attributes, DateTimeOffset.UnixEpoch));
            }
            if (instances)
            {
                if (accountOnly)
                {
                    Object(domain, ["top", "enatelSSOAccount"], relativeDn: "CN=first,CN=enatelSSOStorageV3,CN=user");
                    Object(domain, ["top", "ENATELSSOACCOUNT"], relativeDn: "CN=second,CN=enatelSSOStorageV2,CN=user");
                }
                else
                {
                    if (!storageOnly)
                    {
                        Object(domain, ["top", "enatelSSOAccountParameter", "ENATELSSOACCOUNTPARAMETER"]);
                        Object(domain, ["top", "user", "ENATELUSERMANAGEDAUTH", "auxiliaryClass"]);
                        Object(configuration, ["top", "enatelSyntheticOtherClass"]);
                        Object(domain, ["top", "enatelSyntheticOtherClass"]);
                    }
                    Object(domain, ["top", "enatelSSOStorage"], storageCn: "enatelSSOStorageV3");
                    if (storageOnly)
                        Object(domain, ["top", "ENATELSSOSTORAGE"], storageCn: "enatelSSOStorageV2");
                }
            }
            Object(schema, ["top", "classSchema"], "enatelSSOStorage");
            Object(schema, ["top", "attributeSchema"], "enatelPasswordConfiguration");
            Object(domain, ["top", "user"]);
            Object(domain, missingClasses ? [] : ["top", "user"]);
            writer.Complete(RunCoverage.Of(
                CoverageId.ForDomains("example.com", ["example.com"]), [DomainCoverage.Read("example.com")],
                [ForestPartitionCoverage.Read(configuration.NamingContextDn, NamingContextKind.Configuration),
                    ForestPartitionCoverage.Read(schema.NamingContextDn, NamingContextKind.Schema)],
                SysvolCoverage.Of([])), DateTimeOffset.UnixEpoch.AddMinutes(1), ContinuationReconciliation.NotPerformed, scope);
            return result;
        }

        internal void UsePriorFormat(int version)
        {
            if (version is not (14 or 15)) throw new Program.DiagnosticException("Unsupported synthetic prior format.");
            Alter($"UPDATE bundle SET schema_version={version}; "
                + "DELETE FROM capture_object_class_exclusion WHERE class_name='enatelSSOAccount'; "
                + (version == 14
                    ? "UPDATE capture_object_class_exclusion SET class_name='enatelSSOStorageV3' WHERE class_name='enatelSSOStorage';"
                    : ""));
        }

        internal void Alter(string sql)
        {
            using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = BundleLayout.EvidencePath(Directory), Mode = SqliteOpenMode.ReadWrite, Pooling = false,
            }.ToString()))
            {
                connection.Open();
                using var command = connection.CreateCommand();
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
            BundleSealing.Seal(BundleLayout.EvidencePath(Directory), BundleLayout.SealPath(Directory));
        }

        private static PartitionCoverage Coverage(NamingContextKind kind, string dn) =>
            new(dn, kind, "dc01.example.com", ConnectionSecurityLevel.SignedAndSealed, 1, 0, 0, [], true);

        public void Dispose() => System.IO.Directory.Delete(Parent, recursive: true);
    }
}
