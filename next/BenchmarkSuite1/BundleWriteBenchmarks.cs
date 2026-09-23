using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Microsoft.Data.Sqlite;
using Microsoft.VSDiagnostics;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Security;

namespace SecureAD.Measurements;
// Input construction is outside measurement. Each invocation calls the real writer against
// a fresh database; finalization is timed separately. Retain all outputs, including failures.
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 1, iterationCount: 3, invocationCount: 1)]
[CPUUsageDiagnoser]
public class BundleWriteBenchmarks
{
    private static readonly DateTimeOffset When = new(2026, 9, 14, 0, 0, 0, TimeSpan.Zero);
    private const int DomainCount = 9;
    private sealed record Row(EvidenceObject Object, byte[] Bytes, AceNormalizationResult Descriptor);
    private Row[] rows = null!;
    private PartitionCoverage[] coverages = null!;
    private RunCoverage coverage = null!;
    private BundleWriter writer = null!;
    private string root = null!;
    private string directory = null!;
    private long[] expected = null!;
    private int written;
    private Stopwatch insertion = null!;
    [GlobalSetup(Target = nameof(WriteFocused))]
    public void PrepareFocused() => Prepare(10_000, 170_000, 1);
    [GlobalSetup(Target = nameof(WriteSharedDescriptors))]
    public void PrepareShared() => Prepare(10_000, 170_000, 10);
    [GlobalSetup(Target = nameof(WriteForestVolume))]
    public void PrepareForest() => Prepare(347_000, 5_900_000, 1);
    private void Prepare(int objects, int logicalAces, int sharing)
    {
        var solution = new DirectoryInfo(AppContext.BaseDirectory);
        while (solution is not null && !File.Exists(Path.Combine(solution.FullName, "SecureAD.Next.sln")))
            solution = solution.Parent;
        if (solution is null)
            throw new InvalidOperationException("Run the benchmark within the solution tree.");
        root = Path.Combine(solution.FullName, "artifacts", "p222-writer", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var assemblies = new[]
        {
            typeof(BundleWriter).Assembly,
            typeof(AceNormalizer).Assembly,
            typeof(SqliteConnection).Assembly,
            GetType().Assembly
        };
        File.WriteAllText(Path.Combine(root, "provenance.json"), JsonSerializer.Serialize(new { Process = Environment.ProcessPath, Runtime = RuntimeInformation.FrameworkDescription, Architecture = RuntimeInformation.ProcessArchitecture.ToString(), OS = RuntimeInformation.OSDescription, Objects = objects, LogicalAces = logicalAces, Domains = DomainCount, Sharing = sharing, Assemblies = assemblies.Select(a => new { a.Location, Version = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion, Sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(a.Location))), Optimized = !(a.GetCustomAttribute<DebuggableAttribute>()?.IsJITOptimizerDisabled ?? false) }).ToArray() }, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Retained writer measurement: " + root);
        var domains = Enumerable.Range(0, DomainCount).Select(d => $"domain{d}.measure.invalid").ToArray();
        coverages = Enumerable.Range(0, DomainCount).Select(d => new PartitionCoverage($"DC=domain{d},DC=measure,DC=invalid", NamingContextKind.Domain, "dc." + domains[d], ConnectionSecurityLevel.SignedAndSealed, 1, objects / DomainCount + (d < objects % DomainCount ? 1 : 0), 1, [], false)).ToArray();
        coverage = RunCoverage.Of(CoverageId.ForDomains("measure.invalid", domains), domains.Select(DomainCoverage.Read).ToArray(), [ForestPartitionCoverage.Read("CN=Configuration,DC=measure,DC=invalid", NamingContextKind.Configuration), ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=measure,DC=invalid", NamingContextKind.Schema)], SysvolCoverage.Of([]));
        var descriptors = objects / (DomainCount * sharing) * DomainCount + Math.Min(objects % (DomainCount * sharing), DomainCount);
        if (sharing > 1 && logicalAces % objects != 0)
            throw new InvalidOperationException("The shared-descriptor fixture requires equal ACL lengths.");
        var physicalAces = sharing == 1 ? logicalAces : descriptors * (logicalAces / objects);
        var groups = (objects + 4L) / 5;
        var populatedUsers = (objects + 1L) / 2 - (objects + 9L) / 10;
        expected = [objects, DomainCount, physicalAces, descriptors, objects, groups * 2, objects * 3L - groups, populatedUsers, populatedUsers];
        rows = new Row[objects];
        for (var i = 0; i < objects; i++)
        {
            var d = i % DomainCount;
            var guid = new Guid(i + 1, 0, 0, new byte[8]);
            EvidenceAttribute[] attributes = i % 5 == 0 ? [Text("objectClass", "top", "group"), Text("sAMAccountName", "group" + i), Text("groupType", "-2147483646"), Text("member", Dn((i + 1) % objects), Dn((i + 2) % objects))] : i % 2 == 0 ? [Text("objectClass", "top", "person", "user"), Text("sAMAccountName", "user" + i), Text("userAccountControl", "512"), Text("servicePrincipalName", "HOST/user" + i), new EvidenceAttribute("sIDHistory", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes($"S-1-5-21-1-2-{d + 3}-{i + 1000}")!)])] : [Text("objectClass", "top", "person", "user"), new EvidenceAttribute("sAMAccountName", StoredAttributeCompleteness.NotReturned, [])];
            var first = sharing == 1 ? i : i / (DomainCount * sharing) * (DomainCount * sharing) + d;
            var count = logicalAces / objects + (i < logicalAces % objects ? 1 : 0);
            var bytes = first == i ? MakeDescriptor(i, d, count) : rows[first].Bytes;
            var normalized = AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes));
            if (normalized.Aces.Count != count || normalized.Errors.Count != 0 || normalized.DaclCompleteness != DaclCompleteness.Complete)
                throw new InvalidOperationException("The synthetic descriptor did not normalize completely.");
            rows[i] = new Row(new EvidenceObject(coverages[d], Dn(i), guid, attributes, When), bytes, normalized);
        }
    }

    private static byte[] MakeDescriptor(int source, int domain, int count)
    {
        var sddl = $"O:S-1-5-21-1-2-{domain + 3}-{source + 1000}G:SYD:" + string.Concat(Enumerable.Range(0, count).Select(a => a % 3 == 0 ? $"(OA;;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;;S-1-5-21-1-2-{domain + 3}-{a + 100})" : $"(A;{(a % 3 == 1 ? "CIID" : "")};RP;;;S-1-5-21-1-2-{domain + 3}-{a + 100})"));
        var descriptor = new RawSecurityDescriptor(sddl);
        var bytes = new byte[descriptor.BinaryLength];
        descriptor.GetBinaryForm(bytes, 0);
        return bytes;
    }

    private static string Dn(int i) => $"CN=Object{i:D6},OU=Accounts,OU=Operations,OU=Directory,OU=Synthetic,DC=domain{i % DomainCount},DC=measure,DC=invalid";
    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    [IterationSetup]
    public void OpenWriter()
    {
        directory = Path.Combine(root, Guid.NewGuid().ToString("N"));
        writer = BundleWriter.Create(directory, When);
        foreach (var partition in coverages)
            writer.WriteCoverage(partition);
        written = 0;
    }

    [Benchmark]
    public int WriteFocused() => WriteRows();
    [Benchmark]
    public int WriteSharedDescriptors() => WriteRows();
    [Benchmark]
    public int WriteForestVolume() => WriteRows();
    private int WriteRows()
    {
        insertion = Stopwatch.StartNew();
        foreach (var row in rows)
        {
            var id = writer.WriteObject(row.Object);
            writer.WriteSecurityDescriptor(id, row.Bytes, row.Descriptor);
            written++;
        }

        insertion.Stop();
        return written;
    }

    [IterationCleanup]
    public void SealAndVerify()
    {
        try
        {
            if (written != rows.Length)
                throw new InvalidOperationException($"Wrote {written}, expected {rows.Length}.");
            var sealWatch = Stopwatch.StartNew();
            var phases = writer.Complete(coverage, When.AddHours(1));
            sealWatch.Stop();
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*), COUNT(DISTINCT domain_fqdn), (SELECT COUNT(*) FROM descriptor_entry), (SELECT COUNT(*) FROM security_descriptor), (SELECT COUNT(*) FROM object_security_descriptor), (SELECT COUNT(*) FROM member_value), (SELECT COUNT(*) FROM objectclass_value), (SELECT COUNT(*) FROM serviceprincipalname_value), (SELECT COUNT(*) FROM sidhistory_value) FROM captured_object";
            using var read = command.ExecuteReader();
            if (!read.Read())
                throw new InvalidOperationException("No stored counts returned.");
            var actual = Enumerable.Range(0, expected.Length).Select(read.GetInt64).ToArray();
            RequireCounts(actual, expected);
            for (var i = 0; i < expected.Length; i++)
            {
                var wrong = (long[])expected.Clone();
                wrong[i]++;
                var refused = false;
                try
                {
                    RequireCounts(actual, wrong);
                }
                catch (InvalidOperationException)
                {
                    refused = true;
                }

                if (!refused)
                    throw new InvalidOperationException("Stored-count negative control passed.");
            }

            if (BundleSealing.Verify(directory).State != SealState.Intact)
                throw new InvalidOperationException("Evidence seal is not intact.");
            File.WriteAllText(Path.Combine(directory, "measurement.json"), JsonSerializer.Serialize(new { InsertionMs = insertion.Elapsed.TotalMilliseconds, FinalizationMs = sealWatch.Elapsed.TotalMilliseconds, Phases = phases, ActualCounts = actual, ExpectedCounts = expected, EvidenceBytes = new FileInfo(BundleLayout.EvidencePath(directory)).Length }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"Writer: {insertion.Elapsed.TotalMilliseconds:F3} ms; finalization: {sealWatch.Elapsed.TotalMilliseconds:F3} ms; verified counts: {string.Join(",", actual)}; retained: {directory}");
        }
        finally
        {
            writer.Dispose();
        }
    }

    private static void RequireCounts(long[] actual, long[] expected)
    {
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException($"Stored counts {string.Join(",", actual)} differ from expected {string.Join(",", expected)}.");
    }
}
