using System;
using System.IO;
using System.Linq;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Kernel.Capture;
using Microsoft.VSDiagnostics;

namespace SecureAD.Measurements;
[ShortRunJob]
[CPUUsageDiagnoser]
public class ObjectReadBenchmarks
{
    private string directory = null!;
    private BundleReader reader = null!;
    private string[] names = null!;
    [Params(false, true)]
    public bool Populated { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        directory = Path.Combine(Path.GetTempPath(), "SecureAD-object-read-benchmark-" + Guid.NewGuid().ToString("N"));
        var when = new DateTimeOffset(2026, 9, 7, 0, 0, 0, TimeSpan.Zero);
        const string domain = "DC=synthetic,DC=invalid";
        var coverage = new PartitionCoverage(domain, NamingContextKind.Domain, "dc.synthetic.invalid", ConnectionSecurityLevel.SignedAndSealed, 1, 1000, 1, [], false);
        names = Enumerable.Range(0, 1000).Select(i => $"CN=User{i},OU=Accounts,OU=Security,OU=Directory,{domain}").ToArray();
        using (var writer = BundleWriter.Create(directory, when))
        {
            writer.WriteCoverage(coverage);
            foreach (var name in names)
            {
                EvidenceAttribute[] attributes = Populated ? [Text("objectClass", "top", "person", "user"), Text("sAMAccountName", "synthetic-user"), Text("userAccountControl", "512"), Text("memberOf", "CN=GroupA," + domain, "CN=GroupB," + domain), Text("servicePrincipalName", "HTTP/synthetic.invalid", "HOST/synthetic.invalid"), Text("msDS-AllowedToDelegateTo", "HTTP/other.synthetic.invalid"), Text("msDS-KeyCredentialLink", "B:8:01020304:CN=Key," + domain), new("sIDHistory", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes([1, 2, 3, 4]), EvidenceValue.OfBytes([5, 6, 7, 8])])] : [];
                writer.WriteObject(new EvidenceObject(coverage, name, Guid.NewGuid(), attributes, when));
            }

            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("synthetic.invalid", ["synthetic.invalid"]), [DomainCoverage.Read("synthetic.invalid")], [ForestPartitionCoverage.Read("CN=Configuration," + domain, NamingContextKind.Configuration), ForestPartitionCoverage.Read("CN=Schema,CN=Configuration," + domain, NamingContextKind.Schema)], SysvolCoverage.Of([])), when.AddMinutes(1));
        }

        var opened = BundleReader.Open(directory);
        if (!opened.IsSuccess)
            throw new InvalidOperationException(opened.Error!.Description);
        reader = opened.Value;
        if (reader.ReadObjectAttributes(names[0])is null)
            throw new InvalidOperationException("Synthetic object was not read.");
    }

    [Benchmark(OperationsPerInvoke = 100)]
    public int ReadObjectAttributes()
    {
        var values = 0;
        for (var i = 0; i < 100; i++)
        {
            var result = reader.ReadObjectAttributes(names[i * 7]) ?? throw new InvalidOperationException("Missing synthetic object.");
            values += result.Attributes.Count;
        }

        return values;
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        reader?.Dispose();
        if (Directory.Exists(directory))
            Directory.Delete(directory, true);
    }

    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
}