using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Threading;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Microsoft.VSDiagnostics;

namespace SecureAD.Measurements;
[SimpleJob(RunStrategy.Monitoring, launchCount: 1, warmupCount: 1, iterationCount: 3, invocationCount: 1)]
[CPUUsageDiagnoser]
public class ScanOffJudgingBenchmarks
{
    private const int Domains = 9;
    private const int GroupsPerDomain = 2;
    private const int MembersPerGroup = 5;
    private const string SelfMembership = "bf9679c0-0de6-11d0-a285-00aa003049e2";
    private static readonly DateTimeOffset When = new(2026, 9, 7, 0, 0, 0, TimeSpan.Zero);
    private string directory = null!;
    [Params(1000, 3000)]
    public int Objects { get; set; }

    [Params(17000, 51000)]
    public int Aces { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        directory = Path.Combine(Path.GetTempPath(), "SecureAD-scan-off-benchmark-" + Guid.NewGuid().ToString("N"));
        var domains = Enumerable.Range(0, Domains).Select(d => d == 0 ? "measure.lab" : $"domain{d}.measure.lab").ToArray();
        var written = 0;
        var ordinaryAces = Aces - Domains * GroupsPerDomain;
        var fillers = Objects - Domains * (1 + GroupsPerDomain * (MembersPerGroup + 2));
        using (var writer = BundleWriter.Create(directory, When))
        {
            for (var d = 0; d < Domains; d++)
            {
                var domainDn = d == 0 ? "DC=measure,DC=lab" : $"DC=domain{d},DC=measure,DC=lab";
                var domainSid = $"S-1-5-21-9-{9 + d}-9";
                var parent = $"OU=Accounts,OU=Operations,OU=Directory,OU=Synthetic,{domainDn}";
                var domainFillers = fillers / Domains + (d < fillers % Domains ? 1 : 0);
                var coverage = new PartitionCoverage(domainDn, NamingContextKind.Domain, "dc01." + domains[d], ConnectionSecurityLevel.SignedAndSealed, 3, 1 + GroupsPerDomain * (MembersPerGroup + 2) + domainFillers, 1, [], false);
                writer.WriteCoverage(coverage);
                void Write(string dn, string objectClass, string sid, EvidenceAttribute[] extra, string? holder = null)
                {
                    var evidence = new EvidenceObject(coverage, dn, Guid.NewGuid(), [Text("objectClass", "top", objectClass), new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]), ..extra], When);
                    var id = writer.WriteObject(evidence);
                    var count = ordinaryAces / Objects + (written < ordinaryAces % Objects ? 1 : 0);
                    var sddl = "O:SYG:SYD:" + (holder is null ? "" : $"(OA;;SW;{SelfMembership};;{holder})") + string.Concat(Enumerable.Range(0, count).Select(i => $"(A;;RP;;;{domainSid}-{10_000_000L + (long)written * 1000 + i})"));
                    var descriptor = new RawSecurityDescriptor(sddl);
                    var bytes = new byte[descriptor.BinaryLength];
                    descriptor.GetBinaryForm(bytes, 0);
                    writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(evidence.ObjectGuid!.Value, SecurityDescriptorParser.Parse(bytes)));
                    written++;
                }

                Write(domainDn, "domainDNS", domainSid, []);
                for (var group = 0; group < GroupsPerDomain; group++)
                {
                    var holderDn = $"CN=Holder{group},{parent}";
                    var holderSid = $"{domainSid}-{1000L + written + MembersPerGroup}";
                    var members = new List<string>();
                    for (var m = 0; m < MembersPerGroup; m++)
                    {
                        var dn = $"CN=User{group}-{m},{parent}";
                        members.Add(dn);
                        Write(dn, "user", $"{domainSid}-{1000L + written}", [Text("userAccountControl", "512")]);
                    }

                    Write(holderDn, "group", holderSid, [Text("groupType", "-2147483646"), Text("member", members.ToArray())]);
                    Write($"CN=Target{group},{parent}", "group", $"{domainSid}-{1000L + written}", [Text("groupType", "-2147483646"), Text("member")], holderSid);
                }

                for (var f = 0; f < domainFillers; f++)
                    Write($"CN=Filler{f},{parent}", "user", $"{domainSid}-{1000L + written}", [Text("userAccountControl", "512")]);
            }

            writer.Complete(RunCoverage.Of(CoverageId.ForDomains("measure.lab", domains), domains.Select(DomainCoverage.Read).ToArray(), [ForestPartitionCoverage.Read("CN=Configuration,DC=measure,DC=lab", NamingContextKind.Configuration), ForestPartitionCoverage.Read("CN=Schema,CN=Configuration,DC=measure,DC=lab", NamingContextKind.Schema)], SysvolCoverage.Of([])), When.AddMinutes(1));
        }

        using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = BundleLayout.EvidencePath(directory), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*), COUNT(DISTINCT domain_fqdn), (SELECT COUNT(*) FROM ace) FROM captured_object";
        using var read = command.ExecuteReader();
        if (!read.Read())
            throw new InvalidOperationException("No stored-count result.");
        var actual = (Objects: read.GetInt64(0), Domains: read.GetInt64(1), Aces: read.GetInt64(2));
        RequireCounts(actual, Objects, Domains, Aces);
        foreach (var wrong in new[]
        {
            (Objects + 1, Domains, Aces),
            (Objects, Domains + 1, Aces),
            (Objects, Domains, Aces + 1)
        }

        )
        {
            var rejected = false;
            try
            {
                RequireCounts(actual, wrong.Item1, wrong.Item2, wrong.Item3);
            }
            catch (InvalidOperationException)
            {
                rejected = true;
            }

            if (!rejected)
                throw new InvalidOperationException("Stored-count negative control did not fail.");
        }

        Console.WriteLine($"Verified synthetic input: {actual.Objects} objects, {actual.Domains} domains, {actual.Aces} physical ACEs; count negative controls passed.");
    }

    [Benchmark]
    public JudgementRunState JudgeWithoutDiscovery()
    {
        var opened = RunLogFile.Open(directory, "scan-off-benchmark", TimeProvider.System);
        if (!opened.IsSuccess)
            throw new InvalidOperationException(opened.Error!.Description);
        using var log = opened.Value;
        var result = JudgingRun.Judge(directory, [], (SelfMembershipDiscoveryBudget? )null, When, When, JudgingRun.NobodyIsWatching, log, CancellationToken.None);
        if (!result.IsSuccess)
            throw new InvalidOperationException(result.Error!.Description);
        if (result.Value != JudgementRunState.Completed)
            throw new InvalidOperationException("Judging did not complete.");
        return result.Value;
    }

    [IterationCleanup]
    public void VerifyJudgement()
    {
        var opened = JudgementReader.Open(directory);
        if (!opened.IsSuccess)
            throw new InvalidOperationException(opened.Error!.Description);
        using var reader = opened.Value;
        var summary = reader.ReadSelfMembershipSummary() ?? throw new InvalidOperationException("Missing requester summary.");
        if (summary.AssessmentsStored != 0 || summary.Discovery.PairsDiscovered != 0)
            throw new InvalidOperationException("Discovery was not off.");
        var last = File.ReadLines(BundleLayout.RunLogPath(directory)).Last(l => l.Contains("finished state=", StringComparison.Ordinal));
        if (!last.Contains($"finished state=Completed objects={Objects}", StringComparison.Ordinal))
            throw new InvalidOperationException("Judging did not visit the expected number of objects.");
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(directory))
            Directory.Delete(directory, true);
    }

    private static EvidenceAttribute Text(string name, params string[] values) => new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static void RequireCounts((long Objects, long Domains, long Aces) actual, int objects, int domains, int aces)
    {
        if (actual.Objects != objects || actual.Domains != domains || actual.Aces != aces)
            throw new InvalidOperationException("Stored shape differs from requested shape.");
    }
}