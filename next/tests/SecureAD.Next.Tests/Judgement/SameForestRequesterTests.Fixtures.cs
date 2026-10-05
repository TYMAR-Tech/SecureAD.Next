using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class SameForestRequesterTests
{
    private const string A = "contoso.com";
    private const string B = "branch.example";
    private const string RootA = "DC=contoso,DC=com";
    private const string RootB = "DC=branch,DC=example";
    private const string SidA = "S-1-5-21-1-2-3";
    private const string SidB = "S-1-5-21-4-5-6";
    private const string Actor = "CN=Alice," + RootA;
    private const string Other = "CN=Other," + RootA;
    private const string Global = "CN=Access," + RootA;
    private const string Universal = "CN=Universal," + RootB;
    private const string Local = "CN=Access," + RootB;
    private const string Denying = "CN=Deny," + RootB;
    private const string Target = "CN=Domain Admins," + RootB;
    private const string BuiltinA = "CN=Administrators,CN=Builtin," + RootA;
    private const string BuiltinB = "CN=Administrators,CN=Builtin," + RootB;

    private static string Capture(string variant, string? descriptor = null)
    {
        var directory = TempDirectories.Create("same-forest-requesters");
        using var writer = BundleWriter.Create(directory, Started);
        var a = new PartitionCoverage(RootA, NamingContextKind.Domain, "dc01." + A,
            ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
        var b = new PartitionCoverage(RootB, NamingContextKind.Domain, "dc01." + B,
            ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
        var config = new PartitionCoverage("CN=Configuration," + RootA, NamingContextKind.Configuration, "dc01." + A,
            ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
        writer.WriteCoverage(a);
        writer.WriteCoverage(b);
        writer.WriteCoverage(config);
        Write(a, RootA, ["top", "domainDNS"], SidA, [],
            variant == "outside-domain" ? $"O:SYG:SYD:(A;;WD;;;{SidB}-1400)" : "O:SYG:SYD:");
        Write(b, RootB, ["top", "domainDNS"], SidB, [], "O:SYG:SYD:");
        Write(a, Actor, variant == "computer" ? ["top", "user", "computer"] : ["top", "user"],
            variant == "sid-domain-mismatch" ? SidB + "-1100" : SidA + "-1100",
            [Text("userAccountControl", "512"), Text("primaryGroupID", variant == "primary" ? "1200" : "513"),
                .. variant == "history" ? new[] { Bytes("sIDHistory", Sid.ToBytes(SidB + "-1400")!) } : []], "O:SYG:SYD:");
        Write(a, Other, ["top", "user"], SidA + "-1101",
            [Text("userAccountControl", "512"), Text("primaryGroupID", "513")], "O:SYG:SYD:");
        Write(a, Global, ["top", "group"], SidA + "-1200",
            [Text("groupType", "-2147483646"), Values("member", variant == "primary" ? [] : [Actor])], "O:SYG:SYD:");
        Write(b, Universal, ["top", "group"], SidB + "-1300",
            [Text("groupType", variant == "illegal-global" ? "-2147483646" : "-2147483640"),
                Values("member", variant == "illegal-universal" ? [Local] : [Global])], "O:SYG:SYD:");
        var localType = variant == "distribution" ? "4" : variant == "missing-type" ? null : "-2147483644";
        Write(b, Local, ["top", "group"], SidB + "-1400",
            [.. localType is null ? [] : new[] { Text("groupType", localType) },
                Values("member", variant == "illegal-universal" ? [Global] : variant == "cycle" ? [Local, Universal] : [Universal]),
                .. variant == "group-history" ? new[] { Bytes("sIDHistory", Sid.ToBytes("S-1-5-21-7-8-9-1400")!) } : []], "O:SYG:SYD:");
        Write(b, Denying, ["top", "group"], SidB + "-1500",
            [Text("groupType", "-2147483644"), Text("member", Universal)], "O:SYG:SYD:");
        Write(a, BuiltinA, ["top", "group"], "S-1-5-32-544",
            [Text("groupType", "-2147483643"), Text("member", Other)], "O:SYG:SYD:");
        Write(b, BuiltinB, ["top", "group"], "S-1-5-32-544",
            [Text("groupType", "-2147483643"), Values("member", variant == "builtin" ? [Global] : [])], "O:SYG:SYD:");
        foreach (var (partition, root, sid) in new[] { (a, RootA, SidA), (b, RootB, SidB) })
            Write(partition, "CN=Domain Users," + root, ["top", "group"], sid + "-513",
                [Text("groupType", "-2147483646")], "O:SYG:SYD:");
        if (variant == "expected")
            Write(a, "CN=Enterprise Admins," + RootA, ["top", "group"], SidA + "-519",
                [Text("groupType", "-2147483640"), Text("member", Actor)], "O:SYG:SYD:");
        Write(b, Target, ["top", "group"], SidB + "-512", [Text("groupType", "-2147483646")],
            descriptor ?? $"O:SYG:SYD:(A;;WD;;;{(variant == "builtin" ? "S-1-5-32-544" : variant == "global" ? SidA + "-1200" : variant == "universal" || variant == "illegal-universal" ? SidB + "-1300" : SidB + "-1400")})");
        Write(config, config.NamingContextDn, ["top", "configuration"], null, [], $"O:SYG:SYD:(A;;WD;;;{SidB}-1400)");
        Write(config, "CN=Directory Service,CN=Windows NT,CN=Services," + config.NamingContextDn, ["top", "nTDSService"], null,
            [Text("dSHeuristics", "0")], "O:SYG:SYD:");
        var declared = variant == "undeclared" ? new[] { A } : new[] { A, B };
        writer.Complete(RunCoverage.Of(CoverageId.ForDomains(A, declared),
            declared.Select(domain => variant == "excluded" && domain == B ? DomainCoverage.Excluded(B, ExclusionKind.ByChoice, "Synthetic exclusion")
                : DomainCoverage.Read(domain)).ToArray(),
            [ForestPartitionCoverage.Read(config.NamingContextDn, NamingContextKind.Configuration),
                ForestPartitionCoverage.Read("CN=Schema," + config.NamingContextDn, NamingContextKind.Schema)], SysvolCoverage.Of([])),
            Started.AddMinutes(1));
        return directory;

        void Write(PartitionCoverage partition, string dn, string[] classes, string? sid, EvidenceAttribute[] attributes, string descriptor)
        {
            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(partition, dn, guid,
                [Values("objectClass", classes), .. sid is null ? [] : new[] { Bytes("objectSid", Sid.ToBytes(sid)!) }, .. attributes], Started));
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        }
    }

    private static EvidenceAttribute Text(string name, string value) => Values(name, [value]);
    private static EvidenceAttribute Values(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Bytes(string name, byte[] value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);

    private static string Prepared(string variant, string? descriptor = null, bool automatic = true, string? target = null)
    {
        var directory = Capture(variant, descriptor);
        Derive(directory);
        var result = automatic ? JudgingRun.JudgeAudit(directory, [new UnexpectedTier0Route()], PathRequesterPolicy.SupportedCapturedQuestions,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null)
            : JudgingRun.JudgeWithTier0Discovery(directory, [], [new(Actor, target ?? Target)], Started, Started,
                JudgingRun.NobodyIsWatching, RunLog.Discarded, null, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return directory;
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }

    private static RequesterDaclAssessment Assessment(JudgementReader reader) =>
        Assert.Single(reader.ReadTier0Path(Actor).RequesterAssessments);
}
