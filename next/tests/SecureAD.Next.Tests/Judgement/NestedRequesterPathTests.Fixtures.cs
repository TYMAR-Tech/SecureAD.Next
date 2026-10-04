using System.Security.AccessControl;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Capture;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class NestedRequesterPathTests
{
    private const string Root = "DC=contoso,DC=com";
    private const string EntryDn = "CN=Entry,DC=contoso,DC=com";
    private const string EntrySid = "S-1-5-21-1-2-3-1300";
    private const string DenyDn = "CN=Deny,DC=contoso,DC=com";
    private const string DenySid = "S-1-5-21-1-2-3-1400";
    private const string OtherDn = "CN=Other,DC=contoso,DC=com";
    private const string OtherSid = "S-1-5-21-1-2-3-1500";
    private const string DeeperDn = "CN=Deeper,DC=contoso,DC=com";
    private const string DeeperSid = "S-1-5-21-1-2-3-1600";
    private const string ShortcutDn = "CN=Shortcut,DC=contoso,DC=com";
    private const string ShortcutSid = "S-1-5-21-1-2-3-1700";
    private const string ChildRoot = "DC=child,DC=contoso,DC=com";
    private const string ChildEntry = "CN=Entry,DC=child,DC=contoso,DC=com";

    private static string Capture(string variant, string? descriptor = null, int users = 1)
    {
        var entry = variant == "cross-domain" ? ChildEntry : EntryDn;
        var entrySid = variant == "cross-domain" ? "S-1-5-21-4-5-6-1300" : EntrySid;
        var holderMembers = variant == "shortcut" ? new[] { ShortcutDn, entry }
            : variant == "ordinals" ? new[] { OtherDn, entry } : new[] { entry };
        var groupDescriptor = variant == "operations"
            ? $"O:SYG:SYD:(OA;;SW;bf9679c0-0de6-11d0-a285-00aa003049e2;;{DenySid})(OA;;WP;bf9679c0-0de6-11d0-a285-00aa003049e2;;{DenySid})"
            : "O:SYG:SYD:";
        return Bundle(users: 0, members: holderMembers, sddl: groupDescriptor, writeAdditional: (writer, domain) =>
        {
            for (var index = 0; index < users; index++)
                Write(writer, domain, UserName(index), variant == "computer" ? ["top", "user", "computer"] : ["top", "user"],
                    $"S-1-5-21-1-2-3-{1100 + index}",
                    [Text("userAccountControl", "512"), Text("primaryGroupID", variant == "primary" ? "1300" : "513"),
                        .. variant == "history" ? new[] { Bytes("sIDHistory", Sid.ToBytes(TargetSid)!) } : [],
                        .. variant == "member-of-only" ? new[] { Text("memberOf", entry) } : []], "O:SYG:SYD:");
            Write(writer, domain, OtherDn, ["top", "user"], OtherSid,
                [Text("userAccountControl", "512"), Text("primaryGroupID", "513")], "O:SYG:SYD:");
            var entryDomain = domain;
            if (variant == "cross-domain")
            {
                entryDomain = new(ChildRoot, NamingContextKind.Domain, "dc01.child.contoso.com",
                    ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
                writer.WriteCoverage(entryDomain);
                Write(writer, entryDomain, ChildRoot, ["top", "domainDNS"], "S-1-5-21-4-5-6", [], "O:SYG:SYD:");
            }
            var groupType = variant switch
            {
                "distribution" => "2",
                "universal" => "-2147483640",
                "domain-local" => "-2147483644",
                "missing-type" => null,
                _ => "-2147483646",
            };
            string[] members = variant switch
            {
                "primary" or "member-of-only" => [],
                "missing-member" => ["CN=Missing," + Root],
                "partial" => ["CN=Missing," + Root, UserDn],
                "cycle" => [TargetDn, EntryDn, UserDn],
                "shortcut" => [DeeperDn],
                "ordinals" => [OtherDn, UserDn],
                _ => Enumerable.Range(0, users).Select(UserName).ToArray(),
            };
            Write(writer, entryDomain, entry, ["top", "group"], entrySid,
                [Values("member", members), .. groupType is null ? [] : new[] { Text("groupType", groupType) },
                    .. variant == "group-history" ? new[] { Bytes("sIDHistory", Sid.ToBytes("S-1-5-21-9-8-7-1300")!) } : []],
                "O:SYG:SYD:");
            if (variant == "duplicate")
                Write(writer, domain, "CN=Duplicate," + Root, ["top", "group"], EntrySid,
                    [Text("groupType", "-2147483646"), Text("member", UserDn)], "O:SYG:SYD:");
            if (variant == "shortcut")
            {
                Write(writer, domain, DeeperDn, ["top", "group"], DeeperSid,
                    [Text("groupType", "-2147483646"), Text("member", UserDn)], "O:SYG:SYD:");
                Write(writer, domain, ShortcutDn, ["top", "group"], ShortcutSid,
                    [Text("groupType", "-2147483640"), Text("member", UserDn)], "O:SYG:SYD:");
            }
            Write(writer, domain, DenyDn, ["top", "group"], DenySid,
                [Text("groupType", "-2147483646"), Text("member", entry)], "O:SYG:SYD:");
            Write(writer, domain, "CN=Domain Users," + Root, ["top", "group"], "S-1-5-21-1-2-3-513",
                [Text("groupType", "-2147483646")], "O:SYG:SYD:");
            Write(writer, domain, CoreDn, ["top", "group"], "S-1-5-21-1-2-3-512",
                [Text("groupType", "-2147483646"), Values("member", variant == "administrator" ? [UserDn]
                    : variant == "operations" ? [TargetDn] : variant == "self" ? [EntryDn] : [])],
                descriptor ?? $"O:SYG:SYD:(A;;WD;;;{TargetSid})");
            var configuration = new PartitionCoverage("CN=Configuration," + Root, NamingContextKind.Configuration, "dc01.contoso.com",
                ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(configuration);
            Write(writer, configuration, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + Root,
                ["top", "nTDSService"], null, [Text("dSHeuristics", "0")], "O:SYG:SYD:");
        });
    }

    private static EvidenceAttribute Text(string name, string value) => Values(name, [value]);
    private static EvidenceAttribute Values(string name, string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());
    private static EvidenceAttribute Bytes(string name, byte[] value) =>
        new(name, StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(value)]);

    private static void Write(BundleWriter writer, PartitionCoverage coverage, string dn, string[] classes, string? sid,
        EvidenceAttribute[] attributes, string? descriptor)
    {
        var guid = Guid.NewGuid();
        var id = writer.WriteObject(new(coverage, dn, guid,
            [Values("objectClass", classes), .. sid is null ? [] : new[] { Bytes("objectSid", Sid.ToBytes(sid)!) }, .. attributes], Started));
        if (descriptor is null) return;
        var raw = new RawSecurityDescriptor(descriptor);
        var bytes = new byte[raw.BinaryLength];
        raw.GetBinaryForm(bytes, 0);
        writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
    }

    private static string Prepare(string variant, string? descriptor = null, bool automatic = true, int users = 1)
    {
        var directory = Capture(variant, descriptor, users);
        Derive(directory);
        Judge(directory, automatic);
        return directory;
    }

    private static void Judge(string directory, bool automatic)
    {
        var result = JudgingRun.JudgeAudit(directory, [new UnexpectedTier0Route()],
            automatic ? PathRequesterPolicy.SupportedCapturedQuestions : PathRequesterPolicy.Disabled,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, null);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }

    private static SqliteConnection Connection(JudgementReader reader)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = BundleLayout.AnalysisGenerationDataPath(reader.BundleDirectory, AnalysisStoreKind.Judgement, reader.Description.GenerationId),
            Mode = SqliteOpenMode.ReadOnly, Pooling = false,
        }.ToString());
        connection.Open();
        return connection;
    }

    private static RequesterDaclAssessment Assess(string variant, string? descriptor = null)
    {
        using var reader = Open(Prepare(variant == "deleted" ? "nested" : variant, descriptor, automatic: false));
        using var connection = Connection(reader);
        using var sources = ControlProofVerification.OpenSources(reader);
        var inputs = reader.ReadPathInputs();
        var identities = OwnershipAuditStorage.Targets(connection).ToDictionary(row => row.Identity.DistinguishedName,
            row => row.Identity, StringComparer.OrdinalIgnoreCase);
        ObjectAttributes? Read(string dn)
        {
            var source = sources.Bundle.ReadObjectAttributes(dn);
            return variant == "deleted" && dn == EntryDn && source is not null
                ? source with { Attributes = [.. source.Attributes, new("isDeleted", AttributeCardinality.SingleValued, [new(0, "TRUE", null)])] }
                : source;
        }
        var memberships = new RequesterMembershipContext(sources.OpenDerivation().Value, inputs.Input!, Read, identities,
            sources.ReadNamingContexts().Value, CancellationToken.None);
        return Assert.Single(RequesterDaclProofs.Create(connection, reader.Description, sources, identities, inputs,
            [new(UserDn, CoreDn)], CancellationToken.None, null, memberships)).Assessment;
    }

    private static string[] Snapshot(string directory) => Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories)
        .Where(path => !path.EndsWith(".db-shm", StringComparison.Ordinal)
            && (!path.EndsWith(".db-wal", StringComparison.Ordinal) || new FileInfo(path).Length != 0))
        .Order(StringComparer.Ordinal).Select(path => path + ":" + Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))).ToArray();
}
