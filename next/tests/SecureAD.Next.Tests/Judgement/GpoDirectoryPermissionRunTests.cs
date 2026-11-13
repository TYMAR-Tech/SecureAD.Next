using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Schema;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GpoDirectoryPermissionTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GpoDirectoryPermissionRunTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(12)]
    public void GpoAndLinkJudgingUsesOneFileVerificationAndBindingWithoutPerTargetReselection(int pairs)
    {
        var directory = Prepared($"O:SYG:SYD:(A;;WP;;;{HolderSid})", pairs);
        var generation = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value.GenerationId;
        using var counts = new GmsaPasswordReaderReadTests.InputCounts(directory);
        var snapshots = new List<(long Capture, long Derivation, long Bindings)>();
        var observer = new Observer(() => snapshots.Add((counts.Manifest("capture"), counts.Manifest("derivation"), counts.Bindings)));
        var result = JudgingRun.Judge(directory, [new UnexpectedGpoDirectoryControl(), new UnexpectedGroupPolicyLinkWrite(), observer],
            When, When, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(1, counts.File(Path.Combine(directory, "evidence.db")));
        Assert.Equal(1, counts.File(BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Derivation, generation)));
        Assert.Equal(1, counts.Bindings);
        Assert.Equal(pairs * 2, snapshots.Count);
        Assert.True(snapshots[0].Capture > 0);
        Assert.True(snapshots[0].Derivation > 0);
        Assert.All(snapshots, snapshot => Assert.Equal(snapshots[0], snapshot));
        using var saved = Open(directory);
        Assert.Equal(pairs * 2, saved.Read().Findings.Count);
    }

    [Fact]
    public void NormalJudgingPublishesBothRulesWithOriginalDirectoryBindings()
    {
        var directory = Published();
        using var reader = Open(directory);
        var saved = reader.Read();
        var findings = saved.Findings;
        Assert.True(findings.Count == 2, JsonSerializer.Serialize(saved.RulesRun, ProofSerialization.Options));
        Assert.Equal(new[] { "SEC-080", "SEC-081" }, findings.Select(finding => finding.RuleId).Order());
        foreach (var finding in findings)
        {
            var proof = GpoDirectoryPermissionTests.Evidence(finding);
            Assert.Equal(reader.Description.GenerationId, proof.GenerationId);
            Assert.Equal(reader.Description.EvidenceSeal, proof.EvidenceSeal);
            Assert.Equal(reader.Description.DerivationGenerationId, proof.DerivationGenerationId);
            Assert.Equal(finding.ObjectGuid, proof.Target.ObjectGuid);
            Assert.Equal(finding.DistinguishedName, proof.Permissions.DistinguishedName);
            Assert.Equal(0x20, Assert.Single(proof.Permissions.Entries).AccessMask);
            Assert.Equal(HolderSid, proof.Holder.Sid);
            Assert.True(proof.IsComplete);
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(51)]
    public void SelectedPagesKeepOriginalOccurrencesAndDoNotReconstructWholeProof(int count)
    {
        var directory = Published(count);
        using var reader = Open(directory);
        var rows = reader.ReadListPage(FindingsQuery.Everything()).Value.Findings;
        Assert.Equal(2, rows.Count);
        foreach (var row in rows)
        {
            Result<SavedGpoDirectoryPermission>? firstResult = null;
            var error = Record.Exception(() => firstResult = reader.ReadGpoDirectoryPermission(row.Reference!.Value, null));
            Assert.Null(error);
            var first = Assert.IsType<Result<SavedGpoDirectoryPermission>>(firstResult);
            Assert.True(first.IsSuccess, first.Error?.Description);
            Assert.True(first.Value.Context.Matches(row));
            Assert.Equal(count, first.Value.Context.EntryCount);
            Assert.Equal(Math.Min(50, count), first.Value.Entries.Count);
            Assert.Equal(Enumerable.Range(0, Math.Min(50, count)), first.Value.Entries.Select(entry => entry.Ordinal));
            if (count > 50)
            {
                var second = reader.ReadGpoDirectoryPermission(row.Reference.Value, first.Value.Next);
                Assert.True(second.IsSuccess, second.Error?.Description);
                Assert.Equal(50, Assert.Single(second.Value.Entries).Ordinal);
                Assert.Null(second.Value.Next);
                Assert.True(first.Value.Context.SameQuestion(second.Value.Context));
            }
        }
    }

    internal static string Published(int entryCount = 1)
    {
        var descriptor = "O:SYG:SYD:" + string.Concat(Enumerable.Repeat($"(A;;WP;;;{HolderSid})", entryCount));
        var directory = Prepared(descriptor);
        var before = SelfMembershipDiscoveryTests.Hash(directory);
        Result<JudgementRunState>? result = null;
        var error = Record.Exception(() => result = JudgingRun.Judge(directory,
            [new UnexpectedGpoDirectoryControl(), new UnexpectedGroupPolicyLinkWrite()],
            When, When, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None));
        Assert.Null(error);
        var completed = Assert.IsType<Result<JudgementRunState>>(result);
        Assert.True(completed.IsSuccess, completed.Error?.Description);
        Assert.Equal(before, SelfMembershipDiscoveryTests.Hash(directory));
        return directory;
    }

    internal static string Prepared(string descriptor, int pairs = 1)
    {
        var directory = SelfMembershipDiscoveryTests.Bundle(users: 0, writeAdditional: (writer, domain) =>
        {
            var config = new PartitionCoverage("CN=Configuration," + Root, NamingContextKind.Configuration, "dc01.contoso.com",
                ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            var schema = new PartitionCoverage("CN=Schema,CN=Configuration," + Root, NamingContextKind.Schema, "dc01.contoso.com",
                ConnectionSecurityLevel.SignedAndSealed, 1, 100, 1, [], false);
            writer.WriteCoverage(config);
            writer.WriteCoverage(schema);
            for (var index = 0; index < pairs; index++)
            {
                Write(domain, index == 0 ? GpoDn : "CN=Policy" + index + ",CN=Policies,CN=System," + Root, "groupPolicyContainer", null,
                    [new("displayName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("Captured GPO")])], descriptor);
                Write(domain, index == 0 ? OuDn : "OU=Scope" + index + "," + Root, "organizationalUnit", null, [], descriptor);
            }
            Write(config, "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + Root, "nTDSService", null,
                [new("dSHeuristics", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("0000000001000000")])], null);
            foreach (var (name, rid) in new[] { ("Domain Admins", 512), ("Enterprise Admins", 519), ("Schema Admins", 518) })
                Write(domain, "CN=" + name + "," + Root, "group", DomainSid + "-" + rid,
                    [new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                     new("member", StoredAttributeCompleteness.Complete, [])], "O:SYG:SYD:");
            Write(domain, "CN=Administrators,CN=Builtin," + Root, "group", "S-1-5-32-544",
                [new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483643")]),
                 new("member", StoredAttributeCompleteness.Complete, [])], "O:SYG:SYD:");
            foreach (var definition in Catalogue().Entries.Where(entry => entry.Source == SchemaGuidSource.Captured))
            {
                var objectClass = definition.Kind == SchemaGuidKind.Attribute ? "attributeSchema" : "classSchema";
                var schemaAttributes = new List<EvidenceAttribute>
                {
                    new("lDAPDisplayName", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(definition.LdapName)]),
                    new("schemaIDGUID", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Guid.Parse(definition.Guid).ToByteArray())]),
                };
                if (definition.Kind == SchemaGuidKind.Attribute)
                    schemaAttributes.Add(new("isSingleValued", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("TRUE")]));
                Write(schema, "CN=" + definition.LdapName + ",CN=Schema,CN=Configuration," + Root, objectClass, null,
                    schemaAttributes.ToArray(), null);
            }

            void Write(PartitionCoverage partition, string dn, string kind, string? sid, EvidenceAttribute[] extra, string? sddl)
            {
                var guid = new Guid(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(dn)).AsSpan(0, 16));
                var attributes = new List<EvidenceAttribute>
                {
                    new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText(kind)]),
                };
                if (sid is not null) attributes.Add(new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(sid)!)]));
                attributes.AddRange(extra);
                var id = writer.WriteObject(new(partition, dn, guid, attributes, When));
                if (sddl is null) return;
                var raw = new RawSecurityDescriptor(sddl);
                var bytes = new byte[raw.BinaryLength];
                raw.GetBinaryForm(bytes, 0);
                writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
            }
        });
        SelfMembershipDiscoveryTests.Derive(directory);
        return directory;
    }

    internal static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }

    private sealed class Observer(Action observe) : IObjectRule
    {
        public RuleDefinition Definition { get; } = new("TEST-GPO-INPUTS", "GPO input observation", Severity.Low, 1,
            ["groupPolicyContainer", "organizationalUnit"], ["objectClass"], []);
        public RuleVerdict Judge(ObjectAttributes subject) { observe(); return RuleVerdict.Judged([]); }
    }
}
