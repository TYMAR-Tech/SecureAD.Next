using System.Security.Cryptography;
using System.Text.Json;
using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.GmsaPasswordReaderTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class GmsaPasswordReaderReadTests
{
    [Theory]
    [InlineData(2)]
    [InlineData(25)]
    public void JudgingVerifiesCaptureAndDerivationOnceAndNeverReselectsThemPerGmsa(int accountCount)
    {
        var directory = Prepared(accountCount: accountCount);
        var derived = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value;
        var derivationPath = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Derivation, derived.GenerationId);
        using var counts = new InputCounts(directory);
        var snapshots = new List<(long CaptureReads, long DerivationReads, long Bindings)>();
        var observer = new InputObserver(() => snapshots.Add((counts.Manifest("capture"), counts.Manifest("derivation"), counts.Bindings)));
        var result = JudgingRun.Judge(directory, [new BroadGmsaPasswordReader(), observer], Captured, Captured,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(1, counts.File(Path.Combine(directory, "evidence.db")));
        Assert.Equal(1, counts.File(derivationPath));
        Assert.Equal(1, counts.Bindings);
        Assert.Equal(accountCount, snapshots.Count);
        Assert.True(snapshots[0].CaptureReads > 0);
        Assert.True(snapshots[0].DerivationReads > 0);
        Assert.All(snapshots, snapshot => Assert.Equal(snapshots[0], snapshot));
        using var reader = Open(directory);
        Assert.Equal(accountCount, reader.Read().Findings.Count);
    }

    [Fact]
    public void NormalJudgingPublishesTheNewRuleAndItsExactlyBoundOriginalEmbeddedEvidence()
    {
        var directory = Published();
        using var reader = Open(directory);
        var finding = Assert.Single(reader.Read().Findings);
        var proof = Proof(finding);
        Assert.Equal("SEC-102", finding.RuleId);
        Assert.Equal(AccountGuid, proof.Source.ObjectGuid);
        Assert.Equal(GmsaClass, finding.ObjectClass);
        Assert.Equal(reader.Description.GenerationId, proof.GenerationId);
        Assert.Equal(reader.Description.EvidenceSeal, proof.EvidenceSeal);
        Assert.Equal(reader.Description.DerivationGenerationId, proof.DerivationGenerationId);
        Assert.Equal(FindingInputBinding.DerivationSeal(directory, reader.Description.DerivationGenerationId), proof.DerivationSeal);
        Assert.Equal(0x10, Assert.Single(proof.Source.Entries).AccessMask);
        Assert.Equal(Broad, proof.BroadSid);
        Assert.True(proof.IsComplete);
        Assert.Equal(Descriptor("O:SYG:SYD:(A;;RP;;;AU)"), proof.Source.Descriptor);
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("derivation")]
    [InlineData("generation")]
    [InlineData("target")]
    [InlineData("subject")]
    [InlineData("descriptor")]
    public void TheWriterRefusesWrongSourceGenerationTargetSubjectAndChangedOriginals(string defect)
    {
        var finding = Assert.Single(Assess("O:SYG:SYD:(A;;RP;;;AU)").Findings);
        var proof = Proof(finding);
        finding = defect switch
        {
            "capture" => finding with { Evidence = proof with { EvidenceSeal = new string('c', 64) } },
            "derivation" => finding with { Evidence = proof with { DerivationGenerationId = Guid.NewGuid() } },
            "generation" => finding with { Evidence = proof with { GenerationId = Guid.NewGuid() } },
            "target" => finding with { ObjectGuid = Guid.NewGuid() },
            "subject" => finding with { Subject = new(FindingSubjectKind.Account, "another holder") },
            _ => finding with { Evidence = proof with { Source = proof.Source with
                { Entries = [proof.Source.Entries[0] with { AccessMask = 0x100 }] } } },
        };
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        GmsaPasswordReaderStorage.CreateTables(connection);
        using var transaction = connection.BeginTransaction();
        Assert.Throws<InvalidDataException>(() => GmsaPasswordReaderStorage.Write(connection, transaction, 1, Generation,
            EvidenceSeal, DerivationGeneration, DerivationSeal, finding, Proof(finding)));
    }

    [Fact]
    public void ADeclaredGrantCannotBypassAnEarlierCapturedDenyDuringPublicationValidation()
    {
        var proof = Proof(Assert.Single(Assess("O:SYG:SYD:(A;;RP;;;AU)").Findings));
        var bytes = Descriptor("O:SYG:SYD:(D;;RP;;;AU)(A;;RP;;;AU)");
        var parsed = SecurityDescriptorParser.Parse(bytes);
        var forged = proof with
        {
            Source = proof.Source with { Descriptor = bytes, Entries = parsed.DaclAces, DaclWasCanonical = parsed.DaclWasCanonical },
            Grants = [proof.Grants[0] with { GrantOrdinals = [1] }],
        };
        Assert.Throws<InvalidDataException>(() => GmsaPasswordReaderStorage.Validate(forged));
    }

    [Fact]
    public void PublicationRequiresTheSavedProjectionAndEveryHolderRow()
    {
        var finding = FindingWithHolders(2);
        var proof = Proof(finding);
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE finding(finding_id INTEGER PRIMARY KEY,rule_id TEXT,object_guid TEXT,distinguished_name TEXT,
                domain_fqdn TEXT,object_class TEXT,subject_key TEXT,subject_kind TEXT,severity TEXT);
            CREATE TABLE rule_execution(rule_id TEXT PRIMARY KEY,rule_version INTEGER);
            INSERT INTO rule_execution VALUES('SEC-102',1);
            """;
        command.ExecuteNonQuery();
        command.CommandText = """
            INSERT INTO finding VALUES(1,'SEC-102',$guid,$dn,$domain,$class,$key,'Account','High')
            """;
        command.Parameters.AddWithValue("$guid", finding.ObjectGuid.ToString("D"));
        command.Parameters.AddWithValue("$dn", finding.DistinguishedName);
        command.Parameters.AddWithValue("$domain", finding.DomainFqdn);
        command.Parameters.AddWithValue("$class", finding.ObjectClass);
        command.Parameters.AddWithValue("$key", finding.Subject.Key);
        command.ExecuteNonQuery();
        GmsaPasswordReaderStorage.CreateTables(connection);
        Assert.Throws<InvalidDataException>(() => Check());
        using (var transaction = connection.BeginTransaction())
        {
            GmsaPasswordReaderStorage.Write(connection, transaction, 1, Generation, EvidenceSeal, DerivationGeneration, DerivationSeal, finding, proof);
            transaction.Commit();
        }
        Check();
        command.Parameters.Clear();
        command.CommandText = "DELETE FROM finding_gmsa_reader_holder WHERE ordinal=0";
        Assert.Equal(1, command.ExecuteNonQuery());
        Assert.Throws<InvalidDataException>(() => Check());
        void Check() => GmsaPasswordReaderStorage.RequirePublishable(connection, Generation, EvidenceSeal,
            DerivationGeneration, DerivationSeal, CancellationToken.None);
    }

    internal static string Published(int holderCount = 0)
    {
        var directory = Prepared(holderCount);
        var before = SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, "evidence.db")));
        var result = JudgingRun.Judge(directory, [new BroadGmsaPasswordReader()], Captured, Captured,
            JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, "evidence.db"))));
        return directory;
    }

    private static string Prepared(int holderCount = 0, int accountCount = 1)
    {
        var embedded = Descriptor(holderCount == 0 ? "O:SYG:SYD:(A;;RP;;;AU)"
            : "O:SYG:SYD:" + string.Concat(Enumerable.Range(0, holderCount).Select(index => $"(A;;RP;;;{DomainSid}-{6000 + index})")));
        var directory = SelfMembershipDiscoveryTests.Bundle(users: 0, writeAdditional: (writer, coverage) =>
        {
            for (var accountIndex = 0; accountIndex < accountCount; accountIndex++)
            {
                var account = Account(embedded);
                var guid = accountIndex == 0 ? AccountGuid : Guid.NewGuid();
                var dn = accountIndex == 0 ? account.DistinguishedName : "CN=svc-app-" + accountIndex + "," + Root;
                var objectId = writer.WriteObject(new(coverage, dn, guid,
                    account.Attributes.Select(attribute => new EvidenceAttribute(attribute.LdapDisplayName, StoredAttributeCompleteness.Complete,
                        attribute.Values.Select(value => value.Bytes is { } bytes ? EvidenceValue.OfBytes(bytes) : EvidenceValue.OfText(value.Text!)).ToArray())).ToArray(),
                    Captured));
                var ordinary = Descriptor("O:SYG:SYD:(D;;RP;;;WD)");
                writer.WriteSecurityDescriptor(objectId, ordinary, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(ordinary)));
            }
            if (holderCount == 0) return;
            const string broadDn = "CN=Captured broad identity," + Root;
            writer.WriteObject(new(coverage, broadDn, Guid.NewGuid(),
            [
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("foreignSecurityPrincipal")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(Broad)!)]),
            ], Captured));
            for (var index = 0; index < holderCount; index++)
                writer.WriteObject(new(coverage, "CN=Reader" + index + "," + Root, Guid.NewGuid(),
                [
                    new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("group")]),
                    new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(DomainSid + "-" + (6000 + index))!)]),
                    new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                    new("member", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText(broadDn)]),
                ], Captured));
        });
        var before = SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, "evidence.db")));
        SelfMembershipDiscoveryTests.Derive(directory);
        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(Path.Combine(directory, "evidence.db"))));
        return directory;
    }

    private sealed class InputObserver(Action observe) : IObjectRule
    {
        public RuleDefinition Definition { get; } = new("TEST-GMSA-INPUTS", "gMSA input observation", Severity.Low, 1,
            [GmsaClass], ["objectClass"], []);
        public RuleVerdict Judge(ObjectAttributes subject) { observe(); return RuleVerdict.Judged([]); }
    }

    internal sealed class InputCounts : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentDictionary<string, long> _counts = new(StringComparer.OrdinalIgnoreCase);
        internal InputCounts(string directory)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Name is "store.verifications" or "store.selection_manifest_reads" or "inputs.bindings")
                    listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                string? bundle = null, file = null, kind = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "bundle") bundle = tag.Value as string;
                    if (tag.Key == "file") file = tag.Value as string;
                    if (tag.Key == "kind") kind = tag.Value as string;
                }
                var key = instrument.Name == "store.verifications" && file is not null
                    && file.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ? "file:" + file
                    : string.Equals(bundle, directory, StringComparison.OrdinalIgnoreCase)
                        ? instrument.Name + ":" + kind : null;
                if (key is not null) _counts.AddOrUpdate(key, value, (_, count) => count + value);
            });
            _listener.Start();
        }
        internal long File(string path) => _counts.GetValueOrDefault("file:" + path);
        internal long Manifest(string kind) => _counts.GetValueOrDefault("store.selection_manifest_reads:" + kind);
        internal long Bindings => _counts.GetValueOrDefault("inputs.bindings:");
        public void Dispose() => _listener.Dispose();
    }

    internal static JudgementReader Open(string directory)
    {
        var opened = JudgementReader.Open(directory);
        Assert.True(opened.IsSuccess, opened.Error?.Description);
        return opened.Value;
    }
}
