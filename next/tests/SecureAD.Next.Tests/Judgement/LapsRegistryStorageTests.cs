using System.Text;
using Microsoft.Data.Sqlite;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Evidence.Findings;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Next.Tests.Sysvol;
using Xunit;
using static SecureAD.Next.Tests.Kernel.GroupPolicy.RegistryPolicyInterpreterTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsRegistryStorageTests
{
    private const string Key = @"Software\Microsoft\Windows\CurrentVersion\Policies\LAPS";
    private const string Name = "ADPasswordEncryptionPrincipal";
    private const string Broad = "S-1-5-21-1-2-3-513";

    [Theory]
    [InlineData("complete")]
    [InlineData("capture")]
    [InlineData("parse")]
    [InlineData("operation")]
    [InlineData("membership")]
    public void LapsRegistrySavedListsAndDetailsPreserveIndependentInputAxesAndOriginalBytes(string kind)
    {
        var directory = Build(kind);
        using var reader = JudgementReader.Open(directory).Value;
        var stored = reader.Read();
        var finding = Assert.Single(stored.Findings);
        var evidence = Assert.IsType<LapsDecryptorEvidence>(finding.Evidence);
        Assert.Equal(kind != "capture", evidence.Settings.CaptureWasComplete);
        Assert.Equal(kind is not ("parse" or "operation"), evidence.Settings.InterpretationWasComplete);
        Assert.Equal(kind != "membership", evidence.ExpansionWasComplete);
        Assert.Equal(kind == "complete", evidence.IsComplete);
        Assert.Equal(kind == "complete", Assert.Single(reader.ReadListPage(FindingsQuery.Everything()).Value.Findings).EvidenceIsComplete);
        Assert.Equal(Encoding.Unicode.GetBytes(Broad + "\0"), evidence.Settings.Value.Source.Data);
        Assert.Equal(Key, evidence.Settings.Value.Source.KeyPath);
        Assert.Equal(Name, evidence.Settings.Value.Source.ValueName);
        Assert.Equal(0, evidence.Settings.Value.EntryIndex);
        Assert.Equal(kind == "parse" ? ["Recorded Machine parse error"] : Array.Empty<string>(), evidence.Settings.ParseErrors);
        Assert.Equal(kind == "operation" ? 1 : 0, evidence.Settings.InterpretationIssues.Count);
        if (kind == "operation")
        {
            var issue = Assert.Single(evidence.Settings.InterpretationIssues);
            Assert.Equal((1, Key, "**DelVals"), (issue.EntryIndex, issue.KeyPath, issue.ValueName));
            Assert.False(string.IsNullOrWhiteSpace(issue.Reason));
        }
        Assert.Equal(2, finding.RuleVersion);
        Assert.All(AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.Segments,
            part => Assert.Equal(86, part.SchemaVersion));
    }

    [Fact]
    public void LapsRegistryCapturedParseDiagnosticsAreMachineScopedAndCannotBeLostBehindCompleteCoverage()
    {
        using var reader = BundleReader.Open(Build("parse")).Value;
        var settings = reader.ReadGpoMachineRegistrySettings(GpoProtocolRun.PolicyGuid);
        Assert.Equal(GpoSettingsOutcome.Read, settings.Outcome);
        Assert.False(settings.IsComplete);
        Assert.Equal(["Recorded Machine parse error"], settings.ParseErrors);
        Assert.Single(settings.Settings);
        Assert.Equal(Broad, settings.Settings[0].AsString());
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("parse")]
    [InlineData("operation")]
    public void LapsRegistryListCompletenessUsesTheSavedInputAxesNotACachedCompleteFlag(string kind)
    {
        var directory = Build(kind);
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(directory,
            root.Segment(StoreSegmentRole.Judgement).FileName) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE finding SET evidence_complete=1";
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.False(Assert.Single(reader.ReadListPage(FindingsQuery.Everything()).Value.Findings).EvidenceIsComplete);
    }

    [Theory]
    [InlineData("missing-limit")]
    [InlineData("wrong-ordinal")]
    [InlineData("changed-bytes")]
    [InlineData("wrong-root")]
    [InlineData("wrong-value-name")]
    public void LapsRegistrySavedMissingOrChangedSupportIsRefusedInsteadOfReconstructed(string defect)
    {
        var directory = Build("operation");
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(directory,
            root.Segment(StoreSegmentRole.PermissionProof).FileName) + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = defect switch
            {
                "missing-limit" => "DELETE FROM finding_laps_registry_limit",
                "wrong-ordinal" => "UPDATE finding_laps_registry_limit SET ordinal=5",
                "changed-bytes" => "UPDATE finding_laps_decryptor SET registry_data=X'0000'",
                "wrong-root" => "UPDATE finding_laps_decryptor SET registry_key_path='Unrelated\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS'",
                "wrong-value-name" => "UPDATE finding_laps_decryptor SET registry_value_name='AnotherValue'",
                _ => throw new ArgumentOutOfRangeException(nameof(defect)),
            };
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.Read());
    }

    private static string Build(string kind)
    {
        var directory = TempDirectories.Create("laps-registry-storage");
        RegistryPolicyEntry[] entries = kind == "operation"
            ? [Entry(Key, Name, Broad), Entry(Key, "**DelVals", " ")] : [Entry(Key, Name, Broad)];
        using (var writer = BundleWriter.Create(directory, GpoProtocolRun.Captured))
        {
            GpoProtocolRun.WritePolicy(writer);
            for (var index = 0; index < entries.Length; index++)
            {
                var entry = entries[index];
                writer.WriteGpoRegistrySetting(GpoProtocolRun.PolicyGuid, index, GpoSettingScope.Machine,
                    entry.KeyPath, entry.ValueName, entry.RegistryType, entry.Data);
            }
            if (kind == "parse")
            {
                writer.WriteGpoFileError(GpoProtocolRun.PolicyGuid, 0, @"Machine\Registry.pol", "Recorded Machine parse error");
                writer.WriteGpoFileError(GpoProtocolRun.PolicyGuid, 1, @"User\Registry.pol", "Unrelated User parse error");
            }
            var coverage = kind == "capture"
                ? GpoCoverage.PartiallyRead(GpoProtocolRun.PolicyGuid, "Synthetic LAPS policy", GpoProtocolRun.PolicyPath, "Recorded SYSVOL limit")
                : GpoCoverage.Read(GpoProtocolRun.PolicyGuid, "Synthetic LAPS policy", GpoProtocolRun.PolicyPath);
            writer.Complete(GpoProtocolRun.Coverage(SysvolCoverage.Of([coverage])), GpoProtocolRun.Captured.AddMinutes(1));
        }
        RuleVerdict verdict;
        var rule = new LapsDecryptorBroadPrincipal();
        using (var source = BundleReader.Open(directory).Value)
        {
            var context = LapsDecryptorBroadPrincipalTests.Context(entries,
                (sid, _) => new PrincipalExpansion(sid,
                    kind == "membership" ? PrincipalExpansionOutcome.PrincipalNotFound : PrincipalExpansionOutcome.Expanded, []))
                with { GpoMachineRegistrySettings = source.ReadGpoMachineRegistrySettings };
            verdict = rule.Judge(source.ReadObjectAttributes(GpoProtocolRun.PolicyDn)!, context);
            Assert.Single(verdict.Findings);
            Assert.Equal(kind == "complete", verdict.IsComplete);
        }
        using (var writer = JudgementWriter.Create(directory,
            BundleSealing.ReadSeal(BundleLayout.SealPath(directory))!.Hash, null,
            GpoProtocolRun.Captured, GpoProtocolRun.Captured))
        {
            writer.Write(RuleExecution.Judged(rule.Definition, 1, 0, verdict.Findings));
            writer.Complete(GpoProtocolRun.Captured.AddMinutes(2));
        }
        return directory;
    }
}
