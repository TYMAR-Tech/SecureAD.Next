using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel.GroupPolicy;
using SecureAD.Kernel.Security;
using SecureAD.Next.Tests.Sysvol;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class LapsConfiguredPolicyStorageTests
{
    [Fact]
    public void SavedLapsSettingsAndDirectoryAssessmentPreserveAnswersSourcesAndOriginalAlternatives()
    {
        var (directory, original) = Build();
        Publish(directory, original);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(original.Computer).Value;
        Assert.Equal(reader.Description.GenerationId, saved.JudgementGenerationId);
        Assert.Equal(original.CaptureGenerationId, saved.CaptureGenerationId);
        Assert.Equal(original.EvidenceSeal, saved.EvidenceSeal);
        Assert.Equal(original.Computer, saved.Computer);
        Assert.Equal(GpoDirectoryWmiAssessment.Assumption, saved.DirectoryAssumption);
        Assert.False(saved.IsObservedWmiResult);
        Assert.Equal(Key, saved.RegistryPolicyRoot);
        Assert.True(saved.DefaultsRequireSelectionOfThisPolicyRoot);
        Assert.Equal("S-1-5-21-1-2-3-512", saved.DsrMDecryptorWhenApplicable.Sid);
        Assert.True(saved.HasOpenPolicyScope);
        Assert.Equal(4, saved.Settings.Length);
        var key = saved.Policies[0].Conditional.Wmi!.Condition;
        foreach (var setting in Enum.GetValues<LapsPolicySetting>())
        {
            foreach (var matches in new[] { false, true })
            {
                var assumptions = new Dictionary<GpoWmiConditionKey, bool> { [key] = matches };
                SameAnswer(original.UnderAssumptions(setting, assumptions), saved.UnderAssumptions(setting, assumptions), saved);
            }
            SameAnswer(original.UnderDirectoryAssessment(setting).Value!,
                saved.UnderDirectoryAssessment(setting).Value!, saved);
            Assert.False(saved.Settings.Single(value => value.Setting == setting).IsDefiniteForComputer);
        }
        var value = saved.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool> { [key] = true });
        Assert.Equal(GroupB, value.Principal);
        var source = saved.Sources[value.Source!.Value];
        Assert.Equal(PolicyGuid(2), source.Policy!.ObjectGuid);
        Assert.Equal(0, source.EntryIndex);
        Assert.Equal(TextValue(Principal, GroupB).Data, source.Instruction!.Data);
        Assert.Equal(PathOf(new(2, [])), source.FileSysPath);
        Assert.Equal(original.Inputs.Hierarchy.Links.Length, saved.Hierarchy.Links.Length);
        Assert.All(saved.Policies, policy => Assert.Equal(1, policy.Wmi.Queries.Length));
    }

    [Fact]
    public void SavedLapsUnsavedComputerIsExplicitUnassessedScopeNotAnEmptyPolicy()
    {
        var (directory, original) = Build();
        Publish(directory, null);
        using var reader = JudgementReader.Open(directory).Value;
        var result = reader.ReadLapsConfiguredPolicy(original.Computer);
        Assert.False(result.IsSuccess);
        Assert.Equal("Evidence.LapsConfiguredCalculationNotSaved", result.Error.Code);
        Assert.Contains("unassessed", result.Error.Description);
    }

    [Theory]
    [InlineData("capture")]
    [InlineData("parse")]
    [InlineData("operation")]
    [InlineData("missing-filter")]
    public void SavedLapsUnresolvedInputsAndPredecessorsRemainExplicitInsteadOfBecomingDefaults(string kind)
    {
        var higher = kind switch
        {
            "capture" => new Policy(2, [], Outcome: GpoSettingsOutcome.PartiallyRead),
            "parse" => new Policy(2, [], ParseErrors: ["Recorded parse limitation"]),
            "operation" => new Policy(2, [TextValue("**DelVals", " ")]),
            "missing-filter" => new Policy(2, [TextValue(Principal, GroupB)], NoFilterReference: true),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)]), higher],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        var original = Read(directory);
        Publish(directory, original);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(original.Computer).Value;
        var assumptions = saved.Policies.Where(policy => policy.Conditional.Wmi is not null)
            .Select(policy => policy.Conditional.Wmi!.Condition).Distinct().ToDictionary(key => key, _ => true);
        var value = saved.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal, assumptions);
        Assert.Equal(LapsConfiguredValueState.Unresolved, value.State);
        Assert.Null(value.Principal);
        Assert.NotNull(value.Reason);
        Assert.Contains(saved.Nodes, node => node.Previous is not null);
        Assert.NotEmpty(saved.Limitations);
        Assert.Equal(original.RegistryPolicies[1].Registry?.ParseErrors, saved.RegistryPolicies[1].Registry?.ParseErrors);
    }

    [Fact]
    public void SavedLapsRetainsTheWindowsRecordedTwoQueryValueAndOriginalParsedTokens()
    {
        // Original Windows-created reference, UTF-16LE SHA-256 f339cc90eb247b26b893d1f8eaacc63429991a1ae244bd172b4a394c076366f1.
        const string first = "SELECT * FROM Win32_OperatingSystem WHERE Version >= '10.0.17763'";
        const string second = "SELECT * FROM Win32_OperatingSystem WHERE ProductType = '3'";
        const string recorded = "2;3;10;65;WQL;root\\CIMv2;" + first + ";3;10;59;WQL;root\\CIMv2;" + second + ";";
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])],
            filterDefinitions: new Dictionary<int, string> { [1] = recorded },
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        var original = Read(directory);
        Publish(directory, original);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(original.Computer).Value;
        var policy = Assert.Single(saved.Policies);
        Assert.Equal(recorded, policy.Wmi.Source.FilterValues!.Find("msWMI-Parm2")!.OnlyValue!.Text);
        Assert.Equal(new[] { first, second }, policy.Wmi.Queries.Select(query => query.Query));
        Assert.All(policy.Wmi.Queries, query => Assert.Equal(WqlReadingState.ParsedConditions, query.Reading.State));
        Assert.Equal("Version", Assert.IsType<WqlComparisonToken>(Assert.Single(policy.Wmi.Queries[0].Reading.Conditions!.Postfix)).Property);
        Assert.Equal("3", Assert.IsType<WqlComparisonToken>(Assert.Single(policy.Wmi.Queries[1].Reading.Conditions!.Postfix)).Literal!.Value);
        Assert.Equal(GroupA, saved.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
    }

    [Fact]
    public void SavedLapsSelectedReadDoesNotLoadOrValidateAnotherComputersPayload()
    {
        const string otherDn = "CN=Other computer," + GpoSecurityRun.Parent;
        var other = new GpoSecurityRun.OtherObject(otherDn, Guid.NewGuid(),
            [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("computer")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(GpoSecurityRun.ParentSid + "-1101")!)]),
                new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("4096")]),
                .. GpoDirectoryWmiAssessmentTests.Platform()]);
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), additionalObjects: [other]);
        var original = Read(directory);
        using var inputs = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var second = inputs.Read(inputs.Bundle.ReadObjectIdentity(otherDn)!, CancellationToken.None).Value;
        using (var writer = CreateWriter(directory, original))
        {
            writer.WriteLapsConfiguredPolicy(original);
            writer.WriteLapsConfiguredPolicy(second);
            writer.Complete(GpoSecurityRun.Captured.AddMinutes(2));
        }
        using (var healthy = JudgementReader.Open(directory).Value)
        {
            SavedLapsConfiguredPolicy? otherSaved = null;
            Assert.Null(Record.Exception(() => otherSaved = healthy.ReadLapsConfiguredPolicy(second.Computer).Value));
            Assert.Equal(second.Computer, otherSaved!.Computer);
        }
        Edit(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE laps_configured_calculation SET payload='invalid' WHERE computer_id=$id";
            command.Parameters.AddWithValue("$id", second.Computer.ObjectId);
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = JudgementReader.Open(directory).Value;
        SavedLapsConfiguredPolicy? selected = null;
        Assert.Null(Record.Exception(() => selected = reader.ReadLapsConfiguredPolicy(original.Computer).Value));
        Assert.Equal(GroupA, selected!
            .UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.Throws<InvalidDataException>(() => reader.ReadLapsConfiguredPolicy(second.Computer));
    }

    [Fact]
    public void SavedLapsFortyConditionsRemainAFlatSharedGraphAfterPublication()
    {
        var policies = Enumerable.Range(1, 40).Select(id =>
            new Policy(id, [TextValue(Principal, GroupA)], Filter: id)).ToArray();
        var directory = LapsPrecedenceRun.Build(policies, computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        var original = Read(directory);
        Publish(directory, original);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(original.Computer).Value;
        Assert.Equal(84, saved.Nodes.Length);
        Assert.Equal(81, saved.Settings.Single(setting =>
            setting.Setting == LapsPolicySetting.ADPasswordEncryptionPrincipal).DecisionNodeCount);
        Assert.Equal(40, saved.Policies.Select(policy => policy.Conditional.Wmi!.Condition).Distinct().Count());
        Assert.Equal(GroupA, saved.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
    }

    [Fact]
    public void SavedLapsSelectedJudgementDerivationIsBoundEvenWhenTheQuestionDidNotConsumeMembership()
    {
        var (directory, original) = Build();
        Assert.Null(original.DerivationGenerationId);
        GpoSecurityRun.Derive(directory);
        var generation = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Derivation).Value.GenerationId;
        using (var writer = JudgementWriter.Create(directory, original.EvidenceSeal, generation,
            GpoSecurityRun.Captured.AddMinutes(2), GpoSecurityRun.Captured))
        {
            writer.WriteLapsConfiguredPolicy(original);
            writer.Complete(GpoSecurityRun.Captured.AddMinutes(3));
        }
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(original.Computer).Value;
        Assert.Equal(generation, saved.DerivationGenerationId);
        Assert.NotNull(saved.DerivationSeal);
        Assert.Null(saved.CalculationDerivationGenerationId);
        Assert.All(saved.Policies, policy => Assert.Null(policy.Security.DerivationGenerationId));
        Assert.Equal(GroupB, saved.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
    }

    [Fact]
    public void SavedLapsIncompleteQuestionCannotReplaceThePreviouslySelectedGeneration()
    {
        var (directory, original) = Build();
        Publish(directory, original);
        var previous = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using (var writer = CreateWriter(directory, original))
        {
            writer.WriteLapsConfiguredPolicy(original);
            writer.FlushObjects();
            var file = BundleLayout.AnalysisSegmentDataPath(directory,
                new(AnalysisStoreKind.Judgement, writer.GenerationId), StoreSegmentRole.JudgementFacts);
            using (var connection = new SqliteConnection("Data Source=" + file + ";Pooling=False"))
            {
                connection.Open();
                using var delete = connection.CreateCommand();
                delete.CommandText = "DELETE FROM laps_configured_calculation";
                Assert.Equal(1, delete.ExecuteNonQuery());
            }
            Assert.Throws<InvalidDataException>(() => writer.Complete(GpoSecurityRun.Captured.AddMinutes(3)));
        }
        Assert.Equal(previous, AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void SavedLapsCurrentFormatRefusesAnOlderHeaderWithoutMigratingOrDeletingSavedResults()
    {
        var (directory, original) = Build();
        Publish(directory, original);
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        Assert.All(root.Segments, part => Assert.Equal(86, part.SchemaVersion));
        var main = Path.Combine(directory, root.Segment(StoreSegmentRole.Judgement).FileName);
        using (var connection = new SqliteConnection("Data Source=" + main + ";Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "UPDATE judgement SET schema_version=82";
            Assert.Equal(1, command.ExecuteNonQuery());
            command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            command.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
        var hashes = root.Segments.ToDictionary(part => part.FileName,
            part => BundleSealing.HashFile(Path.Combine(directory, part.FileName)));
        var refused = JudgementReader.Open(directory);
        Assert.False(refused.IsSuccess);
        Assert.Contains("schema version 82", refused.Error.Description);
        Assert.All(hashes, item => Assert.Equal(item.Value, BundleSealing.HashFile(Path.Combine(directory, item.Key))));
    }

    [Fact]
    public void SavedLapsDisposedReaderAndFinishedWriterCannotBeReused()
    {
        var (directory, original) = Build();
        using (var writer = CreateWriter(directory, original))
        {
            writer.WriteLapsConfiguredPolicy(original);
            writer.Complete(GpoSecurityRun.Captured.AddMinutes(2));
            Assert.Throws<InvalidOperationException>(() => writer.WriteLapsConfiguredPolicy(original));
        }
        var reader = JudgementReader.Open(directory).Value;
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.ReadLapsConfiguredPolicy(original.Computer));
    }

    [Theory]
    [InlineData("missing-record")]
    [InlineData("missing-selection")]
    [InlineData("fingerprint")]
    [InlineData("payload")]
    public void SavedLapsMissingOrChangedStoredSupportIsRefused(string defect)
    {
        var (directory, original) = Build();
        Publish(directory, original);
        Edit(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = defect switch
            {
                "missing-record" => "DELETE FROM laps_configured_calculation",
                "missing-selection" => "DELETE FROM laps_configured_selection",
                "fingerprint" => "UPDATE laps_configured_selection SET fingerprint=replace(fingerprint,substr(fingerprint,1,1),'X')",
                "payload" => "UPDATE laps_configured_calculation SET payload='{}'",
                _ => throw new ArgumentOutOfRangeException(nameof(defect)),
            };
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.ReadLapsConfiguredPolicy(original.Computer));
    }

    [Theory]
    [InlineData("judgement")]
    [InlineData("capture")]
    [InlineData("seal")]
    [InlineData("assumption")]
    [InlineData("observed-wmi")]
    [InlineData("computer")]
    [InlineData("source-bytes")]
    [InlineData("cycle")]
    [InlineData("node-count")]
    [InlineData("policy-root")]
    [InlineData("root-default-assumption")]
    [InlineData("directory-value")]
    [InlineData("filter-source-guid")]
    [InlineData("missing-setting")]
    [InlineData("unknown-condition")]
    [InlineData("null-node")]
    [InlineData("numeric-enum")]
    public void SavedLapsRehashedButUnboundOrInconsistentPayloadIsRefusedWithoutReplay(string defect)
    {
        var (directory, original) = Build();
        Publish(directory, original);
        EditPayload(directory, root =>
        {
            switch (defect)
            {
                case "judgement": root["JudgementGenerationId"] = Guid.NewGuid().ToString("D"); break;
                case "capture": root["CaptureGenerationId"] = Guid.NewGuid().ToString("D"); break;
                case "seal": root["EvidenceSeal"] = new string('0', 64); break;
                case "assumption": root["DirectoryAssumption"] = ""; break;
                case "observed-wmi": root["IsObservedWmiResult"] = true; break;
                case "computer": root["Computer"]!["ObjectId"] = original.Computer.ObjectId + 1; break;
                case "source-bytes":
                    root["Sources"]!.AsArray().First(source => source!["Instruction"] is not null)!["Instruction"]!["Data"] = "AAAA";
                    break;
                case "cycle":
                    var branch = root["Nodes"]!.AsArray().First(node => node!["Condition"] is not null)!;
                    branch["WhenMatches"] = branch["Id"]!.GetValue<int>();
                    break;
                case "node-count": root["Settings"]![0]!["DecisionNodeCount"] = 100000; break;
                case "policy-root": root["RegistryPolicyRoot"] = "Unrelated"; break;
                case "root-default-assumption": root["DefaultsRequireSelectionOfThisPolicyRoot"] = false; break;
                case "directory-value":
                    root["Settings"]!.AsArray().First(setting => setting!["Setting"]!.GetValue<string>() == "ADPasswordEncryptionPrincipal")!
                        ["DirectoryAssessment"]!["Value"]!["Principal"] = GroupA;
                    break;
                case "filter-source-guid": root["Policies"]![0]!["Wmi"]!["Source"]!["FilterValues"]!["ObjectGuid"] = Guid.NewGuid().ToString("D"); break;
                case "missing-setting": root["Settings"]!.AsArray().RemoveAt(0); break;
                case "unknown-condition":
                    root["Nodes"]!.AsArray().First(node => node!["Condition"] is not null)!["Condition"]!["FilterObjectId"] = 999999999;
                    break;
                case "null-node": root["Nodes"]!.AsArray()[0] = null; break;
                case "numeric-enum": root["Settings"]![0]!["Setting"] = 0; break;
            }
        });
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.ReadLapsConfiguredPolicy(original.Computer));
    }

    [Theory]
    [InlineData("write")]
    [InlineData("read")]
    [InlineData("complete")]
    public void SavedLapsCancellationDoesNotPublishOrReadAnInventedAnswer(string point)
    {
        var (directory, original) = Build();
        Publish(directory, original);
        var before = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var stop = new CancellationTokenSource();
        stop.Cancel();
        if (point == "read")
        {
            using var reader = JudgementReader.Open(directory).Value;
            Assert.Throws<OperationCanceledException>(() => reader.ReadLapsConfiguredPolicy(original.Computer, stop.Token));
        }
        else
        {
            using var writer = CreateWriter(directory, original);
            if (point == "write")
                Assert.Throws<OperationCanceledException>(() => writer.WriteLapsConfiguredPolicy(original, stop.Token));
            else
            {
                writer.WriteLapsConfiguredPolicy(original);
                Assert.Throws<OperationCanceledException>(() => writer.Complete(GpoSecurityRun.Captured.AddMinutes(2), stop.Token));
            }
        }
        Assert.Equal(before, AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void SavedLapsForeignCaptureCannotBeWrittenIntoAnotherJudgement()
    {
        var (directory, original) = Build();
        var (_, foreign) = Build();
        using var writer = CreateWriter(directory, original);
        Assert.Throws<InvalidDataException>(() => writer.WriteLapsConfiguredPolicy(foreign));
    }

    [Fact]
    public void SavedLapsAssumptionSelectionRefusesMissingAndForeignConditions()
    {
        var (directory, original) = Build();
        Publish(directory, original);
        using var reader = JudgementReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(original.Computer).Value;
        Assert.Throws<InvalidDataException>(() => saved.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool>()));
        var key = saved.Policies[0].Conditional.Wmi!.Condition;
        Assert.Throws<InvalidDataException>(() => saved.UnderAssumptions(LapsPolicySetting.ADPasswordEncryptionPrincipal,
            new Dictionary<GpoWmiConditionKey, bool> { [key] = true, [key with { FilterObjectId = key.FilterObjectId + 100000 }] = true }));
    }

    private static (string Directory, LapsConfiguredPolicy Result) Build()
    {
        var directory = LapsPrecedenceRun.Build(
            [new(1, [Number("BackupDirectory", 2), Number("ADPasswordEncryptionEnabled", 1),
                Number("ADBackupDSRMPassword", 1), TextValue(Principal, GroupA)]),
                new(2, [TextValue(Principal, GroupB)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        return (directory, Read(directory));
    }
    private static LapsConfiguredPolicy Read(string directory)
    {
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        return reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
    }
    private static JudgementWriter CreateWriter(string directory, LapsConfiguredPolicy original) =>
        JudgementWriter.Create(directory, original.EvidenceSeal, original.DerivationGenerationId,
            GpoSecurityRun.Captured.AddMinutes(1), GpoSecurityRun.Captured);
    private static void Publish(string directory, LapsConfiguredPolicy? original)
    {
        var binding = original ?? Read(directory);
        using var writer = CreateWriter(directory, binding);
        if (original is not null) writer.WriteLapsConfiguredPolicy(original);
        writer.Complete(GpoSecurityRun.Captured.AddMinutes(2));
    }
    private static void SameAnswer(LapsConfiguredValue expected, SavedLapsValue actual, SavedLapsConfiguredPolicy saved)
    {
        Assert.Equal(expected.State, actual.State);
        Assert.Equal(expected.Number, actual.Number);
        Assert.Equal(expected.Principal, actual.Principal);
        Assert.Equal(expected.DomainAdmins, actual.DomainAdmins);
        Assert.Equal(expected.Reason, actual.Reason);
        if (expected.Source is null) Assert.Null(actual.Source);
        else
        {
            var source = saved.Sources[actual.Source!.Value];
            Assert.Equal(expected.Source.Policy, source.Policy);
            Assert.Equal(expected.Source.FileSysPath, source.FileSysPath);
            Assert.Equal(expected.Source.EntryIndex, source.EntryIndex);
            Assert.Equal(expected.Source.Instruction?.Data, source.Instruction?.Data);
        }
    }
    private static void EditPayload(string directory, Action<JsonObject> edit)
    {
        Edit(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM laps_configured_calculation";
            var root = JsonNode.Parse((string)command.ExecuteScalar()!)!.AsObject();
            edit(root);
            var payload = root.ToJsonString();
            command.CommandText = "UPDATE laps_configured_calculation SET payload=$payload";
            command.Parameters.AddWithValue("$payload", payload);
            command.ExecuteNonQuery();
            command.CommandText = "UPDATE laps_configured_selection SET fingerprint=$hash";
            command.Parameters.AddWithValue("$hash", LapsConfiguredPolicyStorage.Fingerprint(payload));
            command.ExecuteNonQuery();
        });
    }
    private static void Edit(string directory, Action<SqliteConnection> edit)
    {
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(directory,
            root.Segment(StoreSegmentRole.JudgementFacts).FileName) + ";Pooling=False;Foreign Keys=False"))
        {
            connection.Open();
            edit(connection);
            using var checkpoint = connection.CreateCommand();
            checkpoint.CommandText = "PRAGMA wal_checkpoint(TRUNCATE)";
            checkpoint.ExecuteNonQuery();
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
    }
}
