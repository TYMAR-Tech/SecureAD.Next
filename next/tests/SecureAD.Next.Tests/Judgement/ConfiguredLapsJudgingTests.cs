using System.Collections.Concurrent;
using System.Reflection;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ConfiguredLapsJudgingTests
{
    [Fact]
    public void AutomaticLapsHostPolicyCalculatesCapturedComputersByDefault()
    {
        Assert.Equal(ConfiguredLapsPolicy.AllCapturedComputers, JudgingRun.ProductionConfiguredLapsPolicy);
        var directory = Build();
        using var files = new ProtectedRunFiles(directory);
        var result = JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled,
            GpoSecurityRun.Captured.AddMinutes(2), GpoSecurityRun.Captured, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None, null, files);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        var summary = Scope(reader);
        Assert.Equal(ConfiguredLapsSchedulingState.Complete, summary.State);
        Assert.Equal((1L, 1L, 1L, 0L), (summary.ObservedComputers, summary.QuestionsConsidered,
            summary.SavedCalculations, summary.UnassessedComputers));
        using var captured = BundleReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!);
        Assert.True(saved.IsSuccess);
        Assert.Equal(GroupA, saved.Value.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.Equal(summary.JudgementGenerationId, saved.Value.JudgementGenerationId);
        Assert.Equal(summary.CaptureGenerationId, saved.Value.CaptureGenerationId);
    }

    [Fact]
    public void ExplicitlyDisabledConfiguredLapsStillRecordsDisabledScope()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.Disabled).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        var summary = Scope(reader);
        Assert.Equal(ConfiguredLapsSchedulingState.Disabled, summary.State);
        Assert.Equal(1, summary.ObservedComputers);
        Assert.Equal(0, summary.QuestionsConsidered);
        Assert.Equal(0, summary.SavedCalculations);
        Assert.Equal(1, summary.UnassessedComputers);
        using var captured = BundleReader.Open(directory).Value;
        var missing = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!);
        Assert.False(missing.IsSuccess);
        Assert.Equal("Evidence.LapsConfiguredCalculationDisabled", missing.Error.Code);
    }

    [Fact]
    public void AutomaticLapsRealCoordinatorCalculatesAndSavesWithoutSuppliedTargets()
    {
        var directory = Build();
        var log = new Notes();
        var result = Run(directory, ConfiguredLapsPolicy.AllCapturedComputers, log: log);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var reader = JudgementReader.Open(directory).Value;
        var summary = Scope(reader);
        Assert.Equal(ConfiguredLapsSchedulingState.Complete, summary.State);
        Assert.Equal((1L, 1L, 1L, 0L), (summary.ObservedComputers, summary.QuestionsConsidered,
            summary.SavedCalculations, summary.UnassessedComputers));
        using var captured = BundleReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!).Value;
        Assert.Equal(GroupA, saved.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.False(saved.IsObservedWmiResult);
        Assert.True(saved.HasOpenPolicyScope);
        Assert.Equal(summary.CaptureGenerationId, saved.CaptureGenerationId);
        Assert.Equal(summary.JudgementGenerationId, saved.JudgementGenerationId);
        var note = Assert.Single(log.Values.Where(value => value.Message == "configured-laps"));
        Assert.Contains(note.Details, detail => detail.Name == "saved" && detail.Value == "1");
        Assert.Contains(note.Details, detail => detail.Name == "calculation-ms");
        Assert.Contains(note.Details, detail => detail.Name == "storage-ms");
    }

    [Fact]
    public void AutomaticLapsMissingPlatformStillReceivesASavedUnresolvedAssessment()
    {
        var directory = Build(platform: false);
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        var summary = Scope(reader);
        Assert.Equal(1, summary.SavedCalculations);
        Assert.Equal(0, summary.UnassessedComputers);
        using var captured = BundleReader.Open(directory).Value;
        var saved = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!).Value;
        var projected = saved.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal);
        Assert.Null(projected.Value);
        Assert.NotNull(projected.UnresolvedCondition);
        Assert.NotNull(projected.Reason);
    }

    [Fact]
    public void AutomaticLapsScopeUsesMostDerivedComputerClassNotAnInheritedServiceAccountClass()
    {
        var service = new GpoSecurityRun.OtherObject("CN=Service," + GpoSecurityRun.Parent, Guid.NewGuid(),
            [new("objectClass", StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfText("top"), EvidenceValue.OfText("user"), EvidenceValue.OfText("computer"),
                    EvidenceValue.OfText("msDS-GroupManagedServiceAccount")])]);
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), additionalObjects: [service]);
        using (var captured = BundleReader.Open(directory).Value)
            Assert.Single(captured.StreamComputerIdentities(CancellationToken.None));
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(1, Scope(reader).ObservedComputers);
        Assert.Equal(1, Scope(reader).SavedCalculations);
    }

    [Fact]
    public void AutomaticLapsInputRefusalIsRecordedAsUnassessedAndDegradesThePublishedGeneration()
    {
        var directory = RefusedDirectory();
        var result = Run(directory, ConfiguredLapsPolicy.AllCapturedComputers);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(JudgementRunState.CompletedDegraded, result.Value);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(JudgementRunState.CompletedDegraded, reader.Description.State);
        var summary = Scope(reader);
        Assert.Equal(ConfiguredLapsSchedulingState.CompleteWithUnassessed, summary.State);
        Assert.Equal((1L, 0L, 1L), (summary.QuestionsConsidered, summary.SavedCalculations, summary.UnassessedComputers));
        using var captured = BundleReader.Open(directory).Value;
        var refused = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!);
        Assert.False(refused.IsSuccess);
        Assert.Equal("Evidence.GpoTemplateVersionResourceMismatch", refused.Error.Code);
    }

    [Fact]
    public void AutomaticLapsCancellationBeforePublicationKeepsThePreviousGeneration()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.Disabled).IsSuccess);
        var previous = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        using var cancellation = new CancellationTokenSource();
        var progress = new InlineProgress(value =>
        {
            if (value.Phase == JudgingPhase.EvaluatingObjects && value.WorkUnit == JudgingWorkUnit.Resources
                && value.WorkCompleted == 1) cancellation.Cancel();
        });
        Assert.Throws<OperationCanceledException>(() =>
            Run(directory, ConfiguredLapsPolicy.AllCapturedComputers, progress, token: cancellation.Token));
        Assert.Equal(previous, AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void AutomaticLapsUnexpectedFailureBeforePublicationKeepsThePreviousGeneration()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.Disabled).IsSuccess);
        var previous = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        var log = new Notes(message =>
        {
            if (message == "configured-laps") throw new IOException("Synthetic failure after configured LAPS storage.");
        });
        Assert.Throws<IOException>(() => Run(directory, ConfiguredLapsPolicy.AllCapturedComputers, log: log));
        Assert.Equal(previous, AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Fact]
    public void AutomaticLapsARefusedComputerDoesNotDiscardAnotherDomainsSavedAnswer()
    {
        var other = OtherComputer("CN=Second," + GpoSecurityRun.Child);
        var directory = RefusedDirectory([other]);
        var result = Run(directory, ConfiguredLapsPolicy.AllCapturedComputers);
        Assert.True(result.IsSuccess, result.Error?.Description);
        Assert.Equal(JudgementRunState.CompletedDegraded, result.Value);
        using var reader = JudgementReader.Open(directory).Value;
        var summary = Scope(reader);
        Assert.Equal((2L, 2L, 1L, 1L), (summary.ObservedComputers, summary.QuestionsConsidered,
            summary.SavedCalculations, summary.UnassessedComputers));
        using var captured = BundleReader.Open(directory).Value;
        var refused = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!);
        Assert.False(refused.IsSuccess);
        Assert.Equal("Evidence.GpoTemplateVersionResourceMismatch", refused.Error.Code);
        var saved = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(other.Dn)!);
        Assert.True(saved.IsSuccess, saved.Error?.Description);
        Assert.Equal(other.Guid, saved.Value.Computer.ObjectGuid);
    }

    [Fact]
    public void AutomaticLapsSummaryDoesNotOpenTheOriginalFactsProduct()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        var path = Path.Combine(directory, root.Segment(StoreSegmentRole.JudgementFacts).FileName);
        using (var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite))
        {
            var value = stream.ReadByte();
            stream.Position = 0;
            stream.WriteByte((byte)(value ^ 1));
        }
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Null(Record.Exception(() => reader.ReadConfiguredLapsScope()));
        Assert.Equal(1, Scope(reader).SavedCalculations);
    }

    [Fact]
    public void AutomaticLapsUnknownPolicyCannotBeginANewGeneration()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.Disabled).IsSuccess);
        var previous = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId;
        Assert.Throws<ArgumentOutOfRangeException>(() => Run(directory, (ConfiguredLapsPolicy)999));
        Assert.Equal(previous, AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
    }

    [Theory]
    [InlineData(ConfiguredLapsPolicy.Disabled, "Disabled")]
    [InlineData(ConfiguredLapsPolicy.AllCapturedComputers, "Complete")]
    public void AutomaticLapsEnabledEmptyScopeDiffersFromDisabledScope(ConfiguredLapsPolicy policy,
        string expected)
    {
        var directory = GpoSecurityRun.Build(new() { ComputerClass = "user", Derive = false });
        Assert.True(Run(directory, policy).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        var summary = Scope(reader);
        Assert.Equal(policy, summary.Policy);
        Assert.Equal(expected, summary.State.ToString());
        Assert.Equal((0L, 0L, 0L, 0L), (summary.ObservedComputers, summary.QuestionsConsidered,
            summary.SavedCalculations, summary.UnassessedComputers));
    }

    [Fact]
    public void AutomaticLapsDisabledAccountsRemainConfigurationQuestions()
    {
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])],
            accountControl: 4098, computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal(1, Scope(reader).SavedCalculations);
        using var captured = BundleReader.Open(directory).Value;
        var selected = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(GpoSecurityRun.Computer)!);
        Assert.True(selected.IsSuccess, selected.Error?.Description);
    }

    [Fact]
    public void AutomaticLapsMultipleComputersAreCalculatedWithoutSuppliedTargets()
    {
        var other = OtherComputer("CN=Second," + GpoSecurityRun.Parent);
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), additionalObjects: [other]);
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Equal((2L, 2L), (Scope(reader).QuestionsConsidered, Scope(reader).SavedCalculations));
        using var captured = BundleReader.Open(directory).Value;
        var computers = captured.StreamComputerIdentities(CancellationToken.None).ToArray();
        Assert.Equal(2, computers.Select(computer => computer.ObjectId).Distinct().Count());
        Assert.Equal(new[] { GpoSecurityRun.ComputerGuid, other.Guid }.Order(),
            computers.Select(computer => computer.ObjectGuid!.Value).Order());
        foreach (var computer in computers)
        {
            var selected = reader.ReadLapsConfiguredPolicy(captured.ReadObjectIdentity(computer.DistinguishedName)!);
            Assert.True(selected.IsSuccess, selected.Error?.Description);
            Assert.Equal(computer.ObjectId, selected.Value.Computer.ObjectId);
            Assert.Equal(computer.ObjectGuid, selected.Value.Computer.ObjectGuid);
            Assert.Equal(computer.CaptureGenerationId, selected.Value.CaptureGenerationId);
        }
    }

    [Fact]
    public void AutomaticLapsCompactScopeAndCalculationDoNotRebindDuplicateDnRows()
    {
        var other = OtherComputer(GpoSecurityRun.Computer);
        var directory = LapsPrecedenceRun.Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), additionalObjects: [other]);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var computers = reader.Bundle.StreamComputerIdentities(CancellationToken.None).ToArray();
        Assert.Equal(2, computers.Select(computer => computer.ObjectId).Distinct().Count());
        Assert.Equal(new[] { GpoSecurityRun.ComputerGuid, other.Guid }.Order(),
            computers.Select(computer => computer.ObjectGuid!.Value).Order());
        foreach (var computer in computers)
        {
            var calculated = reader.Read(computer, CancellationToken.None);
            Assert.True(calculated.IsSuccess, calculated.Error?.Description);
            Assert.Equal(computer.ObjectId, calculated.Value.Computer.ObjectId);
            Assert.Equal(computer.ObjectGuid, calculated.Value.Computer.ObjectGuid);
            Assert.Equal(computer.CaptureGenerationId, calculated.Value.CaptureGenerationId);
        }
    }

    [Fact]
    public void AutomaticLapsUsesOneProtectedSourceLifetimeAndDoesNotOwnTheBorrowedFiles()
    {
        var directory = Build();
        GpoSecurityRun.Derive(directory);
        using var counts = new JudgingInputReuseTests.Verifications(directory);
        using var files = new ProtectedRunFiles(directory);
        using (var borrowed = LapsConfiguredPolicyReader.Open(files, CancellationToken.None).Value) { }
        Assert.Null(Record.Exception(() =>
        {
            using var available = JudgingInputs.Open(files, CancellationToken.None).Value;
        }));
        var result = JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled,
            GpoSecurityRun.Captured.AddMinutes(2), GpoSecurityRun.Captured, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None, null, files, ConfiguredLapsPolicy.AllCapturedComputers);
        Assert.True(result.IsSuccess, result.Error?.Description);
        using var after = JudgingInputs.Open(files, CancellationToken.None).Value;
        Assert.NotNull(after.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer));
        Assert.Equal((1L, 1L, 1L), (counts.Evidence, counts.Derivation, counts.Formats));
    }

    [Fact]
    public void AutomaticLapsMembershipPreparationRetainsOnlyTheActiveComputer()
    {
        var directory = GpoSecurityRun.Build(new()
        {
            Entries = [new(GroupA, GpoSecurityRun.Read), new(GroupA, GpoSecurityRun.Apply, Scope: GpoSecurityRun.ApplyGuid)],
            Groups = [new("Computers", 1200, GpoSecurityRun.Global, false, [GpoSecurityRun.Computer], [])],
            OtherObjects = [OtherComputer("CN=Second," + GpoSecurityRun.Parent)],
        });
        using var reader = GpoSecurityFilterReader.Open(directory, CancellationToken.None).Value;
        var computers = reader.Bundle.StreamComputerIdentities(CancellationToken.None).ToArray();
        var policy = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        var cache = Assert.IsAssignableFrom<System.Collections.IDictionary>(typeof(GpoSecurityFilterReader)
            .GetField("_memberships", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(reader));
        foreach (var computer in computers.Append(computers[0]))
        {
            reader.Assess(computer, policy, CancellationToken.None);
            Assert.Single(cache);
            Assert.All(cache.Keys.Cast<(long Computer, string Resource)>(), key => Assert.Equal(computer.ObjectId, key.Computer));
        }
    }

    [Theory]
    [InlineData("state='Writing'")]
    [InlineData("state='2'")]
    [InlineData("policy='1'")]
    [InlineData("generation='00000000-0000-0000-0000-000000000001'")]
    [InlineData("evidence_seal=printf('%064d',0)")]
    [InlineData("derivation_generation='00000000-0000-0000-0000-000000000001'")]
    [InlineData("considered=0")]
    [InlineData("calculated=0")]
    [InlineData("unassessed=1")]
    [InlineData("observed=2")]
    public void AutomaticLapsSummaryRejectsInconsistentOrForeignScope(string assignment)
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        Edit(directory, connection => Execute(connection, "UPDATE laps_configured_scope SET " + assignment));
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.ReadConfiguredLapsScope());
    }

    [Theory]
    [InlineData("DELETE FROM laps_configured_scope")]
    [InlineData("UPDATE laps_configured_scope SET capture_generation='00000000-0000-0000-0000-000000000001'")]
    [InlineData("UPDATE laps_configured_scope SET capture_complete=0")]
    [InlineData("DELETE FROM laps_configured_calculation; DELETE FROM laps_configured_selection")]
    [InlineData("INSERT INTO laps_configured_unassessed SELECT s.computer_id,c.payload,s.fingerprint FROM laps_configured_selection s JOIN laps_configured_calculation c USING(computer_id)")]
    [InlineData("UPDATE laps_configured_scope SET calculated=0,unassessed=1,state='CompleteWithUnassessed'")]
    public void AutomaticLapsPublicationRequiresTheExactCompletedScopeAndStoredQuestionCounts(string mutation)
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        ConfiguredLapsSchedulingSummary expected;
        using (var reader = JudgementReader.Open(directory).Value) expected = Scope(reader);
        Edit(directory, connection =>
        {
            Execute(connection, mutation);
            Assert.Throws<InvalidDataException>(() => LapsSchedulingStorage.RequirePublishable(connection, expected));
        });
    }

    [Theory]
    [InlineData("hash")]
    [InlineData("computer")]
    [InlineData("row")]
    [InlineData("capture")]
    [InlineData("guid")]
    [InlineData("dn")]
    [InlineData("domain")]
    [InlineData("reason")]
    [InlineData("code")]
    [InlineData("description")]
    public void AutomaticLapsRefusalRequiresOriginalComputerBindingAndAnIntactReason(string field)
    {
        var directory = RefusedDirectory();
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        CapturedObjectIdentity computer;
        using (var captured = BundleReader.Open(directory).Value) computer = captured.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        Edit(directory, connection =>
        {
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload FROM laps_configured_unassessed";
            var payload = JsonNode.Parse((string)command.ExecuteScalar()!)!.AsObject();
            switch (field)
            {
                case "computer": payload["Computer"] = null; break;
                case "row": payload["Computer"]!["ObjectId"] = computer.ObjectId + 1; break;
                case "capture": payload["Computer"]!["CaptureGenerationId"] = Guid.NewGuid(); break;
                case "guid": payload["Computer"]!["ObjectGuid"] = Guid.NewGuid(); break;
                case "dn": payload["Computer"]!["DistinguishedName"] = "CN=Different," + GpoSecurityRun.Parent; break;
                case "domain": payload["Computer"]!["DomainFqdn"] = "different.test"; break;
                case "reason": payload["Reason"] = null; break;
                case "code": payload["Reason"]!["Code"] = ""; break;
                case "description": payload["Reason"]!["Description"] = ""; break;
            }
            var text = payload.ToJsonString();
            command.CommandText = "UPDATE laps_configured_unassessed SET payload=$payload,fingerprint=$hash";
            command.Parameters.AddWithValue("$payload", text);
            command.Parameters.AddWithValue("$hash", field == "hash" ? new string('0', 64) : LapsConfiguredPolicyStorage.Fingerprint(text));
            Assert.Equal(1, command.ExecuteNonQuery());
        });
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.ReadLapsConfiguredPolicy(computer));
    }

    [Fact]
    public void AutomaticLapsAComputerWithoutASavedResultOrRefusalCannotBeCalledAnEmptyPolicy()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        CapturedObjectIdentity computer;
        using (var captured = BundleReader.Open(directory).Value) computer = captured.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        Edit(directory, connection =>
        {
            Execute(connection, "DELETE FROM laps_configured_calculation");
            Execute(connection, "DELETE FROM laps_configured_selection");
        });
        using var reader = JudgementReader.Open(directory).Value;
        Assert.Throws<InvalidDataException>(() => reader.ReadLapsConfiguredPolicy(computer));
    }

    [Fact]
    public void AutomaticLapsSummaryReadbackHonoursCancellationAndDisposal()
    {
        var directory = Build();
        Assert.True(Run(directory, ConfiguredLapsPolicy.AllCapturedComputers).IsSuccess);
        using var reader = JudgementReader.Open(directory).Value;
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => reader.ReadConfiguredLapsScope(cancellation.Token));
        reader.Dispose();
        Assert.Throws<ObjectDisposedException>(() => reader.ReadConfiguredLapsScope());
    }

    private static ConfiguredLapsSchedulingSummary Scope(JudgementReader reader)
    {
        var result = reader.ReadConfiguredLapsScope();
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }

    private static string RefusedDirectory(IReadOnlyList<GpoSecurityRun.OtherObject>? additionalObjects = null)
    {
        var options = GpoComputerApplicabilityTests.Inputs() with
        {
            Derive = false,
            ComputerAttributes = GpoDirectoryWmiAssessmentTests.Platform(),
            OtherObjects = additionalObjects ?? [],
        };
        return GpoSecurityRun.Build(options with
        {
            TemplateVersion = (@"\\example.test\SYSVOL\unrelated", options.TemplateVersion!.Value.Observation),
        });
    }

    private static GpoSecurityRun.OtherObject OtherComputer(string dn) => new(dn, Guid.NewGuid(),
        [new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("computer")]),
            new("objectSid", StoredAttributeCompleteness.Complete,
                [EvidenceValue.OfBytes(Sid.ToBytes((dn.EndsWith(GpoSecurityRun.Child, StringComparison.OrdinalIgnoreCase)
                    ? GpoSecurityRun.ChildSid : GpoSecurityRun.ParentSid) + "-1101")!)]),
            new("userAccountControl", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("4096")]),
            .. GpoDirectoryWmiAssessmentTests.Platform()]);

    private static void Edit(string directory, Action<SqliteConnection> edit)
    {
        var root = AnalysisStoreLifecycle.ResolveRoot(directory, AnalysisStoreKind.Judgement).Value;
        using (var connection = new SqliteConnection("Data Source=" + Path.Combine(directory,
            root.Segment(StoreSegmentRole.Judgement).FileName) + ";Pooling=False"))
        {
            connection.Open();
            using var attach = connection.CreateCommand();
            attach.CommandText = "ATTACH DATABASE $file AS facts";
            attach.Parameters.AddWithValue("$file", Path.Combine(directory, root.Segment(StoreSegmentRole.JudgementFacts).FileName));
            attach.ExecuteNonQuery();
            edit(connection);
            Execute(connection, "PRAGMA wal_checkpoint(TRUNCATE)");
            Execute(connection, "PRAGMA facts.wal_checkpoint(TRUNCATE)");
        }
        TestSealing.ResealAnalysis(directory, new(AnalysisStoreKind.Judgement, root.GenerationId));
    }

    private static void Execute(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string Build(bool platform = true) => LapsPrecedenceRun.Build(
        [new(1, [Number("BackupDirectory", 2), Number("ADPasswordEncryptionEnabled", 1), TextValue(Principal, GroupA)])],
        computerAttributes: platform ? GpoDirectoryWmiAssessmentTests.Platform() : []);

    private static Result<JudgementRunState> Run(string directory, ConfiguredLapsPolicy policy,
        IProgress<JudgingRun.JudgingProgress>? progress = null, IRunLog? log = null, CancellationToken token = default)
    {
        using var files = new ProtectedRunFiles(directory);
        return JudgingRun.JudgeAudit(directory, [], PathRequesterPolicy.Disabled,
            GpoSecurityRun.Captured.AddMinutes(2), GpoSecurityRun.Captured, progress ?? JudgingRun.NobodyIsWatching,
            log ?? RunLog.Discarded, token, null, files, policy);
    }

    private sealed class InlineProgress(Action<JudgingRun.JudgingProgress> report) : IProgress<JudgingRun.JudgingProgress>
    {
        public void Report(JudgingRun.JudgingProgress value) => report(value);
    }

    private sealed class Notes(Action<string>? onNote = null) : IRunLog
    {
        internal sealed record Entry(string Message, IReadOnlyList<RunLogDetail> Details);
        internal ConcurrentQueue<Entry> Values { get; } = new();
        public void Note(string phase, string message, IReadOnlyList<RunLogDetail> detail)
        {
            onNote?.Invoke(message);
            Values.Enqueue(new(message, detail));
        }
        public void Record(string phase, AuditError error, IReadOnlyList<RunLogDetail> detail) => Values.Enqueue(new(error.Code, detail));
    }
}
