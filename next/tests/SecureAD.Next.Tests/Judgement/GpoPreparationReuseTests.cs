using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using SecureAD.Measure;
using Xunit;
using static SecureAD.Next.Tests.Judgement.LapsPrecedenceRun;

namespace SecureAD.Next.Tests.Judgement;

[CollectionDefinition("GPO preparation diagnostics", DisableParallelization = true)]
public sealed class GpoPreparationDiagnosticsCollection { }

[Collection("GPO preparation diagnostics")]
public sealed class GpoPreparationReuseTests
{
    [Fact]
    public void MetadataKeepsExactRequestedViewsAndReadsEachCapturedFieldOnce()
    {
        var directory = Build([new(1, [TextValue(Principal, GroupA)])]);
        using var reader = BundleReader.Open(directory).Value;
        using var reference = BundleReader.Open(directory).Value;
        var policy = reader.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        string[][] views = [["objectClass"], ["objectClass", "flags", "versionNumber"],
            ["FLAGS", "objectClass"], ["gPCMachineExtensionNames"], ["displayName", "gPCWQLFilter"]];
        using var counts = new Observations(directory);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        for (var pass = 0; pass < 3; pass++)
            foreach (var view in views)
                Assert.Equal(JsonSerializer.Serialize(reference.ReadObjectAttributesAt(policy, view).Snapshot()),
                    JsonSerializer.Serialize(reader.ReadGpoPolicyValues(policy, view, CancellationToken.None)));
        Assert.Equal(15, counts.Source("policy-metadata-request"));
        Assert.Equal(4, counts.Source("policy-metadata-read"));
        Assert.Equal(11, counts.Source("policy-metadata-hit"));
        Assert.Equal(4, trace.Sql.Count(sql => IsMetadataRead(sql, policy.ObjectId)));
        Assert.Equal(15, trace.Sql.Count(IsIdentityGuard));
        Assert.Single(trace.Sql.Where(sql => sql.Contains(" FROM objectclass_value WHERE object_id = ", StringComparison.Ordinal)));
        var empty = reader.ReadGpoPolicyValues(policy, ["displayName"], CancellationToken.None);
        Assert.Empty(Assert.Single(empty.Attributes).Values);
        Assert.Throws<ArgumentException>(() => reader.ReadGpoPolicyValues(policy, ["not-a-catalogue-field"], CancellationToken.None));
    }

    [Fact]
    public void MetadataSnapshotsCannotPoisonSharedBinaryOrCollectionValues()
    {
        var bytes = Sid.ToBytes(GpoSecurityRun.ParentSid + "-1500")!;
        var directory = GpoSecurityRun.Build(new()
        {
            Derive = false,
            PolicyAttributes = [new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(bytes)])],
        });
        using var reader = BundleReader.Open(directory).Value;
        var policy = reader.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        var first = reader.ReadGpoPolicyValues(policy, ["objectSid", "objectClass"], CancellationToken.None);
        first.Find("objectSid")!.OnlyValue!.Bytes![0] ^= 0xff;
        Assert.Throws<NotSupportedException>(() => ((IList<ObjectAttribute>)first.Attributes)[0] = first.Attributes[1]);
        var second = reader.ReadGpoPolicyValues(policy, ["objectSid", "objectClass"], CancellationToken.None);
        Assert.Equal(bytes, second.Find("objectSid")!.OnlyValue!.Bytes);
    }

    [Fact]
    public void MetadataAndTemplatesBelongToTheirExactReaderCaptureAndSourceRole()
    {
        var firstDirectory = Build([new(1, [TextValue(Principal, GroupA)])]);
        var otherDirectory = Build([new(1, [TextValue(Principal, GroupB)], Flags: "2")]);
        using var file = ProtectedStoreFile.OpenEvidence(firstDirectory).Value;
        using var first = BundleReader.Open(file).Value;
        var original = first.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        Assert.True(first.ReadGpoProtocolInputs(original, CancellationToken.None).IsSuccess);
        using (var second = BundleReader.Open(file).Value)
        {
            using var trace = new JudgingInputReuseTests.Statements(second.Connection);
            Assert.True(second.ReadGpoProtocolInputs(original, CancellationToken.None).IsSuccess);
            Assert.Single(trace.Sql.Where(sql => IsMetadataRead(sql, original.ObjectId)));
            Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM gpo_template_version", StringComparison.Ordinal)));
        }
        using var other = BundleReader.Open(otherDirectory).Value;
        var selected = other.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        Assert.Equal("2", other.ReadGpoProtocolInputs(selected, CancellationToken.None).Value.PolicyValues.Find("flags")!.OnlyValue!.Text);
        Assert.Throws<InvalidDataException>(() => other.ReadGpoProtocolInputs(original, CancellationToken.None));
        using var navigation = BundleReader.OpenNavigation(firstDirectory).Value;
        Assert.Throws<InvalidDataException>(() => navigation.ReadGpoPolicyValues(original, ["objectClass"], CancellationToken.None));
    }

    [Theory]
    [InlineData("caller-cancel")]
    [InlineData("opening-cancel")]
    [InlineData("disposed")]
    public void WarmPreparedInputsStillRefuseCancelledAndDisposedReaders(string lifetime)
    {
        var directory = Build([new(1, [TextValue(Principal, GroupA)])]);
        using var opening = new CancellationTokenSource();
        using var caller = new CancellationTokenSource();
        using var file = ProtectedStoreFile.OpenEvidence(directory, opening.Token).Value;
        using var reader = BundleReader.Open(file, opening.Token).Value;
        var policy = reader.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        reader.ReadGpoProtocolInputs(policy, CancellationToken.None);
        reader.ReadGpoWmiFilter(policy, CancellationToken.None);
        if (lifetime == "caller-cancel") caller.Cancel();
        else if (lifetime == "opening-cancel") opening.Cancel();
        else reader.Dispose();
        Action[] reads = [
            () => reader.ReadGpoPolicyValues(policy, ["objectClass"], caller.Token),
            () => reader.ReadGpoProtocolInputs(policy, caller.Token),
            () => reader.ReadGpoWmiFilter(policy, caller.Token),
        ];
        foreach (var read in reads)
            if (lifetime == "disposed") Assert.Throws<ObjectDisposedException>(read);
            else Assert.Throws<OperationCanceledException>(read);
    }

    [Fact]
    public void WarmTemplateStillRunsIdentityAndGuidUniquenessGuards()
    {
        var directory = Build([new(1, [TextValue(Principal, GroupA)])]);
        using var reader = BundleReader.Open(directory).Value;
        var policy = reader.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        var first = reader.ReadGpoProtocolInputs(policy, CancellationToken.None).Value;
        var second = reader.ReadGpoProtocolInputs(policy, CancellationToken.None).Value;
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Equal(2, trace.Sql.Count(IsIdentityGuard));
        Assert.Equal(2, trace.Sql.Count(sql => sql.StartsWith("SELECT object_id FROM captured_object WHERE object_guid=", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM gpo_template_version", StringComparison.Ordinal)));
        Assert.Throws<InvalidDataException>(() => reader.ReadGpoProtocolInputs(policy with { ObjectGuid = Guid.NewGuid() }, CancellationToken.None));
        Assert.Throws<InvalidDataException>(() => reader.ReadGpoProtocolInputs(policy with { CaptureGenerationId = Guid.NewGuid() }, CancellationToken.None));
    }

    [Fact]
    public void WmiPreparationSharesOnlyExactCapturedFilterRowsNotPolicyOrQueryText()
    {
        Policy[] policies = [new(1, [TextValue(Principal, GroupA)], Filter: 1),
            new(2, [TextValue(Principal, GroupB)], Filter: 1), new(3, [], Filter: 2)];
        var directory = Build(policies);
        using var reader = BundleReader.Open(directory).Value;
        var identities = policies.Select(policy => reader.ReadObjectIdentity(PolicyDn(policy))!).ToArray();
        using var counts = new Observations(directory);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        var first = identities.Select(policy => reader.ReadGpoWmiFilter(policy, CancellationToken.None)).ToArray();
        foreach (var (policy, expected) in identities.Zip(first))
        {
            var repeated = reader.ReadGpoWmiFilter(policy, CancellationToken.None);
            Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(repeated));
            Assert.Equal(policy.ObjectId, repeated.Policy.ObjectId);
        }
        Assert.Equal(first[0].Filter!.ObjectId, first[1].Filter!.ObjectId);
        Assert.NotEqual(first[0].Filter!.ObjectId, first[2].Filter!.ObjectId);
        Assert.Equal(first[0].Definition.Value[0].Query, first[2].Definition.Value[0].Query);
        Assert.Equal(6, counts.Source("wmi-definition-request"));
        Assert.Equal(2, counts.Source("wmi-definition-decode"));
        Assert.Equal(4, counts.Source("wmi-definition-hit"));
        Assert.Equal(3, counts.Source("wmi-reference-decode"));
        Assert.Equal(2, counts.Native("wql.native_parses"));
        Assert.Equal(2, trace.Sql.Count(sql => first.Select(value => value.Filter!.ObjectId).Distinct()
            .Any(id => IsMetadataRead(sql, id))));
    }

    [Theory]
    [InlineData("wrapper")]
    [InlineData("language")]
    [InlineData("native-rejection")]
    public void WmiUnresolvedStatesRemainOriginalAndNativeFailuresAreNotFrozen(string kind)
    {
        const string rejected = "SELECT * FROM Win32_OperatingSystem WHERE";
        const string query = "SELECT * FROM Win32_OperatingSystem WHERE ProductType = 3";
        var definition = kind == "wrapper" ? "2;3;10;55;WQL;root\\CIMv2;short;"
            : FormattableString.Invariant($"1;3;10;{(kind == "native-rejection" ? rejected : query).Length};{(kind == "language" ? "XQL" : "WQL")};root\\CIMv2;{(kind == "native-rejection" ? rejected : query)};");
        var directory = Build([new(1, [])], filterDefinitions: new Dictionary<int, string> { [1] = definition });
        using var reader = BundleReader.Open(directory).Value;
        var policy = reader.ReadObjectIdentity(GpoSecurityRun.Policy)!;
        using var counts = new Observations(directory);
        var first = reader.ReadGpoWmiFilter(policy, CancellationToken.None);
        var second = reader.ReadGpoWmiFilter(policy, CancellationToken.None);
        Assert.Equal(first.Definition.IsSuccess, second.Definition.IsSuccess);
        if (first.Definition.IsSuccess)
            Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        else
        {
            Assert.Equal(first.Definition.Error, second.Definition.Error);
            Assert.Equal(first.Policy, second.Policy);
            Assert.Equal(first.Reference, second.Reference);
            Assert.Equal(first.Filter, second.Filter);
            Assert.Equal(JsonSerializer.Serialize(first.PolicyValues), JsonSerializer.Serialize(second.PolicyValues));
            Assert.Equal(JsonSerializer.Serialize(first.FilterValues), JsonSerializer.Serialize(second.FilterValues));
        }
        if (kind == "wrapper") Assert.False(first.Definition.IsSuccess);
        else Assert.Equal(kind == "language" ? WqlReadingState.Unsupported : WqlReadingState.Rejected,
            Assert.Single(first.Definition.Value).Reading.State);
        Assert.Equal(kind == "native-rejection" ? 2 : 1, counts.Source("wmi-definition-decode"));
        Assert.Equal(kind == "native-rejection" ? 2 : 0, counts.Native("wql.native_parses"));
        Assert.Equal(definition, first.FilterValues!.Find("msWMI-Parm2")!.OnlyValue!.Text);
    }

    [Theory]
    [InlineData("Unavailable", null, false)]
    [InlineData("Unavailable", 0, false)]
    [InlineData("Rejected", -1, false)]
    [InlineData("Unsupported", -1, false)]
    [InlineData("Unsupported", null, true)]
    [InlineData("ParsedConditions", null, true)]
    public void OnlyStableSourceDefinitionReadingsAreReusable(string state, int? native, bool reusable)
    {
        var reading = new WqlQueryReading("SELECT", Enum.Parse<WqlReadingState>(state), null, null, native);
        var result = Result<ImmutableArray<CapturedWmiQuery>>.Success([new("WQL", "root\\CIMv2", "SELECT", reading)]);
        Assert.Equal(reusable, BundleReader.CanReuseWmiDefinition(result));
    }

    [Fact]
    public void SharedPreparationDoesNotShareComputerConditionsOrConfiguredAnswers()
    {
        var other = OtherComputer("CN=Workstation," + GpoSecurityRun.Parent, "Windows 11 Enterprise");
        var directory = Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), additionalObjects: [other]);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        using var counts = new Observations(directory);
        var first = reader.Read(reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!, CancellationToken.None).Value;
        var secondIdentity = reader.Bundle.ReadObjectIdentity(other.Dn)!;
        var second = reader.Read(secondIdentity, CancellationToken.None).Value;
        Assert.Equal(1, counts.Source("protocol-preparation"));
        Assert.Equal(1, counts.Source("registry-extension-preparation"));
        Assert.Equal(1, counts.Source("registry-settings-read"));
        using var fresh = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var independent = fresh.Read(secondIdentity, CancellationToken.None).Value;
        Assert.Equal(JsonSerializer.Serialize(independent), JsonSerializer.Serialize(second));
        var firstPolicy = Assert.Single(first.Inputs.Policies);
        var secondPolicy = Assert.Single(second.Inputs.Policies);
        Assert.NotEqual(firstPolicy.Conditional.Wmi!.Condition.ComputerObjectId, secondPolicy.Conditional.Wmi!.Condition.ComputerObjectId);
        Assert.Equal(firstPolicy.Conditional.Wmi.Condition.FilterObjectId, secondPolicy.Conditional.Wmi.Condition.FilterObjectId);
        Assert.Equal(GpoDirectoryWmiState.MatchesRecordedPlatform, firstPolicy.DirectoryAssessment.State);
        Assert.Equal(GpoDirectoryWmiState.DoesNotMatchRecordedPlatform, secondPolicy.DirectoryAssessment.State);
        Assert.Equal(GroupA, first.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.NotEqual(GroupA, second.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
    }

    [Fact]
    public void ExcludedComputerCannotCacheMissingSettingsForAnotherComputer()
    {
        var other = OtherComputer("CN=Included," + GpoSecurityRun.Parent, "Windows Server 2022 Standard");
        var directory = Build([new(1, [TextValue(Principal, GroupA)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform(), additionalObjects: [other],
            permissions: [new(GpoSecurityRun.ComputerSid, GpoSecurityRun.Apply, Deny: true, Scope: GpoSecurityRun.ApplyGuid),
                new("S-1-5-11", GpoSecurityRun.Read), new("S-1-5-11", GpoSecurityRun.Apply, Scope: GpoSecurityRun.ApplyGuid)]);
        GpoSecurityRun.Derive(directory);
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var excluded = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        var included = reader.Bundle.ReadObjectIdentity(other.Dn)!;
        using var counts = new Observations(directory);
        var first = reader.Read(excluded, CancellationToken.None).Value;
        Assert.Equal(GpoApplicabilityState.DoesNotApply, Assert.Single(first.Inputs.Policies).PolicyState);
        Assert.Null(Assert.Single(first.RegistryPolicies).Registry);
        Assert.Equal(0, counts.Source("registry-settings-read"));
        var second = reader.Read(included, CancellationToken.None).Value;
        Assert.Equal(GpoApplicabilityState.Applies, Assert.Single(second.Inputs.Policies).PolicyState);
        Assert.NotNull(Assert.Single(second.RegistryPolicies).Registry);
        Assert.Equal(GroupA, second.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.Null(Assert.Single(reader.Read(excluded, CancellationToken.None).Value.RegistryPolicies).Registry);
        Assert.Equal(1, counts.Source("registry-settings-read"));
        Assert.Equal(1, counts.Native("registry.instruction_decodes"));
    }

    [Fact]
    public void RegistryPreparationPreservesOccurrenceOrderAndOwnsBytesForEachAnswer()
    {
        var directory = Build([new(1, [TextValue(Principal, GroupA), Number("BackupDirectory", 2),
            TextValue("**DeleteValues", Principal + ";BackupDirectory"), TextValue(Principal, GroupB)])],
            computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        using var counts = new Observations(directory);
        var first = reader.Read(computer, CancellationToken.None).Value;
        var registry = Assert.Single(first.RegistryPolicies);
        Assert.Equal(new[] { 0, 1, 2, 2, 3 }, registry.Instructions.Select(value => value.EntryIndex));
        Assert.Same(registry.Registry!.Settings[2], registry.Instructions[2].Source);
        Assert.Same(registry.Instructions[2].Source, registry.Instructions[3].Source);
        var expected = registry.Registry.Settings[^1].Data.ToArray();
        registry.Registry.Settings[^1].Data[0] ^= 0xff;
        var second = reader.Read(computer, CancellationToken.None).Value;
        var next = Assert.Single(second.RegistryPolicies);
        Assert.Equal(expected, next.Registry!.Settings[^1].Data);
        Assert.Equal(expected, next.Instructions[^1].Source.Data);
        Assert.Equal(GroupB, second.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.Principal);
        Assert.Equal(1, counts.Source("registry-settings-read"));
        Assert.Equal(1, counts.Native("registry.instruction_decodes"));
    }

    [Theory]
    [InlineData("partial")]
    [InlineData("parse")]
    [InlineData("unsupported")]
    public void ReusedRegistryInputsKeepIncompleteAndUnsupportedInfluence(string kind)
    {
        var policy = new Policy(1, kind == "unsupported" ? [TextValue("**DelVals", " ")] : [TextValue(Principal, GroupA)],
            Outcome: kind == "partial" ? GpoSettingsOutcome.PartiallyRead : GpoSettingsOutcome.Read,
            ParseErrors: kind == "parse" ? ["Recorded parse failure"] : []);
        var directory = Build([policy], computerAttributes: GpoDirectoryWmiAssessmentTests.Platform());
        using var reader = LapsConfiguredPolicyReader.Open(directory, CancellationToken.None).Value;
        var computer = reader.Bundle.ReadObjectIdentity(GpoSecurityRun.Computer)!;
        var first = reader.Read(computer, CancellationToken.None).Value;
        var second = reader.Read(computer, CancellationToken.None).Value;
        Assert.Equal(JsonSerializer.Serialize(first), JsonSerializer.Serialize(second));
        Assert.Equal(LapsConfiguredValueState.Unresolved,
            second.UnderDirectoryAssessment(LapsPolicySetting.ADPasswordEncryptionPrincipal).Value!.State);
        Assert.NotEmpty(second.Limitations);
        Assert.Equal(kind != "partial" && kind != "parse", Assert.Single(second.RegistryPolicies).Registry!.IsComplete);
    }

    private static GpoSecurityRun.OtherObject OtherComputer(string name, string platform) => new(name, Guid.NewGuid(),
        [Text("objectClass", "top", "user", "computer"), Text("userAccountControl", "4096"),
            Text("primaryGroupID", "515"), Text("operatingSystem", platform), Text("operatingSystemVersion", "10.0 (20348)"),
            new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes(GpoSecurityRun.ParentSid + "-1101")!)])]);

    private static EvidenceAttribute Text(string name, params string[] values) =>
        new(name, StoredAttributeCompleteness.Complete, values.Select(EvidenceValue.OfText).ToArray());

    private static bool IsMetadataRead(string sql, long id) =>
        sql.StartsWith("SELECT o.object_id, o.distinguished_name,", StringComparison.Ordinal)
        && sql.Contains(" FROM captured_object AS o ", StringComparison.Ordinal)
        && sql.Contains(FormattableString.Invariant($" WHERE o.object_id = {id} LIMIT 1"), StringComparison.Ordinal);

    private static bool IsIdentityGuard(string sql) =>
        sql.StartsWith("SELECT 1 FROM captured_object WHERE object_id=", StringComparison.Ordinal);

    private sealed class Observations : IDisposable
    {
        private readonly CancellationTokenSource _stopping = new();
        private readonly EnterpriseBaselineObservation _observer;
        internal Observations(string directory) => _observer = new(TempDirectories.Create("gpo-preparation-counts"),
            8L * 1024 * 1024 * 1024, _stopping, directory);
        internal long Source(string operation) => _observer.GpoPreparations.GetValueOrDefault(operation);
        internal long Native(string operation) => _observer.NativePreparations.GetValueOrDefault(operation);
        public void Dispose() { _observer.Dispose(); _stopping.Dispose(); }
    }
}
