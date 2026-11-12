using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Measure;
using Xunit;

namespace SecureAD.Next.Tests.Judgement;

public sealed class ConfiguredLapsMeasurementTests
{
    [Theory]
    [InlineData(0, 2, 1, 0)]
    [InlineData(10, 2, 1, 0)]
    [InlineData(9, 1, 1, 0)]
    [InlineData(9, 2, 0, 0)]
    [InlineData(9, 2, 1, -9)]
    [InlineData(9, 2, 1, 1)]
    public void MeasurementRejectsAnUnrepresentableShapeBeforeWriting(int computers, int policies, int depth, int filler) =>
        Assert.Throws<ArgumentException>(() => new ConfiguredLapsShape(computers, policies, depth, filler).Validate());

    [Fact]
    public void SyntheticLapsRecipeHasIndependentComputerPolicyFilterAndPartitionCounts()
    {
        var root = TempDirectories.Create("configured-laps-measure");
        var shape = new ConfiguredLapsShape(27, 2, 1, 9);
        ConfiguredLapsWorkload.Write(root, shape, CancellationToken.None);
        var captured = ConfiguredLapsMeasurement.InspectCaptured(root);
        Assert.Equal(new ConfiguredLapsCapturedCounts(137, 27, 18, 18, 11), captured);
        Assert.Equal(137, shape.Objects);
        using var reader = BundleReader.Open(root).Value;
        var folder = ConfiguredLapsWorkload.Identity("folder/0/0");
        var dn = "CN=" + folder.ToString("B") + ",CN=Policies,CN=System," + ConfiguredLapsWorkload.Domain(0);
        var policy = reader.ReadObjectIdentity(dn)!;
        Assert.NotEqual(folder, policy.ObjectGuid);
        Assert.Equal(ConfiguredLapsWorkload.Identity(dn), policy.ObjectGuid);
    }

    [Fact]
    public void MeasurementNameLookupCountsMatchExecutedSqlAndExcludeOtherSources()
    {
        var directory = LapsPrecedenceRun.Build([new(1,
            [LapsPrecedenceRun.TextValue(LapsPrecedenceRun.Principal, LapsPrecedenceRun.GroupA)])]);
        var other = LapsPrecedenceRun.Build([new(1, [])]);
        using var reader = BundleReader.Open(directory).Value;
        using var unrelated = BundleReader.Open(other).Value;
        using var stopping = new CancellationTokenSource();
        using var observer = new EnterpriseBaselineObservation(TempDirectories.Create("name-lookup-observation"),
            8L * 1024 * 1024 * 1024, stopping, directory);
        using var trace = new JudgingInputReuseTests.Statements(reader.Connection);
        unrelated.ReadObjectIdentity(GpoSecurityRun.Policy);
        observer.Measure("Judgement", () =>
        {
            reader.ReadObjectNameMatch(GpoSecurityRun.Policy);
            reader.ReadObjectIdentity(GpoSecurityRun.Policy);
            reader.ReadObjectNameMatch(GpoSecurityRun.Policy);
            reader.ReadObjectIdentity(GpoSecurityRun.Policy);
            return true;
        });
        observer.Dispose();
        Assert.Equal(new[] { reader.Connection.DataSource }, observer.NameLookupSources);
        Assert.Equal(2, observer.NameLookups.GetValueOrDefault("name-request"));
        Assert.Equal(1, observer.NameLookups.GetValueOrDefault("name-cache-hit"));
        Assert.Equal(2, observer.NameLookups.GetValueOrDefault("identity-request"));
        Assert.Equal(1, observer.NameLookups.GetValueOrDefault("identity-cache-hit"));
        Assert.Equal(1, observer.NameLookups.GetValueOrDefault("exact-hit"));
        Assert.Equal(1, observer.NameLookups.GetValueOrDefault("exact-sql"));
        Assert.Equal(1, observer.NameLookups.GetValueOrDefault("identity-row-sql"));
        Assert.Equal(1, observer.NameLookups.GetValueOrDefault("uniqueness-sql"));
        Assert.False(observer.NameLookups.ContainsKey("identity-nocase-sql"));
        Assert.Equal(3, trace.Sql.Count(sql => sql != "SELECT 73"));
        Assert.Single(trace.Sql.Where(sql => sql.Contains("GROUP BY distinguished_name COLLATE NOCASE", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.StartsWith("SELECT object_id FROM captured_object WHERE distinguished_name=", StringComparison.Ordinal)
            && !sql.Contains("COLLATE NOCASE", StringComparison.Ordinal)));
        Assert.Single(trace.Sql.Where(sql => sql.Contains("FROM captured_object o WHERE o.object_id=", StringComparison.Ordinal)));
    }

    [Theory]
    [InlineData(ConfiguredLapsPolicy.Disabled)]
    [InlineData(ConfiguredLapsPolicy.AllCapturedComputers)]
    public void CorrectScopeCountsHaveWorkingPositiveControls(ConfiguredLapsPolicy policy)
    {
        var scenario = Scenario();
        var enabled = policy == ConfiguredLapsPolicy.AllCapturedComputers;
        var scope = new ConfiguredLapsScope(policy.ToString(), enabled ? "Complete" : "Disabled",
            27, enabled ? 27 : 0, enabled ? 27 : 0, enabled ? 0 : 27,
            Generation, scenario.CaptureGeneration, scenario.EvidenceSeal);
        Assert.Null(Record.Exception(() => ConfiguredLapsMeasurement.ValidateScope(scope, policy, scenario, Generation)));
    }

    [Theory]
    [InlineData("generation")]
    [InlineData("capture")]
    [InlineData("seal")]
    [InlineData("policy")]
    [InlineData("observed")]
    [InlineData("state")]
    [InlineData("considered")]
    [InlineData("calculated")]
    [InlineData("unassessed")]
    public void MeasurementCannotPassWithWrongBindingOrIncompleteQuestions(string field)
    {
        var scenario = Scenario();
        var scope = new ConfiguredLapsScope("AllCapturedComputers", "Complete", 27, 27, 27, 0,
            Generation, scenario.CaptureGeneration, scenario.EvidenceSeal);
        scope = field switch
        {
            "generation" => scope with { Generation = Guid.NewGuid() },
            "capture" => scope with { CaptureGeneration = Guid.NewGuid() },
            "seal" => scope with { EvidenceSeal = new string('b', 64) },
            "policy" => scope with { Policy = "Disabled" },
            "observed" => scope with { Observed = 0 },
            "state" => scope with { State = "CompleteWithUnassessed" },
            "considered" => scope with { Considered = 0 },
            "calculated" => scope with { Calculated = 0 },
            "unassessed" => scope with { Unassessed = 1 },
            _ => throw new InvalidOperationException("Unknown test field."),
        };
        Assert.Throws<InvalidDataException>(() => ConfiguredLapsMeasurement.ValidateScope(scope,
            ConfiguredLapsPolicy.AllCapturedComputers, scenario, Generation));
    }

    private static readonly Guid Generation = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static ConfiguredLapsScenario Scenario() => new(new(27, 2, 1, 9),
        Guid.Parse("00000000-0000-0000-0000-000000000002"), new string('a', 64), []);
}
