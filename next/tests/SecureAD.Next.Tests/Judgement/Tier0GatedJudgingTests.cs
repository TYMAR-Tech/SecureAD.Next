using System.Security.AccessControl;
using Microsoft.Data.Sqlite;
using SecureAD.Evidence;
using SecureAD.Evidence.Run;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Kernel.Security;
using Xunit;
using Xunit.Abstractions;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

/// <summary>
/// Drives the real judging path through the Tier-0 gate, per decision 0116.
/// </summary>
/// <remarks>
/// <para>
/// <b>A standalone selector nobody calls would not be the change.</b> These tests run
/// <see cref="JudgingRun.JudgeWithTier0Discovery"/> over a real bundle and read the stored judgement
/// back, so what they assert is what a run actually produced.
/// </para>
/// <para>
/// <b>New identifiers, not edited expectations.</b> Under this boundary the stored control counts
/// cover the assessed scope, so the existing all-object integration tests measure something the
/// gated path deliberately no longer produces. Per 0116 those counts are history rather than
/// oracles; they are left alone and these are added beside them.
/// </para>
/// </remarks>
public sealed class Tier0GatedJudgingTests(ITestOutputHelper output)
{
    private const string CoreDn = "CN=Domain Admins,DC=contoso,DC=com";

    [Fact]
    public void AnUnrelatedTargetReceivesNoDetailedControlProduct()
    {
        var directory = Captured();
        Derive(directory);
        JudgeGated(directory);
        using var reader = Open(directory);
        Assert.Empty(reader.ReadControlEdges(TargetDn, null, null, true, 0).Edges);
    }

    [Fact]
    public void AnUnrelatedTargetIsStillRecordedAsNotAssessedRatherThanAbsent()
    {
        var directory = Captured();
        Derive(directory);
        JudgeGated(directory);
        using var reader = Open(directory);
        Assert.Equal(OwnershipAssessmentExecution.NotAssessed,
            reader.ReadControlEdges(TargetDn, null, null, true, 0).OwnershipCoverage?.Execution);
    }

    /// <summary>
    /// The captured object row survives for every streamed object, so "captured but unassessed"
    /// stays distinguishable from "never captured".
    /// </summary>
    [Fact]
    public void EveryStreamedObjectKeepsItsDescriptorRecord()
    {
        var directory = Captured();
        Derive(directory);
        JudgeGated(directory);
        using var connection = Database(directory);
        using var objects = connection.CreateCommand();
        objects.CommandText = "SELECT COUNT(*) FROM control_object";
        Assert.True((long)objects.ExecuteScalar()! > 1);
    }

    [Fact]
    public void TheGatedRunDerivesFewerEdgesThanTheAllObjectRun()
    {
        var gated = Captured();
        Derive(gated);
        JudgeGated(gated);
        var everything = Captured();
        Derive(everything);
        JudgeAll(everything);
        Assert.True(Edges(gated) < Edges(everything), $"gated {Edges(gated)} vs all {Edges(everything)}");
    }

    /// <summary>
    /// Ordinary rule findings are independent of the assessment boundary. Removing the unconditional
    /// pass must not change what the rules reported.
    /// </summary>
    [Fact]
    public void EveryRuleStillSeesEveryObjectUnderTheGate()
    {
        var gated = Captured();
        Derive(gated);
        JudgeGated(gated, RuleCatalogue.All);
        var everything = Captured();
        Derive(everything);
        JudgeAll(everything, RuleCatalogue.All);
        var expected = RuleExecutions(everything);

        // A comparison of two empty sets would pass while measuring nothing.
        Assert.NotEmpty(expected);
        Assert.Equal(expected, RuleExecutions(gated));
    }

    [Fact]
    public void OrdinaryRuleFindingsAreUnchangedByTheGate()
    {
        var gated = Captured();
        Derive(gated);
        JudgeGated(gated, RuleCatalogue.All);
        var everything = Captured();
        Derive(everything);
        JudgeAll(everything, RuleCatalogue.All);
        Assert.Equal(Findings(everything), Findings(gated));
    }

    [Fact]
    public void ARunWithoutDerivationInputsStillJudgesRatherThanFailing()
    {
        var directory = Captured();
        var result = JudgingRun.JudgeWithTier0Discovery(directory, [], Tier0DiscoveryBudget.Laboratory,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    [Fact]
    public void TheStoredJudgementRecordsThatItsCountsAreScoped()
    {
        var directory = Captured();
        Derive(directory);
        JudgeGated(directory);
        using var connection = Database(directory);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT discovery_scoped FROM control_product WHERE id=1";
        Assert.Equal(1L, Convert.ToInt64(command.ExecuteScalar()));
    }

    /// <summary>
    /// The negative control: an unscoped run must not claim its counts are scoped, or the screen would
    /// show the scope caveat for a product that in fact covered the whole capture.
    /// </summary>
    [Fact]
    public void AnUnscopedRunDoesNotClaimItsCountsAreScoped()
    {
        var directory = Captured();
        Derive(directory);
        JudgeAll(directory);
        using var connection = Database(directory);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT discovery_scoped FROM control_product WHERE id=1";
        Assert.Equal(0L, Convert.ToInt64(command.ExecuteScalar()));
    }

    [Fact]
    public void ABudgetIsRequiredRatherThanQuietlyDefaulted()
    {
        var directory = Captured();
        Assert.Throws<ArgumentNullException>(() => JudgingRun.JudgeWithTier0Discovery(directory, [], null!,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null));
    }

    private static SqliteConnection Database(string directory)
    {
        var path = BundleLayout.AnalysisGenerationDataPath(directory, AnalysisStoreKind.Judgement,
            AnalysisStoreLifecycle.Resolve(directory, AnalysisStoreKind.Judgement).Value.GenerationId);
        var connection = new SqliteConnection("Data Source=" + path + ";Mode=ReadOnly;Pooling=False");
        connection.Open();
        return connection;
    }

    private static long Edges(string directory)
    {
        using var connection = Database(directory);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM control_edge";
        return (long)command.ExecuteScalar()!;
    }

    private static IReadOnlyList<string> RuleExecutions(string directory)
    {
        using var connection = Database(directory);
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT rule_id,outcome,objects_judged,objects_not_applicable,objects_not_judged
            FROM rule_execution ORDER BY rule_id
            """;
        using var read = command.ExecuteReader();
        var rows = new List<string>();
        while (read.Read())
            rows.Add($"{read.GetString(0)}:{read.GetString(1)}:{read.GetInt64(2)}:{read.GetInt64(3)}:{read.GetInt64(4)}");
        return rows;
    }

    private static IReadOnlyList<string> Findings(string directory)
    {
        using var connection = Database(directory);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT rule_id,subject_key,severity,detail FROM finding ORDER BY rule_id,subject_key";
        using var read = command.ExecuteReader();
        var rows = new List<string>();
        while (read.Read()) rows.Add($"{read.GetString(0)}:{read.GetString(1)}:{read.GetString(2)}:{read.GetString(3)}");
        return rows;
    }

    private string Captured()
    {
        var descriptor = $"O:SYG:SYD:(A;;WOWD;;;{UserSid})";
        var directory = Bundle(sddl: descriptor, writeAdditional: (writer, coverage) =>
        {
            var guid = Guid.NewGuid();
            var id = writer.WriteObject(new(coverage, CoreDn, guid,
            [
                new("objectClass", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("top"), EvidenceValue.OfText("group")]),
                new("objectSid", StoredAttributeCompleteness.Complete, [EvidenceValue.OfBytes(Sid.ToBytes("S-1-5-21-1-2-3-512")!)]),
                new("groupType", StoredAttributeCompleteness.Complete, [EvidenceValue.OfText("-2147483646")]),
                new("member", StoredAttributeCompleteness.Complete, []),
            ], Started));
            var raw = new RawSecurityDescriptor(descriptor);
            var bytes = new byte[raw.BinaryLength];
            raw.GetBinaryForm(bytes, 0);
            writer.WriteSecurityDescriptor(id, bytes, AceNormalizer.Normalize(guid, SecurityDescriptorParser.Parse(bytes)));
        });
        output.WriteLine(directory);
        return directory;
    }

    private static void JudgeGated(string directory, IReadOnlyList<IRule>? rules = null)
    {
        var result = JudgingRun.JudgeWithTier0Discovery(directory, rules ?? [], Tier0DiscoveryBudget.Laboratory,
            Started, Started, JudgingRun.NobodyIsWatching, RunLog.Discarded, CancellationToken.None, selfMembershipDiscoveryBudget: null);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static void JudgeAll(string directory, IReadOnlyList<IRule>? rules = null)
    {
        var result = JudgingRun.Judge(directory, rules ?? [], Started, Started, JudgingRun.NobodyIsWatching,
            RunLog.Discarded, CancellationToken.None);
        Assert.True(result.IsSuccess, result.Error?.Description);
    }

    private static JudgementReader Open(string directory)
    {
        var result = JudgementReader.Open(directory);
        Assert.True(result.IsSuccess, result.Error?.Description);
        return result.Value;
    }
}
