using System.Text.Json;
using SecureAD.Evidence;
using SecureAD.Judgement;
using Xunit;
using static SecureAD.Next.Tests.Judgement.SelfMembershipDiscoveryTests;

namespace SecureAD.Next.Tests.Judgement;

public sealed partial class OwnershipAuditIntegrationTests
{
    [Theory]
    [InlineData("full")]
    [InlineData("deny")]
    [InlineData("owner-rights")]
    [InlineData("null")]
    [InlineData("unreadable")]
    public void PreparedProductionPreservesTheCompleteSelectedControlContract(string variant)
    {
        var inputRoot = Environment.GetEnvironmentVariable("SECUREAD_STAGE6_CONTRACT_INPUTS");
        var outputRoot = Environment.GetEnvironmentVariable("SECUREAD_STAGE6_CONTRACT_OUTPUTS");
        var input = inputRoot is null ? null : Path.Combine(inputRoot, variant);
        string directory;
        if (input is not null && Directory.Exists(input)) directory = input;
        else
        {
            directory = variant switch
            {
                "full" => Captured($"O:SYG:SYD:(A;;0x000F01FF;;;{UserSid})"),
                "deny" => Captured($"O:SYG:SYD:(D;;WD;;;{UserSid})(A;;0x000F01FF;;;{UserSid})"),
                "owner-rights" => Captured($"O:SYG:SYD:(A;;WO;;;{UserSid})(D;;WD;;;S-1-3-4)"),
                "null" => Captured("O:SYG:SY"),
                _ => Captured(coreDescriptor: false),
            };
            Derive(directory);
            if (input is not null)
            {
                Directory.CreateDirectory(input);
                foreach (var source in Directory.GetFiles(directory, "*", SearchOption.AllDirectories))
                {
                    var destination = Path.Combine(input, Path.GetRelativePath(directory, source));
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    File.Copy(source, destination);
                }
                directory = input;
            }
        }
        JudgeGated(directory);
        using var reader = Open(directory);
        var pages = new List<ControlEdgePage>();
        long after = 0;
        do
        {
            var page = reader.ReadControlEdges(null, null, null, true, after);
            pages.Add(page);
            if (!page.HasMore) break;
            Assert.True(page.LastId > after);
            after = page.LastId;
        } while (true);
        Assert.True(pages[0].ProductWasDerived);
        Assert.True(pages[0].IsScopedToDiscovery);
        Assert.All(pages.SelectMany(page => page.Edges), edge => Assert.Equal(reader.Description.GenerationId, edge.GenerationId));
        Assert.All(pages.SelectMany(page => page.FullControlAssessments), answer => Assert.Equal(reader.Description.GenerationId, answer.GenerationId));
        var selected = reader.ReadControlEdges(CoreDn, null, null, true, 0);
        switch (variant)
        {
            case "full":
                Assert.Equal(ControlEvaluationState.Established, Assert.Single(selected.FullControlAssessments).EvaluationState);
                break;
            case "deny":
                Assert.Equal(ControlEvaluationState.NotEstablished, Assert.Single(selected.FullControlAssessments).EvaluationState);
                break;
            case "owner-rights":
                Assert.Equal(ControlEvaluationState.NotEstablished, Assert.Single(selected.Edges.Where(edge =>
                    edge.Capability == ControlCapability.CanBecomeOwnerAndRewriteDacl)).Preconditions
                    .Single(condition => condition.Name == "OwnerWouldReceiveWriteDacl").State);
                break;
            case "null":
                Assert.Equal("S-1-1-0", Assert.Single(selected.FullControlAssessments).Source.Holder.Sid);
                break;
            default:
                Assert.Empty(selected.Edges);
                Assert.Equal(OwnershipAssessmentExecution.CompletedWithLimitations, selected.OwnershipCoverage?.Execution);
                break;
        }
        if (outputRoot is null) return;
        Directory.CreateDirectory(outputRoot);
        // Only the new publication identity changes: source seals, derivation, occurrence order and every saved answer remain exact.
        var canonical = JsonSerializer.Serialize(pages).Replace(reader.Description.GenerationId.ToString("D"), "<judgement>", StringComparison.Ordinal);
        File.WriteAllText(Path.Combine(outputRoot, variant + ".json"), canonical);
    }
}
