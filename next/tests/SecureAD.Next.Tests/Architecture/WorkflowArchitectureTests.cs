using SecureAD.Audit.Capture;
using SecureAD.Cli;
using SecureAD.Derivation;
using SecureAD.Evidence;
using SecureAD.Judgement;
using SecureAD.Kernel;
using SecureAD.Next.Tests.Judgement;
using Xunit;
using Xunit.Abstractions;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Binds the product's stage flow and current host paths to the source tree.
/// </summary>
/// <remarks>
/// <b>These checks inspect code or run an offline host, never a document.</b> Three checks that read WORKFLOW.md,
/// WORKFLOW-PATHS.md and the solution file were removed on 2026-09-12 under the owner's rule that a
/// test keeps the code honest rather than a document. What survives cannot be satisfied by editing
/// prose: judging a bundle before deriving it refuses every rule that reads a derived fact, and a
/// host building its own rule set makes two runs of one bundle disagree.
/// </remarks>
public sealed class WorkflowArchitectureTests(ITestOutputHelper output)
{
    /// <summary>The Shell's current production path preserves capture, derive, judge order.</summary>
    [Fact]
    public void TheShellRunsItsCurrentStagesInTheDocumentedOrder()
    {
        var source = Source("SecureAD.Shell", "ViewModels", "NewAuditViewModel.cs");

        var capture = source.IndexOf("_capture", StringComparison.Ordinal);
        capture = capture < 0
            ? -1
            : source.IndexOf(".RunAsync(", capture, StringComparison.Ordinal);
        var derive = source.IndexOf("await DeriveAsync(sealedEvidence", StringComparison.Ordinal);
        var judge = source.IndexOf("await JudgeAsync(sealedEvidence", StringComparison.Ordinal);

        Assert.True(
            capture >= 0 && capture < derive && derive < judge,
            "The current Shell path is no longer capture -> derive -> judge. Update WORKFLOW.md and "
            + "WORKFLOW-PATHS.md with the accepted replacement rather than letting host sequencing drift.");
    }

    /// <summary>The CLI runs capture, derive and judge, in that order.</summary>
    /// <remarks>
    /// <b>This asserted the opposite until 2026-09-02</b>, when the command line could not judge and
    /// the gate held it there "until the shared workflow replaces that path". It does now: the owner
    /// asked for a run that finishes the whole audit unattended, and a lab check that cannot be
    /// repeated without opening the application is a lab check nobody repeats.
    /// <para>
    /// The order is what matters and is what this pins. Judging a bundle before deriving it would
    /// refuse every rule that reads a derived fact, per <c>docs/decisions/0091</c>.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheCliRunsItsCurrentStagesInOrderAsync()
    {
        var directory = SelfMembershipDiscoveryTests.Bundle(tier0Route: true);
        output.WriteLine(directory);
        var options = Assert.IsType<CommandLine>(CommandLine.Parse(["--library", Path.GetDirectoryName(directory)!]));

        var exit = await Program.RunAsync(options, CancellationToken.None, discoveryBudget: null,
            capture: (protect, token) =>
            {
                token.ThrowIfCancellationRequested();
                Assert.False(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Derivation)));
                Assert.False(File.Exists(AnalysisStoreLifecycle.ManifestPath(directory, AnalysisStoreKind.Judgement)));
                protect(directory);
                return Task.FromResult(Result<CaptureRunResult>.Success(new(RunCompletion.Sealed, directory, null)));
            });

        Assert.Equal(0, exit);
        using var derived = Assert.IsType<DerivationReader>(DerivationReader.Open(directory).Value);
        using var judged = Assert.IsType<JudgementReader>(JudgementReader.Open(directory).Value);
        Assert.Equal(derived.Description.GenerationId, judged.Description.DerivationGenerationId);
    }

    /// <summary>Executable rules are instantiated only by Judgement's single catalogue.</summary>
    [Fact]
    public void OnlyRuleCatalogueConstructsTheProductRuleSet()
    {
        var ruleTypes = typeof(IRule).Assembly.GetTypes()
            .Where(type => typeof(IRule).IsAssignableFrom(type) && type is { IsAbstract: false, IsInterface: false })
            .Select(type => type.Name)
            .ToList();

        var offenders = RebuildTree.ProductionFiles()
            .Where(file => !file.EndsWith("RuleCatalogue.cs", StringComparison.OrdinalIgnoreCase))
            .SelectMany(file => File.ReadAllLines(file)
                .Select((line, index) => (File: file, Line: index + 1, Text: line))
                .Where(site => ruleTypes.Any(rule =>
                    site.Text.Contains($"new {rule}(", StringComparison.Ordinal))))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "Executable rules are constructed outside RuleCatalogue.All, allowing hosts to run "
            + "different audits:" + Environment.NewLine + RebuildTree.Describe(offenders));
    }

    /// <summary>The alternate judging script is explicitly non-product and has a retirement event.</summary>
    [Fact]
    public void TheDeveloperJudgingPathCannotMasqueradeAsAProductEntryPoint()
    {
        var script = File.ReadAllText(Path.Combine(RebuildTree.Root(), "tools", "judge-bundle.ps1"));

        Assert.Contains("developer-only", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("retires when", script, StringComparison.OrdinalIgnoreCase);
    }

    private static string Source(string project, params string[] path) =>
        File.ReadAllText(Path.Combine([RebuildTree.Root(), "src", project, .. path]));
}
