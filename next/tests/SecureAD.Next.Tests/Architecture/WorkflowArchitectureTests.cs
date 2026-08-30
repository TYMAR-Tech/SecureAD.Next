using System.Text.RegularExpressions;
using SecureAD.Judgement;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Binds the product's stage flow, current host paths and replacement obligations to the source tree.
/// </summary>
public sealed class WorkflowArchitectureTests
{
    private static readonly string RepositoryRoot = RepositoryLocation.Root();

    /// <summary>The authoritative workflow declares exactly the nine frozen stages.</summary>
    [Fact]
    public void TheWorkflowDeclaresEveryFrozenStageOnce()
    {
        var rows = File.ReadAllLines(Document("next", "WORKFLOW.md"))
            .Select(line => Regex.Match(line, @"^\| (?<stage>[1-9])\. "))
            .Where(match => match.Success)
            .Select(match => int.Parse(match.Groups["stage"].Value))
            .ToList();

        Assert.Equal(Enumerable.Range(1, 9), rows);
    }

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

    /// <summary>The CLI remains capture then derive until the shared workflow replaces that path.</summary>
    [Fact]
    public void TheCliRunsItsCurrentDocumentedStagesAndDoesNotOwnJudging()
    {
        var source = Source("SecureAD.Cli", "Program.cs");

        Assert.True(
            source.Contains("new CaptureSession(", StringComparison.Ordinal)
            && source.Contains("Stage2aRun.Derive(", StringComparison.Ordinal)
            && !source.Contains("JudgingRun.Judge(", StringComparison.Ordinal));
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

    /// <summary>Every live host adapter has a named replacement and deletion event.</summary>
    [Fact]
    public void EveryTemporaryHostOrchestrationTypeHasADeletionEvent()
    {
        var inventory = File.ReadAllText(Document("next", "WORKFLOW-PATHS.md"));
        var temporary = new[]
        {
            "CaptureLauncher", "ICaptureLauncher",
            "DerivationLauncher", "IDerivationLauncher",
            "JudgingLauncher", "IJudgingLauncher",
            "NewAuditViewModel.DeriveAsync", "NewAuditViewModel.JudgeAsync",
            "SecureAD.Cli.Program.Derive",
        };

        Assert.All(temporary, name => Assert.Contains(name, inventory, StringComparison.Ordinal));
        Assert.Contains("Wave 7", inventory, StringComparison.Ordinal);
        Assert.Contains("replace and delete", inventory, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The alternate judging script is explicitly non-product and has a retirement event.</summary>
    [Fact]
    public void TheDeveloperJudgingPathCannotMasqueradeAsAProductEntryPoint()
    {
        var script = File.ReadAllText(Path.Combine(RebuildTree.Root(), "tools", "judge-bundle.ps1"));

        Assert.Contains("developer-only", script, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("retires when", script, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The workflow documents are visible in the solution rather than orphaned on disk.</summary>
    [Fact]
    public void TheSolutionListsBothWorkflowDocuments()
    {
        var solution = File.ReadAllText(Path.Combine(RebuildTree.Root(), "SecureAD.Next.sln"));

        Assert.Contains("WORKFLOW.md", solution, StringComparison.Ordinal);
        Assert.Contains("WORKFLOW-PATHS.md", solution, StringComparison.Ordinal);
    }

    private static string Source(string project, params string[] path) =>
        File.ReadAllText(Path.Combine([RebuildTree.Root(), "src", project, .. path]));

    private static string Document(params string[] path) =>
        Path.Combine([RepositoryRoot, "docs", .. path]);
}
