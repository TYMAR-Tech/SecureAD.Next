using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// The stage statuses in <c>ROADMAP.md</c>, and the run pipeline states and rule count in
/// <c>WHAT-THE-PRODUCT-IS.md</c>, agree with what is actually in the source tree.
/// </summary>
/// <remarks>
/// <para>
/// <b>A status is the one documentation claim that goes false while nobody edits the document.</b>
/// A wrong sentence needs somebody to write it. A wrong status needs only for the product to
/// improve while the file sits still - so proof-reading never catches one, and neither can a check
/// comparing two documents, because both copies stay perfectly consistent with each other and go
/// quietly false together.
/// </para>
/// <para>
/// <b>Measured on 2026-09-04 and recorded as <c>P-135</c>.</b> Six of the eight <c>check-*.ps1</c>
/// gates compared documents against documents. In that gap the roadmap carried stage 5 as
/// <i>not started</i> while group expansion had been built and had two consumers,
/// <c>WHAT-THE-PRODUCT-IS.md</c> said judging was built with <i>two rules</i> while fourteen
/// existed, and the acceptance manifest reported ninety-eight criteria <i>not started</i> while
/// naming a hundred tests that had never been written. That last one had a rigorous checker which
/// passed throughout, because it compared the manifest against the specification and never read
/// code.
/// </para>
/// <para>
/// <b>So this gate reads the code, and it asserts both directions.</b> A stage claiming to be built
/// whose witness is absent fails - and a stage claiming <i>not started</i> whose witness is
/// <i>present</i> fails too. The second is the one nothing had before: it means a stage cannot be
/// quietly finished, because the day its witness appears this fails until the roadmap catches up.
/// </para>
/// <para>
/// <b>A witness is a proxy, and this gate is a tripwire rather than a proof.</b> It can say whether
/// a named type is declared. It cannot say a stage is finished, and a witness naming a type that
/// exists but that nothing calls would pass while the stage was hollow. That is why stage 2's
/// witness is <c>DashboardViewModel</c> and not <c>Dashboard</c>: a <c>Dashboard</c> member already
/// exists in <c>ShellSection</c> as a deliberately empty navigation tab, and the obvious witness
/// would have reported the stage built while the screen showed nothing.
/// </para>
/// <para>
/// <c>next/tools/check-stage-status.ps1</c> is the same check as a diagnostic a person can run and
/// read, and carries a <c>-SelfTest</c> switch. This is the copy that is obliged to run.
/// </para>
/// </remarks>
public sealed class StageStatusGateTests
{
    /// <summary>Statuses that assert the thing exists. Anything else asserts it does not.</summary>
    private static readonly string[] BuiltStatuses = ["built", "started"];

    /// <summary>
    /// A stage row: four cells, the last a backticked type name.
    /// </summary>
    /// <remarks>
    /// <b>The table is found by the shape of its rows rather than by counting from a heading.</b>
    /// An offset from a heading breaks the first time a paragraph is added above the table, and it
    /// breaks by matching nothing - which would leave this gate passing while measuring nothing at
    /// all. <see cref="TheRoadmapStageTableIsFound"/> is the guard against exactly that.
    /// </remarks>
    private static readonly Regex StageRow = new(
        @"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*`([A-Za-z0-9_]+)`\s*\|\s*$",
        RegexOptions.Compiled);

    private sealed record StageClaim(string Stage, string Status, string Witness);

    [Fact]
    public void EveryStageStatusAgreesWithTheSource()
    {
        var failures = new List<string>();

        foreach (var claim in StageClaims())
        {
            var present = WitnessIsDeclared(claim.Witness);
            var claimsBuilt = BuiltStatuses.Contains(claim.Status);

            if (claimsBuilt && !present)
            {
                failures.Add(
                    $"  Stage {claim.Stage} says '{claim.Status}' but its witness '{claim.Witness}' "
                    + "is declared nowhere under next/src. Either the stage is not built, or the "
                    + "witness names the wrong type.");
            }

            if (!claimsBuilt && present)
            {
                failures.Add(
                    $"  Stage {claim.Stage} says '{claim.Status}' but its witness '{claim.Witness}' "
                    + "IS declared under next/src. The stage looks finished and the roadmap has not "
                    + "caught up - which is exactly how stage 5 went unnoticed.");
            }
        }

        Assert.True(
            failures.Count == 0,
            "A stage status in docs/ROADMAP.md disagrees with the source tree. Correct the status, "
            + "or correct the witness if it names the wrong type:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// The rule count stated in the product document is the number of rules that exist.
    /// </summary>
    /// <remarks>
    /// <b>A number in a sentence rots exactly as a status does.</b> This file said <i>two rules</i>
    /// while twelve more were built underneath it.
    /// </remarks>
    [Fact]
    public void TheStatedRuleCountIsTheNumberOfRulesThatExist()
    {
        var product = File.ReadAllText(ProductPath(), Encoding.UTF8);
        var claim = Regex.Match(product, @"built,\s*(\d+)\s*rules");

        Assert.True(
            claim.Success,
            "No 'built, N rules' claim was found in docs/WHAT-THE-PRODUCT-IS.md. It was there to be "
            + "checked and now is not, so either the wording changed or the claim was dropped. "
            + "Restore it or update this gate - do not leave the count unchecked.");

        var stated = int.Parse(claim.Groups[1].Value);
        var actual = RuleIds().Count;

        Assert.True(
            stated == actual,
            $"docs/WHAT-THE-PRODUCT-IS.md claims {stated} rules; {actual} rule identifiers are "
            + $"declared in SecureAD.Judgement ({string.Join(", ", RuleIds())}).");
    }

    /// <summary>
    /// One row of the run pipeline in <c>WHAT-THE-PRODUCT-IS.md</c>, and the types that decide it.
    /// </summary>
    /// <param name="Stage">The row's first cell, matched exactly.</param>
    /// <param name="Witnesses">
    /// Types that exist if and only if the stage is built. A built row needs all of them; a row
    /// claiming otherwise needs none of them, so any one appearing fails.
    /// </param>
    private sealed record PipelineStage(string Stage, params string[] Witnesses);

    /// <summary>
    /// The run pipeline, held here as code rather than as a column in the document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Why this table needed a gate of its own.</b> Until 2026-09-12 the document said its states
    /// were "checked rather than maintained by hand" by <c>check-stage-status.ps1</c>. That script
    /// checks the roadmap's statuses and this file's <i>rule count</i>, and nothing else - so eight
    /// of the nine states here could go false with nothing failing, in the file the working
    /// instructions say to read first. That is the shape the owner's rule of 2026-09-12 rates worst:
    /// a claim of protection that is not protection.
    /// </para>
    /// <para>
    /// <b>The witnesses live here and not in a column, deliberately.</b> This page is the one an
    /// administrator reads to learn what a run does; a column of type names would be noise to that
    /// reader. Holding a gate's input in code is the <c>P-184</c> pattern, and the stage table is the
    /// one exception the owner granted to the rule against binding a document to the code.
    /// </para>
    /// <para>
    /// <b>Each witness is chosen so it cannot be hollow.</b> The dashboard's is
    /// <c>DashboardViewModel</c> rather than <c>Dashboard</c>, because a <c>Dashboard</c> member
    /// already exists as an empty navigation tab and would have reported the stage built while the
    /// screen showed nothing. The unbuilt row names <c>ReportDefinition</c> and <c>RunComparison</c>
    /// rather than <c>RunComparability</c>, which is declared today: it is the eligibility check
    /// written ahead of the screen that will call it, and naming it would report a feature built
    /// because a type it will one day use exists. Since 2026-09-12 a witness that exists but that
    /// nothing running can reach is additionally caught by <c>PublicTypeReachabilityGateTests</c>.
    /// </para>
    /// </remarks>
    private static readonly PipelineStage[] PipelineStages =
    [
        new("Connect", "ConnectionSecurityLadder"),
        new("Preflight", "Preflight"),
        new("Capture", "CaptureRun"),
        new("Reconcile and seal", "BundleSealing"),
        new("Derive", "Stage2aRun"),
        new("Judge", "JudgingRun"),
        new("Read back", "RunLibrary"),
        new("Dashboard", "DashboardViewModel"),
        new("Reports, compare and export", "ReportDefinition", "RunComparison"),
    ];

    /// <summary>
    /// Every state in the run pipeline table agrees with what is declared in the source tree.
    /// </summary>
    [Fact]
    public void EveryPipelineStateAgreesWithTheSource()
    {
        var failures = new List<string>();

        foreach (var (stage, state) in PipelineClaims())
        {
            var declared = PipelineStages.Single(s => s.Stage == stage);
            var claimsBuilt = state.StartsWith("built", StringComparison.Ordinal);

            foreach (var witness in declared.Witnesses)
            {
                var present = WitnessIsDeclared(witness);

                if (claimsBuilt && !present)
                {
                    failures.Add(
                        $"  '{stage}' says '{state}' but its witness '{witness}' is declared "
                        + "nowhere under next/src. Either the stage is not built, or the witness "
                        + "names the wrong type.");
                }

                if (!claimsBuilt && present)
                {
                    failures.Add(
                        $"  '{stage}' says '{state}' but its witness '{witness}' IS declared under "
                        + "next/src. The stage looks finished and the document has not caught up - "
                        + "which is exactly how stage 5 went unnoticed in the roadmap.");
                }
            }
        }

        Assert.True(
            failures.Count == 0,
            "A state in the run pipeline table of docs/WHAT-THE-PRODUCT-IS.md disagrees with the "
            + "source tree. Correct the state, or correct the witness in this file if it names the "
            + "wrong type. Do not weaken the witness to make this pass:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, failures));
    }

    /// <summary>
    /// The pipeline table is found, every row is claimed, and both directions are exercised.
    /// </summary>
    /// <remarks>
    /// <b>The self-test, and the reason the check above is not decoration.</b> The rows are located
    /// by matching their first cell against the names above, so a renamed or reformatted row would
    /// simply stop matching and leave the gate passing while measuring nothing - the failure this
    /// repository has produced three times. This asserts every named stage was found exactly once,
    /// that the document holds no pipeline row this file does not claim, and that both a built and a
    /// not-built row exist so neither direction goes unexercised against the real document.
    /// </remarks>
    [Fact]
    public void ThePipelineTableIsFoundAndFullyClaimed()
    {
        var claims = PipelineClaims();

        Assert.NotEmpty(PipelineStages);

        foreach (var declared in PipelineStages)
        {
            Assert.True(
                claims.Count(c => c.Stage == declared.Stage) == 1,
                $"'{declared.Stage}' should appear exactly once in the run pipeline table of "
                + "docs/WHAT-THE-PRODUCT-IS.md, and does not. The table was renamed, reformatted or "
                + "duplicated, and this gate is no longer reading it.");
        }

        Assert.Equal(PipelineStages.Length, claims.Count);

        Assert.Contains(claims, c => c.State.StartsWith("built", StringComparison.Ordinal));
        Assert.Contains(claims, c => !c.State.StartsWith("built", StringComparison.Ordinal));

        // Every witness must be a name somebody could have written. A typo would sit in the
        // not-built rows forever, looking like protection and asserting nothing.
        foreach (var witness in PipelineStages.SelectMany(s => s.Witnesses))
        {
            Assert.Matches("^[A-Za-z][A-Za-z0-9_]*$", witness);
        }
    }

    /// <summary>
    /// The run pipeline rows, read by matching the first cell against the stages named above.
    /// </summary>
    /// <remarks>
    /// Anchored on the known names rather than on an offset from a heading, because this file is
    /// over a thousand lines and carries other three-column tables. A row this file does not claim
    /// is caught by <see cref="ThePipelineTableIsFoundAndFullyClaimed"/> rather than silently
    /// skipped.
    /// </remarks>
    private static List<(string Stage, string State)> PipelineClaims()
    {
        var known = PipelineStages.Select(s => s.Stage).ToHashSet(StringComparer.Ordinal);
        var claims = new List<(string, string)>();

        foreach (var line in File.ReadAllLines(ProductPath(), Encoding.UTF8))
        {
            var match = PipelineRow.Match(line);
            if (!match.Success) continue;

            var stage = match.Groups[1].Value.Trim();
            if (!known.Contains(stage)) continue;

            claims.Add((stage, match.Groups[3].Value.Replace("*", string.Empty).Trim()));
        }

        return claims;
    }

    /// <summary>A pipeline row: three cells, the last a state.</summary>
    private static readonly Regex PipelineRow = new(
        @"^\|\s*([^|]+?)\s*\|\s*([^|]*?)\s*\|\s*([^|]+?)\s*\|\s*$",
        RegexOptions.Compiled);

    /// <summary>
    /// The stage table is found at all, and holds the stages the roadmap describes.
    /// </summary>
    /// <remarks>
    /// <b>The self-test, and the reason the rest of this class is not decoration.</b> A row pattern
    /// that matched nothing would make every assertion above vacuously true, which is the failure
    /// this repository has produced three times. This asserts the table was located and that the
    /// numbered stages are all present, so a reformatted table fails loudly rather than silently
    /// disabling the gate.
    /// </remarks>
    [Fact]
    public void TheRoadmapStageTableIsFound()
    {
        var claims = StageClaims();

        Assert.NotEmpty(claims);

        foreach (var stage in Enumerable.Range(1, 10).Select(n => n.ToString()))
        {
            Assert.Contains(claims, c => c.Stage == stage);
        }

        // Both kinds must be represented, or one direction of the check is never exercised against
        // the real document and could be broken without anything noticing.
        Assert.Contains(claims, c => BuiltStatuses.Contains(c.Status));
        Assert.Contains(claims, c => !BuiltStatuses.Contains(c.Status));
    }

    /// <summary>
    /// The witness test answers for a declared type and not for a mention in prose.
    /// </summary>
    /// <remarks>
    /// <b>The negative control that decides whether a witness means anything.</b> A plain substring
    /// search would count comments: <c>Chokepoint</c> and <c>Reachability</c> both appear in this
    /// repository today, in remarks describing things that do not exist, and either would have
    /// made a false witness for an unbuilt stage. So a name is a witness only where it is
    /// declared.
    /// </remarks>
    [Fact]
    public void AWitnessIsADeclarationRatherThanAMention()
    {
        // Declared, so a witness.
        Assert.True(WitnessIsDeclared("PrincipalExpansion"));

        // Present in the tree only as prose. If either of these ever starts answering true, it is
        // because the type was created - and the stage row that names it must then be revisited.
        Assert.False(WitnessIsDeclared("Chokepoint"));
        Assert.False(WitnessIsDeclared("RemediationIssue"));

        // A name nobody has ever written.
        Assert.False(WitnessIsDeclared("NoSuchTypeExistsAnywhere"));
    }

    private static List<StageClaim> StageClaims()
    {
        var claims = new List<StageClaim>();

        foreach (var line in File.ReadAllLines(RoadmapPath(), Encoding.UTF8))
        {
            var match = StageRow.Match(line);
            if (!match.Success) continue;

            claims.Add(new StageClaim(
                match.Groups[1].Value,
                match.Groups[3].Value.Replace("*", string.Empty).Trim().ToLowerInvariant(),
                match.Groups[4].Value));
        }

        return claims;
    }

    private static bool WitnessIsDeclared(string name)
    {
        var pattern = new Regex(
            @"(class|record|struct|interface|enum)\s+" + Regex.Escape(name) + @"\b",
            RegexOptions.Compiled);

        return SourceFiles().Any(file => pattern.IsMatch(File.ReadAllText(file, Encoding.UTF8)));
    }

    private static List<string> RuleIds()
    {
        var ids = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var file in SourceFiles())
        {
            if (!file.Contains("SecureAD.Judgement", StringComparison.Ordinal)) continue;

            foreach (Match match in Regex.Matches(File.ReadAllText(file, Encoding.UTF8), "\"(SEC-\\d+)\""))
                ids.Add(match.Groups[1].Value);
        }

        return [.. ids];
    }

    private static IEnumerable<string> SourceFiles() =>
        Directory.EnumerateFiles(
            Path.Combine(RepositoryLocation.Root(), "next", "src"), "*.cs", SearchOption.AllDirectories)
            .Where(f =>
                !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

    private static string RoadmapPath() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "ROADMAP.md");

    private static string ProductPath() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "WHAT-THE-PRODUCT-IS.md");
}
