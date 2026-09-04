using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// The stage statuses in <c>ROADMAP.md</c>, and the rule count in <c>WHAT-THE-PRODUCT-IS.md</c>,
/// agree with what is actually in the source tree.
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
