using System.Diagnostics;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every capability an area file carried is still written down somewhere after that file was
/// deleted.
/// </summary>
/// <remarks>
/// <para>
/// <b>The hole this closes.</b> <see cref="CapabilityCitationTests"/> checks that a cited test
/// exists. Nothing checked that a citation <i>survives</i> the deletion of the document carrying
/// it, and the rewrite deletes a document every pass. Audited 2026-08-24 across all eight area
/// files deleted so far: 170 citations carried, <b>50 referenced nowhere afterwards</b>.
/// <c>what-the-run-covered.md</c> lost its entire table of fifteen; <c>how-compare-works.md</c>
/// twelve of thirteen; <c>how-failures-are-reported.md</c> eleven of thirteen, and that pass was
/// committed as complete the day before. Every one of those tests still existed and still passed,
/// so nothing went red. Recorded as <c>P-78</c>, all fifty restored, and this is the check that
/// stops it recurring.
/// </para>
/// <para>
/// <b>It is anchored to git rather than to a document.</b> A committed snapshot of what each
/// deleted file contained would be a document checked against documents - the anchor failure
/// <c>F-S44-2</c> describes - and a session that dropped a row could regenerate the snapshot and
/// go green. Git history is the only record of a deletion that no documentation edit can reach.
/// </para>
/// <para>
/// <b>This is the first test in the project to run a process</b>, and that is a real dependency:
/// it needs a git binary and a genuine checkout rather than an export. It is taken deliberately.
/// If git cannot be reached the scan finds nothing, and
/// <see cref="TheCheckReadsTheDeletedFilesAndTheirCitations"/> fails rather than letting every
/// assertion here pass by comparing empty sets - which is the failure mode this whole class
/// exists to prevent, and it would be absurd to reproduce it in the fix.
/// </para>
/// <para>
/// <b>A citation in <c>PUNCH-LIST.md</c> counts as surviving</b>, and that is intended rather than
/// a loophole left open. The routing table sends work that may need doing to the punch list, so a
/// capability whose page does not exist yet is recorded rather than lost - <c>P-79</c> is exactly
/// that case, a SYSVOL row whose subject still lives in an area file. What this gate forbids is a
/// citation that survives in no document at all.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-24 by <c>next/tools/mutate-citation-survival-gate.ps1</c>, five
/// directions, all killed; three touched files verified byte-identical by hash.</b>
/// </para>
/// <list type="bullet">
///   <item>A restored capability row is deleted from its new home - killed by
///   <see cref="EveryCapabilityAnAreaFileCarriedSurvivedItsDeletion"/>.</item>
///   <item>The punch-list record of the one unplaced row is removed - killed by the same, which is
///   what makes recording load-bearing rather than decorative.</item>
///   <item>Git cannot be reached - killed by
///   <see cref="TheCheckReadsTheDeletedFilesAndTheirCitations"/> and by nothing else, which is why
///   that check is separate.</item>
///   <item>The superseded rule is widened to accept any citation, and the survivor scan is narrowed
///   to one document - both killed.</item>
/// </list>
/// <para>
/// <b>It found a real defect on its first run.</b> <c>P-77</c> recorded seventeen shell
/// capabilities by writing the class once and the method names bare. The hand audit that preceded
/// this class matched on the method name alone and called them accounted for; this gate matches
/// the whole citation and did not. Qualifying them was the fix - a bare method name is ambiguous
/// and a reader cannot trace it - and the disagreement is the point: the gate is stricter than the
/// eye that wrote the row.
/// </para>
/// </remarks>
public sealed class AreaFileCitationSurvivalTests
{
    /// <summary>A test citation as the documents write it: <c>`Class`</c> or <c>`Class.Method`</c>.</summary>
    private static readonly Regex Citation = new(
        @"`(?<name>[A-Za-z_][A-Za-z0-9_]*Tests(?:\.[A-Za-z_][A-Za-z0-9_]*)?)`",
        RegexOptions.Compiled);

    [Fact]
    public void EveryCapabilityAnAreaFileCarriedSurvivedItsDeletion()
    {
        var (tokens, classes) = SurvivingCitations();
        var lost = new List<string>();

        foreach (var (file, cited) in CitationsOfDeletedAreaFiles())
        {
            foreach (var citation in cited)
            {
                if (Survives(citation, tokens, classes))
                    continue;

                lost.Add($"  {file} cited `{citation}` and nothing under docs/ cites it any more");
            }
        }

        Assert.True(
            lost.Count == 0,
            "These capabilities were written down in an area file, that file was deleted, and the "
            + "claim was never written anywhere else. The test still exists and still passes, so "
            + "nothing goes red - what is gone is the sentence saying the product promises it, "
            + "which is the only part of this an operator can read. Move the row to the layer "
            + "document that owns the subject, or record it in PUNCH-LIST.md if no such page "
            + "exists yet:" + Environment.NewLine + string.Join(Environment.NewLine, lost));
    }

    /// <summary>
    /// A bare class citation is satisfied by a surviving citation of any of its methods, because a
    /// vague row replaced by specific ones is consolidation rather than loss. Three of the eight
    /// deleted files ended this way and all three are correct.
    /// </summary>
    [Fact]
    public void ABareClassRowIsSatisfiedOnlyByASurvivingCitationOfThatClass()
    {
        var (tokens, classes) = SurvivingCitations();

        Assert.True(
            Survives("RunStateReaderTests", tokens, classes),
            "RunStateReaderTests is cited by method elsewhere, so the bare class row is superseded.");

        Assert.False(
            Survives("AClassNobodyHasEverCitedTests", tokens, classes),
            "A class nothing cites must not be reported as surviving.");

        Assert.False(
            Survives("RunStateReaderTests.AMethodNobodyDocumentsXX", tokens, classes),
            "A method citation must not be satisfied merely because its class is cited.");
    }

    /// <summary>
    /// The scanner self-test. Without it every assertion above passes by finding no deleted files,
    /// no citations and no survivors, and reporting that nothing is wrong with any of them.
    /// </summary>
    /// <remarks>
    /// It asserts no floor on how many area files have been deleted or how many rows they carried.
    /// Those numbers move every pass, and a threshold edited to make a gate pass is the defect
    /// rather than the fix. What it asserts is that git was reached, that deleted files were found,
    /// that citations were read out of them, and that the survivor lookup discriminates.
    /// </remarks>
    [Fact]
    public void TheCheckReadsTheDeletedFilesAndTheirCitations()
    {
        var deleted = CitationsOfDeletedAreaFiles();

        Assert.True(
            deleted.Count > 0,
            "Found no deleted area files. Either git could not be reached from the test process, "
            + "or this is not a real checkout. Both mean every check in this class is comparing "
            + "empty sets, which is the exact failure it was written to stop.");

        Assert.Contains(deleted, d => d.Citations.Count > 0);

        var (tokens, classes) = SurvivingCitations();

        Assert.NotEmpty(tokens);
        Assert.NotEmpty(classes);

        // The lookup discriminates: something real is found, something fabricated is not.
        Assert.True(Survives("RunComparabilityTests.EveryOutcomeIsProducible", tokens, classes));
        Assert.False(Survives("RunComparabilityTests.EveryOutcomeIsProducibleXX", tokens, classes));
    }

    // --- helpers -----------------------------------------------------------------------------------

    private static bool Survives(string citation, HashSet<string> tokens, HashSet<string> classes)
    {
        if (tokens.Contains(citation))
            return true;

        // A bare class row, superseded by a surviving citation of one of its methods.
        return !citation.Contains('.', StringComparison.Ordinal) && classes.Contains(citation);
    }

    /// <summary>
    /// Every test citation written in any document that exists today, plus the set of classes some
    /// surviving citation names by method.
    /// </summary>
    private static (HashSet<string> Tokens, HashSet<string> Classes) SurvivingCitations()
    {
        var tokens = new HashSet<string>(StringComparer.Ordinal);
        var classes = new HashSet<string>(StringComparer.Ordinal);

        var docs = Path.Combine(RepositoryLocation.Root(), "docs");

        foreach (var file in Directory.EnumerateFiles(docs, "*.md", SearchOption.AllDirectories))
        {
            foreach (Match match in Citation.Matches(File.ReadAllText(file)))
            {
                var name = match.Groups["name"].Value;
                tokens.Add(name);

                var dot = name.IndexOf('.', StringComparison.Ordinal);
                if (dot > 0)
                    classes.Add(name[..dot]);
            }
        }

        return (tokens, classes);
    }

    /// <summary>
    /// Each area file the rewrite has deleted, and the citations it carried in its last version.
    /// </summary>
    private static List<(string File, List<string> Citations)> CitationsOfDeletedAreaFiles()
    {
        var result = new List<(string, List<string>)>();

        var deleted = Git("log --diff-filter=D --name-only --pretty=format: -- docs/areas/*.md")
            .Where(line => line.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(line => line, StringComparer.Ordinal);

        foreach (var path in deleted)
        {
            var killer = Git($"log --diff-filter=D --format=%H -n 1 -- {path}").FirstOrDefault();
            if (string.IsNullOrWhiteSpace(killer))
                continue;

            var content = string.Join("\n", Git($"show {killer}^:{path}"));

            var cited = Citation.Matches(content)
                .Select(m => m.Groups["name"].Value)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(n => n, StringComparer.Ordinal)
                .ToList();

            result.Add((Path.GetFileName(path), cited));
        }

        return result;
    }

    /// <summary>
    /// Runs git in the repository root. Returns no lines when git cannot be reached, which the
    /// scanner self-test turns into a failure rather than a quiet pass.
    /// </summary>
    private static List<string> Git(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("git", arguments)
            {
                WorkingDirectory = RepositoryLocation.Root(),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            if (process is null)
                return [];

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(30_000);

            return process.ExitCode == 0
                ? [.. output.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n')]
                : [];
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return [];
        }
    }
}
