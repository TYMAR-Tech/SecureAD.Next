using Xunit;

namespace SecureAD.Next.Tests.Documentation;

/// <summary>
/// Holds the predecessor's rule cards inside <c>docs/rules/</c>, and keeps what they say about the
/// previous product from being read back as a description of this one.
/// </summary>
/// <remarks>
/// <para>
/// <b>This gate exists because the confusion actually happened, twice in one session.</b> Asked what
/// adding a rule costs in this product, a search of the repository answered with <c>rules.yaml</c>,
/// <c>FindingsService.CreateDefaultEvaluators</c> and <c>RuleEvaluatorHelpers</c> - a complete,
/// confident, fifteen-seam answer describing an architecture this product does not have. The paths
/// looked plausible and they were inside the owner's own repository. Nothing marked them as
/// historical.
/// </para>
/// <para>
/// <b>The cards are quarantined rather than rewritten</b>, on the owner's ruling of 2026-08-26: the
/// Active Directory reasoning in them is worth keeping and the implementation detail is not, and
/// rewriting sixty-six documents about rules that do not exist is work spent on speculation. So the
/// content is untouched and every file carries a banner saying what it is. <c>P-101</c> records
/// that.
/// </para>
/// <para>
/// <b>The second check is the one that needed care.</b> A blanket ban on predecessor paths would
/// fail two documents that mention them legitimately - <c>PUNCH-LIST.md</c> discussing deferred GPO
/// work, and <c>0010-the-rule-catalogue-is-data-the-rule-logic-is-code.md</c> recording where the
/// yaml catalogue came from. Both are prose about the old product, which is exactly what a rebuild's
/// documentation should be free to discuss. So the rule is not <i>never mention these paths</i> but
/// <i>never mention them without saying whose they are</i>: a line citing predecessor code must name
/// the predecessor on that same line.
/// </para>
/// <para>
/// <b>The check is line-scoped, and that is a real limit rather than a detail.</b> A sentence
/// wrapped across two lines can name the predecessor on the first and cite its code on the second,
/// and this gate will fail it — which is what happened to <c>0010</c> on the day it was written.
/// The alternative, scanning paragraphs, would let a citation sit arbitrarily far from the word
/// that excuses it, which is the failure that matters. Erring toward too strict is the safe
/// direction here: it costs a reworded line, where the other error costs a false claim about the
/// product nobody notices.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-26, both directions.</b> Stripping the banner from a card failed
/// <see cref="EveryFileInTheRulesFolderIsMarkedAsPredecessorMaterial"/> naming the file. Adding a
/// fabricated citation of <c>src/SecureAD.Infrastructure</c> to a layer document failed
/// <see cref="NoDocumentOutsideTheRulesFolderCitesPredecessorCodeAsThoughItWereOurs"/> naming the
/// line. <see cref="TheScanReadsRealFilesAndFindsTheCitationsThatExist"/> is the self-test: without
/// it both checks pass by reading nothing and comparing empty sets, which is the failure this
/// repository has committed three times.
/// </para>
/// <para>
/// <b>It found something on its first run, and it was worse than the cards.</b>
/// <c>docs/decisions/0010</c> — <c>Status: Accepted</c> — described <c>rules.yaml</c>,
/// <c>IRuleEvaluator</c> and *adding a rule touches two catalogue files* in the present tense, and
/// closed by making <c>docs/rules/</c> load-bearing. An accepted decision record carries more
/// authority than a card, so the same contamination was doing more damage there. It is amended
/// rather than rewritten, in this repository's usual way: the decision stands, the mechanism is
/// marked as the predecessor's.
/// </para>
/// </remarks>
public sealed class PredecessorMaterialGateTests
{
    private const string BannerStart = "<!-- PREDECESSOR-MATERIAL:BEGIN -->";

    private const string BannerEnd = "<!-- PREDECESSOR-MATERIAL:END -->";

    /// <summary>
    /// Code paths and files that belong to the previous product and exist nowhere in this tree.
    /// </summary>
    /// <remarks>
    /// <c>rules.yaml</c> is included because it is the one the search actually followed: a rule
    /// catalogue as data is a shape this product deliberately does not have, since
    /// <c>docs/decisions/0082</c> keeps the rule set out of the customer's hands.
    /// </remarks>
    private static readonly string[] PredecessorPaths =
    [
        "src/SecureAD.Core",
        "src/SecureAD.Infrastructure",
        "src/SecureAD.Application",
        "src/SecureAD.Domain",
        "rules.yaml",
    ];

    /// <summary>
    /// Words that name the previous product, so a line discussing it is telling the truth about
    /// whose code it is describing.
    /// </summary>
    private static readonly string[] NamesThePredecessor =
    [
        "predecessor",
        "previous product",
        "the old tool",
        "the old product",
    ];

    /// <summary>
    /// Every file in the rules folder says what it is, at the top, before anything else.
    /// </summary>
    /// <remarks>
    /// <b>On every file rather than in one README.</b> A folder-level note is read once by whoever
    /// goes looking for it; a card is opened directly, by a person or by a search, and the banner has
    /// to be in the thing that gets opened.
    /// </remarks>
    [Fact]
    public void EveryFileInTheRulesFolderIsMarkedAsPredecessorMaterial()
    {
        var unmarked = new List<string>();

        foreach (var file in RuleFiles())
        {
            var text = File.ReadAllText(file);

            if (!text.StartsWith(BannerStart, StringComparison.Ordinal)
                || !text.Contains(BannerEnd, StringComparison.Ordinal))
            {
                unmarked.Add("  " + Path.GetFileName(file));
            }
        }

        Assert.True(
            unmarked.Count == 0,
            "These files in docs/rules do not open with the predecessor-material banner, so a "
            + "reader arriving at one has no way to know the code it cites belongs to another "
            + "product:" + Environment.NewLine + string.Join(Environment.NewLine, unmarked));
    }

    /// <summary>
    /// No document outside the rules folder cites the predecessor's code without saying so.
    /// </summary>
    /// <remarks>
    /// <b>This is the containment, and it is the point of the gate.</b> The cards are allowed to be
    /// wrong about this product because they are marked. What must not happen is one of those paths
    /// migrating into a layer document, the roadmap or a decision record, where it would read as a
    /// statement about the product being built.
    /// </remarks>
    [Fact]
    public void NoDocumentOutsideTheRulesFolderCitesPredecessorCodeAsThoughItWereOurs()
    {
        var wrong = new List<string>();

        foreach (var file in DocumentsOutsideTheRulesFolder())
        {
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                var cited = PredecessorPaths.FirstOrDefault(
                    p => lines[i].Contains(p, StringComparison.OrdinalIgnoreCase));

                if (cited is null || SaysWhoseCodeItIs(lines[i]))
                    continue;

                wrong.Add(
                    $"  {Relative(file)} line {i + 1} cites {cited} without naming the predecessor");
            }
        }

        Assert.True(
            wrong.Count == 0,
            "These lines name the previous product's code in a document about this one. Either the "
            + "line is describing the predecessor and should say so, or it is describing this "
            + "product and is wrong:" + Environment.NewLine + string.Join(Environment.NewLine, wrong));
    }

    /// <summary>
    /// The scanner self-test. Without it both checks above pass by reading no files.
    /// </summary>
    /// <remarks>
    /// It asserts that the rules folder is the size it is and that the citations really are in
    /// there, so a scan that silently found nothing cannot report that nothing is wrong. The figures
    /// are not thresholds: a change to either means files were added or removed from the folder.
    /// </remarks>
    [Fact]
    public void TheScanReadsRealFilesAndFindsTheCitationsThatExist()
    {
        var cards = RuleFiles();

        Assert.Equal(66, cards.Count);
        Assert.NotEmpty(DocumentsOutsideTheRulesFolder());

        // The material the gate exists for really is in these files: if this ever reaches zero the
        // folder has been rewritten and the quarantine is no longer what is protecting anybody.
        var citing = cards.Count(
            f => PredecessorPaths.Any(
                p => File.ReadAllText(f).Contains(p, StringComparison.OrdinalIgnoreCase)));

        Assert.True(
            citing > 50,
            $"Only {citing} of {cards.Count} rule cards cite the predecessor's code. This gate was "
            + "written because nearly all of them do; if that is no longer true, check whether the "
            + "quarantine is still the right device.");
    }

    /// <summary>
    /// A line that names the predecessor is describing it rather than claiming it as ours.
    /// </summary>
    private static bool SaysWhoseCodeItIs(string line) =>
        NamesThePredecessor.Any(w => line.Contains(w, StringComparison.OrdinalIgnoreCase));

    private static List<string> RuleFiles() =>
        [.. Directory.GetFiles(RulesFolder(), "*.md").OrderBy(f => f, StringComparer.Ordinal)];

    private static List<string> DocumentsOutsideTheRulesFolder()
    {
        var rules = RulesFolder() + Path.DirectorySeparatorChar;

        return
        [
            .. Directory
                .GetFiles(Path.Combine(RepositoryLocation.Root(), "docs"), "*.md", SearchOption.AllDirectories)
                .Where(f => !f.StartsWith(rules, StringComparison.OrdinalIgnoreCase))
                .OrderBy(f => f, StringComparer.Ordinal),
        ];
    }

    private static string RulesFolder()
    {
        var directory = Path.Combine(RepositoryLocation.Root(), "docs", "rules");

        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException(
                "Expected the predecessor's rule cards at " + directory + ". An absent folder must "
                + "fail rather than let this gate pass by checking nothing.");
        }

        return directory;
    }

    private static string Relative(string file) =>
        Path.GetRelativePath(RepositoryLocation.Root(), file).Replace('\\', '/');
}
