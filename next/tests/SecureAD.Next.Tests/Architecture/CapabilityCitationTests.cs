using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The capability gate for the layer documents — the pages the documentation rewrite is producing,
/// one per code folder, under <c>docs/kernel</c>, <c>docs/audit</c>, <c>docs/connect</c> and
/// <c>docs/evidence</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>The hole this closes.</b> <see cref="AreaFileGateTests"/> and
/// <see cref="LabConfirmationColumnTests"/> resolve <c>docs/areas</c> and nothing else, and the
/// per-document gates bind types, members and marker tables rather than capability rows. So the
/// capability tables carried across into the layer documents named test methods that no check
/// resolved. That was not a hypothetical: the catalogue page cited
/// <c>EveryAttributeTheCodeRequestsIsInTheDocument</c> and
/// <c>TheDocumentNamesNoAttributeTheCodeDoesNotRequest</c> long after both methods had been renamed,
/// and nothing noticed. A capability table is an index to evidence; an index nobody checks is prose.
/// </para>
/// <para>
/// <b>Two headings, deliberately.</b> The kernel documents write the table under
/// <i>What an operator can do</i> and the rest write it under <i>What is built</i>. A gate keyed on
/// one of them would pass by scanning nothing in three kernel documents — the failure family this
/// repository has now hit six times, where a check is narrower than its own name. Both openers are
/// matched, and <see cref="TheCheckReadsCapabilityTablesFromEverySubsystem"/> asserts each subsystem
/// was actually reached rather than that some global count was greater than zero.
/// </para>
/// <para>
/// <b>What this does not do.</b> It cannot tell whether a capability sentence describes what the
/// named test asserts. That is review. It closes the gap where the test was renamed, deleted, or
/// never written.
/// </para>
/// </remarks>
public sealed class CapabilityCitationTests
{
    /// <summary>
    /// The two openers a capability table is written under. <c>StartsWith</c> rather than equality,
    /// because a heading may carry trailing words.
    /// </summary>
    private static readonly string[] CapabilityHeadings = ["## What is built", "## What an operator can do"];

    /// <summary>A citation in a table cell, written the way the documents write it: <c>`Name`</c>.</summary>
    private static readonly Regex Citation =
        new(@"`(?<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)`", RegexOptions.Compiled);

    /// <summary>
    /// Every capability in a layer document names a test that exists. A capability citing a
    /// production class fails here, because a class name is not evidence of anything — the class
    /// exists whether or not it does what the sentence beside it claims.
    /// </summary>
    [Fact]
    public void EveryCapabilityInALayerDocumentNamesATestThatExists()
    {
        var unproven = new List<string>();

        foreach (var (file, line, citation) in Capabilities())
        {
            if (!TestCitation.Resolve(citation, out var reason))
                unproven.Add($"  {Subsystem(file)}/{Path.GetFileName(file)} line {line} cites `{citation}` — {reason}");
        }

        Assert.True(
            unproven.Count == 0,
            "Capabilities in layer documents naming something that is not a test. The test is the "
            + "evidence and the table is only the index, so a capability whose test is missing is a "
            + "claim the product may not honour. This is what a rename leaves behind:"
            + Environment.NewLine + string.Join(Environment.NewLine, unproven));
    }

    /// <summary>
    /// The scanner self-test, per subsystem. Without it this check passes by finding no documents,
    /// no tables and no citations, and reports that nothing is wrong with any of them. Counting
    /// globally would not be enough: the kernel documents use the other heading, so a gate that
    /// read only <i>What is built</i> would still find plenty of citations while silently missing
    /// every one of them.
    /// </summary>
    [Fact]
    public void TheCheckReadsCapabilityTablesFromEverySubsystem()
    {
        var capabilities = Capabilities();

        Assert.True(capabilities.Count > 0, "Read no capabilities from any layer document.");

        foreach (var subsystem in LayerDocuments.Subsystems)
        {
            var read = capabilities.Count(c => Subsystem(c.File) == subsystem);
            Assert.True(read > 0, $"Read no capabilities from docs/{subsystem}, so nothing there is checked.");
        }

        // The kernel heading in particular, because it is the one a single-heading gate loses.
        Assert.Contains(capabilities, c =>
            Subsystem(c.File) == "kernel" && c.Citation == nameof(Kernel.Security.GoldenAceHashTests));

        // The resolver can tell a test from something that is not one, in both directions.
        Assert.True(TestCitation.Resolve(nameof(CapabilityCitationTests), out _));
        Assert.False(TestCitation.Resolve(nameof(Citation), out _));
    }

    /// <summary>
    /// A capability table that is present but empty asserts nothing while looking as though it
    /// does. Every layer document carrying a capability heading carries rows under it.
    /// </summary>
    [Fact]
    public void ACapabilityHeadingIsNeverLeftWithoutRows()
    {
        var empty = LayerDocumentFiles()
            .Where(f => CarriesACapabilityHeading(f) && !CapabilitiesIn(f).Any())
            .Select(f => $"  {Subsystem(f)}/{Path.GetFileName(f)}")
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            empty.Count == 0,
            "These layer documents open a capability table and then name no evidence, which reads "
            + "as though the capabilities were proven rather than as though nobody wrote them down:"
            + Environment.NewLine + string.Join(Environment.NewLine, empty));
    }

    private static string Subsystem(string file) => LayerDocuments.SubsystemOf(file);

    private static List<string> LayerDocumentFiles() => LayerDocuments.All();

    private static bool CarriesACapabilityHeading(string file) =>
        File.ReadAllLines(file).Any(IsCapabilityHeading);

    private static bool IsCapabilityHeading(string line) =>
        CapabilityHeadings.Any(h => line.TrimEnd().StartsWith(h, StringComparison.Ordinal));

    private static List<(string File, int Line, string Citation)> Capabilities() =>
        [.. LayerDocumentFiles().SelectMany(CapabilitiesIn)];

    /// <summary>
    /// The citations in the second column of a document's capability table. Only the rows between
    /// the capability heading and the next heading are read, so citations elsewhere on the page —
    /// a gate named in the prose, a type named in <i>The types</i> — are not mistaken for
    /// capabilities.
    /// </summary>
    private static List<(string File, int Line, string Citation)> CapabilitiesIn(string file)
    {
        var found = new List<(string, int, string)>();
        var lines = File.ReadAllLines(file);
        var inSection = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();

            if (line.StartsWith("## ", StringComparison.Ordinal))
            {
                inSection = IsCapabilityHeading(line);
                continue;
            }

            if (!inSection || !line.StartsWith('|'))
                continue;

            var cells = line.Split('|', StringSplitOptions.TrimEntries);
            if (cells.Length < 4)
                continue;

            var evidence = cells[2];
            if (evidence is "Proven by" || evidence.Length == 0 || evidence.All(c => c is '-' or ':'))
                continue;

            var citation = Citation.Match(evidence);
            found.Add((file, i + 1, citation.Success ? citation.Groups["name"].Value : evidence));
        }

        return found;
    }
}
