using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The area gate: the files in <c>docs/areas/</c> are the one place a session is told to start, so
/// what they claim has to be true or the instruction is worse than none.
///
/// <para>
/// Every link out of an area file resolves to a file that exists, so a renamed or deleted decision
/// record cannot leave a page citing something unreadable. Every capability in the <i>What is
/// built</i> table names a test that exists and carries a test attribute, so a capability cannot be
/// asserted in prose alone. And every area file still governs at least one type no layer document
/// names, so a file the rewrite has finished consuming says so rather than sitting on.
/// </para>
/// <para>
/// <b>The three-section check was deleted on 2026-08-21 (<c>P-51</c>).</b> It asserted that each
/// file carried three headings, which no change to the product could ever break, and it forced
/// three headings into a file being emptied — so a file could not be shrunk toward nothing, only
/// deleted whole. Removing it is what makes consumption incremental.
/// </para>
/// <para>
/// <b>What this does not do.</b> It cannot tell whether a capability sentence describes what the
/// named test actually asserts. That is review. It closes the gap where the test was renamed,
/// deleted, or never written.
/// </para>
/// </summary>
public sealed class AreaFileGateTests
{
    private const string BuiltHeading = "## What is built";

    /// <summary>
    /// The index of areas. It is not an area itself, so it is not held to the checks below, and it
    /// is the one file allowed to name an area that has not been written.
    /// </summary>
    private const string IndexFile = "README.md";

    /// <summary>
    /// A markdown link with a relative target: <c>[text](../decisions/0056-....md)</c>. Absolute
    /// links are left alone because this gate cannot reach the network, and an anchor is trimmed
    /// because the question is whether the file is there.
    /// </summary>
    private static readonly Regex RelativeLink = new(@"\]\((?<target>[^)\s]+)\)", RegexOptions.Compiled);

    /// <summary>A citation in a table cell, written the way the area files write it: <c>`Name`</c>.</summary>
    private static readonly Regex Citation = new(@"`(?<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)?)`", RegexOptions.Compiled);

    /// <summary>
    /// The file an unwritten area intends to occupy, named in backticks because there is nothing yet
    /// to link to: <c>`who-is-who.md`</c>.
    /// </summary>
    private static readonly Regex IntendedFile = new(@"`(?<file>[A-Za-z0-9-]+\.md)`", RegexOptions.Compiled);

    [Fact]
    public void EveryLinkOutOfAnAreaFileResolves()
    {
        var broken = new List<string>();

        foreach (var file in AreaFiles())
        {
            var directory = Path.GetDirectoryName(file)!;
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                foreach (Match match in RelativeLink.Matches(lines[i]))
                {
                    var target = match.Groups["target"].Value;
                    if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase) || target.StartsWith('#'))
                        continue;

                    var anchor = target.IndexOf('#', StringComparison.Ordinal);
                    var relative = anchor < 0 ? target : target[..anchor];
                    if (relative.Length == 0)
                        continue;

                    var resolved = Path.GetFullPath(Path.Combine(directory, relative));
                    if (!File.Exists(resolved) && !Directory.Exists(resolved))
                        broken.Add($"  {Path.GetFileName(file)} line {i + 1} links to '{relative}', which is not there");
                }
            }
        }

        Assert.True(
            broken.Count == 0,
            "Area files link to files that do not exist. An area file is the first thing read in a "
            + "session, so a citation that cannot be followed sends the reader to the inventory or the "
            + "old application instead:" + Environment.NewLine
            + string.Join(Environment.NewLine, broken));
    }

    /// <summary>
    /// Every capability names a test, and the test is real. A capability citing a production class
    /// fails here, because a class name is not evidence of anything — the class exists whether or
    /// not it does what the sentence beside it claims.
    /// </summary>
    [Fact]
    public void EveryCapabilityNamesATestThatExists()
    {
        var unproven = new List<string>();

        foreach (var (file, line, citation) in Capabilities())
        {
            if (!TestExists(citation, out var reason))
                unproven.Add($"  {Path.GetFileName(file)} line {line} cites `{citation}` — {reason}");
        }

        Assert.True(
            unproven.Count == 0,
            "Capabilities naming something that is not a test. The test is the evidence and the "
            + "table is only the index, so a capability whose test is missing is a claim the "
            + "product may not honour:" + Environment.NewLine
            + string.Join(Environment.NewLine, unproven));
    }

    /// <summary>
    /// No capability belongs to two areas. Overlap is the safer of the two errors — a question in
    /// two areas gets discussed twice and someone notices, where a question in none is discussed
    /// never — but it still leaves two pages claiming the same evidence, and a reader cannot tell
    /// which one owns it. This is the rule step 5 applies one level up, where a type is claimed by
    /// exactly one area.
    /// </summary>
    [Fact]
    public void NoCapabilityIsClaimedByTwoAreas()
    {
        var shared = Capabilities()
            .GroupBy(c => c.Citation, StringComparer.Ordinal)
            .Select(g => new
            {
                Citation = g.Key,
                Areas = g.Select(c => Path.GetFileName(c.File)).Distinct(StringComparer.Ordinal).ToList()
            })
            .Where(g => g.Areas.Count > 1)
            .Select(g => "  " + g.Citation + " is claimed by " + string.Join(" and ", g.Areas))
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            shared.Count == 0,
            "The same test is cited as evidence by more than one area. Decide which area owns the "
            + "capability and cite it there; the other may point at that area in prose:"
            + Environment.NewLine + string.Join(Environment.NewLine, shared));
    }

    /// <summary>
    /// The index and the directory agree, in both directions. An area listed as written but absent
    /// is a promise nothing keeps; an area file present but unlisted is invisible to anyone reading
    /// the index to find out what exists. The second direction matters most, because the index is
    /// what makes an unwritten area say so rather than say nothing at all.
    /// </summary>
    [Fact]
    public void TheIndexAndTheAreaFilesAgree()
    {
        var listed = IndexEntries();
        var present = AreaFiles().Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();

        foreach (var (file, written, line) in listed)
        {
            if (written && !present.Contains(file))
                problems.Add($"  {IndexFile} line {line} says '{file}' is written, and it is not there");

            if (!written && present.Contains(file))
                problems.Add($"  {IndexFile} line {line} says '{file}' is not written, and it exists");
        }

        var listedFiles = listed.Select(e => e.File).ToHashSet(StringComparer.Ordinal);

        problems.AddRange(present
            .Where(f => !listedFiles.Contains(f))
            .Select(f => $"  {f} exists but is not listed in {IndexFile}"));

        Assert.True(
            problems.Count == 0,
            "The area index and the area files disagree. The index is how an area nobody has "
            + "written yet says so out loud, instead of being silently absent:" + Environment.NewLine
            + string.Join(Environment.NewLine, problems));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by finding no area files, no
    /// links and no capabilities, and reports that nothing is wrong with any of them. That failure
    /// has been committed in this repository before — gate 5's original wording passed against all
    /// fourteen public types while nothing in the tree was reachable.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheAreaFilesTheirLinksAndTheirCapabilities()
    {
        var files = AreaFiles();
        var capabilities = Capabilities();
        var links = files.Sum(f => File.ReadAllLines(f).Sum(l => RelativeLink.Matches(l).Count));

        Assert.True(files.Count > 0, $"Found no area files under {AreaDirectory()}.");
        Assert.True(capabilities.Count > 0, "Read no capabilities from the 'What is built' tables.");
        Assert.True(links > 0, "Read no links out of any area file.");
        Assert.True(IndexEntries().Count > 0, $"Read no areas from {IndexFile}.");

        Assert.Contains(files, f => Path.GetFileName(f) == "which-controller-we-read.md");
        Assert.Contains(capabilities, c => c.Citation == nameof(Connect.ForestDiscoveryTests));

        // The citation check can tell a test from something that is not one, in both directions.
        Assert.True(TestExists(nameof(AreaFileGateTests), out _));
        Assert.False(TestExists(nameof(RelativeLink), out _));
    }

    /// <summary>
    /// The anti-drift device: an area file that no longer governs a single undocumented type is
    /// redundant and must fail, because the rewrite has finished consuming it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The stated goal of the rewrite is <b>fewer files</b> — one layer document per code folder,
    /// with <c>docs/areas</c> emptied as its content is consumed. Nothing measured that. Four area
    /// files were found redundant on 2026-08-20 <b>only because somebody counted by hand</b>, which
    /// means the finding was an accident of who was reading rather than a property of the tree.
    /// </para>
    /// <para>
    /// <b>It derives both sides.</b> An area file's types are its rows in
    /// <c>SURFACE-REGISTER.md</c>, which <see cref="SurfaceRegisterTests"/> already holds to the
    /// exported types of the three production assemblies in both directions — so a type invented in
    /// the register, or a type in the assemblies with no row, fails there before it reaches here.
    /// "Named by a layer document" is the backticked name appearing in a file under
    /// <c>docs/layers</c>. Writing the last of an area's types into a layer document therefore fails
    /// the build until the area file is deleted, and adding a public type to an area that still owns
    /// one keeps it passing.
    /// </para>
    /// <para>
    /// <b>What this does not do.</b> An area file with no register rows at all is not checked. Those
    /// own no built surface — six describe the judgement and reporting half of the product, which is
    /// not written, and <c>how-the-app-looks</c> owns the shell, which the register does not cover
    /// (<c>ShellSurfaceGateTests</c> does). Nothing in the tree distinguishes "not built yet" from
    /// "fully consumed", so those files are left to a reader rather than guessed at here.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryAreaFileStillGovernsAtLeastOneUndocumentedType()
    {
        var layers = string.Concat(LayerDocuments.All().Select(File.ReadAllText));

        var redundant = TypesByArea()
            .Where(area => area.Value.All(type => layers.Contains(Quoted(type), StringComparison.Ordinal)))
            .Select(area =>
                $"  {area.Key}.md governs {area.Value.Count} type(s), and a layer document names "
                + $"every one of them: {string.Join(", ", area.Value.OrderBy(t => t, StringComparer.Ordinal))}")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            redundant.Count == 0,
            "Area files the rewrite has finished consuming. Every type each one governs is already "
            + "described by a layer document, so the area file is a second home for facts that have "
            + "one — delete it, and repoint its rows in " + SurfaceRegister.FileName + " at the "
            + "layer document that now describes them:" + Environment.NewLine
            + string.Join(Environment.NewLine, redundant));
    }

    /// <summary>
    /// The scanner self-test for the check above. Without it the check passes by reading no register
    /// rows and no layer documents, and reports that no area file is redundant. It also proves the
    /// match discriminates: a name is found only when a layer document writes it in backticks, so a
    /// rename does not go on satisfying the check by substring.
    /// </summary>
    [Fact]
    public void TheRedundancyCheckReadsTheRegisterTheLayerDocumentsAndDiscriminates()
    {
        var byArea = TypesByArea();
        var layers = string.Concat(LayerDocuments.All().Select(File.ReadAllText));

        Assert.True(byArea.Count > 0, $"Grouped no area files out of {SurfaceRegister.FileName}.");
        Assert.True(layers.Length > 0, "Read no text from any layer document.");

        // Every area grouped here is a file on disk, so the check cannot report a phantom.
        var present = AreaFiles().Select(Path.GetFileNameWithoutExtension).ToHashSet(StringComparer.Ordinal);
        Assert.All(byArea.Keys, area => Assert.Contains(area, present));

        // A type a layer document genuinely names is found, and a near-miss of it is not.
        Assert.Contains(Quoted(nameof(SecureAD.Kernel.Security.WellKnownSid)), layers, StringComparison.Ordinal);
        Assert.DoesNotContain(Quoted(nameof(SecureAD.Kernel.Security.WellKnownSid) + "XX"), layers, StringComparison.Ordinal);
    }

    /// <summary>
    /// The types each area file governs, taken from the register and keyed by the area's file name
    /// without its extension. Rows governed by a layer document are not area rows and are skipped.
    /// </summary>
    private static Dictionary<string, List<string>> TypesByArea() =>
        SurfaceRegister.Entries()
            .Where(e => e.Document.StartsWith("areas/", StringComparison.Ordinal))
            .GroupBy(e => e.Document["areas/".Length..], StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Type).ToList(), StringComparer.Ordinal);

    /// <summary>
    /// The name as a document must write it. A bare name would match any longer name containing it;
    /// the backticks make the match exact without needing a parser.
    /// </summary>
    private static string Quoted(string name) => "`" + name + "`";

    private static string AreaDirectory() => Path.Combine(RepositoryLocation.Root(), "docs", "areas");

    private static List<string> AreaFiles()
    {
        var directory = AreaDirectory();
        Assert.True(Directory.Exists(directory), $"Expected the area files at {directory}.");
        return
        [
            .. Directory.EnumerateFiles(directory, "*.md")
                .Where(f => !string.Equals(Path.GetFileName(f), IndexFile, StringComparison.Ordinal))
                .OrderBy(f => f, StringComparer.Ordinal)
        ];
    }

    /// <summary>
    /// The index's rows: the file an area is expected to live in, whether it claims to be written,
    /// and the line it sits on. An area is written when its row links to a file; an area nobody has
    /// written yet names its intended file in backticks instead, so the row still says which file
    /// would hold it.
    /// </summary>
    private static List<(string File, bool Written, int Line)> IndexEntries()
    {
        var path = Path.Combine(AreaDirectory(), IndexFile);
        Assert.True(File.Exists(path), $"Expected the area index at {path}.");

        var entries = new List<(string, bool, int)>();
        var lines = File.ReadAllLines(path);

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith('|'))
                continue;

            var cells = line.Split('|', StringSplitOptions.TrimEntries);
            if (cells.Length < 4)
                continue;

            var link = RelativeLink.Match(cells[2]);
            if (link.Success)
            {
                entries.Add((link.Groups["target"].Value, true, i + 1));
                continue;
            }

            var intended = IntendedFile.Match(cells[2]);
            if (intended.Success)
                entries.Add((intended.Groups["file"].Value, false, i + 1));
        }

        return entries;
    }

    /// <summary>
    /// The citations in the second column of each <i>What is built</i> table. Only the rows between
    /// that heading and the next one are read, so the citations elsewhere on the page — a gate named
    /// in the decided table, a type named in the prose — are not mistaken for capabilities.
    /// </summary>
    private static List<(string File, int Line, string Citation)> Capabilities()
    {
        var found = new List<(string, int, string)>();

        foreach (var file in AreaFiles())
        {
            var lines = File.ReadAllLines(file);
            var start = Array.FindIndex(lines, l => l.Trim() == BuiltHeading);
            if (start < 0)
                continue;

            for (var i = start + 1; i < lines.Length; i++)
            {
                var line = lines[i].Trim();
                if (line.StartsWith("## ", StringComparison.Ordinal))
                    break;

                if (!line.StartsWith('|'))
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
        }

        return found;
    }

    /// <summary>
    /// Whether a citation names a test. Shared with <see cref="CapabilityCitationTests"/>, which
    /// asks the same question of the layer documents: two resolvers written separately drift apart,
    /// and this repository has already been bitten by checks each narrower than their own names.
    /// </summary>
    private static bool TestExists(string citation, out string reason) =>
        TestCitation.Resolve(citation, out reason);
}
