using System.Reflection;
using System.Text.RegularExpressions;
using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The area gate: the files in <c>docs/areas/</c> are the one place a session is told to start, so
/// what they claim has to be true or the instruction is worse than none.
///
/// <para>
/// Three claims are checked. Every link out of an area file resolves to a file that exists, so a
/// renamed or deleted decision record cannot leave a page citing something unreadable. Every
/// capability in the <i>What is built</i> table names a test that exists and carries a test
/// attribute, so a capability cannot be asserted in prose alone. Every area file carries the three
/// sections the shape depends on — most of all <i>What has not been discussed</i>, which is where
/// "nobody has answered this" lives and the only thing standing between a session and an inferred
/// answer.
/// </para>
/// <para>
/// <b>What this does not do.</b> It cannot tell whether a capability sentence describes what the
/// named test actually asserts. That is review. It closes the gap where the test was renamed,
/// deleted, or never written.
/// </para>
/// </summary>
public sealed class AreaFileGateTests
{
    private const string DecidedHeading = "## What is decided";
    private const string BuiltHeading = "## What is built";
    private const string NotDiscussedHeading = "## What has not been discussed";

    /// <summary>
    /// The index of areas. It is not an area itself, so the three-section rule does not apply to it,
    /// and it is the one file allowed to name an area that has not been written.
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
    public void EveryAreaFileCarriesTheThreeSections()
    {
        var missing = new List<string>();

        foreach (var file in AreaFiles())
        {
            var text = File.ReadAllText(file);

            foreach (var heading in new[] { DecidedHeading, BuiltHeading, NotDiscussedHeading })
            {
                if (!text.Contains(heading, StringComparison.Ordinal))
                    missing.Add($"  {Path.GetFileName(file)} has no '{heading}' section");
            }
        }

        Assert.True(
            missing.Count == 0,
            "Area files missing a required section. 'What has not been discussed' is the one that "
            + "matters most: it is where a session is told to stop and ask, and a file without it "
            + "reads as though everything in its area is settled:" + Environment.NewLine
            + string.Join(Environment.NewLine, missing));
    }

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

    private static string AreaDirectory() => Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "areas");

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
    /// Whether a citation names a test. Reflection over this assembly rather than a text scan,
    /// because the question is whether the test is really there — a text scan would be satisfied by
    /// the name appearing in a comment, which is how gate 5 came to pass while measuring nothing.
    /// </summary>
    private static bool TestExists(string citation, out string reason)
    {
        var parts = citation.Split('.');
        var typeName = parts[0];

        var type = Assembly.GetExecutingAssembly()
            .GetTypes()
            .FirstOrDefault(t => t.Name == typeName && !t.IsNested);

        if (type is null)
        {
            reason = "no such type in the test assembly";
            return false;
        }

        var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(IsTestMethod)
            .ToList();

        if (methods.Count == 0)
        {
            reason = "that type declares no tests, so it proves nothing";
            return false;
        }

        if (parts.Length == 1)
        {
            reason = string.Empty;
            return true;
        }

        if (methods.All(m => m.Name != parts[1]))
        {
            reason = $"'{typeName}' declares no test named '{parts[1]}'";
            return false;
        }

        reason = string.Empty;
        return true;
    }

    private static bool IsTestMethod(MethodInfo method) =>
        method.GetCustomAttributes()
            .Any(a => a.GetType().Name is "FactAttribute" or "TheoryAttribute");
}
