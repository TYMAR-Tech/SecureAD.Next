using System.Reflection;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate 5a: every public type in the rebuild is accounted for in
/// <c>docs/next/SURFACE-REGISTER.md</c>, and every one names exactly one area that exists.
///
/// <para>
/// The old product carries six unreachable grids and twenty-eight commands bound to nothing. Each
/// was built for a reason and each stopped being connected, and nothing was watching. For an audit
/// tool, a screen that looks like it reports something and reports nothing is worse than a missing
/// screen, because a customer acts on it.
/// </para>
/// <para>
/// <b>This was keyed to the inventory until 2026-08-16.</b> Each entry named the inventory row
/// expected to become the type's first consumer, which made the build depend on an inventory of the
/// predecessor. Keying it to areas instead frees the inventory to stop being a plan, and asks a
/// question that stays meaningful: <i>which part of this product owns this type</i>. A type owned by
/// no area is either dead surface or a capability nobody wrote down.
/// </para>
/// <para>
/// <b>What this does not do.</b> It checks the bookkeeping, not the truth. It cannot tell whether a
/// type is genuinely reached by running code — that is gate 5b. The distinction is kept sharp
/// deliberately: gate 5's original single wording, <i>"every public type has a production
/// consumer"</i>, passed against all fourteen types while nothing in the tree was used at all,
/// because the types reference one another and one of them was "referenced" only from inside an XML
/// doc comment.
/// </para>
/// <para>
/// <b>Mutation-tested 2026-08-16, four directions, each killed by the test named:</b> a row naming
/// an area with no file (<c>EveryAreaNamedIsARealAreaFile</c>); one type given two rows with
/// different areas (<c>NoTypeIsClaimedByTwoAreas</c>); a row deleted for a type that still exists
/// (<c>EveryPublicTypeIsInTheRegister</c>); and a row renamed to a type that does not exist
/// (<c>TheRegisterNamesNoTypeThatDoesNotExist</c>). The last two were also caught by the scanner
/// self-test. Baseline and post-revert both 5 passed, 0 failed.
/// </para>
/// </summary>
public sealed class SurfaceRegisterTests
{
    private const string RegisterFile = "SURFACE-REGISTER.md";
    private const string TableBegin = "<!-- REGISTER:BEGIN -->";
    private const string TableEnd = "<!-- REGISTER:END -->";

    /// <summary>
    /// Assemblies making up the rebuild's production surface. Held once in
    /// <see cref="RebuildAssemblies"/>, which carries the self-test naming the three assemblies a
    /// type move must not change - see <c>F-S24-4</c>.
    /// </summary>
    private static IEnumerable<Assembly> ProductionAssemblies() => RebuildAssemblies.All;

    [Fact]
    public void EveryPublicTypeIsInTheRegister()
    {
        var registered = RegisterEntries().Select(e => e.Type).ToHashSet(StringComparer.Ordinal);

        var missing = PublicTypes()
            .Where(t => !registered.Contains(ReadableName(t)))
            .Select(t => $"  {ReadableName(t)} ({t.Namespace})")
            .OrderBy(t => t, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Public types absent from " + RegisterFile + ". Public surface outlives its author: "
            + "once a type is public, anything may come to depend on it. Add an entry naming the "
            + "area that owns it:" + Environment.NewLine
            + string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public void TheRegisterNamesNoTypeThatDoesNotExist()
    {
        var actual = PublicTypes().Select(ReadableName).ToHashSet(StringComparer.Ordinal);

        var phantom = RegisterEntries()
            .Where(e => !actual.Contains(e.Type))
            .Select(e => $"  {e.Type} (line {e.Line})")
            .ToList();

        Assert.True(
            phantom.Count == 0,
            RegisterFile + " lists types that no longer exist. An entry for a deleted type makes "
            + "the register look more complete than it is:" + Environment.NewLine
            + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// Every area named is a real area file. An entry pointing at a page that does not exist sends a
    /// session nowhere, which is worse than sending it nowhere in particular.
    /// </summary>
    [Fact]
    public void EveryAreaNamedIsARealAreaFile()
    {
        var areas = AreaFileNames();

        var unknown = RegisterEntries()
            .Where(e => !areas.Contains(e.Area))
            .Select(e => $"  {e.Type} claims '{e.Area}' (line {e.Line})")
            .ToList();

        Assert.True(
            unknown.Count == 0,
            RegisterFile + " names areas that have no file in docs/areas/. The register is how a "
            + "session finds the page to read before touching a type, so an area that is not there "
            + "leaves the type unowned while looking owned:"
            + Environment.NewLine + string.Join(Environment.NewLine, unknown));
    }

    /// <summary>
    /// A type belongs to exactly one area. Two rows for one type leaves two pages responsible for it
    /// and a reader unable to tell which owns it — the same rule the area gate applies one level
    /// down, where a capability belongs to one area.
    /// </summary>
    [Fact]
    public void NoTypeIsClaimedByTwoAreas()
    {
        var shared = RegisterEntries()
            .GroupBy(e => e.Type, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => $"  {g.Key} is claimed by {string.Join(" and ", g.Select(e => e.Area).Distinct())}")
            .ToList();

        Assert.True(
            shared.Count == 0,
            RegisterFile + " claims a type from more than one area:"
            + Environment.NewLine + string.Join(Environment.NewLine, shared));
    }

    /// <summary>
    /// The scanner self-test. Without it, the completeness checks above pass by comparing an
    /// empty set of types against an empty register and finding nothing wrong with either — and the
    /// two area checks pass against a column nothing managed to parse.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheTypesTheRegisterAndTheAreas()
    {
        var types = PublicTypes().ToList();
        var entries = RegisterEntries();
        var areas = AreaFileNames();

        Assert.True(types.Count > 0, "Found no public types in the rebuild's production assemblies.");
        Assert.True(entries.Count > 0, $"Read no entries from {RegisterFile}.");
        Assert.True(areas.Count > 0, "Read no area files from docs/areas/.");
        Assert.Contains(types, t => ReadableName(t) == nameof(SecureAD.Kernel.Security.AceNormalizer));
        Assert.Contains(entries, e => e.Type == nameof(SecureAD.Kernel.Security.AceNormalizer));

        // The area column is genuinely parsed out of the link, not left as the raw cell.
        Assert.All(entries, e => Assert.DoesNotContain("(", e.Area, StringComparison.Ordinal));
        Assert.Contains(entries, e => e.Area == "what-a-permission-means");

        // A cell naming an area that does not exist is caught rather than shrugged off.
        Assert.DoesNotContain("no-such-area", areas);
        Assert.Equal("no-such-area", AreaName("[no-such-area](../areas/no-such-area.md)"));
    }

    /// <summary>
    /// Every type the compiler considers public in a production assembly. Reflection rather than
    /// text scanning, because the question is what the surface actually is, and a text scan would
    /// count a type named in a comment.
    /// </summary>
    private static IEnumerable<Type> PublicTypes() =>
        ProductionAssemblies()
            .SelectMany(a => a.GetExportedTypes())
            .Where(t => !t.IsNested);

    /// <summary>
    /// The name as a person would write it. The runtime appends an arity marker to a generic type
    /// — <c>Result</c> is reported as <c>Result`1</c> — which would force the register to carry
    /// compiler notation rather than the name its readers know it by.
    /// </summary>
    private static string ReadableName(Type type)
    {
        var name = type.Name;
        var tick = name.IndexOf('`', StringComparison.Ordinal);
        return tick < 0 ? name : name[..tick];
    }

    private static string RegisterPath() =>
        Path.Combine(RepositoryLocation.Root(), "docs", "next", RegisterFile);

    /// <summary>
    /// The register's rows: the type, the area that owns it, and the line it sits on. Only what
    /// lies between the markers is parsed, so the prose around the table does not have to pretend
    /// to be data.
    /// </summary>
    private static List<(string Type, string Area, int Line)> RegisterEntries()
    {
        var path = RegisterPath();
        Assert.True(File.Exists(path), $"Expected the surface register at {path}.");

        var lines = File.ReadAllLines(path);
        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        Assert.True(
            begin >= 0 && end > begin,
            $"Could not find the {TableBegin} / {TableEnd} markers around the table in {path}. "
            + "The test parses only what lies between them, so a missing marker must fail rather "
            + "than silently empty the scan.");

        var entries = new List<(string, string, int)>();

        for (var i = begin + 1; i < end; i++)
        {
            var cells = lines[i].Split('|', StringSplitOptions.TrimEntries);
            if (cells.Length < 5)
                continue;

            var type = cells[1];
            if (type is "Type" || type.Length == 0 || type.All(c => c is '-' or ':'))
                continue;

            entries.Add((type, AreaName(cells[3]), i + 1));
        }

        return entries;
    }

    /// <summary>
    /// The area out of a cell written as <c>[name](../areas/name.md)</c>. The link target is read
    /// rather than the label, because the label is prose and the target is what has to resolve.
    /// </summary>
    private static string AreaName(string cell)
    {
        var match = AreaLink.Match(cell);
        return match.Success ? match.Groups["name"].Value : cell;
    }

    private static readonly Regex AreaLink =
        new(@"\(\.\./areas/(?<name>[A-Za-z0-9-]+)\.md\)", RegexOptions.Compiled);

    /// <summary>
    /// The areas that actually exist, read off disk rather than listed here, so a renamed area file
    /// fails the register rather than being quietly accepted by a copy of the list.
    /// </summary>
    private static HashSet<string> AreaFileNames() =>
        Directory
            .GetFiles(Path.Combine(RepositoryLocation.Root(), "docs", "areas"), "*.md")
            .Select(Path.GetFileNameWithoutExtension)
            .Where(n => n is not null && n != "README")
            .Select(n => n!)
            .ToHashSet(StringComparer.Ordinal);
}
