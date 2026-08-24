using System.Reflection;
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
/// <para>
/// <b>The self-test was re-anchored 2026-08-24.</b> It used to prove both kinds of governing
/// document were recognised by naming two live documents, one of which was
/// <c>areas/what-a-permission-means</c>. That made it decay with every area file the rewrite
/// deletes, and repointing it at the next area file would have moved the decay rather than removed
/// it. It now derives the kinds the register actually cites and asserts the docs scan discovered
/// one of each, so it retires the areas half by itself when the last areas row goes. A floor such
/// as <i>at least one area file exists</i> was rejected for the same reason: it would have to be
/// edited on the day the rewrite finishes.
/// </para>
/// <para>
/// <b>Re-anchoring mutation-tested 2026-08-24 by
/// <c>next/tools/mutate-register-selftest.ps1</c>, baseline 5 passed, 0 failed:</b> the docs scan
/// stopping at <c>docs/areas</c>, and the docs scan stopping at <c>docs/layers</c>. Each killed by
/// <c>TheCheckFindsTheTypesTheRegisterAndTheAreas</c> and <c>EveryGoverningDocumentExists</c>.
/// Note that the scan returns silently when a directory is absent, so without this check a deleted
/// documentation tree would read as a clean result.
/// </para>
/// </summary>
public sealed class SurfaceRegisterTests
{
    private const string RegisterFile = SurfaceRegister.FileName;

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
    public void EveryGoverningDocumentExists()
    {
        var documents = GoverningDocumentNames();

        var unknown = RegisterEntries()
            .Where(e => !documents.Contains(e.Document))
            .Select(e => $"  {e.Type} claims '{e.Document}' (line {e.Line})")
            .ToList();

        Assert.True(
            unknown.Count == 0,
            RegisterFile + " names governing documents that do not exist. The register is how a "
            + "session finds the page to read before touching a type, so a document that is not "
            + "there leaves the type unowned while looking owned:"
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
            .Select(g => $"  {g.Key} is claimed by {string.Join(" and ", g.Select(e => e.Document).Distinct())}")
            .ToList();

        Assert.True(
            shared.Count == 0,
            RegisterFile + " claims a type from more than one document:"
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
        var documents = GoverningDocumentNames();

        Assert.True(types.Count > 0, "Found no public types in the rebuild's production assemblies.");
        Assert.True(entries.Count > 0, $"Read no entries from {RegisterFile}.");
        Assert.True(documents.Count > 0, "Read no governing documents from docs/.");
        Assert.Contains(types, t => ReadableName(t) == nameof(SecureAD.Kernel.Security.AceNormalizer));
        Assert.Contains(entries, e => e.Type == nameof(SecureAD.Kernel.Security.AceNormalizer));

        // The column is genuinely parsed out of the link, not left as the raw cell.
        Assert.All(entries, e => Assert.DoesNotContain("(", e.Document, StringComparison.Ordinal));

        // Every kind of governing document the register actually cites is one the docs scan
        // discovers. This is the point of the widening, anchored to the register rather than to two
        // filenames: while the register cites areas/ the areas scan is checked, and when the last
        // areas row goes the check stops checking areas by itself, because there is nothing left to
        // check. Naming a live document here instead made the self-test decay with every area file
        // deleted, and repointing it at the next area file would only move the decay.
        var citedKinds = entries
            .Select(e => e.Document)
            .Select(d => d.Split('/')[0])
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Assert.NotEmpty(citedKinds);

        foreach (var kind in citedKinds)
        {
            Assert.True(
                documents.Any(d => d.StartsWith(kind + "/", StringComparison.Ordinal)),
                $"{RegisterFile} cites documents under '{kind}/' but the docs scan discovered none. "
                + "Either the scan no longer walks that directory, or every document of that kind "
                + "has been deleted while rows still point at them.");
        }

        // A cell naming a document that does not exist is caught rather than shrugged off. These
        // use synthetic input, so no deletion can erode them.
        Assert.DoesNotContain("areas/no-such-area", documents);
        Assert.Equal("areas/no-such-area", GoverningDocument("[no-such-area](../areas/no-such-area.md)"));
        Assert.Equal("layers/kernel/naming", GoverningDocument("[naming](../layers/kernel/naming.md)"));
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

    private static string RegisterPath() => SurfaceRegister.Path();

    /// <summary>
    /// The register's rows, parsed by <see cref="SurfaceRegister"/> so this gate and the area gate
    /// read one table through one parser.
    /// </summary>
    private static List<(string Type, string Document, int Line)> RegisterEntries() =>
        SurfaceRegister.Entries();

    private static string GoverningDocument(string cell) =>
        SurfaceRegister.GoverningDocument(cell);

    private static HashSet<string> GoverningDocumentNames() =>
        SurfaceRegister.GoverningDocumentNames();
}
