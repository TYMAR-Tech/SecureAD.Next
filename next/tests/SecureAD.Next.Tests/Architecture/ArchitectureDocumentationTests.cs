using SecureAD.Next.Tests.Inventory;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Binds <c>docs/next/ARCHITECTURE.md</c> to the projects it describes, and enforces the dependency
/// direction it declares.
///
/// <para>
/// <b>Why the direction is a rule.</b> Today the kernel references nothing, the bundle references
/// the kernel, and capture references both. That is correct and it is held up by nothing except
/// three lines in three project files. One reference added the wrong way would compile, pass every
/// other test, and go unnoticed - and what it costs is not tidiness. The kernel is the part with no
/// opinions about this product, which is what lets its answers be tested without a database. A
/// kernel that referenced the bundle stops being that, invisibly at the moment it happens and
/// irreversibly by the time anyone minds. The previous product's domain project targeted Windows
/// for no reason its contents needed, and presentation-shaped types moved in through the gap over
/// years. Nobody decided that either.
/// </para>
/// <para>
/// Stated now, at three projects and three edges, because it is the cheapest it will ever be.
/// </para>
/// <para>
/// <b>What it does not do.</b> It cannot say a dependency is sensible, only that it points
/// downward. And it sees only project references: a dependency expressed through a shared file, a
/// database table or a convention is out of reach, which is the same limit the concept registry
/// records about itself.
/// </para>
/// </summary>
public sealed class ArchitectureDocumentationTests
{
    private const string Document = "ARCHITECTURE.md";
    private const string TableBegin = "<!-- DEPENDENCIES:BEGIN -->";
    private const string TableEnd = "<!-- DEPENDENCIES:END -->";

    /// <summary>One row of the document's dependency table.</summary>
    private sealed record DeclaredProject(string Name, int Layer, IReadOnlyList<string> MayReference, int Line);

    [Fact]
    public void TheDocumentDescribesEveryProjectInTheRebuild()
    {
        var declared = Declared().Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var missing = ProductionProjects()
            .Where(p => !declared.Contains(p))
            .Select(p => "  " + p)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Projects in next/src that " + Document + " does not describe. A project nobody has "
            + "placed in the layering is one whose dependencies nothing checks:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    [Fact]
    public void TheDocumentDescribesNoProjectThatDoesNotExist()
    {
        var actual = ProductionProjects().ToHashSet(StringComparer.OrdinalIgnoreCase);

        var phantom = Declared()
            .Where(p => !actual.Contains(p.Name))
            .Select(p => $"  {p.Name} (line {p.Line})")
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " describes projects that do not exist. A document promising more structure "
            + "than the code has is worse than none, because the layering it asserts is not the "
            + "layering being checked:" + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The specific rule: every actual reference is one the document permits.
    /// </summary>
    [Fact]
    public void EveryProjectReferenceIsOneTheDocumentPermits()
    {
        var permitted = Declared().ToDictionary(
            p => p.Name,
            p => p.MayReference.ToHashSet(StringComparer.OrdinalIgnoreCase),
            StringComparer.OrdinalIgnoreCase);

        var undeclared = ActualReferences()
            .Where(r => permitted.ContainsKey(r.From))
            .Where(r => !permitted[r.From].Contains(r.To))
            .Select(r => $"  {r.From} -> {r.To}")
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            undeclared.Count == 0,
            "Project references " + Document + " does not permit. Either the reference is wrong, or "
            + "the architecture changed and the document has not - and the second is how a design "
            + "becomes whatever the project files happen to say:"
            + Environment.NewLine + string.Join(Environment.NewLine, undeclared));
    }

    /// <summary>
    /// The generic rule, and the one that survives someone editing the table carelessly. A
    /// reference must go to a strictly lower layer - never sideways, never upward. This catches an
    /// inversion even if the permission cell was widened to allow it, because widening it would
    /// also have to renumber the layers, which is a change nobody makes by accident.
    /// </summary>
    [Fact]
    public void EveryProjectReferencePointsDownward()
    {
        var layers = Declared().ToDictionary(p => p.Name, p => p.Layer, StringComparer.OrdinalIgnoreCase);

        var wrongWay = ActualReferences()
            .Where(r => layers.ContainsKey(r.From) && layers.ContainsKey(r.To))
            .Where(r => layers[r.To] >= layers[r.From])
            .Select(r => $"  {r.From} (layer {layers[r.From]}) -> {r.To} (layer {layers[r.To]})")
            .OrderBy(r => r, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            wrongWay.Count == 0,
            "Project references that do not point downward. The kernel is the part with no "
            + "opinions about this product, which is what lets it be tested without a database and "
            + "reused without dragging anything behind it. A reference upward or sideways ends "
            + "that, and the loss is invisible on the day it happens:"
            + Environment.NewLine + string.Join(Environment.NewLine, wrongWay));
    }

    /// <summary>
    /// Two projects may not share a layer. Layers are what the downward rule is expressed in, so a
    /// duplicate number quietly turns a strict comparison into one that permits a sideways
    /// reference between exactly those two.
    /// </summary>
    [Fact]
    public void NoTwoProjectsShareALayer()
    {
        var collisions = Declared()
            .GroupBy(p => p.Layer)
            .Where(g => g.Count() > 1)
            .Select(g => $"  layer {g.Key}: {string.Join(", ", g.Select(p => p.Name))}")
            .ToList();

        Assert.True(
            collisions.Count == 0,
            "Projects sharing a layer in " + Document + ". Two projects on one layer may reference "
            + "each other without the downward rule noticing:"
            + Environment.NewLine + string.Join(Environment.NewLine, collisions));
    }

    /// <summary>
    /// A permission naming a project that does not exist can never be violated, which is how an
    /// allowance outlives the thing it was written for.
    /// </summary>
    [Fact]
    public void EveryPermittedTargetIsARealProject()
    {
        var actual = ProductionProjects().ToHashSet(StringComparer.OrdinalIgnoreCase);

        var phantom = Declared()
            .SelectMany(p => p.MayReference.Select(t => (p, t)))
            .Where(x => !actual.Contains(x.t))
            .Select(x => $"  {x.p.Name} may reference '{x.t}', which does not exist (line {x.p.Line})")
            .ToList();

        Assert.True(
            phantom.Count == 0,
            Document + " permits references to projects that do not exist:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The stages are the part a reader comes here for, and the part most likely to be left behind
    /// as branches land. Each must say what state it is in, so a stage nobody has started is
    /// visibly not started rather than merely undescribed.
    /// </summary>
    [Fact]
    public void EveryStageDeclaresItsState()
    {
        var rows = Read().Split('\n')
            .Where(l => l.TrimStart().StartsWith("| ", StringComparison.Ordinal))
            .Where(l => l.Contains("| A |", StringComparison.Ordinal)
                        || l.Contains("| B |", StringComparison.Ordinal)
                        || l.Contains("| C |", StringComparison.Ordinal)
                        || l.Contains("| D |", StringComparison.Ordinal)
                        || l.Contains("| E |", StringComparison.Ordinal)
                        || l.Contains("| G |", StringComparison.Ordinal)
                        || l.Contains("| I, J |", StringComparison.Ordinal))
            .ToList();

        Assert.True(rows.Count >= 7, $"Found {rows.Count} stage rows in {Document}; expected seven.");

        Assert.All(rows, row => Assert.True(
            row.Contains("Not built", StringComparison.OrdinalIgnoreCase)
            || row.Contains("Building", StringComparison.OrdinalIgnoreCase)
            || row.Contains("Done", StringComparison.OrdinalIgnoreCase),
            "A stage row states no state: " + row.Trim()));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by comparing an empty set of
    /// projects against an empty table and reporting an architecture in perfect order - the failure
    /// this repository has committed three times.
    /// </summary>
    [Fact]
    public void TheCheckFindsTheProjectsTheirReferencesAndTheTable()
    {
        var projects = ProductionProjects();
        var references = ActualReferences();
        var declared = Declared();

        Assert.True(projects.Count > 0, "Found no projects under next/src.");
        Assert.True(references.Count > 0, "Found no project references at all, so nothing is checked.");
        Assert.True(declared.Count > 0, $"Read no rows from the dependency table in {Document}.");

        Assert.Contains(projects, p => p == "SecureAD.Kernel");
        Assert.Contains(declared, d => d.Name == "SecureAD.Kernel");
        Assert.Contains(references, r => r.From == "SecureAD.Audit" && r.To == "SecureAD.Kernel");
    }

    /// <summary>
    /// Project directories under <c>next/src</c>. The test project is deliberately outside this:
    /// a test assembly references everything by design, and policing it would make the rule fire on
    /// the thing that checks the rule.
    /// </summary>
    private static List<string> ProductionProjects() =>
        Directory
            .EnumerateFiles(Path.Combine(RebuildTree.Root(), "src"), "*.csproj", SearchOption.AllDirectories)
            .Select(Path.GetFileNameWithoutExtension)
            .Select(name => name!)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// The references the project files actually declare, read from the files rather than from the
    /// compiled assemblies: the question is what the build is told, and a transitive reference the
    /// compiler resolves is not the same thing as one this tree declares.
    /// </summary>
    private static List<(string From, string To)> ActualReferences()
    {
        var edges = new List<(string, string)>();

        foreach (var project in Directory.EnumerateFiles(
                     Path.Combine(RebuildTree.Root(), "src"), "*.csproj", SearchOption.AllDirectories))
        {
            var from = Path.GetFileNameWithoutExtension(project)!;

            foreach (var line in File.ReadAllLines(project))
            {
                if (!line.Contains("ProjectReference", StringComparison.Ordinal))
                    continue;

                var to = line.Split('"')
                    .FirstOrDefault(part => part.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase));

                if (to is not null)
                    edges.Add((from, Path.GetFileNameWithoutExtension(to)!));
            }
        }

        return edges;
    }

    private static List<DeclaredProject> Declared()
    {
        var lines = File.ReadAllLines(DocumentPath());

        var begin = Array.FindIndex(lines, l => l.Trim() == TableBegin);
        var end = Array.FindIndex(lines, l => l.Trim() == TableEnd);

        if (begin < 0 || end < 0 || end < begin)
        {
            throw new InvalidOperationException(
                "Could not find the " + TableBegin + " / " + TableEnd + " markers in "
                + DocumentPath() + ". The checks parse only what lies between them, so a missing "
                + "marker must fail rather than silently widen or empty the scan.");
        }

        var rows = new List<DeclaredProject>();

        for (var i = begin + 1; i < end; i++)
        {
            var trimmed = lines[i].Trim();
            if (!trimmed.StartsWith('|') || !trimmed.EndsWith('|'))
                continue;

            var cells = trimmed[1..^1].Split('|').Select(c => c.Trim().Trim('`')).ToArray();
            if (cells.Length < 4 || cells[0] == "Project" || cells[0].All(c => c is '-' or ':'))
                continue;

            if (!int.TryParse(cells[1], out var layer))
            {
                throw new InvalidOperationException(
                    $"Row '{cells[0]}' in {Document} has a layer of '{cells[1]}', which is not a "
                    + "number. The downward rule is expressed in layers, so an unparseable one must "
                    + "fail rather than be skipped.");
            }

            var may = cells[2] == "-"
                ? []
                : cells[2].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(t => t.Trim('`'))
                    .ToList();

            rows.Add(new DeclaredProject(cells[0], layer, may, i + 1));
        }

        return rows;
    }

    private static string DocumentPath() =>
        Path.Combine(OldAppInventory.RepositoryRoot(), "docs", "next", Document);

    private static string Read()
    {
        var path = DocumentPath();

        Assert.True(
            File.Exists(path),
            $"Expected the architecture document at {path}. Per docs/next/README.md a document is "
            + "not the new product's documentation until a test binds it to the code, so an absent "
            + "document fails rather than being skipped.");

        return File.ReadAllText(path);
    }
}
