using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Gate: project references point strictly downward, and every project is placed in the layering.
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
/// <b>The layering lives here rather than in <c>ARCHITECTURE.md</c>, as of 2026-09-12.</b> It was
/// parsed out of that document until <c>P-184</c>, which made this a test holding a document to the
/// code - the shape the owner's rule of 2026-09-12 forbids, because a drifting document is a
/// documentation problem and is fixed by reading it rather than by a failing build. The guard is
/// worth keeping and the coupling is not, so the table moved into the code it protects. The
/// document remains as description and says that this file is authoritative.
/// </para>
/// <para>
/// <b>What it does not do.</b> It cannot say a dependency is sensible, only that it points
/// downward. And it sees only project references: a dependency expressed through a shared file, a
/// database table or a convention is out of reach, which is the same limit the concept registry
/// records about itself.
/// </para>
/// </summary>
public sealed class ProjectLayeringGateTests
{
    /// <summary>One project's place in the layering, and what it is allowed to reference.</summary>
    /// <param name="Name">The project, as its file is named.</param>
    /// <param name="Layer">Its rung. Lower is deeper; every reference must go strictly downward.</param>
    /// <param name="MayReference">The projects it is permitted to reference, and no others.</param>
    private sealed record DeclaredProject(string Name, int Layer, IReadOnlyList<string> MayReference);

    /// <summary>
    /// The layering, held as code so that nothing has to be kept in step with it by hand.
    /// </summary>
    /// <remarks>
    /// <b>Each project sits on a layer of its own.</b> Two projects sharing one may reference each
    /// other without the downward comparison noticing, which is why
    /// <see cref="NoTwoProjectsShareALayer"/> exists beside the rule rather than being assumed.
    /// </remarks>
    private static readonly DeclaredProject[] Layering =
    [
        new("SecureAD.Kernel", 1, []),
        new("SecureAD.Evidence", 2, ["SecureAD.Kernel"]),
        new("SecureAD.Audit", 3, ["SecureAD.Kernel", "SecureAD.Evidence"]),
        new("SecureAD.Derivation", 4, ["SecureAD.Kernel", "SecureAD.Evidence"]),
        new("SecureAD.Judgement", 5, ["SecureAD.Kernel", "SecureAD.Evidence", "SecureAD.Derivation"]),
        new(
            "SecureAD.Cli",
            6,
            ["SecureAD.Kernel", "SecureAD.Evidence", "SecureAD.Derivation", "SecureAD.Judgement", "SecureAD.Audit"]),
        new(
            "SecureAD.Shell",
            7,
            ["SecureAD.Kernel", "SecureAD.Evidence", "SecureAD.Derivation", "SecureAD.Judgement", "SecureAD.Audit"]),
    ];

    /// <summary>
    /// Every project in the tree is placed in the layering.
    /// </summary>
    /// <remarks>
    /// A project nobody has placed is one whose dependencies nothing checks, so a new project has
    /// to be classified before it can be referenced freely.
    /// </remarks>
    [Fact]
    public void EveryProjectIsPlacedInTheLayering()
    {
        var placed = Layering.Select(p => p.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var missing = ProductionProjects()
            .Where(p => !placed.Contains(p))
            .Select(p => "  " + p)
            .OrderBy(p => p, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "Projects in next/src that the layering above does not place. A project nobody has "
            + "placed is one whose dependencies nothing checks:"
            + Environment.NewLine + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// The layering places no project that does not exist.
    /// </summary>
    /// <remarks>
    /// A row for a deleted project asserts structure the code does not have, and the permissions it
    /// carries can never be violated - which is how an allowance outlives the thing it was written
    /// for.
    /// </remarks>
    [Fact]
    public void TheLayeringPlacesNoProjectThatDoesNotExist()
    {
        var actual = ProductionProjects().ToHashSet(StringComparer.OrdinalIgnoreCase);

        var phantom = Layering
            .Where(p => !actual.Contains(p.Name))
            .Select(p => "  " + p.Name)
            .ToList();

        Assert.True(
            phantom.Count == 0,
            "The layering above places projects that do not exist:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The specific rule: every actual reference is one the layering permits.
    /// </summary>
    [Fact]
    public void EveryProjectReferenceIsOneTheLayeringPermits()
    {
        var permitted = Layering.ToDictionary(
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
            "Project references the layering does not permit. Either the reference is wrong, or "
            + "the architecture changed and this table has not - and the second is how a design "
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
        var layers = Layering.ToDictionary(p => p.Name, p => p.Layer, StringComparer.OrdinalIgnoreCase);

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
        var collisions = Layering
            .GroupBy(p => p.Layer)
            .Where(g => g.Count() > 1)
            .Select(g => $"  layer {g.Key}: {string.Join(", ", g.Select(p => p.Name))}")
            .ToList();

        Assert.True(
            collisions.Count == 0,
            "Projects sharing a layer. Two projects on one layer may reference each other without "
            + "the downward rule noticing:"
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

        var phantom = Layering
            .SelectMany(p => p.MayReference.Select(t => (p, t)))
            .Where(x => !actual.Contains(x.t))
            .Select(x => $"  {x.p.Name} may reference '{x.t}', which does not exist")
            .ToList();

        Assert.True(
            phantom.Count == 0,
            "The layering permits references to projects that do not exist:"
            + Environment.NewLine + string.Join(Environment.NewLine, phantom));
    }

    /// <summary>
    /// The scanner self-test. Without it every check above passes by comparing an empty set of
    /// projects against an empty table and reporting an architecture in perfect order - the failure
    /// this repository has committed three times.
    /// </summary>
    /// <remarks>
    /// <b>The table is asserted even though it is now a compile-time constant.</b> The compiler
    /// guarantees it parses, not that anybody left anything in it, and a table emptied in a careless
    /// edit would let every other check above pass vacuously - which is the same failure in a new
    /// costume.
    /// </remarks>
    [Fact]
    public void TheCheckFindsTheProjectsTheirReferencesAndTheLayering()
    {
        var projects = ProductionProjects();
        var references = ActualReferences();

        Assert.True(projects.Count > 0, "Found no projects under next/src.");
        Assert.True(references.Count > 0, "Found no project references at all, so nothing is checked.");
        Assert.True(Layering.Length > 0, "The layering table is empty, so nothing is checked.");

        Assert.Contains(projects, p => p == "SecureAD.Kernel");
        Assert.Contains(Layering, d => d.Name == "SecureAD.Kernel");
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
}
