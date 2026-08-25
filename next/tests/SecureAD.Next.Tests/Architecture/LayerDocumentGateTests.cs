using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The layer documents' links, and their presence in the solution.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the deletion check, arrived at from the other side.</b> Step 7 of the rewrite cycle —
/// delete the old documents and correct the solution's items — is the one step no gate enforced, and
/// a pass that skipped it committed green. The obvious remedy, asserting that each consumed document
/// is absent, was rejected: it needs a hand-written list of what should be gone, nothing generates
/// that list, and forgetting an entry makes the check <i>pass</i>. It would rot toward silence.
/// </para>
/// <para>
/// So the consequence is checked instead of the act. A document deleted without its inbound
/// references repointed leaves a link that resolves to nothing, and that is mechanical, needs no
/// list, and catches a broken link arriving from any other cause for free.
/// <c>AreaFileGateTests.EveryLinkOutOfAnAreaFileResolves</c> has done this for <c>docs/areas</c>
/// since the beginning; the layer documents — the pages the rewrite is actually producing — had
/// nothing.
/// </para>
/// </remarks>
public sealed class LayerDocumentGateTests
{
    /// <summary>
    /// A markdown link with a relative target. Absolute links are left alone because this gate
    /// cannot reach the network, and an anchor is trimmed because the question is whether the file
    /// is there.
    /// </summary>
    private static readonly Regex RelativeLink = new(@"\]\((?<target>[^)\s]+)\)", RegexOptions.Compiled);

    /// <summary>
    /// Every directory under <c>docs/layers</c> is a subsystem the gates know about.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The gates iterate a named list, so a folder missing from it is a folder nothing checks.</b>
    /// <see cref="LayerDocuments.Subsystems"/> is deliberately named rather than discovered - see the
    /// reasoning there - and the cost of naming a set is that additions are silent. This closes that
    /// cost without giving it up: the list still decides what is scanned, and this asks whether the
    /// list has fallen behind the tree.
    /// </para>
    /// <para>
    /// It has happened. The shell subsystem was created with two documents, both carrying a
    /// <c>TYPES</c> table, and neither was read by anything for as long as it took somebody to
    /// notice - the tables were decoration and every gate was green. A new subsystem is exactly when
    /// a session is least likely to think about a list in the test project.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryLayerDirectoryIsARegisteredSubsystem()
    {
        var registered = LayerDocuments.Subsystems.ToHashSet(StringComparer.Ordinal);

        var unregistered = Directory.EnumerateDirectories(LayerDocuments.Root())
            .Select(Path.GetFileName)
            .Where(name => name is not null && !registered.Contains(name))
            .Select(name => $"  docs/layers/{name}/ is not in LayerDocuments.Subsystems, so no gate "
                + "reads the documents in it")
            .OrderBy(m => m, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            unregistered.Count == 0,
            "A layer directory nothing scans holds documents that look enforced and are not. Add it "
            + "to LayerDocuments.Subsystems in the same commit that creates it:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, unregistered));
    }

    [Fact]
    public void EveryLinkOutOfALayerDocumentResolves()
    {
        var broken = new List<string>();

        foreach (var file in LayerDocuments.All())
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
                    {
                        broken.Add(
                            $"  {LayerDocuments.SubsystemOf(file)}/{Path.GetFileName(file)} line {i + 1} "
                            + $"links to '{relative}', which is not there");
                    }
                }
            }
        }

        Assert.True(
            broken.Count == 0,
            "Layer documents link to files that do not exist. The usual cause is a document "
            + "deleted without its inbound references repointed, which is the half of the rewrite "
            + "cycle nothing else checks:" + Environment.NewLine
            + string.Join(Environment.NewLine, broken));
    }

    /// <summary>
    /// Every layer document is a solution item.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="SolutionDocumentItemTests"/> checks the other direction and argues that requiring
    /// every document to be listed would be friction for no gain. That argument holds for
    /// <c>docs/decisions</c>, where there are scores of records and an unlisted one costs nothing.
    /// It does not reach the layer documents, and the difference is observed rather than assumed:
    /// the Evidence pass added no solution items, so a newly written document was invisible in the
    /// IDE while the stub it replaced was still listed, and the same defect had gone unnoticed one
    /// subsystem earlier in Kernel. Seventeen files, each one the product of a whole pass.
    /// </para>
    /// </remarks>
    [Fact]
    public void EveryLayerDocumentIsListedInTheSolution()
    {
        var listed = SolutionDocumentItems();

        var missing = LayerDocuments.All()
            .Select(f => $"docs/layers/{LayerDocuments.SubsystemOf(f)}/{Path.GetFileName(f)}")
            .Where(rel => !listed.Contains(rel))
            .OrderBy(rel => rel, StringComparer.Ordinal)
            .ToList();

        Assert.True(
            missing.Count == 0,
            "These layer documents are not listed in the solution, so they are invisible in "
            + "Solution Explorer. Every rewritten layer document is a solution folder item — "
            + "removing what was deleted is only half of the cycle's step 7:" + Environment.NewLine
            + string.Join(Environment.NewLine, missing));
    }

    /// <summary>
    /// The scanner self-test. Without it both checks above pass by reading no documents, no links
    /// and no solution items, and report that nothing is wrong with any of them.
    /// </summary>
    [Fact]
    public void TheCheckReadsTheLayerDocumentsTheirLinksAndTheSolution()
    {
        var documents = LayerDocuments.All();
        var links = documents.Sum(f => File.ReadAllLines(f).Sum(l => RelativeLink.Matches(l).Count));

        Assert.True(documents.Count > 0, "Found no layer documents.");
        Assert.True(links > 0, "Read no links out of any layer document.");
        Assert.True(SolutionDocumentItems().Count > 0, "Read no document items from the solution.");

        foreach (var subsystem in LayerDocuments.Subsystems)
        {
            Assert.Contains(documents, d => LayerDocuments.SubsystemOf(d) == subsystem);
        }

        // A link that is really there and one that is not, so the resolver is known to discriminate.
        var evidence = Path.Combine(LayerDocuments.Root(), "evidence");
        Assert.True(File.Exists(Path.Combine(evidence, "the-bundle-on-disk.md")));
        Assert.False(File.Exists(Path.Combine(evidence, "no-such-document.md")));
    }

    /// <summary>
    /// The document items the solution lists, as repository-relative forward-slashed paths.
    /// </summary>
    private static HashSet<string> SolutionDocumentItems()
    {
        var solution = Path.Combine(RepositoryLocation.Root(), "next", "SecureAD.Next.sln");
        Assert.True(File.Exists(solution), $"Expected the solution at {solution}.");

        return File.ReadAllLines(solution)
            .Select(l => Regex.Match(l, @"^\s*(\.\.\\[^=]+?\.md)\s*="))
            .Where(m => m.Success)
            .Select(m => m.Groups[1].Value.Trim().Replace('\\', '/'))
            .Select(p => p.StartsWith("../", StringComparison.Ordinal) ? p[3..] : p)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }
}
