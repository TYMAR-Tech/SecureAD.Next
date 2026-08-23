using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The layer documents — the pages the documentation rewrite produces, one per code folder.
/// </summary>
/// <remarks>
/// <para>
/// Shared because more than one gate now asks the same question of the same set, and a second
/// hand-maintained copy of this list would drift. <see cref="CapabilityCitationTests"/> resolves the
/// citations in their capability tables; <see cref="LayerDocumentGateTests"/> checks their links and
/// their presence in the solution.
/// </para>
/// <para>
/// <b>Adding a subsystem means adding it here.</b> The gates that use this assert coverage per
/// subsystem rather than in total, so a directory left out of <see cref="Subsystems"/> is not
/// checked and nothing says so. That is the one weakness of naming the set rather than discovering
/// it, and it is the trade taken deliberately: discovering directories would silently start
/// checking `docs/planned` and `docs/history`, which are not layer documents and are not held to
/// this standard.
/// </para>
/// </remarks>
internal static class LayerDocuments
{
    /// <summary>The subsystems whose folders hold layer documents.</summary>
    internal static readonly string[] Subsystems = ["kernel", "audit", "connect", "evidence", "schema"];

    /// <summary>The documentation root for the layer documents.</summary>
    internal static string Root() => Path.Combine(RepositoryLocation.Root(), "docs", "layers");

    /// <summary>The subsystem a document belongs to, taken from its directory.</summary>
    internal static string SubsystemOf(string file) =>
        Path.GetFileName(Path.GetDirectoryName(file)!);

    /// <summary>
    /// Every layer document, ordered. A missing subsystem directory is a failure rather than a
    /// smaller scan.
    /// </summary>
    internal static List<string> All()
    {
        var found = new List<string>();

        foreach (var subsystem in Subsystems)
        {
            var directory = Path.Combine(Root(), subsystem);
            Assert.True(Directory.Exists(directory), $"Expected the layer documents at {directory}.");

            found.AddRange(Directory.EnumerateFiles(directory, "*.md")
                .OrderBy(f => f, StringComparer.Ordinal));
        }

        return found;
    }
}
