using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The surface register — the map from every public type in the rebuild to the document that
/// governs it.
/// </summary>
/// <remarks>
/// <para>
/// Shared for the reason <see cref="LayerDocuments"/> is shared: more than one gate now asks the
/// same question of the same table, and a second parser written separately drifts from the first.
/// <see cref="SurfaceRegisterTests"/> holds the register to the assemblies;
/// <c>AreaFileGateTests.EveryAreaFileStillGovernsAtLeastOneUndocumentedType</c> reads the same rows
/// to find an area file the rewrite has finished consuming.
/// </para>
/// <para>
/// <b>Only what lies between the markers is parsed</b>, so the prose around the table does not have
/// to pretend to be data, and a missing marker fails rather than quietly emptying the scan.
/// </para>
/// </remarks>
internal static class SurfaceRegister
{
    internal const string FileName = "SURFACE-REGISTER.md";

    private const string TableBegin = "<!-- REGISTER:BEGIN -->";
    private const string TableEnd = "<!-- REGISTER:END -->";

    /// <summary>
    /// The governing document out of a cell written as <c>[label](../folder/name.md)</c>, returned
    /// as <c>folder/name</c>. The link target is read rather than the label, because the label is
    /// prose and the target is what has to resolve.
    /// </summary>
    private static readonly Regex DocumentLink =
        new(@"\(\.\./(?<path>[A-Za-z0-9\-/]+)\.md\)", RegexOptions.Compiled);

    internal static string Path() =>
        System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "next", FileName);

    /// <summary>
    /// The register's rows: the type, the document that governs it, and the line it sits on.
    /// </summary>
    internal static List<(string Type, string Document, int Line)> Entries()
    {
        var path = Path();
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

            entries.Add((type, GoverningDocument(cells[3]), i + 1));
        }

        return entries;
    }

    /// <summary>
    /// The governing document a register cell names.
    /// </summary>
    /// <remarks>
    /// <b>A governing document may be a layer document, not only an area file.</b> This used to
    /// resolve <c>../areas/</c> and nothing else, which meant every public type had to point at a
    /// live area file and <b>no area file could ever be deleted</b> — twenty of them survived six
    /// completed passes of a rewrite whose stated goal is to empty <c>docs/areas</c>. The register
    /// is a map from a type to the page describing it; which folder that page lives in is not the
    /// register's business.
    /// </remarks>
    internal static string GoverningDocument(string cell)
    {
        var match = DocumentLink.Match(cell);
        return match.Success ? match.Groups["path"].Value : cell;
    }

    /// <summary>
    /// The documents that actually exist, read off disk rather than listed here, so a renamed or
    /// deleted page fails the register rather than being quietly accepted by a copy of the list.
    /// Area files and layer documents both count.
    /// </summary>
    internal static HashSet<string> GoverningDocumentNames()
    {
        var found = new HashSet<string>(StringComparer.Ordinal);

        Add(System.IO.Path.Combine(RepositoryLocation.Root(), "docs", "areas"), "areas");

        foreach (var subsystem in LayerDocuments.Subsystems)
            Add(System.IO.Path.Combine(LayerDocuments.Root(), subsystem), "layers/" + subsystem);

        return found;

        void Add(string directory, string prefix)
        {
            if (!Directory.Exists(directory))
                return;

            foreach (var file in Directory.GetFiles(directory, "*.md"))
            {
                var name = System.IO.Path.GetFileNameWithoutExtension(file);
                if (name is not null and not "README")
                    found.Add(prefix + "/" + name);
            }
        }
    }
}
