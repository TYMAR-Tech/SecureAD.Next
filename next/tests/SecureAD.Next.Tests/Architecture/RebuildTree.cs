using System.Text.RegularExpressions;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Locates and scans the rebuild tree for the architecture guards.
///
/// The rebuild lives outside <c>src/</c> so that the old tree's architecture tests, which resolve
/// <c>src/</c> and recurse it, do not govern code written to a different design. The cost of that
/// separation is that the invariants once stated in docs/INVARIANTS.md are no longer inherited here
/// by accident of folder placement, so they are asserted explicitly by
/// <see cref="ProductInvariantTests"/>.
///
/// Scanning source text rather than using reflection is deliberate and follows the old tree's
/// pattern: these guards are about code that must not exist, and reflection can only inspect what
/// was compiled.
/// </summary>
internal static class RebuildTree
{
    /// <summary>
    /// The rebuild root — the <c>next/</c> directory holding <c>src/</c> and <c>tests/</c>.
    /// </summary>
    public static string Root()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 12 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "next");
            if (Directory.Exists(Path.Combine(candidate, "src")))
                return candidate;

            // Also match when already inside next/, so the walk works from either side.
            if (string.Equals(dir.Name, "next", StringComparison.Ordinal)
                && Directory.Exists(Path.Combine(dir.FullName, "src")))
            {
                return dir.FullName;
            }
        }

        throw new DirectoryNotFoundException(
            "Could not locate the rebuild root by walking up from " + AppContext.BaseDirectory
            + ". The guards in this project assert properties of next/; if that tree moved, they "
            + "must be updated rather than allowed to pass by finding nothing.");
    }

    /// <summary>Production source under <c>next/src/</c>. Test source is deliberately excluded.</summary>
    public static IEnumerable<string> ProductionFiles() => CsFiles(Path.Combine(Root(), "src"));

    /// <summary>Every <c>.cs</c> file under the rebuild root, tests included.</summary>
    public static IEnumerable<string> AllFiles() => CsFiles(Root());

    private static IEnumerable<string> CsFiles(string root) =>
        Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                     && !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal));

    /// <summary>
    /// Finds executable lines matching any of <paramref name="terms"/> on a word boundary.
    /// Comments and XML docs are skipped, because the guards name the very things they forbid.
    /// </summary>
    public static List<(string File, int Line, string Text)> Scan(
        IEnumerable<string> files, IReadOnlyList<string> terms)
    {
        var pattern = new Regex(
            @"\b(" + string.Join("|", terms.Select(Regex.Escape)) + @")\b",
            RegexOptions.Compiled);

        var sites = new List<(string, int, string)>();

        foreach (var file in files)
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                var trimmed = lines[i].TrimStart();
                if (IsComment(lines[i]))
                {
                    continue;
                }

                var match = pattern.Match(lines[i]);
                if (match.Success)
                    sites.Add((file, i + 1, trimmed));
            }
        }

        return sites;
    }

    /// <summary>
    /// Finds executable lines matching <paramref name="pattern"/>. Comments and XML docs are
    /// skipped for the same reason as in <see cref="Scan"/>: a guard's own explanation names the
    /// thing it forbids.
    /// </summary>
    public static List<(string File, int Line, string Text)> ScanPattern(
        IEnumerable<string> files, Regex pattern)
    {
        var sites = new List<(string, int, string)>();

        foreach (var file in files)
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (IsComment(lines[i]))
                    continue;

                if (pattern.IsMatch(lines[i]))
                    sites.Add((file, i + 1, lines[i].TrimStart()));
            }
        }

        return sites;
    }

    private static bool IsComment(string line)
    {
        var trimmed = line.TrimStart();
        return trimmed.StartsWith("//", StringComparison.Ordinal)
            || trimmed.StartsWith('*')
            || trimmed.StartsWith("/*", StringComparison.Ordinal);
    }

    /// <summary>Renders scan hits for an assertion message.</summary>
    public static string Describe(IEnumerable<(string File, int Line, string Text)> sites) =>
        string.Join(Environment.NewLine, sites.Select(s => $"  {s.File}({s.Line}): {s.Text}"));
}
