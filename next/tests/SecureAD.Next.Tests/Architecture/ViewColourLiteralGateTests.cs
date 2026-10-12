using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// A colour named in a view fails the build. Colour is named for meaning, in one place.
/// </summary>
/// <remarks>
/// <para>
/// <b>What went wrong before.</b> The four screens carried <c>DarkRed</c>, <c>DarkOrange</c>,
/// <c>Gray</c> and <c>LightGray</c>, each chosen in isolation by whoever was writing that screen.
/// Nothing tied them together, so the product had four opinions about what "a problem" looks like
/// and no way to change any of them at once.
/// </para>
/// <para>
/// <b>Why a build failure rather than a convention.</b> This is the same shape as
/// <see cref="SchemaGuidSingleSourceGateTests"/>, which forbids a schema GUID outside the
/// catalogue, and for the same reason: a rule about where a literal may live is followed for as
/// long as someone remembers it, and a rule the build enforces is followed afterwards too.
/// </para>
/// <para>
/// <b>What it cannot catch.</b> It reads text, so it finds a colour written into a view. It cannot
/// tell whether a three-state fact has been bound to a two-state control, which is the defect
/// <c>docs/decisions/0056-the-visual-language-encodes-three-states.md</c> is really about. That
/// needs review against a running window, and 0056 names it so a reviewer knows to look.
/// </para>
/// </remarks>
public sealed class ViewColourLiteralGateTests
{
    /// <summary>
    /// A hex colour - <c>#FFF</c> through <c>#AARRGGBB</c> - written anywhere in a view.
    /// </summary>
    private static readonly Regex HexColour =
        new(@"#[0-9A-Fa-f]{3,8}\b", RegexOptions.Compiled);

    /// <summary>
    /// The named colours WPF understands, restricted to the ones a person actually reaches for.
    /// </summary>
    /// <remarks>
    /// Not the full list of one hundred and forty. A regex matching every WPF colour name matches
    /// <c>Transparent</c>, which is legitimate, and words like <c>Snow</c> and <c>Linen</c> that
    /// would never appear. This list is the colours the four screens actually used plus the
    /// obvious neighbours, which is what a person writing a view in a hurry types.
    /// </remarks>
    private static readonly string[] NamedColours =
    [
        "AliceBlue", "Black", "Blue", "Brown", "Crimson", "Cyan", "DarkBlue", "DarkGray",
        "DarkGreen", "DarkOrange", "DarkRed", "DimGray", "Firebrick", "Gainsboro", "Gold",
        "Gray", "Green", "Grey", "IndianRed", "LightBlue", "LightGray", "LightGreen", "LightGrey",
        "LightYellow", "Lime", "Magenta", "Maroon", "Navy", "Olive", "Orange", "OrangeRed",
        "Pink", "Purple", "Red", "Salmon", "SeaGreen", "Silver", "SlateGray", "SteelBlue",
        "Teal", "Tomato", "Violet", "White", "WhiteSmoke", "Yellow",
    ];

    /// <summary>
    /// Where colour is allowed to be written down: the palette holds the values, and the brush
    /// dictionary is the only thing permitted to name them.
    /// </summary>
    /// <remarks>
    /// <c>Transparent</c> is not a colour in the sense this gate cares about - it is the absence
    /// of one, it survives every palette change, and forbidding it would push views into defining
    /// a brush to mean "nothing here".
    /// </remarks>
    private static readonly string[] ThemeFiles = ["Palette.Dark.xaml", "Palette.Light.xaml", "Brushes.xaml"];

    [Fact]
    public void NoViewNamesAColour()
    {
        var offences = new List<string>();

        foreach (var file in ViewFiles())
        {
            var lines = File.ReadAllLines(file);

            for (var i = 0; i < lines.Length; i++)
            {
                var line = lines[i];

                if (IsComment(line))
                    continue;

                if (HexColour.IsMatch(line))
                    offences.Add(Describe(file, i, line, "a hex colour"));

                foreach (var name in NamedColours)
                {
                    if (NamesColour(line, name))
                        offences.Add(Describe(file, i, line, name));
                }
            }
        }

        Assert.True(
            offences.Count == 0,
            "Colours are named in views. A view that says DarkOrange has recorded an opinion "
            + "about a hue rather than about a fact, and the day the palette changes it will be "
            + "the one thing that does not move. Add a brush named for what the colour MEANS to "
            + "Themes/Brushes.xaml and bind that instead - see "
            + "docs/decisions/0056-the-visual-language-encodes-three-states.md decision 6:"
            + Environment.NewLine + string.Join(Environment.NewLine, offences));
    }

    /// <summary>
    /// The scanner self-test. Without it the check above passes by finding no views to read,
    /// which is the failure this repository has committed before: a check that measures nothing
    /// looks exactly like a check that found nothing wrong.
    /// </summary>
    [Fact]
    public void TheGateReadsTheRealViewsAndWouldRecogniseAColour()
    {
        var views = ViewFiles();

        Assert.NotEmpty(views);
        Assert.Contains(views, v => Path.GetFileName(v) == "NewAuditView.xaml");
        Assert.Contains(views, v => Path.GetFileName(v) == "HomeView.xaml");

        // The two shapes the scan looks for, proved against text rather than against the tree, so
        // this holds even on the day every view is clean.
        Assert.Matches(HexColour, "Background=\"#FF102030\"");
        Assert.True(NamesColour("Foreground=\"DarkOrange\"", "DarkOrange"));

        // And it does not fire on a brush whose NAME contains a colour word, which is the obvious
        // way for this scan to become one that cries wolf until someone deletes it.
        Assert.False(NamesColour("Foreground=\"{StaticResource NotEstablishedBrush}\"", "Red"));
        Assert.False(NamesColour("<Color x:Key=\"Neutral0\">", "Black"));
    }

    /// <summary>
    /// The theme files are exempt, and the exemption is held to its terms: the palette must
    /// actually hold colours. An empty palette would let the gate above pass while the product
    /// had nowhere legitimate to put one.
    /// </summary>
    [Fact]
    public void ThePaletteIsWhereColoursActuallyLive()
    {
        foreach (var name in new[] { "Palette.Dark.xaml", "Palette.Light.xaml" })
        {
            var palette = Path.Combine(ThemesRoot(), name);
            Assert.True(File.Exists(palette), palette + " does not exist.");
            Assert.Matches(HexColour, File.ReadAllText(palette));
        }
    }

    /// <summary>
    /// Whether a line names a colour as a value, rather than merely containing the word.
    /// </summary>
    /// <remarks>
    /// Anchored to a quote on the left so that <c>Foreground="Red"</c> is caught while
    /// <c>{StaticResource CriticalFindingBrush}</c> and a comment mentioning red are not. A scan
    /// that fires on any occurrence of the word is a scan somebody switches off.
    /// </remarks>
    private static bool NamesColour(string line, string colour) =>
        Regex.IsMatch(line, "\"" + Regex.Escape(colour) + "\"");

    private static bool IsComment(string line)
    {
        var trimmed = line.TrimStart();

        return trimmed.StartsWith("<!--", StringComparison.Ordinal)
            || trimmed.StartsWith("--", StringComparison.Ordinal);
    }

    private static string Describe(string file, int index, string line, string what) =>
        $"  {Path.GetFileName(file)}({index + 1}): {what} - {line.Trim()}";

    private static string ShellRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        return Path.Combine(directory!.FullName, "src", "SecureAD.Shell");
    }

    private static string ThemesRoot() => Path.Combine(ShellRoot(), "Themes");

    /// <summary>
    /// Every XAML file in the shell except the theme dictionaries, which is where colour belongs.
    /// </summary>
    private static List<string> ViewFiles() =>
        Directory.EnumerateFiles(ShellRoot(), "*.xaml", SearchOption.AllDirectories)
            .Where(NotBuildOutput)
            .Where(f => !ThemeFiles.Contains(Path.GetFileName(f), StringComparer.Ordinal))
            .ToList();

    private static bool NotBuildOutput(string path) =>
        !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
}
