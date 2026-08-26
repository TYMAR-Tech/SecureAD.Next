using System.IO;
using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every resource a view asks for by name must be one the application defines.
/// </summary>
/// <remarks>
/// <para>
/// <b>This exists because a missing resource key crashed the product in front of the owner on
/// 2026-08-26.</b> <c>FindingsView.xaml</c> asked for a brush called <c>CardBrush</c>, which does
/// not exist and never did. The solution built, all 2,410 tests passed, and the application died
/// with an unhandled <c>XamlParseException</c> the moment the operator pressed <i>View results</i>
/// and the view was first rendered.
/// </para>
/// <para>
/// <b>A missing key is unlike a missing binding, and worse.</b> WPF resolves a binding it cannot
/// find by rendering nothing, so the failure is a silently absent fact -
/// <see cref="ViewBindingGateTests"/> exists for that. A <c>StaticResource</c> that resolves to
/// nothing throws while the visual tree is being built, which takes the process down. It cannot be
/// caught by a view model test because no view model is involved, and it cannot be caught by the
/// compiler because resource lookup is a runtime search through a dictionary chain.
/// </para>
/// <para>
/// <b>Anchored to the dictionaries rather than to a list kept here.</b> The keys are read from the
/// application's own resource files, so a renamed brush breaks this and no edit to a test can
/// satisfy it alone. <see cref="TheGateReadsTheRealViewsAndTheRealDictionaries"/> is the self-test
/// that fails if either side ever stops being found, which is how a gate quietly starts measuring
/// nothing.
/// </para>
/// </remarks>
public sealed class ViewResourceGateTests
{
    /// <summary>A <c>{StaticResource Key}</c> or <c>{DynamicResource Key}</c> reference.</summary>
    private static readonly Regex ResourceReference =
        new(@"\{(?:Static|Dynamic)Resource\s+([^}]+)\}", RegexOptions.Compiled);

    /// <summary>An <c>x:Key</c> a resource dictionary defines.</summary>
    private static readonly Regex ResourceKey =
        new(@"x:Key=""([^""]+)""", RegexOptions.Compiled);

    /// <summary>
    /// No view asks for a resource nothing defines.
    /// </summary>
    [Fact]
    public void EveryResourceAViewAsksForIsOneTheApplicationDefines()
    {
        var defined = DefinedKeys();
        var offences = new List<string>();

        foreach (var file in XamlFiles())
        {
            var text = File.ReadAllText(file);

            foreach (Match match in ResourceReference.Matches(text))
            {
                var key = match.Groups[1].Value.Trim();

                // A resource named through a type - {StaticResource {x:Type TreeViewItem}} - is
                // keyed by the type itself rather than by a string, so there is no x:Key to find.
                if (key.StartsWith('{'))
                    continue;

                if (defined.Contains(key))
                    continue;

                var line = text.Take(match.Index).Count(c => c == '\n') + 1;
                offences.Add($"  {Path.GetFileName(file)}({line}): {key}");
            }
        }

        Assert.True(
            offences.Count == 0,
            "A view asks for a resource nothing defines. Unlike a binding, which WPF resolves to "
            + "nothing and renders as an absent fact, an unresolved StaticResource throws while "
            + "the visual tree is being built and takes the process down - so this is a crash on "
            + "the screen where it appears, not a blank cell. It happened on 2026-08-26 with a "
            + "brush called CardBrush that never existed:"
            + Environment.NewLine + string.Join(Environment.NewLine, offences));
    }

    /// <summary>
    /// The scanner self-test: both sides of the comparison are really being read.
    /// </summary>
    /// <remarks>
    /// The way this gate dies quietly is for one of its two searches to stop matching - a folder
    /// renamed, a regex that no longer fits the markup - at which point it compares an empty set
    /// against an empty set and passes over nothing. That is the failure
    /// <c>docs/next/README.md</c> § Gates names as the worst category, and it has happened twice
    /// in this tree.
    /// </remarks>
    [Fact]
    public void TheGateReadsTheRealViewsAndTheRealDictionaries()
    {
        var views = XamlFiles();
        var defined = DefinedKeys();

        Assert.True(views.Count >= 10, $"Found {views.Count} XAML files; expected the shell's.");
        Assert.True(defined.Count >= 40, $"Found {defined.Count} resource keys; expected more.");

        // Named rather than counted: a threshold alone would pass against forty keys from one
        // unrelated file.
        Assert.Contains("Card", defined);
        Assert.Contains("SecondaryTextBrush", defined);
        Assert.Contains("TableColumnHeader", defined);

        // And the reference side is really being extracted.
        Assert.Contains(
            views,
            v => ResourceReference.IsMatch(File.ReadAllText(v)));
    }

    /// <summary>
    /// The gate would fail on the defect that caused it to be written.
    /// </summary>
    /// <remarks>
    /// A negative control, because a gate that has never been seen to fail is a gate nobody has
    /// shown to work. This is the exact markup that crashed the product.
    /// </remarks>
    [Fact]
    public void TheGateWouldFailOnAResourceNothingDefines()
    {
        var defined = DefinedKeys();

        Assert.DoesNotContain("CardBrush", defined);
    }

    /// <summary>
    /// A resource keyed by a type is skipped rather than reported.
    /// </summary>
    /// <remarks>
    /// <c>{StaticResource {x:Type TreeViewItem}}</c> is keyed by the type object, so there is no
    /// <c>x:Key</c> string to match and reporting it would be crying wolf - which is how a check
    /// ends up deleted.
    /// </remarks>
    [Fact]
    public void AResourceKeyedByATypeIsNotReportedAsMissing()
    {
        const string markup =
            """<Style BasedOn="{StaticResource {x:Type TreeViewItem}}" />""";

        var keys = ResourceReference.Matches(markup)
            .Select(m => m.Groups[1].Value.Trim())
            .Where(k => !k.StartsWith('{'))
            .ToList();

        Assert.Empty(keys);
    }

    /// <summary>Every <c>x:Key</c> the shell's XAML defines, wherever it defines it.</summary>
    private static HashSet<string> DefinedKeys()
    {
        var keys = new HashSet<string>(StringComparer.Ordinal);

        foreach (var file in XamlFiles())
        {
            foreach (Match match in ResourceKey.Matches(File.ReadAllText(file)))
                keys.Add(match.Groups[1].Value.Trim());
        }

        return keys;
    }

    private static string ShellRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        return Path.Combine(directory!.FullName, "src", "SecureAD.Shell");
    }

    private static List<string> XamlFiles() =>
        [.. Directory.EnumerateFiles(ShellRoot(), "*.xaml", SearchOption.AllDirectories)
            .Where(NotBuildOutput)];

    private static bool NotBuildOutput(string path) =>
        !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
}
