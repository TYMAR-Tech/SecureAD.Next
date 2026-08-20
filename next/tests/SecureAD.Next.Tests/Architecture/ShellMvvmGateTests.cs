using System.Text.RegularExpressions;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Guards on the shell's separation of screens from everything else.
///
/// <para>
/// <b>These exist because the promise is otherwise worth nothing.</b> "We will keep logic out of the
/// views" is a sentence in a document, and the predecessor accumulated logic in code-behind where it
/// could not be tested and could not be found. A guard is a sentence the build enforces.
/// </para>
/// <para>
/// Each guard carries a scanner self-test, because a guard that scans nothing passes. Every one of
/// these was mutation-tested in both directions when written: the forbidden thing was introduced,
/// the guard was watched to fail, and the change was reverted.
/// </para>
/// </summary>
public sealed class ShellMvvmGateTests
{
    /// <summary>
    /// Types a view model must not name. Screen types would let it open windows; capability types
    /// would let it reach a disk or a directory server. Either makes it untestable and hides logic
    /// where nobody looks for it.
    /// </summary>
    private static readonly string[] ForbiddenInViewModels =
    [
        // The screen.
        "Window", "MessageBox", "Dispatcher", "UserControl", "OpenFolderDialog", "Visibility",

        // The disk and the directory. Reached through a seam or not at all.
        "File", "Directory", "RunLibrary", "RunStateReader", "CaptureSession", "BundleLayout",
        "BundleReader",

        // Concrete services. A view model naming one has bypassed its seam.
        "RunCatalog", "FolderPicker", "JsonShellSettingsStore", "CaptureLauncher",
        "BundleAssetSource",
    ];

    /// <summary>
    /// Concrete services, which only the composition root may construct. Assembling the product in
    /// more than one place is how a second, differently-wired product appears inside the first.
    /// </summary>
    private static readonly string[] ConstructedOnlyAtTheRoot =
    [
        "new RunCatalog(", "new FolderPicker(", "new JsonShellSettingsStore(", "new CaptureLauncher(",
        "new BundleAssetSource(",
    ];

    [Fact]
    public void AViewModelNamesNeitherTheScreenNorTheDisk()
    {
        var offences = RebuildTree
            .Scan(ViewModelFiles(), ForbiddenInViewModels)
            .Select(s => $"{Path.GetFileName(s.File)}:{s.Line} {s.Text.Trim()}")
            .ToList();

        Assert.True(
            offences.Count == 0,
            "A view model may not name a screen type or reach the disk directly. It is given a "
            + "seam so that it can be tested without one, and so that logic cannot hide in a view. "
            + "Found: " + string.Join("; ", offences));
    }

    [Fact]
    public void CodeBehindDoesNothingButInitialiseItsComponent()
    {
        var offences = new List<string>();

        foreach (var file in CodeBehindFiles())
        {
            var lineNumber = 0;

            foreach (var raw in File.ReadAllLines(file))
            {
                lineNumber++;
                var line = raw.Trim();

                if (IsIgnorable(line) || IsPermittedInCodeBehind(line))
                    continue;

                offences.Add($"{Path.GetFileName(file)}:{lineNumber} {line}");
            }
        }

        Assert.True(
            offences.Count == 0,
            "A view's code-behind may declare its class, its constructor, and call "
            + "InitializeComponent. Anything else is logic in a place that cannot be tested and "
            + "will not be found. Move it to a view model. Found: " + string.Join("; ", offences));
    }

    [Fact]
    public void OnlyTheCompositionRootAssemblesTheProduct()
    {
        var offences = ConstructionSitesOutside("App.xaml.cs");

        Assert.True(
            offences.Count == 0,
            "Concrete services are constructed in App.xaml.cs and nowhere else. A second place "
            + "that wires the product is a second product. Found: " + string.Join("; ", offences));
    }

    /// <summary>
    /// The scanner self-test. Each guard above asserts that something is absent, and would pass
    /// against an empty file list. This proves the lists are not empty and that the terms are the
    /// kind of thing the scanner can see.
    /// </summary>
    [Fact]
    public void TheScannerFindsTheFilesTheGuardsGovern()
    {
        Assert.NotEmpty(ViewModelFiles());
        Assert.NotEmpty(CodeBehindFiles());
        Assert.NotEmpty(ShellFiles());

        // And the construction scan can see a site when one is genuinely present. The composition
        // root constructs every service, so excluding everything *but* it must find several.
        // Without this, the guard above could pass by being unable to match anything at all -
        // which is exactly what it did when its terms were run through a word-boundary scanner.
        Assert.NotEmpty(ConstructionSitesOutside("RunLibraryViewModel.cs"));
    }

    /// <summary>
    /// Sites constructing a concrete service, in every shell file except
    /// <paramref name="exemptFileName"/>.
    /// </summary>
    /// <remarks>
    /// A plain substring search over non-comment lines, deliberately not
    /// <see cref="RebuildTree.Scan"/>: that helper wraps each term in word boundaries, and a term
    /// ending in <c>(</c> can never match one. The guard using it reported clean while a service
    /// was being constructed in a view model.
    /// </remarks>
    private static List<string> ConstructionSitesOutside(string exemptFileName)
    {
        var offences = new List<string>();

        foreach (var file in ShellFiles()
                     .Where(f => !f.EndsWith(exemptFileName, StringComparison.Ordinal)))
        {
            var lineNumber = 0;

            foreach (var raw in File.ReadAllLines(file))
            {
                lineNumber++;
                var line = raw.Trim();

                if (line.StartsWith("//", StringComparison.Ordinal)
                    || line.StartsWith("///", StringComparison.Ordinal))
                {
                    continue;
                }

                if (ConstructedOnlyAtTheRoot.Any(t => line.Contains(t, StringComparison.Ordinal)))
                    offences.Add($"{Path.GetFileName(file)}:{lineNumber} {line}");
            }
        }

        return offences;
    }

    private static string ShellRoot() =>
        Path.Combine(RebuildTree.Root(), "src", "SecureAD.Shell");

    private static List<string> ShellFiles() =>
        Directory.EnumerateFiles(ShellRoot(), "*.cs", SearchOption.AllDirectories)
            .Where(NotBuildOutput)
            .ToList();

    private static List<string> ViewModelFiles() =>
        Directory.EnumerateFiles(
                Path.Combine(ShellRoot(), "ViewModels"), "*.cs", SearchOption.AllDirectories)
            .Where(NotBuildOutput)
            .ToList();

    private static List<string> CodeBehindFiles() =>
        Directory.EnumerateFiles(
                Path.Combine(ShellRoot(), "Views"), "*.xaml.cs", SearchOption.AllDirectories)
            .Where(NotBuildOutput)
            .ToList();

    private static bool NotBuildOutput(string path) =>
        !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
        && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal);

    private static bool IsIgnorable(string line) =>
        line.Length == 0
        || line.StartsWith("//", StringComparison.Ordinal)
        || line.StartsWith("using ", StringComparison.Ordinal)
        || line.StartsWith("namespace ", StringComparison.Ordinal)
        || line.StartsWith('[')
        || line is "{" or "}";

    private static bool IsPermittedInCodeBehind(string line) =>
        Regex.IsMatch(line, @"^(public|internal) partial class \w+ : \w+$")
        || Regex.IsMatch(line, @"^(public|internal) \w+\(\)$")
        || line == "InitializeComponent();";
}
