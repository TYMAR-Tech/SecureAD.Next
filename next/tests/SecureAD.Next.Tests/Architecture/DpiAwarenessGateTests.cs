using System.Xml.Linq;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// The product declares per-monitor DPI awareness, so Windows never stretches its window.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is worth a test when nothing else about how the app looks is.</b> Almost every
/// visual defect in this product can only be judged by a person looking at a running window. This
/// one cannot: it is a fact about a file, and a file can be read. The product had no
/// <c>app.manifest</c> at all until 2026-08-21, which made it system DPI aware - Microsoft's
/// <i>Developing a Per-Monitor DPI-Aware WPF Application</i> states such an app is scaled by the OS
/// when moved to a monitor of a different DPI, and "may result in WPF applications to appear
/// blurry, especially when the scaling is non-integral".
/// </para>
/// <para>
/// <b>It is also the measurement everything else rests on.</b> Spacing and type size judged on a
/// stretched window are judged wrong, so a silent loss of this setting would quietly invalidate
/// every visual decision made after it.
/// </para>
/// </remarks>
public sealed class DpiAwarenessGateTests
{
    private static readonly XNamespace V3 = "urn:schemas-microsoft-com:asm.v3";
    private static readonly XNamespace Settings2016 =
        "http://schemas.microsoft.com/SMI/2016/WindowsSettings";

    /// <summary>The manifest asks Windows for per-monitor v2 awareness.</summary>
    [Fact]
    public void TheProductAsksForPerMonitorAwareness()
    {
        var declared = Manifest()
            .Descendants(Settings2016 + "dpiAwareness")
            .Select(element => element.Value.Trim())
            .SingleOrDefault();

        Assert.Equal("PerMonitorV2", declared);
    }

    /// <summary>
    /// The manifest is referenced by the project, not merely present in the folder.
    /// </summary>
    /// <remarks>
    /// A manifest nothing points at is a file, not a setting. This is the half that would fail
    /// silently: the declaration above would still read correctly while the built executable
    /// carried none of it.
    /// </remarks>
    [Fact]
    public void TheManifestIsReferencedByTheProject()
    {
        var project = File.ReadAllText(Path.Combine(ShellRoot(), "SecureAD.Shell.csproj"));

        Assert.Contains("<ApplicationManifest>app.manifest</ApplicationManifest>",
            project, StringComparison.Ordinal);
    }

    /// <summary>
    /// The gate reads the real manifest and would recognise a weaker setting.
    /// </summary>
    /// <remarks>
    /// The scanner self-test every gate in this tree carries. A check that passes while measuring
    /// nothing is the worst thing here, so this proves the file was found, that it parses, and that
    /// the element being asserted on is the one Windows reads rather than the legacy
    /// <c>dpiAware</c> beside it, which only ever says system aware.
    /// </remarks>
    [Fact]
    public void TheGateReadsTheRealManifestAndWouldRecogniseASystemAwareOne()
    {
        var manifest = Manifest();

        Assert.NotEmpty(manifest.Descendants(V3 + "windowsSettings"));
        Assert.Single(manifest.Descendants(Settings2016 + "dpiAwareness"));

        var weakened = XDocument.Parse(
            manifest.ToString().Replace("PerMonitorV2", "system", StringComparison.Ordinal));

        Assert.NotEqual(
            "PerMonitorV2",
            weakened.Descendants(Settings2016 + "dpiAwareness").Single().Value.Trim());
    }

    private static XDocument Manifest()
    {
        var path = Path.Combine(ShellRoot(), "app.manifest");

        Assert.True(File.Exists(path), path + " does not exist.");

        return XDocument.Parse(File.ReadAllText(path));
    }

    private static string ShellRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !Directory.Exists(Path.Combine(directory.FullName, "src")))
            directory = directory.Parent;

        Assert.NotNull(directory);

        return Path.Combine(directory!.FullName, "src", "SecureAD.Shell");
    }
}
