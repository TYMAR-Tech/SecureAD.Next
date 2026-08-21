using System.Xml.Linq;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// Every column header template keeps the two grippers a column is resized by.
/// </summary>
/// <remarks>
/// <para>
/// <b>What was seen.</b> On a running window the owner could reorder the run list's columns and
/// could not resize any of them, on any grid. Reordering is handled by the header drag logic and
/// needs no template part, which is why it survived and why it is misleading: it looks like proof
/// that column interaction works.
/// </para>
/// <para>
/// <b>The cause.</b> <c>Controls.xaml</c> replaces the <c>DataGridColumnHeader</c> control template
/// with a <c>Border</c> around a <c>ContentPresenter</c>. Microsoft's <i>DataGrid Elements</i> lists
/// two named parts on that control - <c>PART_LeftHeaderGripper</c> and
/// <c>PART_RightHeaderGripper</c>, both of type <c>Thumb</c>, "used to resize the column header" -
/// and <c>DataGridColumnHeader</c> declares both as <c>TemplatePart</c> attributes. A template
/// without them gives the control nothing to find, so resizing is not disabled so much as absent.
/// </para>
/// <para>
/// <b>Why it went unnoticed, and why the gate is anchored outside this repository.</b> The template
/// was written to fix a colour defect - dark text on the navy header, <c>F-0056-2</c> - and the
/// part it dropped had nothing to do with colour. Every one of the four grids names this style, so
/// all four lost resizing at once, including the Assets grid that explicitly declares
/// <c>CanUserResizeColumns="True"</c> and was read as evidence the feature worked. The required
/// part names are WPF's contract rather than this product's opinion, which is what stops this gate
/// being a check that agrees with itself.
/// </para>
/// </remarks>
public sealed class ColumnHeaderGripperGateTests
{
    private const string Left = "PART_LeftHeaderGripper";
    private const string Right = "PART_RightHeaderGripper";

    private static readonly XNamespace Presentation =
        "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

    private static readonly XNamespace Xaml = "http://schemas.microsoft.com/winfx/2006/xaml";

    /// <summary>A column header template that cannot be gripped cannot be resized.</summary>
    [Fact]
    public void EveryColumnHeaderTemplateKeepsBothGrippers()
    {
        foreach (var template in ColumnHeaderTemplates(Controls()))
        {
            Assert.Contains(Left, NamedElements(template));
            Assert.Contains(Right, NamedElements(template));
        }
    }

    /// <summary>
    /// The gate reads the real dictionary and would recognise a template that dropped a gripper.
    /// </summary>
    /// <remarks>
    /// The scanner self-test every gate in this tree carries. It proves a column header template
    /// was actually found - with none found, the loop above would iterate nothing and pass while
    /// measuring nothing, which is exactly how this defect survived in the first place - and that
    /// removing a gripper is noticed.
    /// </remarks>
    [Fact]
    public void TheGateReadsTheRealTemplateAndWouldRecogniseADroppedGripper()
    {
        var controls = Controls();

        Assert.NotEmpty(ColumnHeaderTemplates(controls));

        var stripped = XDocument.Parse(
            controls.ToString().Replace(Right, "PART_SomethingElse", StringComparison.Ordinal));

        Assert.DoesNotContain(
            ColumnHeaderTemplates(stripped).SelectMany(NamedElements),
            name => name == Right);
    }

    private static IReadOnlyList<XElement> ColumnHeaderTemplates(XDocument controls) =>
        [.. controls.Descendants(Presentation + "ControlTemplate")
            .Where(template =>
                (string?)template.Attribute("TargetType") == "DataGridColumnHeader")];

    private static IEnumerable<string> NamedElements(XElement template) =>
        template.Descendants()
            .Select(element => (string?)element.Attribute(Xaml + "Name"))
            .Where(name => name is not null)!;

    private static XDocument Controls()
    {
        var path = Path.Combine(ShellRoot(), "Themes", "Controls.xaml");

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
