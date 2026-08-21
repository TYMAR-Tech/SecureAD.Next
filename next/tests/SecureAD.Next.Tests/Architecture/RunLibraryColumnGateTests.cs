using System.Xml.Linq;
using Xunit;

namespace SecureAD.Next.Tests.Architecture;

/// <summary>
/// No column of the run list on Home takes the leftover width.
/// </summary>
/// <remarks>
/// <para>
/// <b>What was seen, and why a file can be read for it.</b> On a running window on 2026-08-21 the
/// owner could reorder the run list's columns freely, could not resize
/// any of them, and saw a wide gap between <i>Run</i> and <i>When</i>. <b>Those were two defects,
/// not one, and an earlier version of this comment wrongly claimed a single cause.</b> Resizing was
/// dead because the column header template had dropped the <c>Thumb</c> parts a column is resized
/// by - that is <c>ColumnHeaderGripperGateTests</c>, and it affected all four grids. This gate is
/// about the other one.
/// </para>
/// <para>
/// <b>The gap.</b> <c>Run</c> was declared <c>Width="*"</c>, and a star column is defined as the one
/// that absorbs whatever space is left over. So the slack was parked inside the table as a gap
/// rather than left at the table's right edge, and the column could never have been dragged
/// narrower even once the grippers were restored, because it refills the instant it is released.
/// </para>
/// <para>
/// <b>This is a fact about a file, so it can be guarded.</b> Almost nothing about how this product
/// looks can be, which is why the gate is worth carrying: the defect is invisible to a build, was
/// found only by a person dragging a column header, and would come back unnoticed the next time a
/// column is added and given a star to make the table fill its space.
/// </para>
/// <para>
/// <b>This gate does not say the columns are well proportioned.</b> It says none of them swallows
/// the slack. Whether the widths read correctly is a judgement only a running window makes.
/// </para>
/// </remarks>
public sealed class RunLibraryColumnGateTests
{
    private static readonly XNamespace Presentation =
        "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

    /// <summary>No column of the run list is star-sized.</summary>
    [Fact]
    public void NoColumnOfTheRunListSwallowsTheLeftoverWidth()
    {
        var starred = StarSizedColumnHeaders(HomeView());

        Assert.Empty(starred);
    }

    /// <summary>
    /// The gate reads the real view, would recognise a star column, and is not merely
    /// searching the file for a star.
    /// </summary>
    /// <remarks>
    /// The scanner self-test every gate in this tree carries. Three things are proved. That the
    /// view was found and parsed and really does declare the run list's columns - an empty result
    /// from a gate that found nothing would otherwise read exactly like a pass. That a star column
    /// would be caught if one returned. And that the gate discriminates: the outer layout
    /// <c>Grid</c> declares <c>Width="*"</c> legitimately, because a screen's own column
    /// <i>should</i> take the leftover space, so a gate that just searched the text for a star would
    /// fail against a correct file and be exempted or deleted within the week.
    /// </remarks>
    [Fact]
    public void TheGateReadsTheRealViewAndWouldRecogniseAStarColumn()
    {
        var view = HomeView();

        Assert.NotEmpty(Columns(view));

        Assert.Contains(
            view.Descendants(Presentation + "ColumnDefinition"),
            definition => (string?)definition.Attribute("Width") == "*");

        var starred = XDocument.Parse(
            view.ToString().Replace("Width=\"Auto\"", "Width=\"*\"", StringComparison.Ordinal));

        Assert.NotEmpty(StarSizedColumnHeaders(starred));
    }

    private static IReadOnlyList<string> StarSizedColumnHeaders(XDocument view) =>
        [.. Columns(view)
            .Where(column => (string?)column.Attribute("Width") == "*")
            .Select(column => (string?)column.Attribute("Header") ?? "(unnamed)")];

    private static IReadOnlyList<XElement> Columns(XDocument view) =>
        [.. view.Descendants(Presentation + "DataGrid.Columns").Elements()];

    private static XDocument HomeView()
    {
        var path = Path.Combine(ShellRoot(), "Views", "HomeView.xaml");

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
