using System.Windows;
using System.Windows.Controls;

namespace SecureAD.Shell.Views;

/// <summary>
/// Lays children out in equal-width columns, sizing each row to its own tallest child.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this has to exist.</b> The object sections laid their fields out in a
/// <see cref="System.Windows.Controls.Primitives.UniformGrid"/>, which gives every cell the size of
/// the largest cell in the whole panel. One field on the Account screen carries a three-line
/// explanation of why <c>lastLogonTimestamp</c> is days out of date, and that one caveat inflated
/// all eight fields to the same height. Eight facts filled a window, most of it empty, and the same
/// panel is used by every section that shows fields.
/// </para>
/// <para>
/// Rows still align across columns, which is what the owner asked for on 2026-09-20 when offered
/// the alternative: independent columns are denser still, but two fields that happen to sit side by
/// side would drift out of line with each other down the page.
/// </para>
/// <para>
/// The measure pass is what does the work. Each child is measured against one column's width rather
/// than the panel's, so a long value wraps inside its own column instead of forcing the panel wider;
/// then a row is only as tall as the tallest child in that row, rather than as tall as the tallest
/// child anywhere.
/// </para>
/// </remarks>
internal sealed class FieldGrid : Panel
{
    /// <summary>How many equal-width columns to lay children out in.</summary>
    public static readonly DependencyProperty ColumnsProperty = DependencyProperty.Register(
        nameof(Columns),
        typeof(int),
        typeof(FieldGrid),
        new FrameworkPropertyMetadata(2, FrameworkPropertyMetadataOptions.AffectsMeasure));

    /// <inheritdoc cref="ColumnsProperty"/>
    public int Columns
    {
        get => (int)GetValue(ColumnsProperty);
        set => SetValue(ColumnsProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var columns = Math.Max(1, Columns);

        // An infinite width would make every column infinitely wide and every value one long line.
        // The sections cap their own width, so this only bites in a measuring pass with no
        // constraint, where falling back to what the children ask for is the honest answer.
        var columnWidth = double.IsInfinity(availableSize.Width)
            ? double.PositiveInfinity
            : availableSize.Width / columns;

        var childSize = new Size(columnWidth, double.PositiveInfinity);

        var totalHeight = 0d;
        var rowHeight = 0d;

        for (var i = 0; i < InternalChildren.Count; i++)
        {
            var child = InternalChildren[i];
            child.Measure(childSize);

            rowHeight = Math.Max(rowHeight, child.DesiredSize.Height);

            var lastInRow = (i % columns) == columns - 1;
            if (lastInRow || i == InternalChildren.Count - 1)
            {
                totalHeight += rowHeight;
                rowHeight = 0d;
            }
        }

        var width = double.IsInfinity(columnWidth)
            ? WidestChild() * columns
            : availableSize.Width;

        return new Size(width, totalHeight);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var columns = Math.Max(1, Columns);
        var columnWidth = finalSize.Width / columns;

        var y = 0d;
        var rowHeight = 0d;

        for (var i = 0; i < InternalChildren.Count; i++)
        {
            var child = InternalChildren[i];
            var column = i % columns;

            child.Arrange(new Rect(column * columnWidth, y, columnWidth, child.DesiredSize.Height));
            rowHeight = Math.Max(rowHeight, child.DesiredSize.Height);

            if (column == columns - 1)
            {
                y += rowHeight;
                rowHeight = 0d;
            }
        }

        return finalSize;
    }

    private double WidestChild()
    {
        var widest = 0d;
        foreach (UIElement child in InternalChildren)
            widest = Math.Max(widest, child.DesiredSize.Width);

        return widest;
    }
}
