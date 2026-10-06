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

    public static readonly DependencyProperty MinimumColumnWidthProperty = DependencyProperty.Register(
        nameof(MinimumColumnWidth), typeof(double), typeof(FieldGrid),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsMeasure),
        value => value is double width && double.IsFinite(width) && width >= 0);

    /// <summary>When set, reduce the column count to keep fields readable in the available width.</summary>
    public double MinimumColumnWidth
    {
        get => (double)GetValue(MinimumColumnWidthProperty);
        set => SetValue(MinimumColumnWidthProperty, value);
    }

    private int ColumnsFor(double width) =>
        MinimumColumnWidth > 0 && double.IsFinite(width)
            ? (int)Math.Max(1, Math.Min(Math.Max(1, Columns), Math.Floor(width / MinimumColumnWidth)))
            : Math.Max(1, Columns);

    protected override Size MeasureOverride(Size availableSize)
    {
        var columns = ColumnsFor(availableSize.Width);

        // An infinite width would make every column infinitely wide and every value one long line.
        // With no constraint, use what the children ask for.
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
        var columns = ColumnsFor(finalSize.Width);
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
