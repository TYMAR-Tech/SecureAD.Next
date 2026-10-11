using System.Windows;
using System.Windows.Controls;

namespace SecureAD.Shell.Controls;

internal sealed class AdaptiveDetailPanel : Panel
{
    public static readonly DependencyProperty BreakpointProperty = DependencyProperty.Register(
        nameof(Breakpoint), typeof(double), typeof(AdaptiveDetailPanel),
        new FrameworkPropertyMetadata(1050d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public static readonly DependencyProperty GapProperty = DependencyProperty.Register(
        nameof(Gap), typeof(double), typeof(AdaptiveDetailPanel),
        new FrameworkPropertyMetadata(12d, FrameworkPropertyMetadataOptions.AffectsMeasure));

    public double Breakpoint
    {
        get => (double)GetValue(BreakpointProperty);
        set => SetValue(BreakpointProperty, value);
    }

    public double Gap
    {
        get => (double)GetValue(GapProperty);
        set => SetValue(GapProperty, value);
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        if (InternalChildren.Count == 0) return new();
        var width = double.IsInfinity(availableSize.Width) ? 0 : Math.Max(0, availableSize.Width);
        if (InternalChildren.Count == 1)
        {
            InternalChildren[0].Measure(new(width, double.PositiveInfinity));
            return InternalChildren[0].DesiredSize;
        }

        if (UseWideLayout(width))
        {
            var contentWidth = Math.Max(0, width - Gap);
            var masterWidth = contentWidth * 0.6;
            var detailWidth = contentWidth - masterWidth;
            InternalChildren[0].Measure(new(masterWidth, double.PositiveInfinity));
            InternalChildren[1].Measure(new(detailWidth, double.PositiveInfinity));
            return new(width, Math.Max(InternalChildren[0].DesiredSize.Height, InternalChildren[1].DesiredSize.Height));
        }

        foreach (UIElement child in InternalChildren)
            child.Measure(new(width, double.PositiveInfinity));
        return new(width, InternalChildren.Cast<UIElement>().Sum(child => child.DesiredSize.Height)
            + Gap * (InternalChildren.Count - 1));
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        if (InternalChildren.Count == 0) return finalSize;
        if (InternalChildren.Count == 1)
        {
            InternalChildren[0].Arrange(new(new(), finalSize));
            return finalSize;
        }

        if (UseWideLayout(finalSize.Width))
        {
            var contentWidth = Math.Max(0, finalSize.Width - Gap);
            var masterWidth = contentWidth * 0.6;
            InternalChildren[0].Arrange(new(0, 0, masterWidth, finalSize.Height));
            InternalChildren[1].Arrange(new(masterWidth + Gap, 0, contentWidth - masterWidth, finalSize.Height));
            return finalSize;
        }

        var top = 0d;
        foreach (UIElement child in InternalChildren)
        {
            child.Arrange(new(0, top, finalSize.Width, child.DesiredSize.Height));
            top += child.DesiredSize.Height + Gap;
        }
        return finalSize;
    }

    private bool UseWideLayout(double width) => width >= Breakpoint && InternalChildren.Count >= 2;
}
