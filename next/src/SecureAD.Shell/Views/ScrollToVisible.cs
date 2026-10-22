using System.Windows;
using System.Windows.Threading;

namespace SecureAD.Shell.Views;

internal static class ScrollToVisible
{
    public static readonly DependencyProperty EnabledProperty = DependencyProperty.RegisterAttached(
        "Enabled", typeof(bool), typeof(ScrollToVisible), new PropertyMetadata(false, Changed));

    public static bool GetEnabled(DependencyObject element) => (bool)element.GetValue(EnabledProperty);
    public static void SetEnabled(DependencyObject element, bool value) => element.SetValue(EnabledProperty, value);

    private static void Changed(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        if (sender is not FrameworkElement element)
            throw new ArgumentException("Scroll-to-visible requires a framework element.", nameof(sender));
        element.IsVisibleChanged -= Visible;
        if (args.NewValue is true) element.IsVisibleChanged += Visible;
    }

    private static void Visible(object sender, DependencyPropertyChangedEventArgs args)
    {
        if (args.NewValue is not true || sender is not FrameworkElement element) return;
        element.Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            if (element.IsVisible && GetEnabled(element)) element.BringIntoView();
        }));
    }
}
