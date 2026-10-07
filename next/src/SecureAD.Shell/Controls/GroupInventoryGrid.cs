using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace SecureAD.Shell.Controls;

internal sealed class GroupInventoryGrid : DataGrid
{
    public static readonly DependencyProperty OpenItemCommandProperty = DependencyProperty.Register(
        nameof(OpenItemCommand), typeof(ICommand), typeof(GroupInventoryGrid));

    public ICommand? OpenItemCommand
    {
        get => (ICommand?)GetValue(OpenItemCommandProperty);
        set => SetValue(OpenItemCommandProperty, value);
    }

    protected override void OnMouseDoubleClick(MouseButtonEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        if (e.OriginalSource is not DependencyObject source || e.ChangedButton != MouseButton.Left || IsHeader(source)
            || ItemsControl.ContainerFromElement(this, source) is not DataGridRow row) return;
        Activate(row.Item, e);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Enter && SelectedItem is { } item && !IsHeader(e.OriginalSource as DependencyObject))
            Activate(item, e);
        if (!e.Handled) base.OnKeyDown(e);
    }

    private void Activate(object item, RoutedEventArgs e)
    {
        if (OpenItemCommand?.CanExecute(item) != true) return;
        OpenItemCommand.Execute(item);
        e.Handled = true;
    }

    private static bool IsHeader(DependencyObject? current)
    {
        while (current is not null)
        {
            if (current is DataGridColumnHeader or ButtonBase) return true;
            current = current is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(current) : LogicalTreeHelper.GetParent(current);
        }
        return false;
    }
}

internal sealed class GroupSummaryVisibility : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is double width && width >= 1120 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException("Group summary layout is a one-way view measurement.");
}
