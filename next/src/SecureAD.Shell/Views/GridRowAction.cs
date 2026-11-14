using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;

namespace SecureAD.Shell.Views;

internal static class GridRowAction
{
    public static readonly DependencyProperty CommandProperty = DependencyProperty.RegisterAttached(
        "Command", typeof(ICommand), typeof(GridRowAction), new PropertyMetadata(null, Changed));

    public static ICommand? GetCommand(DependencyObject element) => (ICommand?)element.GetValue(CommandProperty);
    public static void SetCommand(DependencyObject element, ICommand? value) => element.SetValue(CommandProperty, value);

    private static void Changed(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        if (sender is not DataGrid grid)
            throw new ArgumentException("A finding row action requires a data grid.", nameof(sender));
        grid.MouseDoubleClick -= OpenRow;
        if (args.NewValue is ICommand) grid.MouseDoubleClick += OpenRow;
    }

    private static void OpenRow(object sender, MouseButtonEventArgs args)
    {
        if (sender is not DataGrid grid || args.ChangedButton != MouseButton.Left
            || args.OriginalSource is not DependencyObject source
            || ItemsControl.ContainerFromElement(grid, source) is not DataGridRow row
            || GetCommand(grid) is not { } command || !command.CanExecute(row.Item)) return;
        grid.SetCurrentValue(Selector.SelectedItemProperty, row.Item);
        command.Execute(row.Item);
        args.Handled = true;
    }
}
